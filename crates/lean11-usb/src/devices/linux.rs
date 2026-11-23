//! Linux: /sys/block for the disks (USB = the device path runs through a USB host), udev's database
//! for file system type and label, /proc/mounts and /proc/swaps for what is in use.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::{Device, Part};

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// /proc/mounts escapes blanks as \040.
fn unescape(s: &str) -> String {
    s.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
}

/// block device name (sdb1, dm-0) -> mount points
fn mounts() -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for line in read("/proc/mounts").lines() {
        let mut f = line.split_whitespace();
        let (Some(src), Some(dir)) = (f.next(), f.next()) else { continue };
        if !src.starts_with("/dev/") {
            continue;
        }
        let real = std::fs::canonicalize(unescape(src)).unwrap_or_else(|_| PathBuf::from(src));
        if let Some(n) = real.file_name() {
            m.entry(n.to_string_lossy().into_owned()).or_default().push(unescape(dir));
        }
    }
    m
}

/// Block devices that carry the running system: mounted at a system path or used as swap,
/// followed through device-mapper/RAID layers down to the partitions below.
fn system_devices(mounts: &HashMap<String, Vec<String>>) -> HashSet<String> {
    const SYS: &[&str] = &["/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home", "/opt", "/srv", "/nix"];
    let mut todo: Vec<String> = mounts.iter().filter(|(_, ms)| ms.iter().any(|m| SYS.contains(&m.as_str()))).map(|(n, _)| n.clone()).collect();
    for line in read("/proc/swaps").lines().skip(1) {
        if let Some(src) = line.split_whitespace().next()
            && let Ok(real) = std::fs::canonicalize(src)
            && real.starts_with("/dev")
            && let Some(n) = real.file_name()
        {
            todo.push(n.to_string_lossy().into_owned());
        }
    }
    let mut out = HashSet::new();
    while let Some(n) = todo.pop() {
        if !out.insert(n.clone()) {
            continue;
        }
        let base = class_dir(&n);
        if let Ok(rd) = std::fs::read_dir(base.join("slaves")) {
            todo.extend(rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()));
        }
    }
    out
}

fn class_dir(name: &str) -> PathBuf {
    PathBuf::from("/sys/class/block").join(name)
}

/// File system type and label from udev's database (no blkid needed, no root needed).
fn udev_props(dev: &Path) -> HashMap<String, String> {
    let mm = read(dev.join("dev"));
    let mut m = HashMap::new();
    for line in read(format!("/run/udev/data/b{mm}")).lines() {
        if let Some(kv) = line.strip_prefix("E:")
            && let Some((k, v)) = kv.split_once('=')
        {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

/// Serial number of the USB device the disk belongs to.
fn usb_serial(real: &Path) -> String {
    let mut p = real.to_path_buf();
    while p.pop() {
        if p.join("idVendor").exists() && p.join("serial").exists() {
            return read(p.join("serial"));
        }
    }
    String::new()
}

pub fn list_all() -> Result<Vec<Device>> {
    let mounts = mounts();
    let system = system_devices(&mounts);
    let mut out = Vec::new();
    let mut names: Vec<String> = std::fs::read_dir("/sys/block").context("cannot read /sys/block")?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    for name in names {
        if ["loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd", "zd"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let dir = PathBuf::from("/sys/block").join(&name);
        let real = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
        let usb = real.components().any(|c| c.as_os_str().to_string_lossy().starts_with("usb"));
        let removable = read(dir.join("removable")) == "1";
        let size = read(dir.join("size")).parse::<u64>().unwrap_or(0) * 512;
        let mut parts = Vec::new();
        let mut sys = system.contains(&name);
        let mut pnames: Vec<String> = std::fs::read_dir(&dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with(&name) && dir.join(n).join("partition").exists()).collect()).unwrap_or_default();
        pnames.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
        for p in pnames {
            let pd = dir.join(&p);
            let props = udev_props(&pd);
            sys |= system.contains(&p);
            parts.push(Part {
                size: read(pd.join("size")).parse::<u64>().unwrap_or(0) * 512,
                fs: props.get("ID_FS_TYPE").cloned().unwrap_or_default(),
                label: props.get("ID_FS_LABEL").cloned().unwrap_or_default(),
                mount: mounts.get(&p).and_then(|m| m.first().cloned()),
                name: p,
            });
        }
        let props = udev_props(&dir);
        out.push(Device {
            path: format!("/dev/{name}"),
            size,
            vendor: read(dir.join("device/vendor")),
            model: read(dir.join("device/model")),
            serial: props.get("ID_SERIAL_SHORT").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| usb_serial(&real)),
            usb,
            removable,
            system: sys,
            parts,
        });
    }
    Ok(out)
}

const BLKRRPART: libc::c_ulong = 0x125f;

/// Unmounts the partitions of `d` and opens it exclusively with O_DIRECT (no page cache, so the
/// read-back check really reads the stick). Returns the open device and its size.
pub fn open_raw(d: &Device, write: bool) -> Result<(File, u64)> {
    if write {
        for p in &d.parts {
            if let Some(m) = &p.mount {
                let c = std::ffi::CString::new(m.as_str())?;
                if unsafe { libc::umount2(c.as_ptr(), 0) } != 0 {
                    bail!("cannot unmount {m}: {}", std::io::Error::last_os_error());
                }
            }
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_DIRECT | if write { libc::O_EXCL } else { 0 })
        .open(&d.path)
        .with_context(|| format!("cannot open {} (in use?)", d.path))?;
    let mut size: u64 = 0;
    // BLKGETSIZE64
    if unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&f), 0x8008_1272, &mut size) } != 0 {
        bail!("cannot read the size of {}", d.path);
    }
    Ok((f, size))
}

/// Flushes the device and makes the kernel read the new partition table.
pub fn finish(f: &File) -> Result<()> {
    f.sync_all()?;
    unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(f), BLKRRPART) };
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn mount_escapes() {
        assert_eq!(super::unescape("/media/u/My\\040Stick"), "/media/u/My Stick");
    }

    /// Smoke test on the build host: listing works and never offers the disk holding /.
    #[test]
    fn lists_without_system_disk() {
        let all = super::list_all().unwrap();
        assert!(super::super::list().unwrap().iter().all(|d| !d.system));
        if let Some(root) = all.iter().find(|d| d.parts.iter().any(|p| p.mount.as_deref() == Some("/"))) {
            assert!(root.system);
        }
    }
}
