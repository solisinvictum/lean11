//! macOS: `diskutil list/info -plist` for the drives (external physical disks only), writing through
//! the raw node /dev/rdiskN after `diskutil unmountDisk`.

use std::fs::{File, OpenOptions};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use super::{Device, Part};

fn to_json(n: roxmltree::Node) -> Value {
    match n.tag_name().name() {
        "dict" => {
            let mut m = Map::new();
            let kids: Vec<_> = n.children().filter(|c| c.is_element()).collect();
            for pair in kids.chunks(2) {
                if let [k, v] = pair {
                    m.insert(k.text().unwrap_or("").to_string(), to_json(*v));
                }
            }
            Value::Object(m)
        }
        "array" => Value::Array(n.children().filter(|c| c.is_element()).map(to_json).collect()),
        "integer" => n.text().and_then(|t| t.trim().parse::<i64>().ok()).map(Value::from).unwrap_or(Value::Null),
        "real" => n.text().and_then(|t| t.trim().parse::<f64>().ok()).map(Value::from).unwrap_or(Value::Null),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(n.text().unwrap_or("").to_string()),
    }
}

fn diskutil(args: &[&str]) -> Result<Value> {
    let out = Command::new("diskutil").args(args).output().context("cannot run diskutil")?;
    if !out.status.success() {
        bail!("diskutil {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    parse_plist(&String::from_utf8_lossy(&out.stdout))
}

/// A plist as diskutil prints it (with Apple's DOCTYPE line, which roxmltree refuses by default).
fn parse_plist(text: &str) -> Result<Value> {
    let opt = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opt).context("diskutil printed no plist")?;
    let root = doc.root_element().children().find(|c| c.is_element()).ok_or_else(|| anyhow::anyhow!("empty plist"))?;
    Ok(to_json(root))
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

pub fn list_all() -> Result<Vec<Device>> {
    let l = diskutil(&["list", "-plist", "external", "physical"])?;
    let mut out = Vec::new();
    for d in l.get("AllDisksAndPartitions").and_then(Value::as_array).into_iter().flatten() {
        let id = s(d, "DeviceIdentifier");
        if id.is_empty() {
            continue;
        }
        let info = diskutil(&["info", "-plist", &id]).unwrap_or(Value::Null);
        let parts: Vec<Part> = d
            .get("Partitions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|p| Part {
                name: s(p, "DeviceIdentifier"),
                size: p.get("Size").and_then(Value::as_u64).unwrap_or(0),
                fs: s(p, "Content"),
                label: s(p, "VolumeName"),
                mount: Some(s(p, "MountPoint")).filter(|m| !m.is_empty()),
            })
            .collect();
        let internal = info.get("Internal").and_then(Value::as_bool).unwrap_or(true);
        out.push(Device {
            path: format!("/dev/{id}"),
            size: info.get("TotalSize").or_else(|| d.get("Size")).and_then(Value::as_u64).unwrap_or(0),
            vendor: String::new(),
            model: s(&info, "MediaName"),
            serial: String::new(),
            usb: s(&info, "BusProtocol") == "USB",
            removable: !internal && (info.get("RemovableMediaOrExternalDevice").and_then(Value::as_bool).unwrap_or(false) || info.get("Ejectable").and_then(Value::as_bool).unwrap_or(false)),
            system: parts.iter().any(|p| p.mount.as_deref() == Some("/")),
            parts,
        });
    }
    Ok(out)
}

pub fn open_raw(d: &Device, write: bool) -> Result<(File, u64)> {
    if write {
        let st = Command::new("diskutil").args(["unmountDisk", "force", &d.path]).status().context("cannot run diskutil")?;
        if !st.success() {
            bail!("cannot unmount {}", d.path);
        }
    }
    let raw = d.path.replacen("/dev/disk", "/dev/rdisk", 1);
    let f = OpenOptions::new().read(true).write(write).open(&raw).with_context(|| format!("cannot open {raw}"))?;
    Ok((f, d.size))
}

/// Flushes the raw disk. `File::sync_all` uses F_FULLFSYNC on macOS, which raw devices refuse (ENOTTY):
/// a plain fsync, then DKIOCSYNCHRONIZECACHE asks the drive to empty its write cache.
pub fn finish(f: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot flush the drive");
    }
    // _IO('d', 22); a drive without a cache may refuse it, the data is on it already
    const DKIOCSYNCHRONIZECACHE: libc::c_ulong = 0x2000_6416;
    unsafe { libc::ioctl(fd, DKIOCSYNCHRONIZECACHE) };
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_to_json() {
        let x = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>AllDisksAndPartitions</key><array><dict><key>DeviceIdentifier</key><string>disk4</string><key>Size</key><integer>126000000000</integer><key>Partitions</key><array><dict><key>DeviceIdentifier</key><string>disk4s1</string><key>VolumeName</key><string>Ventoy</string><key>MountPoint</key><string>/Volumes/Ventoy</string></dict></array></dict></array><key>X</key><true/></dict></plist>"#;
        let doc = roxmltree::Document::parse(x).unwrap();
        let v = super::to_json(doc.root_element().children().find(|c| c.is_element()).unwrap());
        assert_eq!(v["AllDisksAndPartitions"][0]["Partitions"][0]["VolumeName"], "Ventoy");
        assert_eq!(v["AllDisksAndPartitions"][0]["Size"], 126000000000i64);
        assert_eq!(v["X"], true);
    }

    /// diskutil's real output starts with a DOCTYPE (macOS 27, MacBook, no external disk)
    #[test]
    fn plist_with_doctype() {
        let x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>AllDisks</key>\n\t<array/>\n\t<key>AllDisksAndPartitions</key>\n\t<array/>\n</dict>\n</plist>\n";
        let v = super::parse_plist(x).unwrap();
        assert_eq!(v["AllDisksAndPartitions"].as_array().map(Vec::len), Some(0));
    }
}
