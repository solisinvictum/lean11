//! Removable drives: listing (only USB or removable disks, never the system disk), exclusive raw
//! access for writing and verifying, and refreshing the partition table afterwards.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{finish, list_all, open_raw};
// also built for the tests elsewhere, so its plist parsing is tested on every platform
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{finish, list_all, open_raw};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{elevate as windows_elevate, finish, list_all, open_raw};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Part {
    pub name: String,
    pub size: u64,
    pub fs: String,
    pub label: String,
    pub mount: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Device {
    /// What the user and the CLI name it: /dev/sdb, /dev/disk4, \\.\PhysicalDrive2.
    pub path: String,
    pub size: u64,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub usb: bool,
    pub removable: bool,
    /// Holds the running system (or its boot, home or swap): never offered.
    pub system: bool,
    pub parts: Vec<Part>,
}

impl Device {
    /// May be written: on USB or removable, and not the system disk.
    pub fn eligible(&self) -> bool {
        (self.usb || self.removable) && !self.system && self.size > 0
    }

    pub fn title(&self) -> String {
        let name = [self.vendor.trim(), self.model.trim()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ");
        let name = if name.is_empty() { "USB drive".to_string() } else { name };
        format!("{name}, {} ({})", human(self.size), self.path)
    }

    /// One line per partition, for the confirmation.
    pub fn part_lines(&self) -> Vec<String> {
        self.parts
            .iter()
            .map(|p| {
                let mut s = format!("{} {}", p.name, human(p.size));
                if !p.fs.is_empty() {
                    s += &format!(" {}", p.fs);
                }
                if !p.label.is_empty() {
                    s += &format!(" \"{}\"", p.label);
                }
                if let Some(m) = &p.mount {
                    s += &format!(" mounted at {m}");
                }
                s
            })
            .collect()
    }

    /// A Ventoy stick whose data partition is mounted: an ISO can simply be copied there.
    pub fn ventoy_mount(&self) -> Option<&str> {
        // Ventoy's EFI partition "VTOYEFI" is always 32 MiB; macOS does not mount it, so its label can be missing
        let is_ventoy = self.parts.iter().any(|p| p.label.eq_ignore_ascii_case("VTOYEFI") || (p.label.is_empty() && p.size == 32 << 20));
        self.parts.iter().find(|p| is_ventoy && p.label.eq_ignore_ascii_case("Ventoy")).and_then(|p| p.mount.as_deref())
    }

    /// The Ventoy data partition, when it is mounted writable (macOS mounts NTFS read-only).
    pub fn ventoy_writable(&self) -> Option<&str> {
        let m = self.ventoy_mount()?;
        let probe = std::path::Path::new(m).join(format!(".lean11-write-test-{}", std::process::id()));
        // create_new: never follow or truncate something already there
        let ok = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
        if ok {
            let _ = std::fs::remove_file(&probe);
        }
        ok.then_some(m)
    }
}

pub fn human(b: u64) -> String {
    let g = b as f64 / (1u64 << 30) as f64;
    if g >= 1.0 { format!("{g:.1} GiB") } else { format!("{} MiB", b >> 20) }
}

/// The drives that may be written.
pub fn list() -> anyhow::Result<Vec<Device>> {
    Ok(list_all()?.into_iter().filter(Device::eligible).collect())
}

/// The drive at `path` as it is now (to compare with what the user chose).
pub fn find(path: &str) -> anyhow::Result<Option<Device>> {
    Ok(list_all()?.into_iter().find(|d| d.path == path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_and_ventoy() {
        let mut d = Device { path: "/dev/sdb".into(), size: 128 << 30, model: "Savage".into(), vendor: "HyperX".into(), usb: true, ..Default::default() };
        assert!(d.eligible());
        d.system = true;
        assert!(!d.eligible(), "the system disk is never offered");
        d.system = false;
        d.usb = false;
        assert!(!d.eligible(), "internal fixed disks are not offered");
        d.usb = true;
        d.parts = vec![
            Part { name: "sdb1".into(), label: "Ventoy".into(), mount: Some("/media/u/Ventoy".into()), ..Default::default() },
            Part { name: "sdb2".into(), label: "VTOYEFI".into(), ..Default::default() },
        ];
        assert_eq!(d.ventoy_mount(), Some("/media/u/Ventoy"));
        // macOS: the 32 MiB EFI partition is not mounted and has no label
        d.parts[1] = Part { name: "disk5s2".into(), size: 32 << 20, ..Default::default() };
        assert_eq!(d.ventoy_mount(), Some("/media/u/Ventoy"));
        d.parts[1].size = 100 << 20;
        assert_eq!(d.ventoy_mount(), None, "a partition named Ventoy alone is not Ventoy");
        assert_eq!(d.title(), "HyperX Savage, 128.0 GiB (/dev/sdb)");
    }
}
