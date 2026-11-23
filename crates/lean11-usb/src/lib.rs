//! Bootable Windows installation USB sticks without external tools.
//!
//! The unprivileged side builds a [`Plan`] (the media files, split for FAT32 if needed, and the target);
//! [`execute`] does the privileged part: check the drive again, write MBR + FAT32 + files + BIOS boot
//! code, read everything back. When lean11 does not run as root/administrator, [`run_elevated`] starts
//! `lean11 usb-write <plan>` through sudo/pkexec (Linux, macOS) or UAC (Windows).

pub mod boot;
pub mod devices;
pub mod disk;
pub mod fat;
pub mod media;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub use devices::Device;
pub use media::Media;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Target {
    /// A disk image file (created or replaced).
    Image(PathBuf),
    /// A drive as the user chose it; size and serial must still match when writing.
    Device { path: String, size: u64, serial: String, title: String },
}

impl Target {
    pub fn of(d: &Device) -> Target {
        Target::Device { path: d.path.clone(), size: d.size, serial: d.serial.clone(), title: d.title() }
    }

    pub fn describe(&self) -> String {
        match self {
            Target::Image(p) => p.display().to_string(),
            Target::Device { title, .. } => title.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub media: Media,
    pub target: Target,
    pub verify: bool,
}

/// Re-reads the drive and refuses when it is no longer the one that was chosen.
fn recheck(path: &str, size: u64, serial: &str) -> Result<Device> {
    let d = devices::find(path)?.ok_or_else(|| anyhow::anyhow!("{path} is gone"))?;
    if d.system {
        bail!("{path} holds the running system: refusing to write");
    }
    if !d.eligible() {
        bail!("{path} is neither a USB nor a removable drive: refusing to write");
    }
    if d.size != size || d.serial != serial {
        bail!("{path} is not the drive that was chosen any more (size or serial changed): nothing was written");
    }
    Ok(d)
}

fn pct_logger<'a>(what: &'a str, log: &'a mut dyn FnMut(&str)) -> impl FnMut(u64, u64) + 'a {
    let mut last = u64::MAX;
    move |done, total| {
        let p = if total == 0 { 100 } else { done * 100 / total };
        if p / 5 != last {
            last = p / 5;
            log(&format!("{what}: {} of {} ({p}%)", devices::human(done), devices::human(total)));
        }
    }
}

/// The privileged part: write the media to the target and check it. Needs root/administrator for drives.
pub fn execute(plan: &Plan, log: &mut dyn FnMut(&str)) -> Result<()> {
    let m = &plan.media;
    let iso = m.open_iso()?;
    let code = match m.read_all("boot/bootsect.exe", iso.as_ref())? {
        Some(exe) => {
            let c = boot::from_bootsect(&exe);
            if c.is_none() {
                log("note: the BIOS boot code in boot/bootsect.exe was not recognized; the stick boots on UEFI only");
            }
            c
        }
        None => {
            log("note: the media has no boot/bootsect.exe; the stick boots on UEFI only");
            None
        }
    };
    let layout = fat::plan(m);
    log(&format!("Writing {} to {} (FAT32 partition of {})", devices::human(m.total()), plan.target.describe(), devices::human(layout.part_len)));
    match &plan.target {
        Target::Image(p) => {
            let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(p).with_context(|| format!("cannot create {}", p.display()))?;
            f.set_len(layout.disk_len())?;
            let mut d = disk::CachedDisk::new(f, layout.disk_len(), true);
            let written = fat::write(&mut d, layout.disk_len(), layout, m, iso.as_ref(), code.as_ref(), &mut pct_logger("Writing", log))?;
            let f = d.into_inner()?;
            f.sync_all()?;
            if plan.verify {
                let mut d = disk::CachedDisk::new(f, layout.disk_len(), false);
                fat::verify(&mut d, layout, &written, &mut pct_logger("Checking", log))?;
            }
        }
        Target::Device { path, size, serial, .. } => {
            let dev = recheck(path, *size, serial)?;
            let (f, len) = devices::open_raw(&dev, true)?;
            if len < layout.disk_len() {
                bail!("{} holds {}, the media needs {}", dev.title(), devices::human(len), devices::human(layout.disk_len()));
            }
            let mut d = disk::CachedDisk::new(f, len, true);
            let written = fat::write(&mut d, len, layout, m, iso.as_ref(), code.as_ref(), &mut pct_logger("Writing", log))?;
            let f = d.into_inner()?;
            devices::finish(&f)?;
            drop(f);
            if plan.verify {
                let (f, len) = devices::open_raw(&dev, false)?;
                let mut d = disk::CachedDisk::new(f, len, false);
                fat::verify(&mut d, layout, &written, &mut pct_logger("Checking", log))?;
            }
        }
    }
    log(if plan.verify { "Done: written and checked." } else { "Done: written." });
    log(if code.is_some() { "It boots on UEFI (also with Secure Boot) and on BIOS." } else { "It boots on UEFI (also with Secure Boot)." });
    Ok(())
}

/// Whether this process may write to drives itself.
pub fn privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        lean11_wim::platform::is_admin()
    }
}

/// Runs `exe usb-write <plan>` with root/administrator rights and waits for it.
/// Unix: sudo (password on the terminal) or pkexec; Windows: UAC prompt, the helper writes its
/// output to `<plan>.log`, which is shown afterwards.
pub fn run_elevated(exe: &Path, plan_file: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let which = |n: &str| std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(n)).find(|c| c.is_file()));
        let (tool, args): (PathBuf, Vec<&std::ffi::OsStr>) = if let Some(s) = which("sudo") {
            (s, vec!["--".as_ref()])
        } else if let Some(p) = which("pkexec") {
            (p, vec![])
        } else {
            bail!("writing to a drive needs root: run lean11 as root (neither sudo nor pkexec found)");
        };
        eprintln!("Writing to the drive needs administrator rights ({}):", tool.display());
        let digest = plan_digest(plan_file)?;
        let st = std::process::Command::new(&tool)
            .args(args)
            .arg(exe)
            .arg("usb-write")
            .arg(plan_file)
            .arg("--sha256")
            .arg(&digest)
            .status()
            .with_context(|| format!("cannot start {}", tool.display()))?;
        if !st.success() {
            bail!("writing the stick failed (see above)");
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        devices::windows_elevate(exe, plan_file, &plan_digest(plan_file)?)
    }
}

/// Plan file next to the work data (JSON).
pub fn save_plan(plan: &Plan, dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join("usb-plan.json");
    std::fs::write(&p, serde_json::to_vec_pretty(plan)?)?;
    Ok(p)
}

/// SHA-256 of the plan file: it goes on the helper's command line (which sudo, pkexec or UAC runs as
/// given), so a plan changed after the user's confirmation is refused.
pub fn plan_digest(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?)))
}

/// Loads the plan for the elevated helper: only with the digest the caller passed, and only for a drive
/// (an image file never needs administrator rights, and root must not write files on a plan's word).
pub fn load_plan(p: &Path, digest: &str) -> Result<Plan> {
    let bytes = std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?;
    use sha2::{Digest, Sha256};
    if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(digest.trim()) {
        bail!("the plan file {} was changed after it was written: nothing was written", p.display());
    }
    let plan: Plan = serde_json::from_slice(&bytes).context("bad plan file")?;
    if !matches!(plan.target, Target::Device { .. }) {
        bail!("the helper only writes drives");
    }
    Ok(plan)
}
