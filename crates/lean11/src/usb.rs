//! `lean11 usb`: write installation media to a USB stick (or an image file), and the helper that does
//! the privileged part (`usb-write`). Also used after `build --usb` and by the TUI.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use lean11_usb::{Device, Plan, Target, devices, media};

#[derive(clap::Args, Clone, Debug, Default)]
pub struct UsbArgs {
    /// ISO or media directory to write
    pub source: Option<PathBuf>,
    /// Drive to erase and write (e.g. /dev/sdb, /dev/disk4, \\.\PhysicalDrive2); asked when missing
    #[arg(long)]
    pub device: Option<String>,
    /// Write a disk image file instead of a drive (for VMs or a later dd)
    #[arg(long, conflicts_with = "device")]
    pub image: Option<PathBuf>,
    /// Only list the drives that can be written
    #[arg(long)]
    pub list: bool,
    /// Do not ask before erasing the drive (scripts)
    #[arg(long)]
    pub yes: bool,
    /// Do not read the stick back after writing
    #[arg(long)]
    pub no_verify: bool,
    /// Directory for a split install image (install image over 4 GiB; default: next to the source)
    #[arg(long)]
    pub work: Option<PathBuf>,
    /// On a Ventoy stick: erase it instead of copying the ISO onto it
    #[arg(long)]
    pub no_ventoy: bool,
}

fn prompt(q: &str) -> Result<String> {
    eprint!("{q}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

pub fn print_devices(list: &[Device]) {
    if list.is_empty() {
        eprintln!("No USB or removable drive found.");
    }
    for (i, d) in list.iter().enumerate() {
        eprintln!("  [{}] {}{}", i + 1, d.title(), if d.ventoy_mount().is_some() { "  (Ventoy)" } else { "" });
        for p in d.part_lines() {
            eprintln!("        {p}");
        }
    }
}

/// Lets the user pick a drive (or takes the one given) and returns it as it is now.
pub fn choose_device(given: Option<&str>) -> Result<Device> {
    if let Some(p) = given {
        let d = devices::find(p)?.ok_or_else(|| anyhow::anyhow!("no drive {p}"))?;
        if !d.eligible() {
            bail!("{p} is not a USB or removable drive, or it holds the running system: lean11 does not write to it");
        }
        return Ok(d);
    }
    let list = devices::list()?;
    if list.is_empty() {
        bail!("No USB or removable drive found. Plug in a stick and try again.");
    }
    eprintln!("Drives that can be written:");
    print_devices(&list);
    let a = prompt(&format!("Which drive? [1-{}, empty = cancel] ", list.len()))?;
    let n: usize = a.parse().map_err(|_| anyhow::anyhow!("cancelled"))?;
    list.get(n.wrapping_sub(1)).cloned().ok_or_else(|| anyhow::anyhow!("no drive {n}"))
}

pub fn confirm_erase(d: &Device) -> Result<bool> {
    eprintln!("ALL DATA on {} will be erased:", d.title());
    for p in d.part_lines() {
        eprintln!("    {p}");
    }
    let a = prompt("Erase it and write the installation media? [y/N] ")?;
    Ok(matches!(a.to_lowercase().as_str(), "y" | "yes" | "j" | "ja"))
}

/// Copies an ISO onto the mounted data partition of a Ventoy stick (nothing is erased).
pub fn copy_to_ventoy(iso: &Path, mount: &str) -> Result<PathBuf> {
    let dest = Path::new(mount).join(iso.file_name().ok_or_else(|| anyhow::anyhow!("no file name"))?);
    if dest.exists() {
        bail!("{} already exists on the Ventoy stick (--no-ventoy erases the stick instead)", dest.display());
    }
    let total = std::fs::metadata(iso)?.len();
    let tmp = dest.with_extension("iso.part");
    let mut r = std::fs::File::open(iso)?;
    // a leftover partial copy goes first (remove_file removes a link itself, not its target)
    let _ = std::fs::remove_file(&tmp);
    let mut w = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).with_context(|| format!("cannot write to {mount}"))?;
    let mut buf = vec![0u8; 8 << 20];
    let (mut done, mut last) = (0u64, u64::MAX);
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n])?;
        done += n as u64;
        if done * 20 / total.max(1) != last {
            last = done * 20 / total.max(1);
            eprintln!("Copying to Ventoy: {} of {} ({}%)", devices::human(done), devices::human(total), done * 100 / total.max(1));
        }
    }
    w.sync_all()?;
    drop(w);
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

/// Builds the plan for `source` and runs it (directly as root/administrator, else through the helper).
pub fn write_media(source: &Path, target: Target, verify: bool, work: Option<&Path>) -> Result<()> {
    write_media_log(source, target, verify, work, &mut |l| eprintln!("{l}"))
}

/// As [`write_media`], with the messages going to `log` (the build log).
pub fn write_media_log(source: &Path, target: Target, verify: bool, work: Option<&Path>, log: &mut dyn FnMut(&str)) -> Result<()> {
    let mut m = if source.is_dir() { media::from_dir(source, "lean11")? } else { media::from_iso(source)? };
    // our own folder below the chosen place, removed afterwards
    let base = work.map(Path::to_path_buf).unwrap_or_else(|| source.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf());
    let work = base.join(format!("lean11-usb-{}", std::process::id()));
    media::fit_fat32(&mut m, &work, log)?;
    let plan = Plan { media: m, target, verify };
    let r = if lean11_usb::privileged() || matches!(plan.target, Target::Image(_)) {
        lean11_usb::execute(&plan, log)
    } else {
        let file = lean11_usb::save_plan(&plan, &work)?;
        lean11_usb::run_elevated(&std::env::current_exe()?, &file)
    };
    if work.exists() {
        let _ = std::fs::remove_dir_all(&work);
    }
    r
}

pub fn usb_cmd(a: UsbArgs) -> Result<()> {
    if a.list {
        print_devices(&devices::list()?);
        return Ok(());
    }
    let source = a.source.clone().ok_or_else(|| anyhow::anyhow!("name the ISO or media directory to write (lean11 usb <ISO>)"))?;
    if !source.exists() {
        bail!("{} does not exist", source.display());
    }
    if let Some(img) = &a.image {
        if img.exists() && !a.yes && !matches!(prompt(&format!("{} exists. Replace it? [y/N] ", img.display()))?.to_lowercase().as_str(), "y" | "yes" | "j" | "ja") {
            bail!("cancelled");
        }
        return write_media(&source, Target::Image(img.clone()), !a.no_verify, a.work.as_deref());
    }
    let d = choose_device(a.device.as_deref())?;
    if d.ventoy_mount().is_some() && d.ventoy_writable().is_none() && source.is_file() && !a.no_ventoy {
        eprintln!("{} is a Ventoy stick, but its data partition is mounted read-only (NTFS on macOS): the ISO cannot be copied onto it.", d.title());
    }
    if let Some(mount) = d.ventoy_writable()
        && source.is_file()
        && !a.no_ventoy
    {
        let copy = a.yes || !matches!(prompt(&format!("{} is a Ventoy stick: copy the ISO onto it and keep everything [Y], or erase the whole stick [e]? ", d.title()))?.to_lowercase().as_str(), "e");
        if copy {
            let dest = copy_to_ventoy(&source, mount)?;
            eprintln!("Copied to {}. Boot the stick and pick it in the Ventoy menu.", dest.display());
            return Ok(());
        }
    }
    if !a.yes && !confirm_erase(&d)? {
        bail!("cancelled, nothing was written");
    }
    write_media(&source, Target::of(&d), !a.no_verify, a.work.as_deref())?;
    eprintln!("The stick is ready.");
    Ok(())
}

/// The privileged helper: runs the plan, mirrors its output into `log` (Windows: shown by the caller).
pub fn usb_write_cmd(plan: &Path, digest: &str, log: Option<&Path>) -> Result<()> {
    let mut file = log.map(std::fs::File::create).transpose()?;
    let mut out = |l: &str| {
        eprintln!("{l}");
        if let Some(f) = file.as_mut() {
            let _ = writeln!(f, "{l}");
        }
    };
    let r = lean11_usb::load_plan(plan, digest).and_then(|p| lean11_usb::execute(&p, &mut out));
    if let Err(e) = &r {
        out(&format!("Error: {e:#}"));
    }
    r
}
