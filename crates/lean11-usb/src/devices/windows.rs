//! Windows: physical drives \\.\PhysicalDriveN (bus type and serial from IOCTL_STORAGE_QUERY_PROPERTY),
//! their volumes by drive letter; for writing every volume of the drive is locked and dismounted and the
//! drive is opened unbuffered (all transfers are sector aligned, see disk.rs). The descriptors are read
//! as raw bytes with their documented offsets, the IOCTL codes are the documented values.

use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE, GetVolumeInformationW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

use super::{Device, Part};

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00a0;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405c;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
const IOCTL_DISK_UPDATE_PROPERTIES: u32 = 0x0007_0140;
const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
const BUS_TYPE_USB: u32 = 7;
const BUS_TYPE_SD: u32 = 12;
const BUS_TYPE_MMC: u32 = 13;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct H(HANDLE);

// a kernel handle may be used and closed from any thread
unsafe impl Send for H {}

impl Drop for H {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn open(path: &str, access: u32, flags: u32) -> Option<H> {
    let w = wide(path);
    let h = unsafe { CreateFileW(w.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut()) };
    (h != INVALID_HANDLE_VALUE).then_some(H(h))
}

fn ioctl(h: &H, code: u32, input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h.0,
            code,
            if input.is_empty() { std::ptr::null() } else { input.as_ptr().cast() },
            input.len() as u32,
            if out.is_empty() { std::ptr::null_mut() } else { out.as_mut_ptr().cast() },
            out.len() as u32,
            &mut n,
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(n as usize)
}

fn cstr_at(buf: &[u8], off: usize) -> String {
    if off == 0 || off >= buf.len() {
        return String::new();
    }
    let end = buf[off..].iter().position(|&b| b == 0).map(|p| off + p).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[off..end]).trim().to_string()
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Drive letter -> (disk number, partition offset, length) for every volume.
fn volumes() -> Vec<(char, u32, u64)> {
    let mut v = Vec::new();
    for l in 'A'..='Z' {
        let Some(h) = open(&format!("\\\\.\\{l}:"), 0, 0) else { continue };
        let mut buf = [0u8; 8 + 24 * 8];
        if ioctl(&h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], &mut buf).is_some() {
            let n = u32_at(&buf, 0) as usize;
            for i in 0..n.min(8) {
                let e = 8 + i * 24;
                let disk = u32_at(&buf, e);
                let len = u64::from_le_bytes(buf[e + 16..e + 24].try_into().unwrap());
                v.push((l, disk, len));
            }
        }
    }
    v
}

fn volume_info(l: char) -> (String, String) {
    let root = wide(&format!("{l}:\\"));
    let (mut name, mut fs) = ([0u16; 261], [0u16; 261]);
    let ok = unsafe { GetVolumeInformationW(root.as_ptr(), name.as_mut_ptr(), 261, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), 261) };
    if ok == 0 {
        return (String::new(), String::new());
    }
    let s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
    (s(&name), s(&fs).to_lowercase())
}

fn windows_letter() -> Option<char> {
    let mut b = [0u16; 261];
    let n = unsafe { GetWindowsDirectoryW(b.as_mut_ptr(), 261) } as usize;
    String::from_utf16_lossy(&b[..n.min(261)]).chars().next().map(|c| c.to_ascii_uppercase())
}

pub fn list_all() -> Result<Vec<Device>> {
    let vols = volumes();
    let sys_letter = windows_letter();
    let sys_disks: Vec<u32> = vols.iter().filter(|(l, _, _)| Some(*l) == sys_letter).map(|v| v.1).collect();
    // without knowing the system disk no drive is safe to offer
    if sys_disks.is_empty() {
        bail!("cannot tell which disk holds Windows ({}:)", sys_letter.unwrap_or('?'));
    }
    let mut out = Vec::new();
    for n in 0..64u32 {
        let path = format!("\\\\.\\PhysicalDrive{n}");
        let Some(h) = open(&path, 0, 0) else { continue };
        // STORAGE_PROPERTY_QUERY { StorageDeviceProperty, PropertyStandardQuery }
        let q = [0u8; 12];
        let mut d = vec![0u8; 1024];
        let (mut usb, mut removable, mut vendor, mut model, mut serial) = (false, false, String::new(), String::new(), String::new());
        if ioctl(&h, IOCTL_STORAGE_QUERY_PROPERTY, &q, &mut d).is_some() {
            removable = d[10] != 0;
            vendor = cstr_at(&d, u32_at(&d, 12) as usize);
            model = cstr_at(&d, u32_at(&d, 16) as usize);
            serial = cstr_at(&d, u32_at(&d, 24) as usize);
            usb = matches!(u32_at(&d, 28), BUS_TYPE_USB | BUS_TYPE_SD | BUS_TYPE_MMC);
        }
        // the handle has no read access (listing works without administrator rights), which
        // IOCTL_DISK_GET_LENGTH_INFO needs; the geometry (DISK_GEOMETRY_EX: 24 bytes geometry, then DiskSize)
        // does not
        let mut len = [0u8; 8];
        let mut geo = [0u8; 256];
        let size = ioctl(&h, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut len)
            .map(|_| u64::from_le_bytes(len))
            .or_else(|| ioctl(&h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut geo).map(|_| u64::from_le_bytes(geo[24..32].try_into().unwrap())))
            .unwrap_or(0);
        let parts = vols
            .iter()
            .filter(|v| v.1 == n)
            .map(|(l, _, plen)| {
                let (label, fs) = volume_info(*l);
                Part { name: format!("{l}:"), size: *plen, fs, label, mount: Some(format!("{l}:\\")) }
            })
            .collect();
        out.push(Device { path, size, vendor, model, serial, usb, removable, system: sys_disks.contains(&n), parts });
    }
    Ok(out)
}

/// Volumes locked and dismounted while the drive is written; released when dropped.
pub struct Locks(#[allow(dead_code)] Vec<H>);

static LOCKS: std::sync::Mutex<Vec<Locks>> = std::sync::Mutex::new(Vec::new());

pub fn open_raw(d: &Device, write: bool) -> Result<(File, u64)> {
    if write {
        let mut held = Vec::new();
        for p in &d.parts {
            let letter = p.name.trim_end_matches(':');
            let Some(h) = open(&format!("\\\\.\\{letter}:"), GENERIC_READ | GENERIC_WRITE, 0) else { bail!("cannot open volume {}", p.name) };
            if ioctl(&h, FSCTL_LOCK_VOLUME, &[], &mut []).is_none() {
                bail!("volume {} is in use (close programs that use it) and cannot be locked", p.name);
            }
            if ioctl(&h, FSCTL_DISMOUNT_VOLUME, &[], &mut []).is_none() {
                bail!("volume {} cannot be dismounted", p.name);
            }
            held.push(h);
        }
        LOCKS.lock().unwrap().push(Locks(held));
    }
    let access = if write { GENERIC_READ | GENERIC_WRITE } else { GENERIC_READ };
    let Some(h) = open(&d.path, access, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH) else { bail!("cannot open {} (run as administrator)", d.path) };
    let raw = h.0 as RawHandle;
    std::mem::forget(h);
    Ok((unsafe { File::from_raw_handle(raw) }, d.size))
}

/// Tells Windows about the new partition table and releases the volume locks.
pub fn finish(f: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    f.sync_all()?;
    let h = H(f.as_raw_handle() as HANDLE);
    ioctl(&h, IOCTL_DISK_UPDATE_PROPERTIES, &[], &mut []);
    std::mem::forget(h);
    LOCKS.lock().unwrap().clear();
    Ok(())
}

/// Starts `exe usb-write <plan> --log <plan>.log` elevated (UAC) and shows its log afterwards.
pub fn elevate(exe: &Path, plan: &Path, digest: &str) -> Result<()> {
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    let log = plan.with_extension("log");
    let _ = std::fs::remove_file(&log);
    let verb = wide("runas");
    let file = wide(&exe.display().to_string());
    let params = wide(&format!("usb-write \"{}\" --sha256 {digest} --log \"{}\"", plan.display(), log.display()));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 1;
    eprintln!("Writing to the drive needs administrator rights: confirm the Windows prompt.");
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        bail!("the administrator prompt was declined or failed");
    }
    let h = H(info.hProcess);
    unsafe { WaitForSingleObject(h.0, INFINITE) };
    let mut code = 1u32;
    unsafe { GetExitCodeProcess(h.0, &mut code) };
    if let Ok(t) = std::fs::read_to_string(&log) {
        eprint!("{t}");
    }
    if code != 0 {
        bail!("writing the stick failed (see above)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn strings() {
        let mut b = vec![0u8; 64];
        b[40..47].copy_from_slice(b"Kingstn");
        assert_eq!(super::cstr_at(&b, 40), "Kingstn");
        assert_eq!(super::cstr_at(&b, 0), "");
    }
}
