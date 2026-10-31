//! Operating-system specifics in one place (Linux, macOS, Windows): file identity and times, positional
//! reads, free space and file-system kind, available memory, privileges.

use std::io;
use std::path::Path;

/// What the workspace needs to know about a file: identity (volume and file index, to recognise hard
/// links and replaced files), link count, size and times in nanoseconds since 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub len: u64,
    pub mtime_ns: i64,
    /// Last metadata change (Unix ctime, Windows ChangeTime).
    pub ctime_ns: i64,
}

/// File-system family of a volume, as far as the build cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Fat,
    ExFat,
    Other,
}

/// Positional reads that fill the whole buffer (Unix `pread`, Windows `ReadFile` with an offset).
pub trait ReadExactAt {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::{FileExt, MetadataExt};

    impl ReadExactAt for std::fs::File {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            FileExt::read_exact_at(self, buf, offset)
        }
    }

    pub fn stat_of(_p: &Path, m: &std::fs::Metadata) -> io::Result<Stat> {
        Ok(Stat {
            dev: m.dev(),
            ino: m.ino(),
            nlink: m.nlink(),
            len: m.len(),
            mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        })
    }

    pub fn fs_info(p: &Path) -> io::Result<(FsKind, u64)> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)?;
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        let kind = match st.f_type as u64 & 0xffff_ffff {
            0x4d44 => FsKind::Fat,
            0x2011_bab0 => FsKind::ExFat,
            _ => FsKind::Other,
        };
        #[cfg(target_os = "macos")]
        let kind = {
            let name = unsafe { std::ffi::CStr::from_ptr(st.f_fstypename.as_ptr()) }.to_string_lossy().to_ascii_lowercase();
            match name.as_str() {
                "msdos" => FsKind::Fat,
                "exfat" => FsKind::ExFat,
                _ => FsKind::Other,
            }
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let kind = FsKind::Other;
        Ok((kind, (st.f_bavail as u64).saturating_mul(st.f_bsize as u64)))
    }

    pub fn volume_id(p: &Path) -> Option<u64> {
        std::fs::metadata(p).ok().map(|m| m.dev())
    }

    pub fn available_memory() -> Option<u64> {
        let m = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kib: u64 = m.lines().find(|l| l.starts_with("MemAvailable:"))?.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib * 1024)
    }

    pub fn is_admin() -> bool {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{FileExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FileBasicInfo,
        GetDiskFreeSpaceExW, GetFileInformationByHandle, GetFileInformationByHandleEx, GetVolumeInformationW, GetVolumePathNameW,
    };

    impl ReadExactAt for std::fs::File {
        fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
            while !buf.is_empty() {
                match self.seek_read(buf, offset) {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
                    Ok(n) => {
                        buf = &mut buf[n..];
                        offset += n as u64;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
    }

    /// 100 ns intervals since 1601 → ns since 1970.
    fn ns(t: i64) -> i64 {
        (t - 116_444_736_000_000_000).saturating_mul(100)
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain([0]).collect()
    }

    /// Identity and times through a handle (std exposes neither the file index nor the link count on
    /// stable Rust); directories and reparse points are opened themselves, not followed.
    pub fn stat_of(p: &Path, _m: &std::fs::Metadata) -> io::Result<Stat> {
        let f = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(p)?;
        let h = f.as_raw_handle() as HANDLE;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandleEx(h, FileBasicInfo, (&mut basic as *mut FILE_BASIC_INFO).cast(), std::mem::size_of::<FILE_BASIC_INFO>() as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Stat {
            dev: info.dwVolumeSerialNumber as u64,
            ino: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            nlink: info.nNumberOfLinks as u64,
            // size from the same handle as identity and times
            len: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            mtime_ns: ns(basic.LastWriteTime),
            ctime_ns: ns(basic.ChangeTime),
        })
    }

    fn volume_root(p: &Path) -> io::Result<Vec<u16>> {
        let abs = std::path::absolute(p)?;
        let w = wide(&abs);
        // room for an extended-length mount path
        let mut root = vec![0u16; 32_768];
        if unsafe { GetVolumePathNameW(w.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(root)
    }

    pub fn fs_info(p: &Path) -> io::Result<(FsKind, u64)> {
        let root = volume_root(p)?;
        let mut free: u64 = 0;
        if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fs_name = [0u16; 64];
        let ok = unsafe {
            GetVolumeInformationW(root.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs_name.as_mut_ptr(), fs_name.len() as u32)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let name = String::from_utf16_lossy(&fs_name[..fs_name.iter().position(|&c| c == 0).unwrap_or(0)]).to_ascii_uppercase();
        let kind = match name.as_str() {
            "FAT" | "FAT32" => FsKind::Fat,
            "EXFAT" => FsKind::ExFat,
            _ => FsKind::Other,
        };
        Ok((kind, free))
    }

    pub fn volume_id(p: &Path) -> Option<u64> {
        let m = std::fs::metadata(p).ok()?;
        stat_of(p, &m).ok().map(|s| s.dev)
    }

    pub fn available_memory() -> Option<u64> {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut st: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (unsafe { GlobalMemoryStatusEx(&mut st) } != 0).then_some(st.ullAvailPhys)
    }

    /// Building needs no administrator on Windows either (hard links on NTFS, no mounts).
    pub fn is_admin() -> bool {
        false
    }
}

pub use imp::{available_memory, fs_info, is_admin, stat_of, volume_id};

/// [`stat_of`] for a path (not following a final link).
pub fn stat(p: &Path) -> io::Result<Stat> {
    let m = std::fs::symlink_metadata(p)?;
    stat_of(p, &m)
}
