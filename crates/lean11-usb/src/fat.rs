//! Stick layout: an MBR with one active FAT32 (LBA, type 0x0C) partition from 1 MiB, only as large as
//! the media needs. UEFI firmware boots `efi/boot/bootx64.efi` from it (Secure Boot keeps working: the
//! loader is Microsoft-signed); BIOS runs the NT6 MBR and FAT32 boot code, which load `bootmgr`.

use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result, bail};
use fscommon::StreamSlice;
use sha2::{Digest, Sha256};

use crate::boot::{BootCode, patch_vbr};
use crate::media::{IsoSrc, Media};

pub const SECTOR: u64 = 512;
pub const PART_START: u64 = 1 << 20;
const CLUSTER: u32 = 32 << 10;
const MIB: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Layout {
    /// Bytes of the partition (a multiple of 1 MiB).
    pub part_len: u64,
    pub cluster: u32,
}

impl Layout {
    /// Bytes the target needs: the first MiB plus the partition.
    pub fn disk_len(&self) -> u64 {
        PART_START + self.part_len
    }
}

/// Partition size for the media: the files in whole clusters, directories, both FATs, 2 % and 64 MiB to spare.
pub fn plan(m: &Media) -> Layout {
    let c = CLUSTER as u64;
    let files: u64 = m.files.iter().map(|f| f.size.div_ceil(c).max(1)).sum();
    // every directory takes at least a cluster; long names need about 3 entries of 32 bytes per file
    let dirs = m.dirs.len() as u64 + 1 + (m.files.len() as u64 * 96).div_ceil(c);
    let mut clusters = files + dirs;
    clusters += clusters / 50 + (64 * MIB) / c;
    // FAT32 needs at least 65525 clusters
    clusters = clusters.max(65_525 + 64);
    let fat = ((clusters + 2) * 4).div_ceil(SECTOR) * SECTOR;
    let len = 32 * SECTOR + 2 * fat + clusters * c;
    Layout { part_len: len.div_ceil(MIB) * MIB, cluster: CLUSTER }
}

fn chs(lba: u64) -> mbrman::CHS {
    // the usual translated geometry (255 heads, 63 sectors); beyond cylinder 1023 the maximum
    let (heads, spt) = (255u64, 63u64);
    let c = lba / (heads * spt);
    if c > 1023 {
        return mbrman::CHS::new(1023, 254, 63);
    }
    let h = (lba / spt) % heads;
    let s = lba % spt + 1;
    mbrman::CHS::new(c as u16, h as u8, s as u8)
}

/// FAT32 with 32 reserved sectors (as Windows formats it): the NT6 boot code needs sector 12 for its
/// second part, which fatfs' formatter (8 reserved sectors) does not leave free.
const RESERVED: u32 = 32;
/// Sector of the partition holding the second part of the BIOS boot code.
pub const BOOT_CODE2: u64 = 12;

/// Writes an empty FAT32 file system into `part` (`len` bytes, starting `hidden` sectors into the disk).
/// Returns boot sector 0 (to put the BIOS boot code around its BPB).
fn format32<D: Write + Seek>(part: &mut D, len: u64, cluster: u32, hidden: u32, label: [u8; 11], vid: u32) -> Result<[u8; 512]> {
    let total = u32::try_from(len / SECTOR).context("partition too large for FAT32")?;
    let spc = cluster / SECTOR as u32;
    // Microsoft's FAT size formula (fatgen103): slightly generous, never too small
    let tmp2 = (256 * spc + 2) / 2;
    let fat_sectors = (total - RESERVED).div_ceil(tmp2);
    let clusters = (total - RESERVED - 2 * fat_sectors) / spc;
    if clusters < 65_525 {
        bail!("partition too small for FAT32 ({clusters} clusters)");
    }
    let mut b = [0u8; 512];
    b[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    b[3..11].copy_from_slice(b"MSWIN4.1");
    b[0x0b..0x0d].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    b[0x0d] = spc as u8;
    b[0x0e..0x10].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    b[0x10] = 2;
    b[0x15] = 0xf8;
    b[0x18..0x1a].copy_from_slice(&63u16.to_le_bytes());
    b[0x1a..0x1c].copy_from_slice(&255u16.to_le_bytes());
    b[0x1c..0x20].copy_from_slice(&hidden.to_le_bytes());
    b[0x20..0x24].copy_from_slice(&total.to_le_bytes());
    b[0x24..0x28].copy_from_slice(&fat_sectors.to_le_bytes());
    b[0x2c..0x30].copy_from_slice(&2u32.to_le_bytes());
    b[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
    b[0x32..0x34].copy_from_slice(&6u16.to_le_bytes());
    b[0x40] = 0x80;
    b[0x42] = 0x29;
    b[0x43..0x47].copy_from_slice(&vid.to_le_bytes());
    b[0x47..0x52].copy_from_slice(&label);
    b[0x52..0x5a].copy_from_slice(b"FAT32   ");
    b[510] = 0x55;
    b[511] = 0xaa;
    let mut info = [0u8; 512];
    info[..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    info[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    info[488..492].copy_from_slice(&(clusters - 1).to_le_bytes());
    info[492..496].copy_from_slice(&3u32.to_le_bytes());
    info[508..512].copy_from_slice(&0xaa55_0000u32.to_le_bytes());
    // reserved area, both FATs and the root directory cluster are written out (old stick data goes)
    let meta = (RESERVED + 2 * fat_sectors + spc) as u64 * SECTOR;
    part.seek(SeekFrom::Start(0))?;
    let zeros = vec![0u8; MIB as usize];
    let mut left = meta;
    while left > 0 {
        let n = left.min(MIB);
        part.write_all(&zeros[..n as usize])?;
        left -= n;
    }
    for (sector, data) in [(0u64, &b), (1, &info), (6, &b), (7, &info)] {
        part.seek(SeekFrom::Start(sector * SECTOR))?;
        part.write_all(data)?;
    }
    let mut head = [0u8; 12];
    head[..4].copy_from_slice(&0x0fff_fff8u32.to_le_bytes());
    head[4..8].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    head[8..12].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    for f in 0..2u64 {
        part.seek(SeekFrom::Start((RESERVED as u64 + f * fat_sectors as u64) * SECTOR))?;
        part.write_all(&head)?;
    }
    // the volume label as the first root directory entry (where Windows and fsck look for it)
    let mut entry = [0u8; 32];
    entry[..11].copy_from_slice(&label);
    entry[11] = 0x08;
    part.seek(SeekFrom::Start((RESERVED as u64 + 2 * fat_sectors as u64) * SECTOR))?;
    part.write_all(&entry)?;
    Ok(b)
}

/// fatfs 0.3 writes a long-name entry before "." and ".." of every directory it creates, which
/// chkdsk and fsck reject. This moves "." and ".." to the first two slots, where they belong, and marks
/// the two long-name slots after them as deleted; ".." of the directories in the root gets cluster 0.
fn fix_dot_entries<D: Read + Write + Seek>(part: &mut D) -> Result<()> {
    let mut b = [0u8; 512];
    part.seek(SeekFrom::Start(0))?;
    part.read_exact(&mut b)?;
    let bps = u16::from_le_bytes([b[11], b[12]]) as u64;
    let cluster = bps * b[13] as u64;
    let fat = u16::from_le_bytes([b[14], b[15]]) as u64 * bps;
    let fat_len = u32::from_le_bytes(b[36..40].try_into().unwrap()) as u64 * bps;
    let data = fat + b[16] as u64 * fat_len;
    let root = u32::from_le_bytes(b[44..48].try_into().unwrap());
    let max = (fat_len / 4) as u32;
    let pos = |c: u32| data + (c as u64 - 2) * cluster;
    let next = |part: &mut D, c: u32| -> Result<u32> {
        let mut e = [0u8; 4];
        part.seek(SeekFrom::Start(fat + c as u64 * 4))?;
        part.read_exact(&mut e)?;
        Ok(u32::from_le_bytes(e) & 0x0fff_ffff)
    };
    let mut todo = vec![root];
    let mut seen = std::collections::HashSet::new();
    let mut buf = vec![0u8; cluster as usize];
    while let Some(first) = todo.pop() {
        if !seen.insert(first) {
            continue;
        }
        if first != root {
            let mut head = [0u8; 128];
            part.seek(SeekFrom::Start(pos(first)))?;
            part.read_exact(&mut head)?;
            let lfn = |i: usize| head[i * 32 + 11] == 0x0f;
            let name = |i: usize| &head[i * 32..i * 32 + 11];
            let mut fixed = head;
            if lfn(0) && name(1) == b".          " && lfn(2) && name(3) == b"..         " {
                fixed = [0u8; 128];
                fixed[..32].copy_from_slice(&head[32..64]);
                fixed[32..64].copy_from_slice(&head[96..128]);
                fixed[64] = 0xe5;
                fixed[96] = 0xe5;
            }
            // ".." of a directory in the root points to cluster 0, not to the root's cluster
            let dd = &mut fixed[32..64];
            if &dd[..11] == b"..         " && ((u16::from_le_bytes([dd[20], dd[21]]) as u32) << 16 | u16::from_le_bytes([dd[26], dd[27]]) as u32) == root {
                dd[20..22].fill(0);
                dd[26..28].fill(0);
            }
            if fixed != head {
                part.seek(SeekFrom::Start(pos(first)))?;
                part.write_all(&fixed)?;
            }
        }
        // the subdirectories of this one
        let mut c = first;
        let mut steps = 0;
        'chain: while (2..max).contains(&c) && steps < max {
            part.seek(SeekFrom::Start(pos(c)))?;
            part.read_exact(&mut buf)?;
            for e in buf.chunks_exact(32) {
                match e[0] {
                    0 => break 'chain,
                    0xe5 | b'.' => continue,
                    _ => {}
                }
                if e[11] & 0x10 != 0 && e[11] != 0x0f {
                    let sub = (u16::from_le_bytes([e[20], e[21]]) as u32) << 16 | u16::from_le_bytes([e[26], e[27]]) as u32;
                    if sub >= 2 {
                        todo.push(sub);
                    }
                }
            }
            c = next(part, c)?;
            steps += 1;
        }
    }
    Ok(())
}

/// File times for the stick: the system clock in UTC (FAT has no time zone; this avoids a time-zone
/// library, which would link platform frameworks).
#[derive(Debug)]
struct SystemTimeProvider;

static SYSTEM_TIME: SystemTimeProvider = SystemTimeProvider;

/// (year, month, day, hour, minute, second, millisecond) in UTC of seconds and milliseconds since 1970.
fn civil(secs: u64, millis: u16) -> (u16, u16, u16, u16, u16, u16, u16) {
    // days to civil date (Howard Hinnant's algorithm)
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y as u16, m as u16, d as u16, (rem / 3600) as u16, (rem / 60 % 60) as u16, (rem % 60) as u16, millis)
}

impl SystemTimeProvider {
    fn now() -> (u16, u16, u16, u16, u16, u16, u16) {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let c = civil(t.as_secs(), t.subsec_millis() as u16);
        // FAT dates cover 1980 to 2107
        if c.0 < 1980 || c.0 > 2107 { (1980, 1, 1, 0, 0, 0, 0) } else { c }
    }
}

impl fatfs::TimeProvider for SystemTimeProvider {
    fn get_current_date(&self) -> fatfs::Date {
        let (year, month, day, ..) = Self::now();
        fatfs::Date { year, month, day }
    }
    fn get_current_date_time(&self) -> fatfs::DateTime {
        let (year, month, day, hour, min, sec, millis) = Self::now();
        fatfs::DateTime { date: fatfs::Date { year, month, day }, time: fatfs::Time { hour, min, sec, millis } }
    }
}

fn label11(label: &str) -> [u8; 11] {
    let mut l = [b' '; 11];
    for (i, b) in label.bytes().take(11).enumerate() {
        l[i] = b;
    }
    l
}

/// What was written: the path on the stick and its SHA-256, for the read-back check.
pub type Written = Vec<(String, [u8; 32])>;

/// Writes the partition table, the FAT32 file system with all files and (with `code`) the BIOS boot
/// code. `disk` is the whole target; its length must be at least `layout.disk_len()`.
pub fn write<D: Read + Write + Seek>(
    disk: &mut D,
    disk_len: u64,
    layout: Layout,
    m: &Media,
    iso: Option<&IsoSrc>,
    code: Option<&BootCode>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Written> {
    if disk_len < layout.disk_len() {
        bail!("the target holds {} MiB, the media needs {} MiB", disk_len / MIB, layout.disk_len() / MIB);
    }
    // a backup GPT at the end of a former GPT disk would contradict the new MBR
    if disk_len > layout.disk_len() + MIB {
        disk.seek(SeekFrom::Start(disk_len - MIB))?;
        disk.write_all(&vec![0u8; MIB as usize])?;
    }
    let start_lba = (PART_START / SECTOR) as u32;
    let sectors = (layout.part_len / SECTOR) as u32;
    let sig = *uuid::Uuid::new_v4().as_bytes();
    let mut mbr = mbrman::MBR::new_from(disk, SECTOR as u32, [sig[0], sig[1], sig[2], sig[3]]).map_err(|e| anyhow::anyhow!("partition table: {e}"))?;
    if let Some(c) = code {
        mbr.header.bootstrap_code = c.mbr;
    }
    mbr[1] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_ACTIVE,
        first_chs: chs(start_lba as u64),
        sys: 0x0c,
        last_chs: chs(start_lba as u64 + sectors as u64 - 1),
        starting_lba: start_lba,
        sectors,
    };
    // the first MiB starts as zeros (old partition tables and boot records go)
    disk.seek(SeekFrom::Start(0))?;
    disk.write_all(&vec![0u8; PART_START as usize])?;
    disk.seek(SeekFrom::Start(0))?;
    mbr.write_into(disk).map_err(|e| anyhow::anyhow!("partition table: {e}"))?;

    let end = PART_START + layout.part_len;
    let vid = u32::from_le_bytes([sig[4], sig[5], sig[6], sig[7]]);
    let bpb = {
        let mut part = StreamSlice::new(&mut *disk, PART_START, end)?;
        format32(&mut part, layout.part_len, layout.cluster, start_lba, label11(&m.label), vid)?
    };
    let total = m.total();
    let mut done = 0u64;
    let mut written = Vec::with_capacity(m.files.len());
    {
        let part = StreamSlice::new(&mut *disk, PART_START, end)?;
        let fs = fatfs::FileSystem::new(part, fatfs::FsOptions::new().time_provider(&SYSTEM_TIME)).context("cannot open the new FAT32 file system")?;
        let root = fs.root_dir();
        for d in &m.dirs {
            root.create_dir(d).with_context(|| format!("cannot create {d}"))?;
        }
        let mut buf = vec![0u8; 4 << 20];
        // boot files first, the large images last
        let mut order: Vec<_> = m.files.iter().collect();
        order.sort_by_key(|f| (f.size > 64 * MIB, f.rel.to_lowercase()));
        for f in order {
            let mut src = m.open(f, iso)?;
            let mut out = root.create_file(&f.rel).with_context(|| format!("cannot create {}", f.rel))?;
            out.truncate()?;
            let mut h = Sha256::new();
            let mut n = 0u64;
            loop {
                let k = src.read(&mut buf).with_context(|| format!("cannot read {}", f.rel))?;
                if k == 0 {
                    break;
                }
                h.update(&buf[..k]);
                out.write_all(&buf[..k]).with_context(|| format!("cannot write {}", f.rel))?;
                n += k as u64;
                done += k as u64;
                progress(done, total);
            }
            if n != f.size {
                bail!("{} has {n} bytes instead of {}", f.rel, f.size);
            }
            out.flush()?;
            written.push((f.rel.clone(), h.finalize().into()));
        }
        drop(root);
        fs.unmount().context("cannot finish the FAT32 file system")?;
    }
    {
        let mut part = StreamSlice::new(&mut *disk, PART_START, end)?;
        fix_dot_entries(&mut part).context("cannot finish the directories")?;
    }
    if let Some(c) = code {
        // boot sector 0 and its backup at 6 with the BIOS code around our BPB, the second part at 12
        let v = patch_vbr(c, &bpb, start_lba);
        for (sector, data) in [(0, &v), (6, &v), (BOOT_CODE2, &c.vbr2)] {
            disk.seek(SeekFrom::Start(PART_START + sector * SECTOR))?;
            disk.write_all(data)?;
        }
    }
    disk.flush()?;
    Ok(written)
}

/// Reads every written file back from the target and compares its SHA-256.
pub fn verify<D: Read + Write + Seek>(disk: &mut D, layout: Layout, files: &Written, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
    let part = StreamSlice::new(disk, PART_START, PART_START + layout.part_len)?;
    let fs = fatfs::FileSystem::new(part, fatfs::FsOptions::new()).context("cannot open the FAT32 file system for checking")?;
    let root = fs.root_dir();
    let mut buf = vec![0u8; 4 << 20];
    let mut bad = Vec::new();
    let (mut done, mut total) = (0u64, 0u64);
    for (rel, _) in files {
        total += root.open_file(rel).map(|mut f| f.seek(SeekFrom::End(0)).unwrap_or(0)).unwrap_or(0);
    }
    for (rel, want) in files {
        let mut f = match root.open_file(rel) {
            Ok(f) => f,
            Err(_) => {
                bad.push(format!("{rel} (missing)"));
                continue;
            }
        };
        let mut h = Sha256::new();
        loop {
            let k = f.read(&mut buf).with_context(|| format!("cannot read {rel} back"))?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            done += k as u64;
            progress(done, total);
        }
        let got: [u8; 32] = h.finalize().into();
        if &got != want {
            bad.push(rel.clone());
        }
    }
    if !bad.is_empty() {
        bail!("{} file(s) on the stick differ from the media: {}. The stick may be faulty.", bad.len(), bad.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::{MFile, Src};

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0, 0), (1970, 1, 1, 0, 0, 0, 0));
        assert_eq!(civil(951_782_400, 5), (2000, 2, 29, 0, 0, 0, 5));
        // 2026-11-23 17:30:15 UTC
        assert_eq!(civil(1_795_455_015, 0), (2026, 11, 23, 17, 30, 15, 0));
    }

    #[test]
    fn chs_values() {
        assert_eq!(chs(0), mbrman::CHS::new(0, 0, 1));
        assert_eq!(chs(2048), mbrman::CHS::new(0, 32, 33));
        assert_eq!(chs(50_000_000), mbrman::CHS::new(1023, 254, 63));
    }

    #[test]
    fn plan_has_room() {
        let m = Media {
            iso: None,
            dirs: vec!["sources".into()],
            files: vec![MFile { rel: "sources/install.esd".into(), size: 4_000_000_000, src: Src::Path("/x".into()) }],
            label: "T".into(),
        };
        let l = plan(&m);
        assert!(l.part_len > 4_000_000_000 + 64 * MIB);
        assert!(l.part_len < 4_300_000_000);
        assert_eq!(l.part_len % MIB, 0);
    }

    /// Writes a small media tree into an image file and reads it back with fatfs and the checker.
    #[test]
    fn write_and_verify_image() {
        let dir = std::env::temp_dir().join(format!("lean11-usb-test-{}", std::process::id()));
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("efi/boot")).unwrap();
        std::fs::create_dir_all(src.join("sources")).unwrap();
        std::fs::write(src.join("efi/boot/bootx64.efi"), vec![7u8; 100_000]).unwrap();
        std::fs::write(src.join("sources/boot.wim"), vec![1u8; 3_000_000]).unwrap();
        std::fs::write(src.join("sources/install.wim"), (0..5_000_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()).unwrap();
        std::fs::write(src.join("A long file name with spaces.txt"), b"hello").unwrap();
        let m = crate::media::from_dir(&src, "lean11 test").unwrap();
        let l = plan(&m);
        let img = dir.join("stick.img");
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&img).unwrap();
        f.set_len(l.disk_len()).unwrap();
        let mut d = crate::disk::CachedDisk::new(f, l.disk_len(), true);
        let w = write(&mut d, l.disk_len(), l, &m, None, None, &mut |_, _| {}).unwrap();
        assert_eq!(w.len(), 4);
        let f = d.into_inner().unwrap();
        let mut d = crate::disk::CachedDisk::new(f, l.disk_len(), false);
        verify(&mut d, l, &w, &mut |_, _| {}).unwrap();
        // a wrong hash is reported
        let mut bad = w.clone();
        bad[0].1[0] ^= 1;
        assert!(verify(&mut d, l, &bad, &mut |_, _| {}).is_err());
        // MBR: active FAT32 LBA partition at 2048
        let raw = std::fs::read(&img).unwrap();
        assert_eq!(&raw[510..512], &[0x55, 0xaa]);
        assert_eq!(raw[446], 0x80);
        assert_eq!(raw[446 + 4], 0x0c);
        assert_eq!(u32::from_le_bytes(raw[454..458].try_into().unwrap()), 2048);
        let p = PART_START as usize;
        assert_eq!(&raw[p + 0x52..p + 0x5a], b"FAT32   ");
        assert_eq!(u16::from_le_bytes([raw[p + 0x0e], raw[p + 0x0f]]), 32, "32 reserved sectors");
        assert_eq!(u32::from_le_bytes(raw[p + 0x1c..p + 0x20].try_into().unwrap()), 2048, "hidden sectors");
        assert_eq!(&raw[p + 6 * 512..p + 6 * 512 + 90], &raw[p..p + 90], "backup boot sector");
        // every directory starts with "." and ".." (no long-name entries before them)
        let fs = fatfs::FileSystem::new(fscommon::StreamSlice::new(std::fs::File::open(&img).unwrap(), PART_START, l.disk_len()).unwrap(), fatfs::FsOptions::new()).unwrap();
        let bpb_data = {
            let b = &raw[p..p + 512];
            let bps = u16::from_le_bytes([b[11], b[12]]) as usize;
            (u16::from_le_bytes([b[14], b[15]]) as usize + 2 * u32::from_le_bytes(b[36..40].try_into().unwrap()) as usize) * bps
        };
        for d in ["efi", "efi/boot", "sources"] {
            let mut it = fs.root_dir().open_dir(d).unwrap().iter();
            let first = it.next().unwrap().unwrap();
            assert_eq!(first.short_file_name(), ".", "{d}");
            let up = it.next().unwrap().unwrap();
            assert_eq!(up.short_file_name(), "..", "{d}");
        }
        let root = &raw[p + bpb_data..];
        assert_eq!(&root[..11], b"LEAN11TEST ", "label entry");
        assert_eq!(root[11], 0x08);
        // ".." of a directory in the root is cluster 0
        let cl = u16::from_le_bytes([raw[p + 11], raw[p + 12]]) as usize * raw[p + 13] as usize;
        let efi = root.chunks_exact(32).find(|e| &e[..11] == b"EFI        " && e[11] == 0x10).unwrap();
        let c = (u16::from_le_bytes([efi[20], efi[21]]) as usize) << 16 | u16::from_le_bytes([efi[26], efi[27]]) as usize;
        let dd = &root[(c - 2) * cl + 32..(c - 2) * cl + 64];
        assert_eq!(&dd[..11], b"..         ");
        assert_eq!((dd[20], dd[21], dd[26], dd[27]), (0, 0, 0, 0));
        drop(fs);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
