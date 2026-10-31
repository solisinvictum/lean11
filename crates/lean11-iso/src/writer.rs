//! Bootable Windows installation ISO writer.
//!
//! Produces the same layout as `oscdimg -m -o -u2 -udfver102 -bootdata:2#p0,e,b<etfsboot>#pEF,e,b<efisys>`:
//! a UDF 1.02 file system holding all files, an ISO 9660 part that only contains README.TXT,
//! and an El Torito catalog with a BIOS no-emulation entry and a UEFI (platform 0xEF) entry
//! pointing into the UDF file data.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::udf::*;

const PART_START: u64 = 304;
const MAIN_VDS: u64 = 257;
const LVID_SECTOR: u64 = 273;
const RESERVE_VDS: u64 = 275;
const CATALOG: u64 = 22;
const PATH_L: u64 = 23;
const PATH_M: u64 = 24;
const README: u64 = 25;
const ISO_ROOT: u64 = 26;
/// Largest extent length that is a multiple of the block size (30-bit length field).
const MAX_EXTENT: u64 = 0x3FFF_F800;
const README_TEXT: &[u8] = b"This disc contains a \"UDF\" file system and requires an operating system\r\n\
that supports the ISO-13346 \"UDF\" file system specification.\r\n";

#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    /// Volume label (ISO 9660 d-characters are derived from it).
    pub label: String,
    /// BIOS boot image, path relative to the source root (e.g. `boot/etfsboot.com`).
    pub bios_image: Option<String>,
    /// UEFI boot image (FAT image), e.g. `efi/microsoft/boot/efisys.bin`.
    pub uefi_image: Option<String>,
}

enum Kind {
    Dir { children: Vec<usize>, data_len: u64 },
    File { src: PathBuf, size: u64 },
}

struct Node {
    name: String,
    rel: String,
    parent: usize,
    kind: Kind,
    uniq: u64,
    fe_lbn: u32,
    data_lbn: u32,
}

fn fid_len(name_bytes: usize) -> u64 {
    ((38 + name_bytes + 3) & !3) as u64
}

fn blocks(bytes: u64) -> u64 {
    bytes.div_ceil(SECTOR as u64)
}

struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn scan(root: &Path) -> Result<Self> {
        let mut t = Tree { nodes: Vec::new() };
        t.nodes.push(Node {
            name: String::new(),
            rel: String::new(),
            parent: 0,
            kind: Kind::Dir { children: Vec::new(), data_len: 0 },
            uniq: 0,
            fe_lbn: 0,
            data_lbn: 0,
        });
        // breadth-first so that file entries of one directory are adjacent
        let mut queue = std::collections::VecDeque::from([(0usize, root.to_path_buf())]);
        while let Some((idx, path)) = queue.pop_front() {
            let mut items: Vec<_> = fs::read_dir(&path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .collect::<std::io::Result<_>>()?;
            items.sort_by_key(|e| e.file_name().to_string_lossy().to_lowercase());
            let mut children = Vec::new();
            for item in items {
                let name = item.file_name().into_string().map_err(|n| anyhow::anyhow!("file name is not UTF-8: {n:?}"))?;
                if cs0_encode(&name).len() > 255 {
                    bail!("file name too long for UDF: {name}");
                }
                let meta = fs::metadata(item.path())?;
                let rel = if t.nodes[idx].rel.is_empty() { name.clone() } else { format!("{}/{}", t.nodes[idx].rel, name) };
                let kind = if meta.is_dir() {
                    Kind::Dir { children: Vec::new(), data_len: 0 }
                } else if meta.is_file() {
                    Kind::File { src: item.path(), size: meta.len() }
                } else {
                    bail!("unsupported file type: {}", item.path().display());
                };
                let id = t.nodes.len();
                t.nodes.push(Node { name, rel, parent: idx, kind, uniq: 0, fe_lbn: 0, data_lbn: 0 });
                if meta.is_dir() {
                    queue.push_back((id, item.path()));
                }
                children.push(id);
            }
            let data_len = fid_len(0) + children.iter().map(|&c| fid_len(cs0_encode(&t.nodes[c].name).len())).sum::<u64>();
            t.nodes[idx].kind = Kind::Dir { children, data_len };
        }
        Ok(t)
    }

    fn find(&self, rel: &str) -> Option<&Node> {
        let want = rel.trim_matches('/').to_lowercase();
        self.nodes.iter().find(|n| n.rel.to_lowercase() == want)
    }
}

struct Out {
    w: BufWriter<File>,
    sector: u64,
}

impl Out {
    fn put(&mut self, at: u64, data: &[u8]) -> Result<()> {
        if at < self.sector {
            bail!("internal layout error: sector {at} already written (at {})", self.sector);
        }
        self.zero_to(at)?;
        self.w.write_all(data)?;
        let pad = (SECTOR - data.len() % SECTOR) % SECTOR;
        self.w.write_all(&vec![0u8; pad])?;
        self.sector += blocks(data.len() as u64).max(if data.is_empty() { 0 } else { 1 });
        Ok(())
    }

    fn zero_to(&mut self, at: u64) -> Result<()> {
        let zero = [0u8; SECTOR];
        while self.sector < at {
            self.w.write_all(&zero)?;
            self.sector += 1;
        }
        Ok(())
    }
}

fn both16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    b[o + 2..o + 4].copy_from_slice(&v.to_be_bytes());
}
fn both32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    b[o + 4..o + 8].copy_from_slice(&v.to_be_bytes());
}

fn iso_dir_record(name: &[u8], extent: u32, size: u32, dir: bool, t: &Time) -> Vec<u8> {
    let len = 33 + name.len() + (name.len() + 1) % 2;
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    both32(&mut r, 2, extent);
    both32(&mut r, 10, size);
    r[18..25].copy_from_slice(&t.iso_short());
    r[25] = if dir { 2 } else { 0 };
    both16(&mut r, 28, 1);
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r
}

fn iso_label(label: &str) -> Vec<u8> {
    let mut v: Vec<u8> = label
        .to_ascii_uppercase()
        .bytes()
        .map(|c| if c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' { c } else { b'_' })
        .take(32)
        .collect();
    v.resize(32, b' ');
    v
}

fn padded(s: &[u8], len: usize, fill: u8) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(len, fill);
    v
}

/// Writes `src` as a bootable ISO to `out`. `progress` gets (bytes written, total bytes).
pub fn write_iso(src: &Path, out: &Path, opts: &WriteOptions, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
    let mut tree = Tree::scan(src)?;
    let t = Time::now();

    // ---- partition layout (partition-relative logical blocks) ----
    let mut next: u64 = 2; // 0 = FSD, 1 = terminating descriptor
    let mut uniq = 16u64;
    for (i, n) in tree.nodes.iter_mut().enumerate() {
        n.fe_lbn = next as u32;
        next += 1;
        if i > 0 {
            n.uniq = uniq;
            uniq += 1;
        }
    }
    for n in tree.nodes.iter_mut() {
        if let Kind::Dir { data_len, .. } = n.kind {
            n.data_lbn = next as u32;
            next += blocks(data_len);
        }
    }
    for n in tree.nodes.iter_mut() {
        if let Kind::File { size, .. } = n.kind {
            n.data_lbn = next as u32;
            next += blocks(size);
        }
    }
    let part_len = next;
    if PART_START + part_len + 1 > u32::MAX as u64 {
        bail!("image too large");
    }
    let total = PART_START + part_len + 1;
    let files = tree.nodes.iter().filter(|n| matches!(n.kind, Kind::File { .. })).count() as u32;
    let dirs = tree.nodes.len() as u32 - files;

    let boot_sector = |rel: &Option<String>| -> Result<Option<(u32, u64)>> {
        match rel {
            None => Ok(None),
            Some(r) => match tree.find(r) {
                Some(Node { kind: Kind::File { size, .. }, data_lbn, .. }) => Ok(Some(((PART_START + *data_lbn as u64) as u32, *size))),
                _ => bail!("boot image {r} not found in {}", src.display()),
            },
        }
    };
    let bios = boot_sector(&opts.bios_image)?;
    let uefi = boot_sector(&opts.uefi_image)?;

    let mut o = Out { w: BufWriter::with_capacity(8 << 20, File::create(out).with_context(|| format!("cannot create {}", out.display()))?), sector: 0 };
    let label = if opts.label.is_empty() { "LEAN11".to_string() } else { opts.label.clone() };

    // ---- ISO 9660 primary volume descriptor ----
    let mut pvd = vec![0u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[8..40].copy_from_slice(&padded(b"", 32, b' '));
    pvd[40..72].copy_from_slice(&iso_label(&label));
    both32(&mut pvd, 80, total as u32);
    both16(&mut pvd, 120, 1);
    both16(&mut pvd, 124, 1);
    both16(&mut pvd, 128, SECTOR as u16);
    both32(&mut pvd, 132, 10);
    pvd[140..144].copy_from_slice(&(PATH_L as u32).to_le_bytes());
    pvd[148..152].copy_from_slice(&(PATH_M as u32).to_be_bytes());
    pvd[156..190].copy_from_slice(&iso_dir_record(&[0], ISO_ROOT as u32, SECTOR as u32, true, &t));
    for (o_, l) in [(190usize, 128usize), (318, 128), (446, 128), (574, 128), (702, 37), (739, 37), (776, 37)] {
        pvd[o_..o_ + l].fill(b' ');
    }
    pvd[574..574 + 6].copy_from_slice(b"LEAN11");
    pvd[813..830].copy_from_slice(&t.iso_long());
    pvd[830..847].copy_from_slice(&t.iso_long());
    for o_ in [847usize, 864] {
        pvd[o_..o_ + 16].fill(b'0');
    }
    pvd[881] = 1;
    o.put(16, &pvd)?;

    let mut next_vd = 17;
    if bios.is_some() || uefi.is_some() {
        let mut br = vec![0u8; SECTOR];
        br[1..6].copy_from_slice(b"CD001");
        br[6] = 1;
        br[7..7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
        br[71..75].copy_from_slice(&(CATALOG as u32).to_le_bytes());
        o.put(17, &br)?;
        next_vd = 18;
    }
    let mut term = vec![0u8; SECTOR];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    o.put(next_vd, &term)?;

    // ---- UDF volume recognition sequence ----
    for (s, id) in [(19u64, b"BEA01"), (20, b"NSR02"), (21, b"TEA01")] {
        let mut v = vec![0u8; SECTOR];
        v[1..6].copy_from_slice(id);
        v[6] = 1;
        o.put(s, &v)?;
    }

    // ---- El Torito boot catalog ----
    let mut cat = vec![0u8; SECTOR];
    if bios.is_some() || uefi.is_some() {
        cat[0] = 1;
        cat[1] = if bios.is_some() { 0 } else { 0xEF };
        cat[4..4 + 6].copy_from_slice(b"lean11");
        cat[30] = 0x55;
        cat[31] = 0xAA;
        let sum = cat[0..32].chunks_exact(2).fold(0u16, |a, c| a.wrapping_add(u16::from_le_bytes([c[0], c[1]])));
        cat[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
        let entry = |lba: u32, count: u16| -> [u8; 32] {
            let mut e = [0u8; 32];
            e[0] = 0x88; // bootable, no emulation, load segment 0 (= 0x7C0)
            e[6..8].copy_from_slice(&count.to_le_bytes());
            e[8..12].copy_from_slice(&lba.to_le_bytes());
            e
        };
        match (bios, uefi) {
            (Some((lba, _)), Some((ulba, _))) => {
                cat[32..64].copy_from_slice(&entry(lba, 8));
                cat[64] = 0x91; // final section header
                cat[65] = 0xEF;
                cat[66..68].copy_from_slice(&1u16.to_le_bytes());
                cat[96..128].copy_from_slice(&entry(ulba, 1));
            }
            (Some((lba, _)), None) => cat[32..64].copy_from_slice(&entry(lba, 8)),
            (None, Some((ulba, _))) => cat[32..64].copy_from_slice(&entry(ulba, 1)),
            (None, None) => {}
        }
    }
    o.put(CATALOG, &cat)?;

    // ---- ISO 9660 path tables, README.TXT, root directory ----
    let mut pl = vec![0u8; 10];
    pl[0] = 1;
    pl[2..6].copy_from_slice(&(ISO_ROOT as u32).to_le_bytes());
    pl[6..8].copy_from_slice(&1u16.to_le_bytes());
    o.put(PATH_L, &pl)?;
    let mut pm = vec![0u8; 10];
    pm[0] = 1;
    pm[2..6].copy_from_slice(&(ISO_ROOT as u32).to_be_bytes());
    pm[6..8].copy_from_slice(&1u16.to_be_bytes());
    o.put(PATH_M, &pm)?;
    o.put(README, README_TEXT)?;
    let mut root = Vec::new();
    root.extend(iso_dir_record(&[0], ISO_ROOT as u32, SECTOR as u32, true, &t));
    root.extend(iso_dir_record(&[1], ISO_ROOT as u32, SECTOR as u32, true, &t));
    root.extend(iso_dir_record(b"README.TXT", README as u32, README_TEXT.len() as u32, false, &t));
    o.put(ISO_ROOT, &root)?;

    // ---- UDF anchor, volume descriptor sequences, integrity ----
    let avdp = {
        let mut a = vec![0u8; 512];
        put32(&mut a, 16, 16 * SECTOR as u32);
        put32(&mut a, 20, MAIN_VDS as u32);
        put32(&mut a, 24, 16 * SECTOR as u32);
        put32(&mut a, 28, RESERVE_VDS as u32);
        a
    };
    let mut a = avdp.clone();
    finish_tag(&mut a, TAG_AVDP, 256, 496);
    o.put(256, &a)?;

    let lv_ident = dstring(&label, 128);
    let vds = |base: u64| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        // primary volume descriptor
        let mut d = vec![0u8; 512];
        put32(&mut d, 16, 1);
        d[24..56].copy_from_slice(&dstring(&label, 32));
        put16(&mut d, 56, 1);
        put16(&mut d, 58, 1);
        put16(&mut d, 60, 2);
        put16(&mut d, 62, 2);
        put32(&mut d, 64, 1);
        put32(&mut d, 68, 1);
        let set = format!("{:016X}{}", 0x7469_6e79_3131u64 ^ (total << 16), label);
        d[72..200].copy_from_slice(&dstring(&set, 128));
        d[200..264].copy_from_slice(&charspec());
        d[264..328].copy_from_slice(&charspec());
        d[344..376].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        d[376..388].copy_from_slice(&t.udf());
        d[388..420].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        out.push((TAG_PVD, d));
        // logical volume descriptor
        let mut d = vec![0u8; 512];
        put32(&mut d, 16, 2);
        d[20..84].copy_from_slice(&charspec());
        d[84..212].copy_from_slice(&lv_ident);
        put32(&mut d, 212, SECTOR as u32);
        d[216..248].copy_from_slice(&regid(b"*OSTA UDF Compliant", &DOMAIN_SUFFIX));
        put32(&mut d, 248, SECTOR as u32); // FSD long_ad: length, lbn 0, partition 0
        put32(&mut d, 264, 6);
        put32(&mut d, 268, 1);
        d[272..304].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        put32(&mut d, 432, 2 * SECTOR as u32);
        put32(&mut d, 436, LVID_SECTOR as u32);
        d[440] = 1;
        d[441] = 6;
        put16(&mut d, 442, 1);
        put16(&mut d, 444, 0);
        out.push((TAG_LVD, d));
        // partition descriptor
        let mut d = vec![0u8; 512];
        put32(&mut d, 16, 3);
        put16(&mut d, 20, 1);
        put16(&mut d, 22, 0);
        d[24..56].copy_from_slice(&regid(b"+NSR02", &[]));
        put32(&mut d, 184, 1); // read-only
        put32(&mut d, 188, PART_START as u32);
        put32(&mut d, 192, part_len as u32);
        d[196..228].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        out.push((TAG_PD, d));
        // unallocated space descriptor
        let mut d = vec![0u8; 512];
        put32(&mut d, 16, 4);
        out.push((TAG_USD, d));
        // implementation use volume descriptor (UDF LV Info)
        let mut d = vec![0u8; 512];
        put32(&mut d, 16, 5);
        d[20..52].copy_from_slice(&regid(b"*UDF LV Info", &UDF_REV));
        d[52..116].copy_from_slice(&charspec());
        d[116..244].copy_from_slice(&lv_ident);
        d[352..384].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        out.push((TAG_IUVD, d));
        out.push((TAG_TD, vec![0u8; 512]));
        out.into_iter()
            .enumerate()
            .map(|(i, (tag, mut d))| {
                finish_tag(&mut d, tag, (base + i as u64) as u32, 496);
                d
            })
            .collect()
    };
    for (i, d) in vds(MAIN_VDS).into_iter().enumerate() {
        o.put(MAIN_VDS + i as u64, &d)?;
    }
    // logical volume integrity descriptor (closed)
    let mut lvid = vec![0u8; 512];
    lvid[16..28].copy_from_slice(&t.udf());
    put32(&mut lvid, 28, 1);
    put64(&mut lvid, 40, uniq);
    put32(&mut lvid, 72, 1);
    put32(&mut lvid, 76, 46);
    put32(&mut lvid, 80, 0);
    put32(&mut lvid, 84, part_len as u32);
    lvid[88..120].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
    put32(&mut lvid, 120, files);
    put32(&mut lvid, 124, dirs);
    for o_ in [128usize, 130, 132] {
        put16(&mut lvid, o_, 0x0102);
    }
    finish_tag(&mut lvid, TAG_LVID, LVID_SECTOR as u32, 134 - 16);
    o.put(LVID_SECTOR, &lvid[..134])?;
    let mut td = vec![0u8; 512];
    finish_tag(&mut td, TAG_TD, LVID_SECTOR as u32 + 1, 496);
    o.put(LVID_SECTOR + 1, &td)?;
    for (i, d) in vds(RESERVE_VDS).into_iter().enumerate() {
        o.put(RESERVE_VDS + i as u64, &d)?;
    }

    // ---- partition: file set descriptor ----
    let mut fsd = vec![0u8; 512];
    fsd[16..28].copy_from_slice(&t.udf());
    put16(&mut fsd, 28, 3);
    put16(&mut fsd, 30, 3);
    put32(&mut fsd, 32, 1);
    put32(&mut fsd, 36, 1);
    fsd[48..112].copy_from_slice(&charspec());
    fsd[112..240].copy_from_slice(&lv_ident);
    fsd[240..304].copy_from_slice(&charspec());
    fsd[304..336].copy_from_slice(&dstring(&label, 32));
    put32(&mut fsd, 400, SECTOR as u32);
    put32(&mut fsd, 404, tree.nodes[0].fe_lbn);
    fsd[416..448].copy_from_slice(&regid(b"*OSTA UDF Compliant", &DOMAIN_SUFFIX));
    finish_tag(&mut fsd, TAG_FSD, 0, 496);
    o.put(PART_START, &fsd)?;
    let mut td = vec![0u8; 512];
    finish_tag(&mut td, TAG_TD, 1, 496);
    o.put(PART_START + 1, &td)?;

    // ---- file entries ----
    let child_dirs = |n: &Node| match &n.kind {
        Kind::Dir { children, .. } => children.iter().filter(|&&c| matches!(tree.nodes[c].kind, Kind::Dir { .. })).count(),
        _ => 0,
    };
    for n in &tree.nodes {
        let (is_dir, size) = match &n.kind {
            Kind::Dir { data_len, .. } => (true, *data_len),
            Kind::File { size, .. } => (false, *size),
        };
        let mut ads = Vec::new();
        let mut left = size;
        let mut lbn = n.data_lbn as u64;
        while left > 0 {
            let len = left.min(MAX_EXTENT);
            ads.extend_from_slice(&(len as u32).to_le_bytes());
            ads.extend_from_slice(&(lbn as u32).to_le_bytes());
            lbn += blocks(len);
            left -= len;
        }
        if 176 + ads.len() > SECTOR {
            bail!("{} is too large for a single file entry", n.rel);
        }
        let mut fe = vec![0u8; 176 + ads.len()];
        put16(&mut fe, 20, 4); // strategy 4
        put16(&mut fe, 24, 1); // max entries
        fe[27] = if is_dir { 4 } else { 5 };
        put16(&mut fe, 34, 0); // short allocation descriptors
        put32(&mut fe, 36, u32::MAX);
        put32(&mut fe, 40, u32::MAX);
        put32(&mut fe, 44, 0x14A5); // r-x for owner, group, other
        put16(&mut fe, 48, if is_dir { 1 + child_dirs(n) as u16 } else { 1 });
        put64(&mut fe, 56, size);
        put64(&mut fe, 64, blocks(size));
        for o_ in [72usize, 84, 96] {
            fe[o_..o_ + 12].copy_from_slice(&t.udf());
        }
        put32(&mut fe, 108, 1);
        fe[128..160].copy_from_slice(&regid(IMPL_ID, &IMPL_SUFFIX));
        put64(&mut fe, 160, n.uniq);
        put32(&mut fe, 168, 0);
        put32(&mut fe, 172, ads.len() as u32);
        fe[176..].copy_from_slice(&ads);
        let body = fe.len() - 16;
        finish_tag(&mut fe, TAG_FE, n.fe_lbn, body);
        o.put(PART_START + n.fe_lbn as u64, &fe)?;
    }

    // ---- directory contents (file identifier descriptors) ----
    for n in &tree.nodes {
        let Kind::Dir { children, data_len } = &n.kind else { continue };
        let mut d = Vec::with_capacity(*data_len as usize);
        let fid = |d: &mut Vec<u8>, chars: u8, name: &[u8], target: &Node| {
            let start = d.len();
            let len = fid_len(name.len()) as usize;
            let mut f = vec![0u8; len];
            put16(&mut f, 16, 1);
            f[18] = chars;
            f[19] = name.len() as u8;
            put32(&mut f, 20, SECTOR as u32);
            put32(&mut f, 24, target.fe_lbn);
            put32(&mut f, 32, target.uniq as u32);
            f[38..38 + name.len()].copy_from_slice(name);
            let loc = n.data_lbn + (start / SECTOR) as u32;
            finish_tag(&mut f, TAG_FID, loc, len - 16);
            d.extend(f);
        };
        fid(&mut d, 0x0A, &[], &tree.nodes[n.parent]);
        for &c in children {
            let child = &tree.nodes[c];
            let chars = if matches!(child.kind, Kind::Dir { .. }) { 0x02 } else { 0 };
            fid(&mut d, chars, &cs0_encode(&child.name), child);
        }
        debug_assert_eq!(d.len() as u64, *data_len);
        o.put(PART_START + n.data_lbn as u64, &d)?;
    }

    // ---- file data ----
    let total_bytes: u64 = tree.nodes.iter().map(|n| if let Kind::File { size, .. } = n.kind { size } else { 0 }).sum();
    let mut done = 0u64;
    let mut buf = vec![0u8; 8 << 20];
    for n in &tree.nodes {
        let Kind::File { src: path, size } = &n.kind else { continue };
        if *size == 0 {
            continue;
        }
        o.zero_to(PART_START + n.data_lbn as u64)?;
        let mut f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mut left = *size;
        while left > 0 {
            let c = left.min(buf.len() as u64) as usize;
            f.read_exact(&mut buf[..c]).with_context(|| format!("{} changed while writing", path.display()))?;
            o.w.write_all(&buf[..c])?;
            left -= c as u64;
            done += c as u64;
            progress(done, total_bytes);
        }
        let pad = (SECTOR as u64 - size % SECTOR as u64) % SECTOR as u64;
        o.w.write_all(&vec![0u8; pad as usize])?;
        o.sector += blocks(*size);
    }

    // ---- closing anchor ----
    o.zero_to(PART_START + part_len)?;
    let mut a = avdp;
    finish_tag(&mut a, TAG_AVDP, (PART_START + part_len) as u32, 496);
    o.put(PART_START + part_len, &a)?;
    if o.sector != total {
        bail!("internal layout error: wrote {} sectors, expected {total}", o.sector);
    }
    o.w.flush()?;
    o.w.get_ref().sync_all()?;
    Ok(())
}
