//! Read-only UDF reader for Windows installation media (UDF 1.02 bridge discs from oscdimg,
//! also UDF 2.x with extended file entries and inline data).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
/// Positional reads that fill the whole buffer (Unix `pread`, Windows `ReadFile` at an offset).
trait ReadExactAt {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()>;
}

impl ReadExactAt for std::fs::File {
    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
        while !buf.is_empty() {
            match std::os::windows::fs::FileExt::seek_read(self, buf, offset) {
                Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::udf::*;

#[derive(Debug, Clone)]
pub enum Data {
    /// (absolute byte offset in the image, length) runs.
    Extents(Vec<(u64, u64)>),
    Inline(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Path with `/` separators, relative to the root, e.g. `sources/install.wim`.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Data,
}

pub struct UdfReader {
    file: File,
    partition_start: u64,
    block: u64,
    root: (u32, u32),
    fsd_lbn: u32,
}

struct Node {
    is_dir: bool,
    size: u64,
    data: Data,
}

impl UdfReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mut r = UdfReader { file, partition_start: 0, block: SECTOR as u64, root: (0, 0), fsd_lbn: 0 };
        let avdp = r.sector(256)?;
        if check_tag(&avdp) != Some(TAG_AVDP) {
            bail!("{} has no UDF anchor at sector 256 (not a Windows installation ISO?)", path.display());
        }
        let (len, loc) = (le32(&avdp, 16), le32(&avdp, 20));
        let mut fsd: Option<(u32, u32)> = None;
        let mut part = None;
        for i in 0..(len as u64 / SECTOR as u64).max(1) {
            let d = r.sector(loc as u64 + i)?;
            match check_tag(&d) {
                Some(TAG_PD) => part = Some(le32(&d, 188)),
                Some(TAG_LVD) => {
                    r.block = le32(&d, 212) as u64;
                    // logical volume contents use = long_ad of the file set descriptor
                    fsd = Some((le32(&d, 252), le16(&d, 256) as u32));
                }
                Some(TAG_TD) => break,
                _ => {}
            }
        }
        r.partition_start = part.ok_or_else(|| anyhow!("UDF partition descriptor missing"))? as u64;
        let (fsd_lbn, _) = fsd.ok_or_else(|| anyhow!("UDF logical volume descriptor missing"))?;
        r.fsd_lbn = fsd_lbn;
        let f = r.block_at(fsd_lbn)?;
        if check_tag(&f) != Some(TAG_FSD) {
            bail!("UDF file set descriptor not found");
        }
        // root directory ICB long_ad: (location, length)
        r.root = (le32(&f, 404), le32(&f, 400));
        Ok(r)
    }

    fn sector(&self, n: u64) -> Result<Vec<u8>> {
        let mut b = vec![0u8; SECTOR];
        self.file.read_exact_at(&mut b, n * SECTOR as u64)?;
        Ok(b)
    }

    fn block_at(&self, lbn: u32) -> Result<Vec<u8>> {
        let mut b = vec![0u8; self.block as usize];
        self.file.read_exact_at(&mut b, self.abs(lbn))?;
        Ok(b)
    }

    fn abs(&self, lbn: u32) -> u64 {
        self.partition_start * SECTOR as u64 + lbn as u64 * self.block
    }

    fn read_node(&self, lbn: u32) -> Result<Node> {
        let fe = self.block_at(lbn)?;
        let tag = check_tag(&fe).ok_or_else(|| anyhow!("corrupt UDF file entry at block {lbn}"))?;
        let (ea, ad, base, size) = match tag {
            TAG_FE => (le32(&fe, 168), le32(&fe, 172), 176usize, le64(&fe, 56)),
            TAG_EFE => (le32(&fe, 208), le32(&fe, 212), 216usize, le64(&fe, 56)),
            t => bail!("unexpected descriptor {t} at block {lbn}, expected file entry"),
        };
        let file_type = fe[16 + 11];
        let flags = le16(&fe, 16 + 18);
        let start = base + ea as usize;
        let ads = fe.get(start..start + ad as usize).ok_or_else(|| anyhow!("file entry overflow"))?.to_vec();
        let data = match flags & 7 {
            3 => Data::Inline(ads[..size.min(ads.len() as u64) as usize].to_vec()),
            kind @ (0 | 1) => {
                let mut runs = Vec::new();
                let mut queue = ads;
                let step = if kind == 0 { 8 } else { 16 };
                let mut guard = 0;
                'outer: loop {
                    for chunk in queue.chunks_exact(step) {
                        let raw = le32(chunk, 0);
                        let (etype, elen) = (raw >> 30, (raw & 0x3FFF_FFFF) as u64);
                        if elen == 0 {
                            break 'outer;
                        }
                        let pos = le32(chunk, 4);
                        match etype {
                            0 => runs.push((self.abs(pos), elen)),
                            1 | 2 => runs.push((u64::MAX, elen)), // sparse
                            _ => {
                                // continuation: next block holds an allocation extent descriptor
                                guard += 1;
                                if guard > 10000 {
                                    bail!("allocation descriptor loop");
                                }
                                let aed = self.block_at(pos)?;
                                let l = le32(&aed, 20) as usize;
                                queue = aed[24..24 + l].to_vec();
                                continue 'outer;
                            }
                        }
                    }
                    break;
                }
                Data::Extents(runs)
            }
            k => bail!("unsupported allocation descriptor type {k}"),
        };
        Ok(Node { is_dir: file_type == 4, size, data })
    }

    fn read_data(&self, data: &Data, size: u64) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size as usize);
        self.copy_data(data, size, &mut out)?;
        Ok(out)
    }

    fn copy_data(&self, data: &Data, size: u64, out: &mut dyn Write) -> Result<u64> {
        match data {
            Data::Inline(b) => {
                out.write_all(b)?;
                Ok(b.len() as u64)
            }
            Data::Extents(runs) => {
                let mut left = size;
                let mut buf = vec![0u8; 8 << 20];
                for &(pos, len) in runs {
                    let mut n = len.min(left);
                    let mut off = pos;
                    while n > 0 {
                        let c = n.min(buf.len() as u64) as usize;
                        if pos == u64::MAX {
                            buf[..c].fill(0);
                        } else {
                            self.file.read_exact_at(&mut buf[..c], off)?;
                            off += c as u64;
                        }
                        out.write_all(&buf[..c])?;
                        n -= c as u64;
                        left -= c as u64;
                    }
                    if left == 0 {
                        break;
                    }
                }
                Ok(size - left)
            }
        }
    }

    fn dir_entries(&self, node: &Node) -> Result<Vec<(String, u32, bool)>> {
        let d = self.read_data(&node.data, node.size)?;
        let mut out = Vec::new();
        let mut i = 0;
        while i + 38 <= d.len() {
            if le16(&d, i) != TAG_FID {
                // FIDs never span blocks in a way that leaves garbage; stop on padding.
                break;
            }
            let chars = d[i + 18];
            let lfi = d[i + 19] as usize;
            let icb_lbn = le32(&d, i + 24);
            let liu = le16(&d, i + 36) as usize;
            let name_at = i + 38 + liu;
            let name = d.get(name_at..name_at + lfi).map(cs0_decode).unwrap_or_default();
            let total = (38 + liu + lfi + 3) & !3;
            if chars & 0x0C == 0 && !name.is_empty() {
                // not deleted (4), not parent (8)
                out.push((name, icb_lbn, chars & 2 != 0));
            }
            i += total;
        }
        Ok(out)
    }

    /// Lists every file and directory (depth first, sorted by name within a directory).
    pub fn walk(&self) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        let root = self.read_node(self.root.0)?;
        self.walk_into(&root, "", &mut out, 0)?;
        Ok(out)
    }

    fn walk_into(&self, dir: &Node, prefix: &str, out: &mut Vec<Entry>, depth: u32) -> Result<()> {
        if depth > 64 {
            bail!("directory tree too deep");
        }
        let mut entries = self.dir_entries(dir)?;
        entries.sort_by_key(|e| e.0.to_lowercase());
        for (name, lbn, _) in entries {
            if name.contains('/') || name == "." || name == ".." {
                bail!("unsafe file name {name:?} in image");
            }
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let node = self.read_node(lbn)?;
            out.push(Entry { path: path.clone(), is_dir: node.is_dir, size: if node.is_dir { 0 } else { node.size }, data: node.data.clone() });
            if node.is_dir {
                self.walk_into(&node, &path, out, depth + 1)?;
            }
        }
        Ok(())
    }

    pub fn find(&self, path: &str) -> Result<Option<Entry>> {
        let want = path.trim_matches('/').to_lowercase();
        Ok(self.walk()?.into_iter().find(|e| e.path.to_lowercase() == want))
    }

    /// Reads `len` bytes at `offset` within a file.
    pub fn read_range(&self, e: &Entry, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        match &e.data {
            Data::Inline(b) => {
                let s = (offset as usize).min(b.len());
                let n = len.min(b.len() - s);
                out[..n].copy_from_slice(&b[s..s + n]);
                out.truncate(n);
            }
            Data::Extents(runs) => {
                let (mut skip, mut filled) = (offset, 0usize);
                for &(pos, rlen) in runs {
                    if filled == len {
                        break;
                    }
                    if skip >= rlen {
                        skip -= rlen;
                        continue;
                    }
                    let n = ((rlen - skip) as usize).min(len - filled);
                    if pos == u64::MAX {
                        out[filled..filled + n].fill(0);
                    } else {
                        self.file.read_exact_at(&mut out[filled..filled + n], pos + skip)?;
                    }
                    filled += n;
                    skip = 0;
                }
                out.truncate(filled);
            }
        }
        Ok(out)
    }

    pub fn read_file(&self, e: &Entry) -> Result<Vec<u8>> {
        self.read_data(&e.data, e.size)
    }

    pub fn copy_file(&self, e: &Entry, out: &mut dyn Write) -> Result<u64> {
        self.copy_data(&e.data, e.size, out)
    }

    /// Extracts the whole tree below `dest`. `skip` decides per path whether to leave a file out.
    pub fn extract(&self, dest: &Path, skip: &dyn Fn(&str) -> bool, progress: &mut dyn FnMut(&str, u64)) -> Result<()> {
        std::fs::create_dir_all(dest)?;
        for e in self.walk()? {
            let target = dest.join(&e.path);
            if e.is_dir {
                std::fs::create_dir_all(&target)?;
                continue;
            }
            if skip(&e.path) {
                continue;
            }
            let mut f = io::BufWriter::with_capacity(8 << 20, File::create(&target)?);
            let n = self.copy_file(&e, &mut f)?;
            f.flush()?;
            if n != e.size {
                bail!("{}: short read ({n} of {})", e.path, e.size);
            }
            progress(&e.path, n);
        }
        Ok(())
    }

    /// Volume label from the logical volume descriptor's file set.
    pub fn label(&self) -> Result<String> {
        let f = self.block_at(self.fsd_lbn).ok();
        let fsd = match f {
            Some(f) if check_tag(&f) == Some(TAG_FSD) => f,
            _ => return Ok(String::new()),
        };
        let d = &fsd[112..112 + 128];
        let n = d[127] as usize;
        Ok(cs0_decode(&d[..n.min(127)]))
    }
}

/// Reads `len` bytes at `offset` from a file (helper for tests and tools).
pub fn read_at(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b)?;
    Ok(b)
}
