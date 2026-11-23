//! Split a WIM into a spanned set (`install.swm`, `install2.swm`, ...) for FAT32 media, streaming: the
//! stored resources are copied unchanged, nothing is held in memory but the blob tables.
//!
//! Layout and rules follow wimlib's split.c (as in `wim_format::split_join::split_archive`): blobs in
//! file order, a new part starts before a blob would reach the size budget, a single resource is never
//! split, all metadata resources go to part one, every part carries its own blob table and the XML.
//! Solid archives (install.esd) cannot be split: export them to LZX first.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use wim_format::lookup::{LookupBlob, LookupEntry};
use wim_format::{HEADER_SIZE, ResourceHeader, WIM_MAGIC};

use crate::Log;
use crate::native::Wim;

/// Largest part Microsoft's guide uses for FAT32 media (`DISM /Split-Image /FileSize:3800`).
pub const FAT32_PART: u64 = 3800 << 20;

const FLAG_METADATA: u8 = 2;
const HDR_FLAG_SPANNED: u32 = 8;

/// Names of the parts: `install.swm`, `install2.swm`, ... next to `first`.
pub fn part_path(first: &Path, n: u16) -> PathBuf {
    if n == 1 {
        return first.to_path_buf();
    }
    let stem = first.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = first.extension().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "swm".into());
    first.with_file_name(format!("{stem}{n}.{ext}"))
}

/// Whether the archive has solid resources (then it must be exported to a non-solid WIM before splitting).
pub fn is_solid(src: &Path) -> Result<bool> {
    let wim = Wim::open(src)?;
    Ok(wim.lookup().resources.iter().any(|r| r.solid))
}

/// Splits `src` into parts of at most `part_size` bytes of stored data each; returns the part files.
pub fn split(src: &Path, first: &Path, part_size: u64, log: Log) -> Result<Vec<PathBuf>> {
    if part_size == 0 {
        bail!("part size must not be 0");
    }
    let wim = Wim::open(src)?;
    let h = wim.header().clone();
    let lookup = wim.lookup();
    if h.part_number != 1 || h.total_parts != 1 {
        bail!("{} is already part of a split set", src.display());
    }
    if lookup.resources.iter().any(|r| r.solid) {
        bail!("{} has solid resources (install.esd): export it to a non-solid WIM before splitting", src.display());
    }
    if wim.is_pipable() {
        bail!("{} is a pipable WIM, which cannot be split", src.display());
    }
    let stored = |b: &LookupBlob| lookup.resources[b.resource_index].header.size_in_wim;
    let mut blobs: Vec<&LookupBlob> = lookup.blobs.iter().collect();
    blobs.sort_by_key(|b| lookup.resources[b.resource_index].header.offset_in_wim);
    let mut groups: Vec<Vec<&LookupBlob>> = vec![Vec::new()];
    let mut size: u64 = lookup.metadata.iter().map(stored).sum();
    for b in blobs {
        let s = stored(b);
        if size != 0 && size + s >= part_size {
            if groups.len() == u16::MAX as usize {
                bail!("too many parts");
            }
            groups.push(Vec::new());
            size = 0;
        }
        size += s;
        groups.last_mut().expect("one group").push(b);
    }
    let total = groups.len() as u16;
    let mut input = File::open(src).with_context(|| format!("cannot open {}", src.display()))?;
    let xml = read_raw(&mut input, &h.xml_data)?;
    let guid = *uuid::Uuid::new_v4().as_bytes();
    let mut parts = Vec::with_capacity(total as usize);
    for (i, group) in groups.iter().enumerate() {
        let number = i as u16 + 1;
        let path = part_path(first, number);
        log(&format!("writing {} (part {number} of {total})", path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()));
        let f = File::create_new(&path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut out = BufWriter::with_capacity(4 << 20, f);
        out.write_all(&[0u8; HEADER_SIZE])?;
        let mut pos = HEADER_SIZE as u64;
        let mut table = Vec::with_capacity(group.len() * 50 + 64);
        let mut copy = |b: &LookupBlob, out: &mut BufWriter<File>, pos: &mut u64, table: &mut Vec<u8>| -> Result<()> {
            let mut res = lookup.resources[b.resource_index].header;
            input.seek(SeekFrom::Start(res.offset_in_wim))?;
            let n = std::io::copy(&mut (&mut input).take(res.size_in_wim), out)?;
            if n != res.size_in_wim {
                bail!("{} ends inside a resource", src.display());
            }
            res.offset_in_wim = *pos;
            *pos += n;
            table.extend_from_slice(&LookupEntry { resource: res, part_number: number, reference_count: b.reference_count, hash: b.hash }.encode());
            Ok(())
        };
        for b in group {
            copy(b, &mut out, &mut pos, &mut table)?;
        }
        if number == 1 {
            for b in &lookup.metadata {
                copy(b, &mut out, &mut pos, &mut table)?;
            }
        }
        let mut header = h.clone();
        header.magic = WIM_MAGIC;
        header.guid = guid;
        header.part_number = number;
        header.total_parts = total;
        // keep only the compression flags (as wimlib), mark the set as spanned
        header.flags &= 0x84 | 2 | 0xe0000;
        if total != 1 {
            header.flags |= HDR_FLAG_SPANNED;
            header.boot_index = 0;
        }
        header.reserved = [0; 60];
        header.boot_metadata = ResourceHeader::default();
        header.integrity_table = ResourceHeader::default();
        header.blob_table = ResourceHeader { size_in_wim: table.len() as u64, flags: FLAG_METADATA, offset_in_wim: pos, uncompressed_size: table.len() as u64 };
        out.write_all(&table)?;
        pos += table.len() as u64;
        header.xml_data = ResourceHeader { size_in_wim: xml.len() as u64, flags: FLAG_METADATA, offset_in_wim: pos, uncompressed_size: xml.len() as u64 };
        out.write_all(&xml)?;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&header.encode_canonical())?;
        let f = out.into_inner().map_err(|e| anyhow::anyhow!("cannot write {}: {}", path.display(), e.error()))?;
        f.sync_all()?;
        parts.push(path);
    }
    Ok(parts)
}

fn read_raw(f: &mut File, r: &ResourceHeader) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; usize::try_from(r.size_in_wim)?];
    f.seek(SeekFrom::Start(r.offset_in_wim))?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_names() {
        let p = Path::new("/m/sources/install.swm");
        assert_eq!(part_path(p, 1), Path::new("/m/sources/install.swm"));
        assert_eq!(part_path(p, 2), Path::new("/m/sources/install2.swm"));
        assert_eq!(part_path(p, 12), Path::new("/m/sources/install12.swm"));
    }
}
