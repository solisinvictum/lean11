//! Native WIM/ESD writer: streaming output, parallel compression with a deterministic layout,
//! raw copies of resources that already have the target compression, and LZMS solid resources.
//!
//! Layout follows wimlib's writer (via `wim-format`): header, data resources, metadata resources,
//! blob table, XML data, integrity table.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use crate::platform::ReadExactAt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;

use anyhow::{Context, Result, anyhow, bail};
use sha1::{Digest, Sha1};
use wim_format::lookup::{LookupEntry, SOLID_RESOURCE_MARKER};
use wim_format::metadata::Metadata;
use wim_format::resource::ResourceLayout;
use wim_format::resource_write::encode_resource;
use wim_format::xml::XmlInfo;
use wim_format::{Compression as C, HEADER_SIZE, Header, ParseError, ResourceHeader, WIM_MAGIC};

use crate::native::{Wim, hex, pe};
use crate::{Compression, Log};

/// Uncompressed size of one LZMS solid chunk (wimlib's default for LZMS).
pub const SOLID_CHUNK: u32 = 1 << 26;
const FLAG_METADATA: u8 = 2;
const FLAG_COMPRESSED: u8 = 4;
const FLAG_SOLID: u8 = 16;
/// Uncompressed bytes that ordinary-resource workers may hold at once (besides the next blob).
const INFLIGHT_BUDGET: u64 = 2 << 30;

/// Output compression: codec and chunk size of ordinary resources, solid data or not.
#[derive(Debug, Clone, Copy)]
pub struct Codec {
    pub kind: C,
    pub chunk: u32,
    pub solid: bool,
    /// wimlib compression level (50 default, 100 for `maximum`)
    pub level: u32,
}

impl Codec {
    pub fn of(c: Compression) -> Self {
        match c {
            Compression::Recovery => Codec { kind: C::Lzms, chunk: 1 << 17, solid: true, level: lean11_codecs::DEFAULT_LEVEL },
            Compression::Fast => Codec { kind: C::Xpress, chunk: 32768, solid: false, level: lean11_codecs::DEFAULT_LEVEL },
            Compression::Lzx => Codec { kind: C::Lzx, chunk: 32768, solid: false, level: lean11_codecs::DEFAULT_LEVEL },
            Compression::Maximum => Codec { kind: C::Lzx, chunk: 32768, solid: false, level: lean11_codecs::MAXIMUM_LEVEL },
        }
    }

    fn header_flags(self) -> u32 {
        2 | match self.kind {
            C::Xpress => 0x20000,
            C::Lzx => 0x40000,
            C::Lzms => 0x80000,
            C::None => return 0,
        }
    }
}

thread_local! {
    /// One compressor per thread, reused while kind, block size and level stay the same.
    static COMPRESSOR: std::cell::RefCell<Option<((C, u32, u32), lean11_codecs::Compressor)>> = const { std::cell::RefCell::new(None) };
}

/// Compresses one chunk with wimlib's compressors (`lean11-codecs`); `None` stores it verbatim.
pub fn compress_chunk(kind: C, chunk_size: u32, level: u32, data: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    let k = match kind {
        C::Xpress => lean11_codecs::Kind::Xpress,
        C::Lzx => lean11_codecs::Kind::Lzx,
        C::Lzms => lean11_codecs::Kind::Lzms,
        C::None => return Ok(None),
    };
    COMPRESSOR.with(|cell| {
        let mut slot = cell.borrow_mut();
        let key = (kind, chunk_size, level);
        if slot.as_ref().is_none_or(|(have, _)| *have != key) {
            *slot = None; // free the old buffers first
            let c = lean11_codecs::Compressor::new(k, chunk_size as usize, level).ok_or(ParseError::Nomem)?;
            *slot = Some((key, c));
        }
        Ok(slot.as_mut().unwrap().1.compress(data))
    })
}

/// Memory of one compressor thread in bytes (compressor plus input and output buffers).
pub fn thread_memory(codec: Codec) -> u64 {
    let (k, block) = match codec.kind {
        C::Lzms if codec.solid => (lean11_codecs::Kind::Lzms, SOLID_CHUNK as usize),
        C::Lzms => (lean11_codecs::Kind::Lzms, codec.chunk as usize),
        C::Lzx => (lean11_codecs::Kind::Lzx, codec.chunk as usize),
        C::Xpress => (lean11_codecs::Kind::Xpress, codec.chunk as usize),
        C::None => return 1 << 20,
    };
    lean11_codecs::Compressor::needed_memory(k, block, codec.level) + 3 * block as u64
}

/// Where the bytes of a blob come from.
#[derive(Debug, Clone)]
pub enum BlobSrc {
    /// Blob of a source archive (index into the writer's sources).
    Wim(usize),
    /// A file whose content hash was computed before.
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct Blob {
    pub hash: [u8; 20],
    pub size: u64,
    pub src: BlobSrc,
    /// References from all written images.
    pub refs: u32,
    /// Solid ordering key (extension, then name), like wimlib's solid sort.
    pub sort_key: String,
}

pub fn sort_key(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.rsplit_once('.') {
        Some((stem, ext)) => format!("{ext}\0{stem}"),
        None => format!("\0{lower}"),
    }
}

struct Piece {
    bytes: Vec<u8>,
    header: ResourceHeader,
}

pub fn threads(solid: bool) -> usize {
    crate::threads_for(if solid { Compression::Recovery } else { Compression::Lzx })
}

type View = (wim_format::file_archive::FileArchive<File>, File, crate::native::SolidCache);

/// A WIM being written. Create, add blobs and metadata, then `finish`.
pub struct WimWriter<'a> {
    out: BufWriter<File>,
    path: PathBuf,
    pos: u64,
    codec: Codec,
    sources: &'a [&'a Wim],
    table: Vec<u8>,
    metadata: Vec<(ResourceHeader, [u8; 20])>,
}

impl<'a> WimWriter<'a> {
    /// Creates `path` (must not exist).
    pub fn create(path: &Path, codec: Codec, sources: &'a [&'a Wim]) -> Result<Self> {
        let f = File::create_new(path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut out = BufWriter::with_capacity(4 << 20, f);
        out.write_all(&[0u8; HEADER_SIZE])?;
        Ok(WimWriter { out, path: path.to_path_buf(), pos: HEADER_SIZE as u64, codec, sources, table: Vec::new(), metadata: Vec::new() })
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let at = self.pos;
        self.out.write_all(bytes).with_context(|| format!("cannot write {}", self.path.display()))?;
        self.pos += bytes.len() as u64;
        Ok(at)
    }

    fn entry(&mut self, resource: ResourceHeader, refs: u32, hash: [u8; 20]) {
        self.table.extend_from_slice(&LookupEntry { resource, reference_count: refs, hash, part_number: 1 }.encode());
    }

    /// Writes all data blobs (ordinary resources, or one solid resource).
    pub fn write_blobs(&mut self, mut blobs: Vec<Blob>, log: Log) -> Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }
        if self.codec.solid {
            blobs.sort_by(|a, b| a.sort_key.cmp(&b.sort_key).then(a.size.cmp(&b.size)).then(a.hash.cmp(&b.hash)));
            self.write_solid(&blobs, log)
        } else {
            // source archive order first (sequential reads), then new files
            let sources = self.sources;
            blobs.sort_by_cached_key(|b| match &b.src {
                BlobSrc::Wim(s) => {
                    let lb = sources[*s].lookup().find(&b.hash);
                    (0usize, *s, lb.map(|l| (l.resource_index, l.offset)).unwrap_or((usize::MAX, 0)), String::new())
                }
                BlobSrc::File(p) => (1, 0, (0, 0), p.to_string_lossy().into_owned()),
            });
            self.write_ordinary(&blobs, log)
        }
    }

    fn write_ordinary(&mut self, blobs: &[Blob], log: Log) -> Result<()> {
        // consecutive blobs from one solid source chunk form a group (decoded once by one worker)
        let mut groups: Vec<std::ops::Range<usize>> = Vec::new();
        let mut last_key = None;
        for (i, b) in blobs.iter().enumerate() {
            let key = match &b.src {
                BlobSrc::Wim(s) => self.sources[*s].lookup().find(&b.hash).and_then(|lb| {
                    let r = &self.sources[*s].lookup().resources[lb.resource_index];
                    r.solid.then(|| (*s, lb.resource_index, lb.offset / u64::from(r.chunk_size.max(1))))
                }),
                BlobSrc::File(_) => None,
            };
            match (key, last_key) {
                (Some(k), Some(l)) if k == l => groups.last_mut().unwrap().end = i + 1,
                _ => groups.push(i..i + 1),
            }
            last_key = key;
        }
        let workers = threads(false).min(groups.len());
        let next = AtomicUsize::new(0);
        let written = AtomicUsize::new(0);
        // uncompressed bytes held by workers and the reorder buffer
        let inflight = AtomicU64::new(0);
        let failed = AtomicBool::new(false);
        let (tx, rx) = sync_channel::<(usize, Result<Piece>)>(workers * 2);
        let codec = self.codec;
        let sources = self.sources;
        let total: u64 = blobs.iter().map(|b| b.size).sum();
        let mut result: Result<()> = Ok(());
        std::thread::scope(|s| {
            for _ in 0..workers {
                let tx = tx.clone();
                let (next, written, failed, inflight, groups) = (&next, &written, &failed, &inflight, &groups);
                s.spawn(move || {
                    let mut views: HashMap<usize, View> = HashMap::new();
                    loop {
                        let g = next.fetch_add(1, Ordering::Relaxed);
                        if g >= groups.len() || failed.load(Ordering::Relaxed) {
                            return;
                        }
                        for i in groups[g].clone() {
                            // the next blob to be written always proceeds, others wait for the byte budget
                            while i != written.load(Ordering::Acquire)
                                && inflight.load(Ordering::Acquire) + blobs[i].size > INFLIGHT_BUDGET
                                && !failed.load(Ordering::Relaxed)
                            {
                                std::thread::sleep(std::time::Duration::from_millis(2));
                            }
                            if failed.load(Ordering::Relaxed) {
                                return;
                            }
                            inflight.fetch_add(blobs[i].size, Ordering::AcqRel);
                            let piece = make_piece(&blobs[i], codec, sources, &mut views);
                            if tx.send((i, piece)).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
            drop(tx);
            let mut pending: BTreeMap<usize, Piece> = BTreeMap::new();
            let mut next_write = 0usize;
            let (mut done, mut last_tenth) = (0u64, -1i64);
            for (i, piece) in rx {
                if result.is_err() {
                    continue;
                }
                match piece {
                    Ok(p) => {
                        pending.insert(i, p);
                    }
                    Err(e) => {
                        failed.store(true, Ordering::Relaxed);
                        result = Err(e);
                        continue;
                    }
                }
                while let Some(p) = pending.remove(&next_write) {
                    let b = &blobs[next_write];
                    match self.append(&p.bytes) {
                        Ok(at) => self.entry(ResourceHeader { offset_in_wim: at, ..p.header }, b.refs, b.hash),
                        Err(e) => {
                            failed.store(true, Ordering::Relaxed);
                            result = Err(e);
                            break;
                        }
                    }
                    done += b.size;
                    inflight.fetch_sub(b.size, Ordering::AcqRel);
                    next_write += 1;
                    written.store(next_write, Ordering::Release);
                    let pct = if total == 0 { 100 } else { (done * 100 / total) as i64 };
                    if pct / 10 != last_tenth {
                        last_tenth = pct / 10;
                        log(&format!("Archiving file data: {:.2} GiB of {:.2} GiB ({pct}%) done", gib(done), gib(total)));
                    }
                }
            }
        });
        result
    }

    fn write_solid(&mut self, blobs: &[Blob], log: Log) -> Result<()> {
        let mut starts = Vec::with_capacity(blobs.len());
        let mut total = 0u64;
        for b in blobs {
            starts.push(total);
            total += b.size;
        }
        let csize = u64::from(SOLID_CHUNK);
        let count = total.div_ceil(csize) as usize;
        let prefix_len = 16 + 4 * count;
        let res_at = self.append(&vec![0u8; prefix_len])?;
        let workers = threads(true).min(count);
        log(&format!("Compressing {:.2} GiB into {count} solid LZMS chunks with {workers} threads", gib(total)));
        let next = AtomicUsize::new(0);
        let written = AtomicUsize::new(0);
        let failed = AtomicBool::new(false);
        let (tx, rx) = sync_channel::<(usize, Result<Vec<u8>>)>(workers);
        let sources = self.sources;
        let kind = self.codec.kind;
        let level = self.codec.level;
        let mut sizes: Vec<u32> = Vec::with_capacity(count);
        let mut result: Result<()> = Ok(());
        std::thread::scope(|s| {
            for _ in 0..workers {
                let tx = tx.clone();
                let (next, written, failed, starts) = (&next, &written, &failed, &starts);
                s.spawn(move || {
                    let mut views: HashMap<usize, View> = HashMap::new();
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= count || failed.load(Ordering::Relaxed) {
                            return;
                        }
                        while k >= written.load(Ordering::Acquire) + workers + 1 && !failed.load(Ordering::Relaxed) {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        let r = (|| -> Result<Vec<u8>> {
                            let (a, b) = (k as u64 * csize, ((k as u64 + 1) * csize).min(total));
                            let mut buf = Vec::with_capacity((b - a) as usize);
                            let mut i = starts.partition_point(|&s| s <= a) - 1;
                            while i < blobs.len() && starts[i] < b {
                                let (from, to) = (a.max(starts[i]) - starts[i], b.min(starts[i] + blobs[i].size) - starts[i]);
                                if to > from {
                                    read_range(&blobs[i], from..to, sources, &mut views, &mut buf)?;
                                }
                                i += 1;
                            }
                            let c = compress_chunk(kind, SOLID_CHUNK, level, &buf).map_err(pe)?;
                            Ok(c.filter(|c| !c.is_empty() && c.len() < buf.len()).unwrap_or(buf))
                        })();
                        if tx.send((k, r)).is_err() {
                            return;
                        }
                    }
                });
            }
            drop(tx);
            let mut pending = BTreeMap::new();
            let mut last_tenth = -1i64;
            for (k, r) in rx {
                if result.is_err() {
                    continue;
                }
                match r {
                    Ok(c) => {
                        pending.insert(k, c);
                    }
                    Err(e) => {
                        failed.store(true, Ordering::Relaxed);
                        result = Err(e);
                        continue;
                    }
                }
                while let Some(c) = pending.remove(&sizes.len()) {
                    if let Err(e) = self.append(&c) {
                        failed.store(true, Ordering::Relaxed);
                        result = Err(e);
                        break;
                    }
                    sizes.push(c.len() as u32);
                    written.store(sizes.len(), Ordering::Release);
                    let pct = (sizes.len() * 100 / count) as i64;
                    if pct / 10 != last_tenth {
                        last_tenth = pct / 10;
                        log(&format!("Archiving file data: {:.2} GiB of {:.2} GiB ({pct}%) done", gib((sizes.len() as u64 * csize).min(total)), gib(total)));
                    }
                }
            }
        });
        result?;
        // patch the solid header and chunk table
        let mut prefix = Vec::with_capacity(prefix_len);
        prefix.extend_from_slice(&total.to_le_bytes());
        prefix.extend_from_slice(&SOLID_CHUNK.to_le_bytes());
        prefix.extend_from_slice(&(kind as u32).to_le_bytes());
        for s in &sizes {
            prefix.extend_from_slice(&s.to_le_bytes());
        }
        self.out.seek(SeekFrom::Start(res_at))?;
        self.out.write_all(&prefix)?;
        self.out.seek(SeekFrom::Start(self.pos))?;
        let res_size = self.pos - res_at;
        self.entry(ResourceHeader { size_in_wim: res_size, flags: FLAG_SOLID, offset_in_wim: res_at, uncompressed_size: SOLID_RESOURCE_MARKER }, 1, [0; 20]);
        for (b, &start) in blobs.iter().zip(&starts) {
            self.entry(ResourceHeader { size_in_wim: b.size, flags: FLAG_SOLID, offset_in_wim: start, uncompressed_size: 0 }, b.refs, b.hash);
        }
        Ok(())
    }

    /// Adds one image's metadata resource (images in order).
    pub fn add_metadata(&mut self, bytes: &[u8]) -> Result<()> {
        let codec = self.codec;
        let enc = encode_resource(bytes, codec.kind, codec.chunk, ResourceLayout::Ordinary, |k, c| compress_chunk(k, codec.chunk, codec.level, c)).map_err(pe)?;
        let at = self.append(&enc.bytes)?;
        let hash: [u8; 20] = Sha1::digest(bytes).into();
        self.metadata.push((ResourceHeader { offset_in_wim: at, flags: enc.header.flags | FLAG_METADATA, ..enc.header }, hash));
        Ok(())
    }

    /// Writes blob table, XML and integrity table and the final header.
    pub fn finish(mut self, mut xml: XmlInfo, boot_index: u32, integrity: bool) -> Result<()> {
        let metadata = std::mem::take(&mut self.metadata);
        for (h, hash) in &metadata {
            self.entry(*h, 1, *hash);
        }
        let table = std::mem::take(&mut self.table);
        let at = self.append(&table)?;
        let blob_table = ResourceHeader { size_in_wim: table.len() as u64, flags: FLAG_METADATA, offset_in_wim: at, uncompressed_size: table.len() as u64 };
        let check_end = self.pos;
        xml.set_total_bytes(Some(check_end)).map_err(pe)?;
        let x = xml.encode_utf16le().map_err(pe)?;
        let at = self.append(&x)?;
        let xml_data = ResourceHeader { size_in_wim: x.len() as u64, flags: FLAG_METADATA, offset_in_wim: at, uncompressed_size: x.len() as u64 };
        self.out.flush()?;
        let mut integrity_table = ResourceHeader::default();
        if integrity {
            let mut f = File::open(&self.path)?;
            let t = wim_format::integrity::calculate_file(&mut f, check_end, wim_format::integrity::DEFAULT_CHUNK_SIZE, |_, _| Ok(())).map_err(pe)?;
            let b = t.encode().map_err(pe)?;
            let at = self.append(&b)?;
            integrity_table = ResourceHeader { size_in_wim: b.len() as u64, flags: 0, offset_in_wim: at, uncompressed_size: b.len() as u64 };
        }
        let boot_metadata = if boot_index > 0 {
            metadata.get(boot_index as usize - 1).map(|m| m.0).ok_or_else(|| anyhow!("invalid boot index"))?
        } else {
            ResourceHeader::default()
        };
        let header = Header {
            magic: WIM_MAGIC,
            version: if self.codec.kind == C::Lzms || self.codec.solid { 0xe00 } else { 0x10d00 },
            flags: self.codec.header_flags(),
            chunk_size: if self.codec.kind == C::None { 0 } else { self.codec.chunk },
            guid: *uuid::Uuid::new_v4().as_bytes(),
            part_number: 1,
            total_parts: 1,
            image_count: metadata.len() as u32,
            blob_table,
            xml_data,
            boot_metadata,
            boot_index,
            integrity_table,
            reserved: [0; 60],
        };
        self.out.seek(SeekFrom::Start(0))?;
        self.out.write_all(&header.encode_canonical())?;
        let f = self.out.into_inner().map_err(|e| anyhow!("cannot write {}: {}", self.path.display(), e.error()))?;
        f.sync_all()?;
        Ok(())
    }
}

fn gib(b: u64) -> f64 {
    b as f64 / (1u64 << 30) as f64
}

fn view<'v>(views: &'v mut HashMap<usize, View>, sources: &[&Wim], s: usize) -> Result<&'v mut View> {
    if !views.contains_key(&s) {
        let w = sources[s];
        views.insert(s, (w.view()?, File::open(w.path())?, crate::native::SolidCache::default()));
    }
    Ok(views.get_mut(&s).unwrap())
}

fn read_file_checked(path: &Path, size: u64, hash: &[u8; 20]) -> Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if data.len() as u64 != size || <[u8; 20]>::from(Sha1::digest(&data)) != *hash {
        bail!("{} changed while the image was written", path.display());
    }
    Ok(data)
}

fn make_piece(b: &Blob, codec: Codec, sources: &[&Wim], views: &mut HashMap<usize, View>) -> Result<Piece> {
    let data = match &b.src {
        BlobSrc::Wim(s) => {
            let lb = sources[*s].lookup().find(&b.hash).ok_or_else(|| anyhow!("blob {} is missing", hex(&b.hash)))?;
            let r = &sources[*s].lookup().resources[lb.resource_index];
            let same = !r.solid
                && !sources[*s].is_pipable()
                && r.header.flags & FLAG_COMPRESSED != 0
                && r.compression_code == codec.kind as u32
                && r.chunk_size == codec.chunk
                && lb.offset == 0
                && r.uncompressed_size == lb.size;
            let (header, size_in_wim, offset) = (r.header, r.header.size_in_wim, r.header.offset_in_wim);
            let (archive, file, cache) = view(views, sources, *s)?;
            if same {
                let mut bytes = vec![0u8; size_in_wim as usize];
                file.read_exact_at(&mut bytes, offset)?;
                let header = ResourceHeader { size_in_wim, flags: header.flags & !(FLAG_METADATA | FLAG_SOLID), offset_in_wim: 0, uncompressed_size: lb.size };
                return Ok(Piece { bytes, header });
            }
            sources[*s].read_blob_cached(archive, file, cache, &b.hash).with_context(|| format!("cannot read blob {}", hex(&b.hash)))?
        }
        BlobSrc::File(p) => read_file_checked(p, b.size, &b.hash)?,
    };
    let enc = encode_resource(&data, codec.kind, codec.chunk, ResourceLayout::Ordinary, |k, c| compress_chunk(k, codec.chunk, codec.level, c)).map_err(pe)?;
    Ok(Piece { bytes: enc.bytes, header: enc.header })
}

fn read_range(b: &Blob, range: std::ops::Range<u64>, sources: &[&Wim], views: &mut HashMap<usize, View>, out: &mut Vec<u8>) -> Result<()> {
    match &b.src {
        BlobSrc::Wim(s) => {
            let (archive, _, _) = view(views, sources, *s)?;
            let bytes = crate::native::read_blob_range(archive, &b.hash, range).with_context(|| format!("cannot read blob {}", hex(&b.hash)))?;
            out.extend_from_slice(&bytes);
        }
        // Only the size is rechecked here: solid chunks read blobs piecewise, so the hash computed
        // at commit is not recomputed (workspace files are private to the job).
        BlobSrc::File(p) => {
            let f = File::open(p).with_context(|| format!("cannot read {}", p.display()))?;
            if f.metadata()?.len() != b.size {
                bail!("{} changed while the image was written", p.display());
            }
            let start = out.len();
            out.resize(start + (range.end - range.start) as usize, 0);
            f.read_exact_at(&mut out[start..], range.start)?;
        }
    }
    Ok(())
}

/// Counts the blob references of an image (one per dentry stream) and remembers a file name.
pub fn image_refs(meta: &Metadata<'_>, refs: &mut HashMap<[u8; 20], (u32, String)>) {
    for i in 0..meta.nodes.len() {
        let Some(e) = meta.inode_entry(i) else { continue };
        for s in &e.streams {
            if s.hash != [0; 20] {
                let r = refs.entry(s.hash).or_insert_with(|| (0, crate::native::wim_name(meta.nodes[i].entry.name).unwrap_or_default()));
                r.0 += 1;
            }
        }
    }
}

/// Exports one image of `src` into a new WIM/ESD `dest` (like `wimlib-imagex export … --check`).
pub fn export(src: &Path, index: u32, dest: &Path, compression: Compression, log: Log) -> Result<()> {
    let wim = Wim::open(src)?;
    if index == 0 || index > wim.image_count() {
        bail!("{} has no image {index}", src.display());
    }
    let raw = wim.metadata(index)?;
    let meta = Metadata::parse(&raw).map_err(pe)?;
    let mut refs = HashMap::new();
    image_refs(&meta, &mut refs);
    let mut blobs = Vec::with_capacity(refs.len());
    for (hash, (n, name)) in refs {
        let lb = wim.lookup().find(&hash).ok_or_else(|| anyhow!("blob {} ({name}) is missing from {}", hex(&hash), src.display()))?;
        blobs.push(Blob { hash, size: lb.size, src: BlobSrc::Wim(0), refs: n, sort_key: sort_key(&name) });
    }
    let xml = wim.xml()?.select_images(&[index]).map_err(pe)?;
    let boot = if wim.header().boot_index == index { 1 } else { 0 };
    let codec = Codec::of(compression);
    log(&format!("Exporting image {index} of {} to {} ({:?}{})", src.display(), dest.display(), codec.kind, if codec.solid { ", solid" } else { "" }));
    let sources = [&wim];
    // created outside the cleanup below: an existing dest must be refused, never removed
    let mut w = WimWriter::create(dest, codec, &sources)?;
    let r = (|| {
        w.write_blobs(blobs, log)?;
        w.add_metadata(&raw)?;
        w.finish(xml, boot, true)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    r
}

impl Wim {
    /// The XML data of the archive.
    pub fn xml(&self) -> Result<XmlInfo> {
        let h = &self.header().xml_data;
        if h.flags & FLAG_COMPRESSED != 0 {
            bail!("compressed XML data is not supported");
        }
        let mut bytes = vec![0u8; h.size_in_wim as usize];
        File::open(self.path())?.read_exact_at(&mut bytes, h.offset_in_wim)?;
        XmlInfo::parse_utf16le(&bytes).map_err(pe)
    }
}
