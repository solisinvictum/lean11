//! Native WIM/ESD access without wimlib: archive opening, image metadata, extraction of an image
//! into a directory (real hard links), with blobs read in archive order by parallel workers.
//!
//! Format code comes from the `wim-format` crate (a Rust translation of wimlib's format layer).

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use wim_format::Header;
use wim_format::file_archive::FileArchive;
use wim_format::file_resource::ChunkCache;
use wim_format::lookup::LookupTable;
use wim_format::metadata::Metadata;

use crate::Log;

pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_REPARSE_POINT: u32 = 0x400;

pub fn pe(e: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("WIM format error: {e:?}")
}

/// Unbuffered: resource reads seek for every chunk, and a read buffer would be refilled each time.
type Reader = File;

/// An opened WIM/ESD: header and blob table, shared by worker views.
pub struct Wim {
    path: PathBuf,
    header: Header,
    lookup: Arc<LookupTable>,
}

impl Wim {
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let a = FileArchive::open(f).map_err(pe).with_context(|| format!("cannot read WIM {}", path.display()))?;
        if a.header.total_parts > 1 {
            bail!("{} is a split WIM (part {} of {}), not supported", path.display(), a.header.part_number, a.header.total_parts);
        }
        Ok(Wim { path: path.to_path_buf(), header: a.header.clone(), lookup: a.lookup.clone() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_pipable(&self) -> bool {
        &self.header.magic == b"WLPWM\0\0\0"
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn lookup(&self) -> &LookupTable {
        &self.lookup
    }

    pub fn image_count(&self) -> u32 {
        self.lookup.metadata.len() as u32
    }

    /// A reader view with its own file handle and solid-chunk cache (one per thread).
    pub fn view(&self) -> Result<FileArchive<Reader>> {
        let f = File::open(&self.path).with_context(|| format!("cannot open {}", self.path.display()))?;
        Ok(FileArchive::with_lookup(f, self.header.clone(), self.lookup.clone())
            .with_chunk_cache(Arc::new(Mutex::new(ChunkCache::default()))))
    }

    /// Raw (uncompressed, hash-checked) metadata resource of a one-based image index.
    pub fn metadata(&self, index: u32) -> Result<Vec<u8>> {
        self.view()?.read_metadata(index).map_err(pe).with_context(|| format!("cannot read the metadata of image {index}"))
    }
}

thread_local! {
    /// wimlib decoders (lean11-codecs), one per kind and chunk size and thread.
    static DECODERS: std::cell::RefCell<Vec<((wim_format::Compression, u32), lean11_codecs::Decompressor)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Chunk decoder for `wim-format` reads, using wimlib's decoders.
pub fn decode(kind: wim_format::Compression, input: &[u8], output: &mut [u8], chunk_size: u32) -> Result<(), wim_format::ParseError> {
    use wim_format::{Compression as C, ParseError};
    let k = match kind {
        C::Xpress => lean11_codecs::Kind::Xpress,
        C::Lzx => lean11_codecs::Kind::Lzx,
        C::Lzms => lean11_codecs::Kind::Lzms,
        C::None => return Err(ParseError::Decompression),
    };
    DECODERS.with(|cell| {
        let mut v = cell.borrow_mut();
        let i = match v.iter().position(|(key, _)| *key == (kind, chunk_size)) {
            Some(i) => i,
            None => {
                let d = lean11_codecs::Decompressor::new(k, (chunk_size as usize).max(output.len())).ok_or(ParseError::Nomem)?;
                v.push(((kind, chunk_size), d));
                v.len() - 1
            }
        };
        if v[i].1.decompress(input, output) { Ok(()) } else { Err(ParseError::Decompression) }
    })
}

/// Reads a complete blob with wimlib's decoders and checks its SHA-1.
pub fn read_blob(view: &FileArchive<Reader>, hash: &[u8; 20], size: u64) -> Result<Vec<u8>> {
    use sha1::{Digest, Sha1};
    let data = view.read_blob_range_with_decoder(hash, 0..size, decode).map_err(pe)?;
    if <[u8; 20]>::from(Sha1::digest(&data)) != *hash {
        bail!("content hash mismatch for blob {}", hex(hash));
    }
    Ok(data)
}

/// Reads part of a blob with wimlib's decoders (no hash check).
pub fn read_blob_range(view: &FileArchive<Reader>, hash: &[u8; 20], range: std::ops::Range<u64>) -> Result<Vec<u8>> {
    view.read_blob_range_with_decoder(hash, range, decode).map_err(pe)
}

/// Decoded solid-resource data of one worker: (resource index, start offset, bytes).
#[derive(Default)]
pub struct SolidCache {
    span: Option<(usize, u64, Vec<u8>)>,
}

impl Wim {
    /// Reads a complete blob (SHA-1 checked). Blobs of solid resources come from `cache`, which holds
    /// whole decoded chunks: wim-format's own chunk cache rereads the compressed chunk on every hit.
    pub fn read_blob_cached(&self, view: &FileArchive<Reader>, file: &mut File, cache: &mut SolidCache, hash: &[u8; 20]) -> Result<Vec<u8>> {
        use sha1::{Digest, Sha1};
        let lb = self.lookup.find(hash).ok_or_else(|| anyhow!("blob {} is missing", hex(hash)))?;
        let r = &self.lookup.resources[lb.resource_index];
        if !r.solid {
            return read_blob(view, hash, lb.size);
        }
        let need = lb.offset..lb.offset + lb.size;
        let hit = matches!(&cache.span, Some((ri, s, d)) if *ri == lb.resource_index && *s <= need.start && need.end <= *s + d.len() as u64);
        if !hit {
            cache.span = None;
            let cs = u64::from(r.chunk_size.max(1));
            let start = need.start / cs * cs;
            let end = (need.end.div_ceil(cs) * cs).min(r.uncompressed_size).max(need.end);
            let comp = wim_format::Compression::from_i32(r.compression_code as i32).map_err(pe)?;
            let chunk = r.chunk_size;
            let data = wim_format::file_resource::read_resource_range(
                file,
                &r.header,
                comp,
                chunk,
                wim_format::file_archive::layout(&self.header, true),
                start..end,
                |k, i, o| decode(k, i, o, chunk),
            )
            .map_err(pe)
            .with_context(|| format!("cannot read solid data of blob {}", hex(hash)))?;
            cache.span = Some((lb.resource_index, start, data));
        }
        let Some((_, s, d)) = &cache.span else { unreachable!() };
        let out = d[(need.start - s) as usize..(need.end - s) as usize].to_vec();
        if <[u8; 20]>::from(Sha1::digest(&out)) != *hash {
            bail!("content hash mismatch for blob {}", hex(hash));
        }
        Ok(out)
    }
}

/// Decodes a UTF-16LE WIM name.
pub fn wim_name(raw: &[u8]) -> Result<String> {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16(&units).map_err(|_| anyhow!("file name is not valid UTF-16: {}", String::from_utf16_lossy(&units)))
}

/// What extraction did with one metadata node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Root,
    Dir,
    File,
    /// Reparse point (junction, symlink): extracted as an empty placeholder, kept as is on commit.
    Reparse,
}

/// The extracted state of one node, used to detect changes on commit.
#[derive(Debug, Clone)]
pub struct NodeState {
    pub kind: NodeKind,
    /// Path relative to the extraction directory.
    pub rel: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

/// An extracted image: its original metadata resource and the state of every node.
pub struct Extracted {
    pub metadata: Vec<u8>,
    pub nodes: Vec<NodeState>,
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}


struct Job {
    hash: [u8; 20],
    size: u64,
    /// One entry per inode: its paths (the first is written, the others are hard links).
    inodes: Vec<Vec<PathBuf>>,
}

fn threads() -> usize {
    std::env::var("LEAN11_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16))
        .max(1)
}

/// Extracts image `index` of `wim` into `dir` (created; must not exist or be empty).
pub fn extract(wim: &Wim, index: u32, dir: &Path, log: Log) -> Result<Extracted> {
    if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
        bail!("extraction directory {} is not empty", dir.display());
    }
    std::fs::create_dir_all(dir)?;
    let raw = wim.metadata(index)?;
    let meta = Metadata::parse(&raw).map_err(pe).context("cannot parse the image metadata")?;

    // Paths, directories, placeholders; file inodes grouped by content.
    let n = meta.nodes.len();
    let mut rel: Vec<PathBuf> = vec![PathBuf::new(); n];
    let mut kind = vec![NodeKind::Root; n];
    let mut inode_paths: HashMap<usize, Vec<usize>> = HashMap::new();
    let (mut files, mut dirs) = (0usize, 0usize);
    let mut stack = vec![0usize];
    while let Some(i) = stack.pop() {
        let node = &meta.nodes[i];
        // macOS and Windows file systems are case-insensitive
        #[cfg(any(target_os = "macos", windows))]
        {
            let mut seen = std::collections::HashSet::new();
            for &c in &node.children {
                let name = wim_name(meta.nodes[c].entry.name)?.to_lowercase();
                if !seen.insert(name.clone()) {
                    bail!("{} contains names differing only in case ({name}); the file system is case-insensitive", rel[i].display());
                }
            }
        }
        for &c in &node.children {
            let e = &meta.nodes[c].entry;
            let name = wim_name(e.name)?;
            if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
                bail!("invalid file name {name:?} in {}", rel[i].display());
            }
            rel[c] = rel[i].join(&name);
            let path = dir.join(&rel[c]);
            if e.attributes & ATTR_REPARSE_POINT != 0 {
                kind[c] = NodeKind::Reparse;
                if e.is_directory() {
                    std::fs::create_dir(&path)
                } else {
                    File::create_new(&path).map(drop)
                }
                .with_context(|| format!("cannot create {}", path.display()))?;
            } else if e.is_directory() {
                kind[c] = NodeKind::Dir;
                dirs += 1;
                std::fs::create_dir(&path).with_context(|| format!("cannot create {}", path.display()))?;
                stack.push(c);
            } else {
                kind[c] = NodeKind::File;
                files += 1;
                inode_paths.entry(meta.nodes[c].inode).or_default().push(c);
            }
        }
    }

    // Group inodes by content hash; empty files are created right away.
    let mut by_hash: HashMap<[u8; 20], Vec<Vec<PathBuf>>> = HashMap::new();
    let mut inodes: Vec<(usize, Vec<usize>)> = inode_paths.into_iter().collect();
    inodes.sort_unstable_by_key(|(_, p)| p[0]);
    for (inode, paths) in inodes {
        let e = meta.inode_entry(inode).ok_or_else(|| anyhow!("missing inode entry"))?;
        let hash = e.streams.iter().find(|s| s.name.is_empty()).map(|s| s.hash).unwrap_or([0; 20]);
        let ps: Vec<PathBuf> = paths.iter().map(|&p| dir.join(&rel[p])).collect();
        if hash == [0; 20] {
            File::create_new(&ps[0]).with_context(|| format!("cannot create {}", ps[0].display()))?;
            for p in &ps[1..] {
                std::fs::hard_link(&ps[0], p).with_context(|| format!("cannot link {}", p.display()))?;
            }
        } else {
            by_hash.entry(hash).or_default().push(ps);
        }
    }
    let mut jobs: Vec<(usize, u64, Job)> = Vec::with_capacity(by_hash.len());
    for (hash, inodes) in by_hash {
        let b = wim.lookup.find(&hash).ok_or_else(|| anyhow!("blob {} of {} is missing from the WIM", hex(&hash), inodes[0][0].display()))?;
        jobs.push((b.resource_index, b.offset, Job { hash, size: b.size, inodes }));
    }
    // Archive order; blobs of one solid chunk form one work item so the chunk is decoded once.
    jobs.sort_unstable_by_key(|j| (j.0, j.1));
    let mut groups: Vec<Vec<Job>> = Vec::new();
    let mut last: Option<(usize, u64)> = None;
    for (res, off, job) in jobs {
        let r = &wim.lookup.resources[res];
        let key = (res, if r.solid { off / u64::from(r.chunk_size.max(1)) } else { off });
        if r.solid && last == Some(key) {
            groups.last_mut().unwrap().push(job);
        } else {
            groups.push(vec![job]);
        }
        last = Some(key);
    }
    let total: u64 = groups.iter().flatten().map(|j| j.size).sum();
    let done = AtomicU64::new(0);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let error: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let workers = threads().min(groups.len().max(1));
    log(&format!("Extracting image {index}: {files} files, {dirs} directories, {:.2} GiB with {workers} threads", total as f64 / (1u64 << 30) as f64));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                let run = || -> Result<()> {
                    let view = wim.view()?;
                    let mut file = File::open(&wim.path)?;
                    let mut cache = SolidCache::default();
                    loop {
                        if failed.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        let g = next.fetch_add(1, Ordering::Relaxed);
                        let Some(group) = groups.get(g) else { return Ok(()) };
                        for job in group {
                            let data = wim.read_blob_cached(&view, &mut file, &mut cache, &job.hash).with_context(|| format!("cannot read {}", job.inodes[0][0].display()))?;
                            for paths in &job.inodes {
                                // create_new: two WIM names mapping to one path (case-folding file systems) must fail
                                File::create_new(&paths[0])
                                    .and_then(|mut f| std::io::Write::write_all(&mut f, &data))
                                    .with_context(|| format!("cannot write {}", paths[0].display()))?;
                                for p in &paths[1..] {
                                    std::fs::hard_link(&paths[0], p).with_context(|| format!("cannot link {}", p.display()))?;
                                }
                            }
                            done.fetch_add(job.size, Ordering::Relaxed);
                        }
                    }
                };
                if let Err(e) = run() {
                    failed.store(true, Ordering::Relaxed);
                    error.lock().unwrap().get_or_insert(e);
                }
            });
        }
        let mut last_tenth = -1i64;
        while next.load(Ordering::Relaxed) < groups.len() + workers && !failed.load(Ordering::Relaxed) {
            let d = done.load(Ordering::Relaxed);
            let pct = if total == 0 { 100 } else { (d * 100 / total) as i64 };
            if pct / 10 != last_tenth {
                last_tenth = pct / 10;
                log(&format!("Extracting file data: {:.2} GiB of {:.2} GiB ({pct}%) done", d as f64 / (1u64 << 30) as f64, total as f64 / (1u64 << 30) as f64));
            }
            if d >= total {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    if let Some(e) = error.into_inner().unwrap() {
        return Err(e);
    }

    // Record the extracted state (after all links exist: linking changes ctime).
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let s = crate::platform::stat(&dir.join(&rel[i])).with_context(|| format!("cannot stat {}", rel[i].display()))?;
        nodes.push(NodeState { kind: kind[i], rel: std::mem::take(&mut rel[i]), dev: s.dev, ino: s.ino, size: s.len, mtime_ns: s.mtime_ns, ctime_ns: s.ctime_ns });
    }
    log(&format!("Extracted {files} files, {dirs} directories ({:.2} GiB)", total as f64 / (1u64 << 30) as f64));
    Ok(Extracted { metadata: raw, nodes, files, dirs, bytes: total })
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
