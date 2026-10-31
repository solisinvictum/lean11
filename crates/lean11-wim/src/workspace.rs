//! Workspace: one image extracted into a directory, edited with ordinary file operations and
//! written back into its WIM. Replaces wimlib's FUSE mount.
//!
//! The original image metadata stays the source of truth. On commit the directory is compared
//! with it: deleted paths drop out; files keep their security descriptor, attributes, times,
//! short name and streams, and get a new content hash if they changed; new files and directories
//! inherit the parent's security descriptor. Unchanged blobs are copied without recompression.
//!
//! Limitations: renamed entries are stored as new entries (their WIM-only metadata such as the
//! security descriptor is not carried over); reparse points (junctions, symbolic links) are empty
//! placeholders that must stay unchanged. Callers serialize work on one WIM (the build job lock).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use sha1::{Digest, Sha1};
use wim_format::metadata::Metadata;
use wim_format::metadata_write::{OwnedDentry, OwnedMetadata};

use crate::native::{ATTR_DIRECTORY, ATTR_REPARSE_POINT, Extracted, NodeKind, Wim, extract, pe, wim_name};
use crate::write::{Blob, BlobSrc, Codec, WimWriter, image_refs, sort_key};
use crate::{Compression, Log};

const ATTR_ARCHIVE: u32 = 0x20;

/// An image extracted for editing. Dropping it without `commit` discards the changes.
pub struct Workspace {
    pub dir: PathBuf,
    wim: PathBuf,
    index: u32,
    state: Option<Extracted>,
    writable: bool,
    /// (length, mtime, inode) of the WIM when it was extracted: commits of stale workspaces are refused
    source_id: (u64, i64, u64),
}

fn file_id(p: &Path) -> Result<(u64, i64, u64)> {
    let m = std::fs::metadata(p).with_context(|| format!("cannot inspect {}", p.display()))?;
    let s = crate::platform::stat_of(p, &m).with_context(|| format!("cannot inspect {}", p.display()))?;
    Ok((s.len, s.mtime_ns, s.ino))
}

/// Marker next to an extraction directory: only marked (or empty) directories are ever removed.
fn marker(dir: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(dir.file_name().unwrap_or_default());
    name.push(".lean11-workspace");
    dir.with_file_name(name)
}

impl Workspace {
    pub fn rw(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        Self::open(wim, index, dir, true, log)
    }

    pub fn ro(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        Self::open(wim, index, dir, false, log)
    }

    fn open(wim: &Path, index: u32, dir: &Path, writable: bool, log: Log) -> Result<Self> {
        release_stale(wim, dir, log)?;
        let w = Wim::open(wim)?;
        let source_id = file_id(wim)?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(marker(dir), wim.as_os_str().as_encoded_bytes())?;
        let state = match extract(&w, index, dir, log) {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(dir);
                let _ = std::fs::remove_file(marker(dir));
                return Err(e);
            }
        };
        Ok(Workspace { dir: dir.to_path_buf(), wim: wim.to_path_buf(), index, state: Some(state), writable, source_id })
    }

    /// Path of a file inside the image, `rel` with `/` separators.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel.trim_start_matches('/'))
    }

    /// Writes the changes into the WIM (a new file replacing it), then removes the directory.
    pub fn commit(mut self, log: Log) -> Result<()> {
        if !self.writable {
            bail!("the workspace of {} is read-only", self.wim.display());
        }
        if file_id(&self.wim)? != self.source_id {
            bail!("{} changed after this workspace was extracted; the commit is refused", self.wim.display());
        }
        let state = self.state.take().ok_or_else(|| anyhow!("workspace already closed"))?;
        commit_image(&self.wim, self.index, &self.dir, &state, log)?;
        remove_dir(&self.dir, log)
    }

    pub fn discard(mut self, log: Log) -> Result<()> {
        self.state = None;
        remove_dir(&self.dir, log)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if self.state.is_some() {
            let _ = std::fs::remove_dir_all(&self.dir);
            let _ = std::fs::remove_file(marker(&self.dir));
        }
    }
}

fn remove_dir(dir: &Path, log: Log) -> Result<()> {
    log(&format!("removing {}", dir.display()));
    std::fs::remove_dir_all(dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    let _ = std::fs::remove_file(marker(dir));
    Ok(())
}

/// Cleans up after an interrupted run: a leftover wimlib mount is released, a leftover extraction
/// directory and partial commit file are removed. The WIM itself is unchanged.
pub fn release_stale(wim: &Path, dir: &Path, log: Log) -> Result<()> {
    // leftovers of the wimlib fallback (mounts of older versions, staging directories)
    crate::release_stale_fuse(wim, dir, log)?;
    if dir.symlink_metadata().is_ok() {
        let empty = std::fs::read_dir(dir).map(|mut d| d.next().is_none()).unwrap_or(false);
        if !empty && !marker(dir).exists() {
            bail!("{} exists and is not a lean11 workspace; remove it or choose another directory", dir.display());
        }
        log(&format!("removing a leftover workspace {} (interrupted run)", dir.display()));
        std::fs::remove_dir_all(dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(marker(dir));
    // partial commits of interrupted runs (the caller holds the job lock)
    if let (Some(parent), Some(name)) = (wim.parent().filter(|p| p.is_dir()), wim.file_name()) {
        let prefix = format!("{}.lean11-commit", name.to_string_lossy());
        for e in std::fs::read_dir(parent)?.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) && e.path().is_file() {
                log(&format!("removing a partial commit {}", e.path().display()));
                std::fs::remove_file(e.path())?;
            }
        }
    }
    Ok(())
}

fn commit_tmp(wim: &Path) -> PathBuf {
    let mut name = wim.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".lean11-commit-{}", std::process::id()));
    wim.with_file_name(name)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn filetime(secs: i64, nsec: i64) -> u64 {
    (secs * 10_000_000 + nsec / 100 + 116_444_736_000_000_000).max(0) as u64
}

/// The output compression of an existing archive.
pub fn codec_of(w: &Wim) -> Codec {
    let h = w.header();
    let solid = w.lookup().resources.iter().any(|r| r.solid);
    let kind = if h.flags & 2 == 0 {
        wim_format::Compression::None
    } else if h.flags & 0x80000 != 0 {
        wim_format::Compression::Lzms
    } else if h.flags & 0x40000 != 0 {
        wim_format::Compression::Lzx
    } else {
        wim_format::Compression::Xpress
    };
    if solid {
        return Codec::of(Compression::Recovery);
    }
    Codec { kind, chunk: h.chunk_size, solid: false, level: lean11_codecs::DEFAULT_LEVEL }
}

/// Directory, file and byte counts as wimlib keeps them in the XML data.
pub fn image_stats(meta: &Metadata<'_>, size_of: &dyn Fn(&[u8; 20]) -> u64) -> (u64, u64, u64, u64) {
    let (mut dirs, mut files, mut total, mut hard) = (0u64, 0u64, 0u64, 0u64);
    let mut seen_inode = HashSet::new();
    for i in 1..meta.nodes.len() {
        let n = &meta.nodes[i];
        let Some(e) = meta.inode_entry(i) else { continue };
        if e.attributes & (ATTR_DIRECTORY | ATTR_REPARSE_POINT) == ATTR_DIRECTORY {
            dirs += 1;
        } else {
            files += 1;
        }
        let first = seen_inode.insert(n.inode);
        // the unnamed stream of a reparse point holds its reparse data, which DISM does not count
        let reparse = e.attributes & ATTR_REPARSE_POINT != 0;
        for s in e.streams.iter().filter(|s| !(reparse && s.name.is_empty())) {
            if s.hash != [0; 20] {
                let sz = size_of(&s.hash);
                total += sz;
                if !first {
                    hard += sz;
                }
            }
        }
    }
    (dirs, files, total, hard)
}

struct Walk<'a> {
    state: &'a Extracted,
    om: OwnedMetadata,
    n0: usize,
    /// file nodes to hash: node, absolute path
    todo: Vec<(usize, PathBuf)>,
    /// file node → (device, inode) on disk
    ino: HashMap<usize, (u64, u64)>,
    new_nodes: usize,
    deleted: usize,
}

impl Walk<'_> {
    fn dir(&mut self, node: usize, path: &Path) -> Result<()> {
        let mut orig: HashMap<String, usize> = HashMap::new();
        if node < self.n0 {
            for &c in &self.om.nodes[node].children {
                orig.insert(wim_name(&self.om.nodes[c].name)?, c);
            }
        }
        let before = self.om.nodes[node].children.len();
        let mut entries = Vec::new();
        for e in std::fs::read_dir(path).with_context(|| format!("cannot read {}", path.display()))? {
            let e = e?;
            let name = e.file_name().into_string().map_err(|n| anyhow!("{}: file name {n:?} is not UTF-8", path.display()))?;
            entries.push((name, e.path().symlink_metadata()?));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut lower = HashSet::new();
        for (name, _) in &entries {
            if !lower.insert(name.to_lowercase()) {
                bail!("{}: {name} differs from another name only in case; Windows cannot hold both", path.display());
            }
        }
        let mut children = Vec::with_capacity(entries.len());
        let mut kept = 0;
        for (name, md) in entries {
            let p = path.join(&name);
            let ft = md.file_type();
            let st = crate::platform::stat_of(&p, &md).with_context(|| format!("cannot inspect {}", p.display()))?;
            if !(ft.is_file() || ft.is_dir()) {
                bail!("{}: unsupported file type (symbolic links and special files cannot be stored)", p.display());
            }
            let old = orig.get(&name).copied();
            match old.map(|c| (c, self.state.nodes[c].kind)) {
                Some((c, NodeKind::Reparse)) if ft.is_dir() == (self.om.nodes[c].attributes & ATTR_DIRECTORY != 0) => {
                    // placeholders cannot carry edits: refuse instead of silently keeping the original
                    let s = &self.state.nodes[c];
                    let unchanged = (st.dev, st.ino) == (s.dev, s.ino)
                        && if ft.is_dir() { std::fs::read_dir(&p)?.next().is_none() } else { md.len() == 0 && st.mtime_ns == s.mtime_ns };
                    if !unchanged {
                        bail!("{} is a reparse point (junction or symbolic link) in the image and cannot be edited", p.display());
                    }
                    kept += 1;
                    children.push(c);
                }
                Some((c, NodeKind::Dir)) if ft.is_dir() => {
                    kept += 1;
                    children.push(c);
                    self.dir(c, &p)?;
                }
                Some((c, NodeKind::File)) if ft.is_file() => {
                    kept += 1;
                    children.push(c);
                    let s = &self.state.nodes[c];
                    self.ino.insert(c, (st.dev, st.ino));
                    if (st.dev, st.ino) != (s.dev, s.ino) || md.len() != s.size || st.mtime_ns != s.mtime_ns || st.ctime_ns != s.ctime_ns {
                        self.todo.push((c, p));
                    }
                }
                _ => {
                    let mut d = OwnedDentry::new(utf16(&name), if ft.is_dir() { ATTR_DIRECTORY } else { ATTR_ARCHIVE });
                    d.security_id = self.om.nodes[node].security_id;
                    let t = filetime(st.mtime_ns.div_euclid(1_000_000_000), st.mtime_ns.rem_euclid(1_000_000_000));
                    d.creation_time = t;
                    d.last_write_time = t;
                    d.last_access_time = t;
                    let idx = self.om.nodes.len();
                    self.om.nodes.push(d);
                    self.new_nodes += 1;
                    children.push(idx);
                    if ft.is_dir() {
                        self.dir(idx, &p)?;
                    } else {
                        self.ino.insert(idx, (st.dev, st.ino));
                        self.todo.push((idx, p));
                    }
                }
            }
        }
        self.deleted += before - kept;
        self.om.nodes[node].children = children;
        Ok(())
    }
}

fn hash_file(p: &Path) -> Result<([u8; 20], u64)> {
    let mut f = File::open(p).with_context(|| format!("cannot read {}", p.display()))?;
    let mut h = Sha1::new();
    let n = std::io::copy(&mut f, &mut h).with_context(|| format!("cannot read {}", p.display()))?;
    Ok((if n == 0 { [0; 20] } else { h.finalize().into() }, n))
}

/// Rebuilds image `index` of `wim_path` from the edited directory.
pub fn commit_image(wim_path: &Path, index: u32, dir: &Path, state: &Extracted, log: Log) -> Result<()> {
    let src = Wim::open(wim_path)?;
    let meta = Metadata::parse(&state.metadata).map_err(pe)?;
    let om = OwnedMetadata::from_metadata(&meta).map_err(pe)?;
    let n0 = om.nodes.len();
    let mut w = Walk { state, om, n0, todo: Vec::new(), ino: HashMap::new(), new_nodes: 0, deleted: 0 };
    w.dir(0, dir)?;
    log(&format!("Commit: {} changed or new files, {} new entries, {} entries removed", w.todo.len(), w.new_nodes, w.deleted));

    // hash changed and new files in parallel
    let next = AtomicUsize::new(0);
    let hashes: Mutex<Vec<Option<Result<([u8; 20], u64)>>>> = Mutex::new((0..w.todo.len()).map(|_| None).collect());
    let todo = &w.todo;
    std::thread::scope(|s| {
        for _ in 0..crate::write::threads(false).min(todo.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((_, p)) = todo.get(i) else { return };
                    let r = hash_file(p);
                    hashes.lock().unwrap()[i] = Some(r);
                }
            });
        }
    });
    let mut new_blobs: HashMap<[u8; 20], (PathBuf, u64)> = HashMap::new();
    let mut om = w.om;
    for ((node, p), r) in w.todo.iter().zip(hashes.into_inner().unwrap()) {
        let (hash, size) = r.ok_or_else(|| anyhow!("{} was not hashed", p.display()))??;
        let d = &mut om.nodes[*node];
        if *node < n0 && d.main_hash != hash {
            let st = crate::platform::stat(p)?;
            d.last_write_time = filetime(st.mtime_ns.div_euclid(1_000_000_000), st.mtime_ns.rem_euclid(1_000_000_000));
        }
        d.main_hash = hash;
        if hash != [0; 20] && src.lookup().find(&hash).is_none() {
            new_blobs.entry(hash).or_insert_with(|| (p.clone(), size));
        }
    }

    // hard link groups follow the directory: one group per inode on disk
    let max_id = om.nodes.iter().filter(|d| d.attributes & ATTR_REPARSE_POINT == 0).map(|d| d.inode_union).max().unwrap_or(0);
    let mut fresh = max_id;
    let mut groups: BTreeMap<(u64, u64), Vec<usize>> = BTreeMap::new();
    for (&node, &ino) in &w.ino {
        groups.entry(ino).or_default().push(node);
    }
    let mut groups: Vec<Vec<usize>> = groups.into_values().map(|mut g| {
        g.sort_unstable();
        g
    }).collect();
    groups.sort_unstable_by_key(|g| g[0]);
    let mut claimed = HashSet::new();
    for g in &groups {
        let rep = g[0];
        let orig_id = if rep < n0 { om.nodes[rep].inode_union } else { 0 };
        let id = if orig_id != 0 && claimed.insert(orig_id) {
            orig_id
        } else if g.len() > 1 {
            fresh += 1;
            fresh
        } else {
            0
        };
        let r = om.nodes[rep].clone();
        for &n in g {
            let d = &mut om.nodes[n];
            d.inode_union = id;
            if n != rep {
                d.attributes = r.attributes;
                d.security_id = r.security_id;
                d.creation_time = r.creation_time;
                d.last_access_time = r.last_access_time;
                d.last_write_time = r.last_write_time;
                d.main_hash = r.main_hash;
                d.extra_streams = r.extra_streams.clone();
            }
        }
    }

    // keep only reachable nodes
    let mut map = vec![usize::MAX; om.nodes.len()];
    let mut order = Vec::new();
    let mut stack = vec![0usize];
    while let Some(i) = stack.pop() {
        map[i] = order.len();
        order.push(i);
        stack.extend(om.nodes[i].children.iter().rev().copied());
    }
    let mut nodes = Vec::with_capacity(order.len());
    for &i in &order {
        let mut d = std::mem::replace(&mut om.nodes[i], OwnedDentry::new(Vec::new(), 0));
        d.children = d.children.iter().map(|&c| map[c]).collect();
        nodes.push(d);
    }
    let new = OwnedMetadata { security_descriptors: std::mem::take(&mut om.security_descriptors), nodes };
    let new_raw = new.encode().map_err(pe).context("cannot encode the edited image metadata")?;

    // all images of the archive, the edited one replaced
    let mut raws = Vec::new();
    for i in 1..=src.image_count() {
        raws.push(if i == index { new_raw.clone() } else { src.metadata(i)? });
    }
    let mut refs = HashMap::new();
    for raw in &raws {
        image_refs(&Metadata::parse(raw).map_err(pe)?, &mut refs);
    }
    let mut blobs = Vec::with_capacity(refs.len());
    for (hash, (n, name)) in refs {
        let (size, s) = match (src.lookup().find(&hash), new_blobs.get(&hash)) {
            (Some(lb), _) => (lb.size, BlobSrc::Wim(0)),
            (None, Some((p, size))) => (*size, BlobSrc::File(p.clone())),
            (None, None) => bail!("content of {name} is missing"),
        };
        blobs.push(Blob { hash, size, src: s, refs: n, sort_key: sort_key(&name) });
    }
    let sizes: HashMap<[u8; 20], u64> = blobs.iter().map(|b| (b.hash, b.size)).collect();
    let size_of = |h: &[u8; 20]| sizes.get(h).copied().or_else(|| src.lookup().find(h).map(|b| b.size)).unwrap_or(0);
    let mut xml = src.xml()?;
    let (od, of, ot, oh) = image_stats(&meta, &size_of);
    let (dirs, files, total, hard) = image_stats(&Metadata::parse(&new_raw).map_err(pe)?, &size_of);
    let get = |k: &str| xml.get_property(index as i32, k).map(str::to_owned).unwrap_or_default();
    log(&format!(
        "Image stats: directories {od} -> {dirs}, files {of} -> {files}, bytes {ot} -> {total}, hard link bytes {oh} -> {hard} (recorded {}/{}/{}/{})",
        get("DIRCOUNT"),
        get("FILECOUNT"),
        get("TOTALBYTES"),
        get("HARDLINKBYTES")
    ));
    let now = filetime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64, 0);
    for (k, v) in [
        ("DIRCOUNT", dirs.to_string()),
        ("FILECOUNT", files.to_string()),
        ("TOTALBYTES", total.to_string()),
        ("HARDLINKBYTES", hard.to_string()),
        ("LASTMODIFICATIONTIME/HIGHPART", format!("0x{:08X}", now >> 32)),
        ("LASTMODIFICATIONTIME/LOWPART", format!("0x{:08X}", now & 0xFFFF_FFFF)),
    ] {
        xml.set_property(index as i32, k, Some(&v)).map_err(pe)?;
    }

    let tmp = commit_tmp(wim_path);
    let _ = std::fs::remove_file(&tmp);
    let codec = codec_of(&src);
    log(&format!("Writing {} ({} new blobs, {:?})", wim_path.display(), new_blobs.len(), codec.kind));
    let sources = [&src];
    let r = (|| {
        let mut wr = WimWriter::create(&tmp, codec, &sources)?;
        wr.write_blobs(blobs, log)?;
        for raw in &raws {
            wr.add_metadata(raw)?;
        }
        wr.finish(xml, src.header().boot_index, true)
    })();
    if let Err(e) = r {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(src);
    std::fs::rename(&tmp, wim_path).with_context(|| format!("cannot replace {}", wim_path.display()))?;
    Ok(())
}
