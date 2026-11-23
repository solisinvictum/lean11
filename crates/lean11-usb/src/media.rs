//! The files that go onto the stick: a media directory (lean11's build) or a Windows ISO, with an
//! install image over the FAT32 file limit replaced by split parts (install.swm, install2.swm, ...).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Largest file FAT32 can hold.
pub const FAT32_MAX: u64 = u32::MAX as u64;

/// Where the bytes of a file come from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Src {
    /// A file on disk.
    Path(PathBuf),
    /// A file inside the source ISO (its path there).
    Iso(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MFile {
    /// Path on the stick, `/` separated, e.g. `sources/install.swm`.
    pub rel: String,
    pub size: u64,
    pub src: Src,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Media {
    /// The ISO the `Src::Iso` files come from.
    pub iso: Option<PathBuf>,
    /// Directories (parents before children).
    pub dirs: Vec<String>,
    pub files: Vec<MFile>,
    /// Volume label of the stick (at most 11 characters).
    pub label: String,
}

impl Media {
    pub fn total(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn file(&self, rel: &str) -> Option<&MFile> {
        self.files.iter().find(|f| f.rel.eq_ignore_ascii_case(rel))
    }

    /// Opens the source ISO (if any) with an index of its files.
    pub fn open_iso(&self) -> Result<Option<IsoSrc>> {
        let Some(p) = &self.iso else { return Ok(None) };
        let r = lean11_iso::UdfReader::open(p)?;
        let idx = r.walk()?.into_iter().filter(|e| !e.is_dir).map(|e| (e.path.to_lowercase(), e)).collect();
        Ok(Some(IsoSrc { r, idx }))
    }

    /// Opens a file of the media for reading.
    pub fn open<'a>(&self, f: &MFile, iso: Option<&'a IsoSrc>) -> Result<Box<dyn Read + 'a>> {
        Ok(match &f.src {
            Src::Path(p) => Box::new(std::fs::File::open(p).with_context(|| format!("cannot open {}", p.display()))?),
            Src::Iso(path) => {
                let s = iso.ok_or_else(|| anyhow::anyhow!("{path} is in an ISO that is not open"))?;
                let e = s.idx.get(&path.to_lowercase()).ok_or_else(|| anyhow::anyhow!("{path} is missing from the ISO"))?.clone();
                Box::new(IsoFile { r: &s.r, e, pos: 0 })
            }
        })
    }

    /// Reads a whole (small) file of the media.
    pub fn read_all(&self, rel: &str, iso: Option<&IsoSrc>) -> Result<Option<Vec<u8>>> {
        let Some(f) = self.file(rel) else { return Ok(None) };
        let mut v = Vec::with_capacity(f.size as usize);
        self.open(f, iso)?.read_to_end(&mut v)?;
        Ok(Some(v))
    }
}

/// An open source ISO with its files by lower-case path.
pub struct IsoSrc {
    pub r: lean11_iso::UdfReader,
    idx: std::collections::HashMap<String, lean11_iso::Entry>,
}

struct IsoFile<'a> {
    r: &'a lean11_iso::UdfReader,
    e: lean11_iso::Entry,
    pos: u64,
}

impl Read for IsoFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.e.size.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left).min(8 << 20) as usize;
        if n == 0 {
            return Ok(0);
        }
        let b = self.r.read_range(&self.e, self.pos, n).map_err(std::io::Error::other)?;
        buf[..b.len()].copy_from_slice(&b);
        self.pos += b.len() as u64;
        Ok(b.len())
    }
}

fn label_of(s: &str) -> String {
    let l: String = s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(11).collect::<String>().to_uppercase();
    if l.is_empty() { "WINDOWS".into() } else { l }
}

/// Media from a directory (e.g. the `media` folder of a lean11 job).
pub fn from_dir(dir: &Path, label: &str) -> Result<Media> {
    let mut m = Media { iso: None, dirs: Vec::new(), files: Vec::new(), label: label_of(label) };
    walk(dir, "", &mut m)?;
    check(&m)?;
    Ok(m)
}

fn walk(dir: &Path, prefix: &str, m: &mut Media) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name().to_string_lossy().to_lowercase());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let t = e.file_type()?;
        if t.is_dir() {
            m.dirs.push(rel.clone());
            walk(&e.path(), &rel, m)?;
        } else if t.is_file() {
            m.files.push(MFile { rel, size: e.metadata()?.len(), src: Src::Path(e.path()) });
        }
    }
    Ok(())
}

/// Media from a Windows ISO.
pub fn from_iso(iso: &Path) -> Result<Media> {
    let r = lean11_iso::UdfReader::open(iso)?;
    let label = r.label().unwrap_or_default();
    let mut m = Media { iso: Some(iso.to_path_buf()), dirs: Vec::new(), files: Vec::new(), label: label_of(&label) };
    for e in r.walk()? {
        if e.is_dir {
            m.dirs.push(e.path);
        } else {
            m.files.push(MFile { rel: e.path.clone(), size: e.size, src: Src::Iso(e.path) });
        }
    }
    check(&m)?;
    Ok(m)
}

fn check(m: &Media) -> Result<()> {
    let has = |p: &str| m.file(p).is_some();
    if !has("sources/boot.wim") || !(has("sources/install.wim") || has("sources/install.esd") || has("sources/install.swm")) {
        bail!("this is not Windows installation media (sources/boot.wim and sources/install.* are needed)");
    }
    if !has("efi/boot/bootx64.efi") && !has("efi/boot/bootaa64.efi") && !has("bootmgr") {
        bail!("the media has no boot loader (efi/boot/bootx64.efi or bootmgr)");
    }
    Ok(())
}

/// Replaces an install image over the FAT32 limit by split parts written to `work` (a solid
/// install.esd is first exported to an LZX WIM there). Returns whether something was split.
pub fn fit_fat32(m: &mut Media, work: &Path, log: &mut dyn FnMut(&str)) -> Result<bool> {
    let Some(big) = m.files.iter().position(|f| f.size > FAT32_MAX && f.rel.to_lowercase().starts_with("sources/install.")) else {
        if let Some(f) = m.files.iter().find(|f| f.size > FAT32_MAX) {
            bail!("{} is larger than 4 GiB, which FAT32 cannot hold", f.rel);
        }
        return Ok(false);
    };
    let f = m.files[big].clone();
    std::fs::create_dir_all(work)?;
    log(&format!("{} is {:.1} GiB, more than FAT32 holds: splitting it into parts of {} MiB", f.rel, f.size as f64 / (1u64 << 30) as f64, lean11_wim::split::FAT32_PART >> 20));
    // a file inside an ISO is extracted first
    let src = match &f.src {
        Src::Path(p) => p.clone(),
        Src::Iso(path) => {
            let r = lean11_iso::UdfReader::open(m.iso.as_ref().expect("iso source"))?;
            let e = r.find(path)?.expect("listed file");
            let out = work.join(Path::new(path).file_name().expect("file name"));
            log(&format!("extracting {path} from the ISO"));
            let mut w = std::io::BufWriter::with_capacity(8 << 20, std::fs::File::create(&out)?);
            r.copy_file(&e, &mut w)?;
            std::io::Write::flush(&mut w)?;
            out
        }
    };
    let src = if lean11_wim::split::is_solid(&src)? {
        let wim = work.join("install-split.wim");
        let _ = std::fs::remove_file(&wim);
        log("the image is solid (install.esd): converting it to an LZX WIM first, this takes a few minutes");
        lean11_wim::write::export_images(&src, &[], &wim, lean11_wim::Compression::Lzx, &mut |l| log(l))?;
        wim
    } else {
        src
    };
    let dir = work.join("swm");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let parts = lean11_wim::split::split(&src, &dir.join("install.swm"), lean11_wim::split::FAT32_PART, &mut |l| log(l))?;
    m.files.remove(big);
    for p in parts {
        let size = std::fs::metadata(&p)?.len();
        if size > FAT32_MAX {
            bail!("{} is still larger than 4 GiB (one resource of the image is too big to split)", p.display());
        }
        let name = p.file_name().expect("part name").to_string_lossy().into_owned();
        m.files.push(MFile { rel: format!("sources/{name}"), size, src: Src::Path(p) });
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(label_of("CCCOMA_X64FRE_DE-DE_DV9"), "CCCOMA_X64F");
        assert_eq!(label_of("lean11"), "LEAN11");
        assert_eq!(label_of("  "), "WINDOWS");
    }
}
