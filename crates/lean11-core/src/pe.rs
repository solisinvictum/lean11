//! Minimal PE resource reader: string table entries (RT_STRING) of DLL/SYS/EXE and their .mui files,
//! used to resolve indirect display names like `@%SystemRoot%\system32\AarSvc.dll,-100`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const RT_STRING: u32 = 6;

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}

/// Resource data of a PE image. All offsets from the file are untrusted: every read is bounds-checked
/// and directory offsets stay inside the declared resource range.
struct Pe<'a> {
    b: &'a [u8],
    /// The resource directory bytes (file-backed part of its declared size).
    res: &'a [u8],
    sections: Vec<(u32, u32, u32)>, // (virtual address, raw size, raw pointer)
}

impl<'a> Pe<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        if b.get(0..2)? != b"MZ" {
            return None;
        }
        let pe = u32_at(b, 0x3c)? as usize;
        if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let coff = pe.checked_add(4)?;
        let nsec = u16_at(b, coff.checked_add(2)?)? as usize;
        let opt_size = u16_at(b, coff.checked_add(16)?)? as usize;
        let opt = coff.checked_add(20)?;
        let dirs = match u16_at(b, opt)? {
            0x10b => opt + 96,
            0x20b => opt + 112,
            _ => return None,
        };
        let res_rva = u32_at(b, dirs.checked_add(16)?)?;
        let res_size = u32_at(b, dirs.checked_add(20)?)? as usize;
        if res_rva == 0 || res_size == 0 {
            return None;
        }
        let st = opt.checked_add(opt_size)?;
        let sections: Vec<(u32, u32, u32)> = (0..nsec)
            .filter_map(|i| {
                let s = st.checked_add(i.checked_mul(40)?)?;
                let va = u32_at(b, s.checked_add(12)?)?;
                let raw_size = u32_at(b, s.checked_add(16)?)?;
                let raw = u32_at(b, s.checked_add(20)?)?;
                Some((va, raw_size, raw))
            })
            .collect();
        let mut pe = Pe { b, res: &[], sections };
        let (start, avail) = pe.span(res_rva)?;
        pe.res = b.get(start..start.checked_add(res_size.min(avail))?)?;
        Some(pe)
    }

    /// File offset of an RVA and the file-backed bytes left in its section.
    fn span(&self, rva: u32) -> Option<(usize, usize)> {
        self.sections.iter().find_map(|&(va, raw_size, raw)| {
            let delta = rva.checked_sub(va)?;
            (delta < raw_size).then(|| Some(((raw as usize).checked_add(delta as usize)?, (raw_size - delta) as usize)))?
        })
    }

    /// Entries (id, offset with the directory bit) of the resource directory at `dir` (offset in `res`).
    fn entries(&self, dir: u32) -> Vec<(u32, u32)> {
        let d = dir as usize;
        let (Some(named), Some(ids)) = (u16_at(self.res, d.saturating_add(12)), u16_at(self.res, d.saturating_add(14))) else { return Vec::new() };
        (0..named as usize + ids as usize)
            .map_while(|i| {
                let e = d.checked_add(16)?.checked_add(i * 8)?;
                Some((u32_at(self.res, e)?, u32_at(self.res, e.checked_add(4)?)?))
            })
            .collect()
    }

    fn string(&self, id: u32) -> Option<String> {
        const DIR: u32 = 0x8000_0000;
        let block = id / 16 + 1;
        // type and name levels must be directories, the language level a data entry
        let (_, types) = self.entries(0).into_iter().find(|(n, o)| *n == RT_STRING && o & DIR != 0)?;
        let (_, names) = self.entries(types & !DIR).into_iter().find(|(n, o)| *n == block && o & DIR != 0)?;
        let (_, data) = self.entries(names & !DIR).into_iter().next()?;
        if data & DIR != 0 {
            return None;
        }
        let rva = u32_at(self.res, data as usize)?;
        let size = u32_at(self.res, (data as usize).checked_add(4)?)? as usize;
        let (start, avail) = self.span(rva)?;
        if size > avail {
            return None;
        }
        let tbl = self.b.get(start..start.checked_add(size)?)?;
        let mut o = 0usize;
        for n in 0..16 {
            let len = u16_at(tbl, o)? as usize;
            o += 2;
            if n == id % 16 {
                // a length past the table end rejects the string instead of returning a prefix
                let bytes = tbl.get(o..o.checked_add(2 * len)?)?;
                let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                // some tables count the terminating NUL into the length
                let s = String::from_utf16_lossy(&units);
                let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
                return (!s.is_empty()).then(|| s.to_string());
            }
            o = o.checked_add(2 * len)?;
        }
        None
    }
}

/// String resource `id` of a PE file.
pub fn load_string(bytes: &[u8], id: u32) -> Option<String> {
    Pe::parse(bytes)?.string(id)
}

/// Resolves `@<path>,-<id>` display names against an offline image (root = mounted image). The
/// language resources live in `<dir>/<lang>/<file>.mui`; English is preferred when present, else the
/// image language. Files are cached.
pub struct Resolver<'r> {
    root: &'r Path,
    cache: HashMap<String, Option<Vec<u8>>>,
}

impl<'r> Resolver<'r> {
    pub fn new(root: &'r Path) -> Self {
        Resolver { root, cache: HashMap::new() }
    }

    fn file(&mut self, rel: &str) -> Option<&[u8]> {
        let key = rel.to_ascii_lowercase();
        if !self.cache.contains_key(&key) {
            let data = lean11_wim::resolve_ci(self.root, rel).and_then(|p| fs::read(p).ok());
            self.cache.insert(key.clone(), data);
        }
        self.cache.get(&key).and_then(|d| d.as_deref())
    }

    fn mui_candidates(&self, rel: &str) -> Vec<String> {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        let mut langs: Vec<String> = lean11_wim::resolve_ci(self.root, dir)
            .and_then(|d| fs::read_dir(d).ok())
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.len() == 5 && n.as_bytes()[2] == b'-')
                    .collect()
            })
            .unwrap_or_default();
        langs.sort_by_key(|l| (!l.eq_ignore_ascii_case("en-us"), l.to_ascii_lowercase()));
        langs.into_iter().map(|l| format!("{dir}/{l}/{name}.mui")).collect()
    }

    /// `raw` is a registry display name; returns the readable text or None if it is not indirect.
    pub fn resolve(&mut self, raw: &str) -> Option<String> {
        let rest = raw.strip_prefix('@')?;
        // `@file.inf,%key%;Default text`
        if let Some((_, text)) = rest.split_once(';') {
            return (!text.trim().is_empty()).then(|| text.trim().to_string());
        }
        let (path, id) = rest.rsplit_once(',')?;
        let id: u32 = id.trim().trim_start_matches('-').parse().ok()?;
        let rel = image_path(path)?;
        for mui in self.mui_candidates(&rel) {
            if let Some(s) = self.file(&mui).and_then(|b| load_string(b, id)) {
                return Some(s);
            }
        }
        self.file(&rel).and_then(|b| load_string(b, id))
    }
}

/// `%SystemRoot%\system32\x.dll` → `Windows/System32/x.dll` (relative to the image root).
fn image_path(p: &str) -> Option<String> {
    let p = p.trim().trim_matches('"').replace('\\', "/");
    // stay inside the image
    if p.split('/').any(|c| c == "..") {
        return None;
    }
    let lower = p.to_ascii_lowercase();
    let rel = if let Some(r) = ["%systemroot%/", "%windir%/", "c:/windows/"].iter().find_map(|pre| lower.starts_with(pre).then(|| &p[pre.len()..])) {
        format!("Windows/{r}")
    } else if !p.contains('/') {
        format!("Windows/System32/{p}")
    } else if let Some(r) = lower.strip_prefix("system32/").map(|_| &p[9..]) {
        format!("Windows/System32/{r}")
    } else {
        return None;
    };
    Some(PathBuf::from(rel).to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_paths() {
        assert_eq!(image_path(r"%SystemRoot%\system32\AarSvc.dll").as_deref(), Some("Windows/system32/AarSvc.dll"));
        assert_eq!(image_path(r"%systemroot%\system32\drivers\afd.sys").as_deref(), Some("Windows/system32/drivers/afd.sys"));
        assert_eq!(image_path("netprofm.dll").as_deref(), Some("Windows/System32/netprofm.dll"));
        assert_eq!(image_path(r"%SystemRoot%\..\..\etc\passwd"), None);
    }

    #[test]
    fn garbage_does_not_panic() {
        let mut b = vec![0u8; 512];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        for v in [0u8, 0x7f, 0xff] {
            for x in b.iter_mut().skip(0x44) {
                *x = v;
            }
            assert_eq!(load_string(&b, 100), None);
        }
        assert_eq!(load_string(b"MZ", 1), None);
    }

    #[test]
    fn inf_default_text() {
        let mut r = Resolver::new(Path::new("/nonexistent"));
        assert_eq!(r.resolve("@acpi.inf,%ACPI.SvcDesc%;Microsoft ACPI Driver").as_deref(), Some("Microsoft ACPI Driver"));
        assert_eq!(r.resolve("Plain"), None);
    }
}
