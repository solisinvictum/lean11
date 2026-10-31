//! WIM/ESD handling. The native implementation (`native`, `write`, `workspace`) is the default;
//! `LEAN11_WIMLIB=1` switches back to wimlib's command line tool (`wimlib-imagex`, package `wimtools`)
//! with FUSE mounts, kept as a fallback and test oracle until the native path is fully verified.
//!
//! wimlib's mount call runs a FUSE main loop (and daemonizes), which does not fit a multithreaded
//! Rust process, so the fallback runs the tool as a child process.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

pub mod native;
pub mod platform;
pub mod workspace;
pub mod write;

pub const TOOL: &str = "wimlib-imagex";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ImageInfo {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub display_name: String,
    pub edition_id: String,
    pub installation_type: String,
    pub architecture: String,
    pub product_type: String,
    pub build: String,
    pub service_pack_build: String,
    pub major: String,
    pub minor: String,
    pub default_language: String,
    pub languages: String,
    pub total_bytes: u64,
}

impl ImageInfo {
    /// "10.0.26300.9457"
    pub fn version(&self) -> String {
        format!("{}.{}.{}.{}", self.major, self.minor, self.build, self.service_pack_build)
    }
    /// "x64" / "arm64" / "x86"
    pub fn arch(&self) -> &str {
        match self.architecture.as_str() {
            "x86_64" => "x64",
            "ARM64" | "arm64" => "arm64",
            "x86" => "x86",
            other => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    /// LZMS solid ("recovery", install.esd)
    Recovery,
    /// LZX, high effort ("maximum")
    Maximum,
    /// XPRESS ("fast")
    Fast,
    /// LZX default effort (working images)
    Lzx,
}

impl Compression {
    fn args(self) -> Vec<String> {
        let mut v: Vec<String> = self.base_args().iter().map(|s| s.to_string()).collect();
        v.push(format!("--threads={}", threads_for(self)));
        v
    }

    fn base_args(self) -> Vec<&'static str> {
        match self {
            Compression::Recovery => vec!["--solid", "--compress=LZMS"],
            Compression::Maximum => vec!["--compress=maximum"],
            Compression::Fast => vec!["--compress=fast"],
            Compression::Lzx => vec!["--compress=LZX"],
        }
    }
    pub fn file_name(self) -> &'static str {
        if self == Compression::Recovery { "install.esd" } else { "install.wim" }
    }
}

/// Compressor threads: LZMS solid needs roughly 0.6 GiB per thread, so cap by available memory
/// (build hosts and desktops are shared) and leave headroom. `LEAN11_THREADS` overrides.
pub fn threads_for(c: Compression) -> usize {
    if let Some(n) = std::env::var("LEAN11_THREADS").ok().and_then(|v| v.parse().ok()) {
        return n;
    }
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let avail_gib = platform::available_memory().map(|b| b as f64 / (1u64 << 30) as f64).unwrap_or(8.0);
    // GiB per compressor thread: the native writer asks the compressor (LZMS solid: 64 MiB chunk with
    // its match finder); wimlib's LZMS needs about 0.65
    let per = if native() {
        write::thread_memory(write::Codec::of(c)) as f64 / (1u64 << 30) as f64
    } else if c == Compression::Recovery {
        0.65
    } else {
        0.15
    };
    let by_mem = ((avail_gib * 0.5) / per).floor() as usize;
    cpus.min(by_mem).clamp(1, 16)
}

/// Progress/output line callback.
pub type Log<'a> = &'a mut dyn FnMut(&str);

fn run(args: &[&std::ffi::OsStr], log: Log) -> Result<String> {
    let mut cmd = Command::new(TOOL);
    cmd.args(args).env("LC_ALL", "C").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // own process group: a terminal Ctrl+C asks the build to stop at the next stage boundary and must
    // not kill an export or commit half way
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let shown: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    log(&format!("$ {TOOL} {}", shown.join(" ")));
    let mut child = cmd.spawn().with_context(|| format!("cannot run {TOOL} (install the wimtools package)"))?;
    let mut stderr = child.stderr.take().unwrap();
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let mut out = String::new();
    // wimlib redraws progress with \r: split on both
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut buf = Vec::new();
    let mut last_tenth: i32 = -1;
    loop {
        buf.clear();
        let mut byte = [0u8; 1];
        let mut got = false;
        while reader.read(&mut byte)? == 1 {
            got = true;
            if byte[0] == b'\n' || byte[0] == b'\r' {
                break;
            }
            buf.push(byte[0]);
        }
        if !got {
            break;
        }
        let line = String::from_utf8_lossy(&buf).trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        out.push_str(&line);
        out.push('\n');
        // collapse progress redraws: report every 10 %
        if let Some(pct) = progress_percent(&line) {
            let tenth = pct / 10;
            if tenth != last_tenth {
                last_tenth = tenth;
                log(&line);
            }
        } else {
            last_tenth = -1;
            log(&line);
        }
    }
    let status = child.wait()?;
    let err = err_thread.join().unwrap_or_default();
    for l in err.lines().filter(|l| !l.trim().is_empty()) {
        log(l);
    }
    if !status.success() {
        bail!("{TOOL} {} failed ({status}): {}", shown.first().map(String::as_str).unwrap_or(""), err.trim());
    }
    Ok(out)
}

fn progress_percent(line: &str) -> Option<i32> {
    let open = line.rfind('(')?;
    let rest = &line[open + 1..];
    let end = rest.find('%')?;
    rest[..end].trim().parse().ok()
}

macro_rules! os {
    ($($a:expr),* $(,)?) => { vec![$(std::ffi::OsStr::new($a)),*] };
}

/// True unless `LEAN11_WIMLIB=1` selects the wimlib fallback.
pub fn native() -> bool {
    std::env::var("LEAN11_WIMLIB").map_or(true, |v| v.is_empty() || v == "0")
}

/// Lists the images of a WIM/ESD.
pub fn info(wim: &Path) -> Result<Vec<ImageInfo>> {
    if native() {
        // validates header, blob table and metadata descriptors like `wimlib-imagex info`;
        // the XML is normalized by wim-format before the field parser reads it
        let w = native::Wim::open(wim)?;
        let images = parse_xml(&w.xml()?.to_xml().map_err(native::pe)?);
        if images.len() != w.image_count() as usize {
            bail!("{}: XML data lists {} images, the archive has {}", wim.display(), images.len(), w.image_count());
        }
        return Ok(images);
    }
    let out = run(&os![ "info", wim.as_os_str()], &mut |_| {})?;
    Ok(parse_info(&out))
}

pub fn parse_info(text: &str) -> Vec<ImageInfo> {
    let mut images = Vec::new();
    let mut cur: Option<ImageInfo> = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim().to_string());
        if k == "Index" {
            if let Some(c) = cur.take() {
                images.push(c);
            }
            cur = Some(ImageInfo { index: v.parse().unwrap_or(0), ..Default::default() });
            continue;
        }
        let Some(c) = cur.as_mut() else { continue };
        match k {
            "Name" => c.name = v,
            "Description" => c.description = v,
            "Display Name" => c.display_name = v,
            "Edition ID" => c.edition_id = v,
            "Installation Type" => c.installation_type = v,
            "Architecture" => c.architecture = v,
            "Product Type" => c.product_type = v,
            "Build" => c.build = v,
            "Service Pack Build" => c.service_pack_build = v,
            "Major Version" => c.major = v,
            "Minor Version" => c.minor = v,
            "Default Language" => c.default_language = v,
            "Languages" => c.languages = v,
            "Total Bytes" => c.total_bytes = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    if let Some(c) = cur {
        images.push(c);
    }
    images
}

/// Reads image information straight from a WIM/ESD header and its XML resource, without wimlib.
/// `read(offset, len)` returns bytes of the WIM file (works on a file inside an ISO).
pub fn info_from_header(read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>>) -> Result<Vec<ImageInfo>> {
    let h = read(0, 208)?;
    if h.len() < 208 || &h[..8] != b"MSWIM\0\0\0" {
        bail!("not a WIM file");
    }
    let size = u64::from_le_bytes([h[72], h[73], h[74], h[75], h[76], h[77], h[78], 0]);
    let offset = u64::from_le_bytes(h[80..88].try_into()?);
    if size == 0 || size > 64 << 20 {
        bail!("WIM has no usable XML data");
    }
    let xml = read(offset, size as usize)?;
    let units: Vec<u16> = xml.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(parse_xml(String::from_utf16_lossy(&units).trim_start_matches('\u{feff}')))
}

fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&format!("</{name}>"))? + start;
    Some(&s[start..end])
}

pub fn parse_xml(xml: &str) -> Vec<ImageInfo> {
    let mut out = Vec::new();
    for part in xml.split("<IMAGE INDEX=\"").skip(1) {
        let index = part.split('"').next().and_then(|i| i.parse().ok()).unwrap_or(0);
        let body = part.split("</IMAGE>").next().unwrap_or("");
        let t = |n: &str| tag(body, n).unwrap_or("").trim().to_string();
        let windows = tag(body, "WINDOWS").unwrap_or("");
        let w = |n: &str| tag(windows, n).unwrap_or("").trim().to_string();
        let version = tag(windows, "VERSION").unwrap_or("");
        let v = |n: &str| tag(version, n).unwrap_or("").trim().to_string();
        let arch = match w("ARCH").as_str() {
            "9" => "x86_64",
            "12" => "ARM64",
            "0" => "x86",
            other => other,
        }
        .to_string();
        let langs = tag(windows, "LANGUAGES").unwrap_or("");
        out.push(ImageInfo {
            index,
            name: t("NAME"),
            description: t("DESCRIPTION"),
            display_name: t("DISPLAYNAME"),
            edition_id: w("EDITIONID"),
            installation_type: w("INSTALLATIONTYPE"),
            architecture: arch,
            product_type: w("PRODUCTTYPE"),
            build: v("BUILD"),
            service_pack_build: v("SPBUILD"),
            major: v("MAJOR"),
            minor: v("MINOR"),
            default_language: tag(langs, "DEFAULT").unwrap_or("").trim().to_string(),
            languages: tag(langs, "LANGUAGE").unwrap_or("").trim().to_string(),
            total_bytes: t("TOTALBYTES").parse().unwrap_or(0),
        });
    }
    out
}

/// Exports one image into a new WIM (the native writer refuses an existing `dest`).
pub fn export(src: &Path, index: u32, dest: &Path, compression: Compression, log: Log) -> Result<()> {
    if native() {
        return write::export(src, index, dest, compression, log);
    }
    let idx = index.to_string();
    let mut args = os!["export", src.as_os_str(), &idx, dest.as_os_str()];
    let comp = compression.args();
    args.extend(comp.iter().map(std::ffi::OsStr::new));
    args.push(std::ffi::OsStr::new("--check"));
    run(&args, log).map(|_| ())
}

/// Exports every image of `src` to a fresh `dest` (rebuild without leftover data).
pub fn export_all(src: &Path, dest: &Path, compression: Compression, log: Log) -> Result<()> {
    let mut args = os!["export", src.as_os_str(), "all", dest.as_os_str()];
    let comp = compression.args();
    args.extend(comp.iter().map(std::ffi::OsStr::new));
    run(&args, log).map(|_| ())
}

/// True if `dir` is a mount point (from /proc/self/mountinfo).
pub fn is_mountpoint(dir: &Path) -> bool {
    let Ok(want) = std::fs::canonicalize(dir).or_else(|_| std::path::absolute(dir)) else { return false };
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else { return false };
    info.lines().filter_map(|l| l.split(' ').nth(4)).any(|m| {
        // mountinfo escapes blanks and backslashes as octal (\040)
        let mut out = String::new();
        let mut it = m.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\' {
                let oct: String = it.by_ref().take(3).collect();
                out.push(u8::from_str_radix(&oct, 8).map(char::from).unwrap_or('?'));
            } else {
                out.push(c);
            }
        }
        Path::new(&out) == want
    })
}

/// `wimlib-imagex unmount` can return before the FUSE mount is gone; wait for it (up to 10 s), then
/// detach lazily so nothing deletes through a still mounted directory.
fn wait_released(dir: &Path, log: Log) -> Result<()> {
    for _ in 0..50 {
        if !is_mountpoint(dir) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    log(&format!("{} is still mounted after unmount; detaching it", dir.display()));
    let st = Command::new("fusermount").arg("-uz").arg(dir).status();
    if !st.is_ok_and(|s| s.success()) && is_mountpoint(dir) {
        bail!("{} is still mounted", dir.display());
    }
    Ok(())
}

/// Cleans up after an interrupted build: a mount of a previous (killed) run is discarded, a dead FUSE
/// mount is detached, and wimlib's leftover staging directories next to the WIM are removed. The WIM
/// itself is unchanged because nothing was committed.
pub fn release_stale(wim: &Path, dir: &Path, log: Log) -> Result<()> {
    if native() {
        return workspace::release_stale(wim, dir, log);
    }
    release_stale_fuse(wim, dir, log)
}

/// FUSE part of `release_stale` (also used by the native workspace for mounts of older versions).
pub fn release_stale_fuse(wim: &Path, dir: &Path, log: Log) -> Result<()> {
    let dead = std::fs::read_dir(dir).is_err() && dir.symlink_metadata().is_ok();
    if is_mountpoint(dir) || dead {
        log(&format!("discarding a leftover mount at {} (interrupted run)", dir.display()));
        if run(&os!["unmount", dir.as_os_str()], log).is_err() || is_mountpoint(dir) {
            let st = Command::new("fusermount").arg("-uz").arg(dir).status();
            if !st.is_ok_and(|s| s.success()) && is_mountpoint(dir) {
                bail!("cannot release the leftover mount at {}", dir.display());
            }
        }
    }
    if let (Some(parent), Some(name)) = (wim.parent().filter(|p| p.is_dir()), wim.file_name()) {
        let prefix = format!("{}.staging", name.to_string_lossy());
        for e in std::fs::read_dir(parent)?.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) && e.path().is_dir() {
                log(&format!("removing leftover staging directory {}", e.path().display()));
                std::fs::remove_dir_all(e.path())?;
            }
        }
    }
    Ok(())
}

/// An editable image: a native workspace (extracted directory) or, with `LEAN11_WIMLIB=1`, a wimlib
/// FUSE mount. Dropping it without `commit` discards changes.
pub struct Mount {
    pub dir: PathBuf,
    inner: MountKind,
}

enum MountKind {
    Native(workspace::Workspace),
    Fuse(FuseMount),
}

impl Mount {
    pub fn rw(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        let inner = if native() { MountKind::Native(workspace::Workspace::rw(wim, index, dir, log)?) } else { MountKind::Fuse(FuseMount::rw(wim, index, dir, log)?) };
        Ok(Mount { dir: dir.to_path_buf(), inner })
    }

    pub fn ro(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        let inner = if native() { MountKind::Native(workspace::Workspace::ro(wim, index, dir, log)?) } else { MountKind::Fuse(FuseMount::ro(wim, index, dir, log)?) };
        Ok(Mount { dir: dir.to_path_buf(), inner })
    }

    /// Writes the changes into the WIM and releases the directory.
    pub fn commit(self, log: Log) -> Result<()> {
        match self.inner {
            MountKind::Native(w) => w.commit(log),
            MountKind::Fuse(m) => m.commit(log),
        }
    }

    pub fn discard(self, log: Log) -> Result<()> {
        match self.inner {
            MountKind::Native(w) => w.discard(log),
            MountKind::Fuse(m) => m.discard(log),
        }
    }

    /// Path of a file inside the image, `rel` with `/` separators.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel.trim_start_matches('/'))
    }
}

/// A FUSE mount of one image through wimlib. Dropping it without `commit` discards changes.
pub struct FuseMount {
    pub dir: PathBuf,
    active: bool,
}

impl FuseMount {
    pub fn rw(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        release_stale_fuse(wim, dir, log)?;
        std::fs::create_dir_all(dir)?;
        if std::fs::read_dir(dir)?.next().is_some() {
            bail!("mount directory {} is not empty", dir.display());
        }
        let idx = index.to_string();
        run(&os!["mountrw", wim.as_os_str(), &idx, dir.as_os_str()], log)?;
        Ok(FuseMount { dir: dir.to_path_buf(), active: true })
    }

    pub fn ro(wim: &Path, index: u32, dir: &Path, log: Log) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let idx = index.to_string();
        run(&os!["mount", wim.as_os_str(), &idx, dir.as_os_str()], log)?;
        Ok(FuseMount { dir: dir.to_path_buf(), active: true })
    }

    /// Unmounts and writes the changes into the WIM.
    pub fn commit(mut self, log: Log) -> Result<()> {
        // make sure nothing in this process holds files open
        run(&os!["unmount", self.dir.as_os_str(), "--commit", "--check"], log)?;
        self.active = false;
        wait_released(&self.dir, log)
    }

    pub fn discard(mut self, log: Log) -> Result<()> {
        run(&os!["unmount", self.dir.as_os_str()], log)?;
        self.active = false;
        wait_released(&self.dir, log)
    }
}

impl Drop for FuseMount {
    fn drop(&mut self) {
        if self.active {
            let _ = run(&os!["unmount", self.dir.as_os_str(), "--force"], &mut |_| {});
        }
    }
}

/// Finds a path inside a mounted image case-insensitively (Windows semantics). Returns the real path.
pub fn resolve_ci(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut cur = root.to_path_buf();
    for part in rel.split(['/', '\\']).filter(|p| !p.is_empty()) {
        let direct = cur.join(part);
        if direct.symlink_metadata().is_ok() {
            cur = direct;
            continue;
        }
        let found = std::fs::read_dir(&cur).ok()?.flatten().find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(part))?;
        cur = found.path();
    }
    Some(cur)
}

/// Picks an image: by index ("5"), exact name ("Windows 11 Pro") or edition id ("Professional").
/// Without a selection: Professional if present, else the first image.
pub fn select<'a>(images: &'a [ImageInfo], wanted: Option<&str>) -> Result<&'a ImageInfo> {
    match wanted {
        Some(w) => {
            if let Ok(i) = w.parse::<u32>() {
                return images.iter().find(|x| x.index == i).ok_or_else(|| anyhow!("no image with index {i}"));
            }
            images
                .iter()
                .find(|x| x.name.eq_ignore_ascii_case(w) || x.display_name.eq_ignore_ascii_case(w))
                .or_else(|| images.iter().find(|x| x.edition_id.eq_ignore_ascii_case(w)))
                .ok_or_else(|| anyhow!("no image named {w:?}"))
        }
        None => images
            .iter()
            .find(|x| x.edition_id == "Professional")
            .or(images.first())
            .ok_or_else(|| anyhow!("the WIM contains no images")),
    }
}

/// Lines of `BufRead`, used by tests.
pub fn lines(r: impl BufRead) -> Vec<String> {
    r.lines().map_while(Result::ok).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "WIM Information:\n----------------\nPath:           x\nImage Count:    2\n\nAvailable Images:\n----------------\n\
Index:                  1\nName:                   Windows 11 Home\nDescription:            Windows 11 Home\nDisplay Name:           Windows 11 Home\n\
Total Bytes:            25882198259\nArchitecture:           x86_64\nProduct Type:           WinNT\nEdition ID:             Core\nInstallation Type:      Client\n\
Major Version:          10\nMinor Version:          0\nBuild:                  26300\nService Pack Build:     9457\nDefault Language:       de-DE\n\n\
Index:                  5\nName:                   Windows 11 Pro\nEdition ID:             Professional\nArchitecture:           x86_64\nBuild:                  26300\n";

    #[test]
    fn parse_and_select() {
        let v = parse_info(SAMPLE);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].version(), "10.0.26300.9457");
        assert_eq!(v[0].arch(), "x64");
        assert_eq!(select(&v, None).unwrap().index, 5);
        assert_eq!(select(&v, Some("1")).unwrap().name, "Windows 11 Home");
        assert_eq!(select(&v, Some("windows 11 pro")).unwrap().index, 5);
        assert_eq!(select(&v, Some("Core")).unwrap().index, 1);
        assert!(select(&v, Some("Enterprise")).is_err());
    }
}
