//! Resolves and downloads application installers from the winget community catalog, the package source
//! Windows' own `winget` uses (served by Microsoft's CDN).
//!
//! Chain: `source2.msix` (a signed package holding the SQLite index `Public/index.db`: package id, latest
//! version, hash) → `packages/<id>/<hash prefix>/versionData.mszyml` (versions with the manifest path and the
//! manifest's SHA-256) → the manifest (installer URL on the vendor's server, the installer's SHA-256, type,
//! silent switches, scope, architecture, locale). Every manifest and every installer is checked against
//! the SHA-256 the previous step names.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::openssh::{cache_dir, sha256_file};

pub const CDN: &str = "https://cdn.winget.microsoft.com/cache/";
/// The index is fetched again when the cached copy is older than this.
const INDEX_MAX_AGE: Duration = Duration::from_secs(6 * 3600);

fn agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder().user_agent("lean11").timeout_global(Some(Duration::from_secs(timeout))).build().into()
}

fn get(url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut resp = agent(120).get(url).call().with_context(|| format!("cannot download {url}"))?;
    if resp.status() != 200 {
        bail!("{url} answered HTTP {}", resp.status());
    }
    resp.body_mut().with_config().limit(limit).read_to_vec().with_context(|| format!("cannot read {url}"))
}

/// A small text file over HTTPS (e.g. an installer script).
pub fn fetch_text(url: &str) -> Result<String> {
    String::from_utf8(get(url, 8 << 20)?).with_context(|| format!("{url} is not UTF-8 text"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Writes `bytes` to `dest` through a unique temporary file (parallel builds share the cache).
fn store(dest: &Path, bytes: &[u8]) -> Result<()> {
    let dir = dest.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("download");
    let tmp = dir.join(format!(".{name}.{}.{}.part", std::process::id(), uuid::Uuid::new_v4().simple()));
    let r = File::create_new(&tmp).and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all())).and_then(|()| fs::rename(&tmp, dest));
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r.with_context(|| format!("cannot store {}", dest.display()))
}

/// Decodes the Windows Compression API "MSZIP" container winget uses for `.mszyml` files: a 24-byte header
/// (magic 0x0A51E5C0, uncompressed size) followed by blocks of `u32 size` + `"CK"` + raw deflate, each
/// block allowed to refer back into the output of the previous ones.
pub fn mszip(data: &[u8]) -> Result<Vec<u8>> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    if data.len() < 24 || data[..4] != [0x0A, 0x51, 0xE5, 0xC0] {
        bail!("not an MSZIP container");
    }
    let header = u16::from_le_bytes([data[4], data[5]]) as usize;
    let total = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    if header < 24 || total > 256 << 20 {
        bail!("unexpected MSZIP header");
    }
    let mut out = vec![0u8; total];
    let (mut p, mut pos) = (header, 0usize);
    while p + 4 <= data.len() && pos < total {
        let size = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        let blk = data.get(p + 4..p + 4 + size).ok_or_else(|| anyhow!("truncated MSZIP block"))?;
        if !blk.starts_with(b"CK") {
            bail!("MSZIP block without CK signature");
        }
        let mut r = DecompressorOxide::new();
        let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (st, _, n) = decompress(&mut r, &blk[2..], &mut out, pos, flags);
        if st != TINFLStatus::Done {
            bail!("MSZIP block does not inflate ({st:?})");
        }
        pos += n;
        p += 4 + size;
    }
    if pos != total {
        bail!("MSZIP data ends after {pos} of {total} bytes");
    }
    Ok(out)
}

/// Text of a CDN file: MSZIP-compressed or plain YAML.
fn text(bytes: &[u8]) -> Result<String> {
    let raw = if bytes.starts_with(&[0x0A, 0x51, 0xE5, 0xC0]) { mszip(bytes)? } else { bytes.to_vec() };
    String::from_utf8(raw).context("winget data is not UTF-8")
}

/// The catalog index (a local copy of `source2.msix`'s SQLite database).
pub struct Index {
    db: rusqlite::Connection,
}

/// One package of the index.
#[derive(Debug, Clone)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub latest: String,
    hash: String,
}

impl Index {
    /// Loads the index from the cache, fetching it again when it is missing or older than six hours.
    pub fn load(log: &mut dyn FnMut(&str)) -> Result<Index> {
        let dir = cache_dir().join("winget");
        fs::create_dir_all(&dir).with_context(|| format!("cannot create the cache {}", dir.display()))?;
        let db = dir.join("index.db");
        let fresh = fs::metadata(&db)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age < INDEX_MAX_AGE);
        if !fresh {
            log("downloading the winget catalog index");
            let msix = get(&format!("{CDN}source2.msix"), 256 << 20)?;
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(msix)).context("winget source2.msix is not a package")?;
            let f = zip.by_name("Public/index.db").context("winget source2.msix has no Public/index.db")?;
            let limit = 512u64 << 20;
            if f.size() > limit {
                bail!("winget index exceeds the uncompressed size limit");
            }
            let mut bytes = Vec::new();
            f.take(limit + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                bail!("winget index exceeds the uncompressed size limit");
            }
            store(&db, &bytes)?;
        }
        Self::open(&db)
    }

    pub fn open(path: &Path) -> Result<Index> {
        let db = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| format!("cannot open the winget index {}", path.display()))?;
        Ok(Index { db })
    }

    /// The package with this identifier (case-insensitive), if the catalog has it.
    pub fn package(&self, id: &str) -> Result<Option<Package>> {
        let mut st = self.db.prepare_cached("SELECT id, name, latest_version, hex(hash) FROM packages WHERE id = ?1 COLLATE NOCASE")?;
        let mut rows = st.query([id])?;
        Ok(match rows.next()? {
            Some(r) => Some(Package { id: r.get(0)?, name: r.get(1)?, latest: r.get(2)?, hash: r.get::<_, String>(3)?.to_ascii_lowercase() }),
            None => None,
        })
    }
}

#[derive(Debug, Deserialize)]
struct VersionData {
    #[serde(rename = "vD")]
    versions: Vec<VersionEntry>,
}

#[derive(Debug, Deserialize)]
struct VersionEntry {
    v: String,
    #[serde(rename = "rP")]
    path: String,
    #[serde(rename = "s256H")]
    sha256: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Switches {
    silent: Option<String>,
    custom: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ManifestInstaller {
    architecture: Option<String>,
    installer_type: Option<String>,
    nested_installer_type: Option<String>,
    scope: Option<String>,
    installer_locale: Option<String>,
    installer_url: String,
    installer_sha256: String,
    installer_switches: Option<Switches>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Manifest {
    package_identifier: String,
    package_version: String,
    package_name: Option<String>,
    publisher: Option<String>,
    license: Option<String>,
    installer_type: Option<String>,
    scope: Option<String>,
    installer_locale: Option<String>,
    installer_switches: Option<Switches>,
    #[serde(default)]
    installers: Vec<ManifestInstaller>,
}

/// A resolved installer: where it comes from and how it runs silently, machine-wide.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Installer {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub license: String,
    pub version: String,
    pub architecture: String,
    /// msi, nullsoft, inno, burn or exe.
    pub kind: String,
    pub url: String,
    pub sha256: String,
    /// Arguments for a silent machine-wide install (for msi: arguments to `msiexec /i <file>`).
    pub args: String,
    /// File name in the image.
    pub file_name: String,
}

/// Default silent arguments per installer type (winget's own defaults).
fn default_silent(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "msi" | "wix" => "/quiet /norestart",
        "burn" => "/quiet /norestart",
        "nullsoft" => "/S",
        "inno" => "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
        _ => return None,
    })
}

fn locale_rank(have: Option<&str>, lang: &str) -> u8 {
    let lang = lang.to_ascii_lowercase();
    let primary = lang.split('-').next().unwrap_or("");
    match have.map(|h| h.to_ascii_lowercase()) {
        Some(h) if h == lang => 0,
        Some(h) if h.split('-').next() == Some(primary) => 1,
        None => 2,
        Some(h) if h == "en-us" => 3,
        Some(_) => 4,
    }
}

fn type_rank(kind: &str) -> u8 {
    match kind {
        "msi" | "wix" => 0,
        "burn" => 1,
        "nullsoft" | "inno" => 2,
        "exe" => 3,
        _ => 9,
    }
}

/// Fetches and verifies the manifest of a package's latest version.
fn manifest(pkg: &Package) -> Result<Manifest> {
    let prefix = pkg.hash.get(..8).ok_or_else(|| anyhow!("winget index entry for {} has no hash", pkg.id))?;
    let bytes = get(&format!("{CDN}packages/{}/{prefix}/versionData.mszyml", pkg.id), 16 << 20)?;
    let got = sha256_hex(&bytes);
    if !got.eq_ignore_ascii_case(&pkg.hash) {
        bail!("winget version list of {} has SHA-256 {got}, the index names {}", pkg.id, pkg.hash);
    }
    let vd: VersionData = yaml_serde::from_str(&text(&bytes)?)
        .with_context(|| format!("winget version list of {}", pkg.id))?;
    let v = vd
        .versions
        .iter()
        .find(|v| v.v == pkg.latest)
        .ok_or_else(|| anyhow!("winget catalog inconsistent: the version list of {} lacks its latest version {}", pkg.id, pkg.latest))?;
    let bytes = get(&format!("{CDN}{}", v.path), 16 << 20)?;
    let got = hex::encode(Sha256::digest(&bytes));
    if !got.eq_ignore_ascii_case(&v.sha256) {
        bail!("winget manifest of {} {} has SHA-256 {got}, the version list names {}", pkg.id, v.v, v.sha256);
    }
    yaml_serde::from_str(&text(&bytes)?).with_context(|| format!("winget manifest of {} {}", pkg.id, v.v))
}

/// Resolves the first of `ids` the catalog has (ids may contain `{lang}`, replaced by the image language
/// and its primary subtag) to a machine-wide installer for `arch` (x64 or arm64).
pub fn resolve(index: &Index, ids: &[&str], arch: &str, lang: &str) -> Result<Installer> {
    let primary = lang.split('-').next().unwrap_or(lang);
    let mut tried = Vec::new();
    let mut pkg = None;
    'outer: for id in ids {
        let variants: Vec<String> =
            if id.contains("{lang}") { vec![id.replace("{lang}", lang), id.replace("{lang}", primary)] } else { vec![id.to_string()] };
        for v in variants {
            if let Some(p) = index.package(&v)? {
                pkg = Some(p);
                break 'outer;
            }
            tried.push(v);
        }
    }
    let pkg = pkg.ok_or_else(|| anyhow!("the winget catalog has none of {}", tried.join(", ")))?;
    let m = manifest(&pkg)?;
    let arch = match arch.to_ascii_lowercase().as_str() {
        "amd64" | "x86_64" | "x64" => "x64",
        "arm64" | "aarch64" => "arm64",
        other => bail!("unsupported architecture {other}"),
    };
    // x64 Windows also runs x86 installers; arm64 runs x64 ones (emulated) as a last resort
    let arch_rank = |a: &str| -> Option<u8> {
        match (arch, a) {
            (want, have) if want == have => Some(0),
            (_, "neutral") => Some(1),
            ("x64", "x86") => Some(2),
            ("arm64", "x64") => Some(3),
            _ => None,
        }
    };
    let mut best: Option<((u8, u8, u8, u8), ManifestInstaller, String)> = None;
    for i in &m.installers {
        let kind = i.installer_type.clone().or(m.installer_type.clone()).unwrap_or_default().to_ascii_lowercase();
        if i.nested_installer_type.is_some() || type_rank(&kind) == 9 {
            continue;
        }
        let Some(ar) = arch_rank(i.architecture.as_deref().unwrap_or("neutral")) else { continue };
        let scope = i.scope.clone().or(m.scope.clone());
        // per-user installers run in SYSTEM's profile from SetupComplete: useless
        let sr = match scope.as_deref() {
            Some("machine") => 0,
            None => 1,
            Some(_) => continue,
        };
        // only candidates with a known silent invocation (own, the manifest's, or the type's default)
        let silent_known = i.installer_switches.as_ref().and_then(|s| s.silent.as_ref()).is_some()
            || m.installer_switches.as_ref().and_then(|s| s.silent.as_ref()).is_some()
            || default_silent(&kind).is_some();
        if !silent_known {
            continue;
        }
        let lr = locale_rank(i.installer_locale.as_deref().or(m.installer_locale.as_deref()), lang);
        let key = (ar, sr, lr, type_rank(&kind));
        if best.as_ref().is_none_or(|(k, _, _)| key < *k) {
            best = Some((key, i.clone(), kind));
        }
    }
    let (_, ins, kind) = best.ok_or_else(|| anyhow!("{} {} has no machine-wide {arch} installer winget can run silently", pkg.id, m.package_version))?;
    let sw = ins.installer_switches.clone().unwrap_or_default();
    let top = m.installer_switches.clone().unwrap_or_default();
    let silent = sw.silent.or(top.silent).or_else(|| default_silent(&kind).map(str::to_string)).ok_or_else(|| {
        anyhow!("{} {}: the {kind} installer has no known silent switch", pkg.id, m.package_version)
    })?;
    let args = [Some(silent), sw.custom.or(top.custom)].into_iter().flatten().collect::<Vec<_>>().join(" ");
    let kind = if kind == "wix" { "msi".to_string() } else { kind };
    let ext = if kind == "msi" { "msi" } else { "exe" };
    let safe: String = m.package_identifier.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    Ok(Installer {
        id: m.package_identifier.clone(),
        name: m.package_name.clone().unwrap_or(pkg.name.clone()),
        publisher: m.publisher.clone().unwrap_or_default(),
        license: m.license.clone().unwrap_or_default(),
        version: m.package_version.clone(),
        architecture: ins.architecture.clone().unwrap_or_else(|| "neutral".into()),
        kind,
        url: ins.installer_url.clone(),
        sha256: ins.installer_sha256.to_ascii_lowercase(),
        args,
        file_name: format!("{safe}-{}.{ext}", m.package_version.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_")),
    })
}

/// Downloads an installer into the cache (or reuses the cached copy) and verifies its SHA-256.
pub fn download(ins: &Installer, log: &mut dyn FnMut(&str)) -> Result<PathBuf> {
    let dir = cache_dir().join("software");
    let dest = dir.join(format!("{}-{}", &ins.sha256[..12.min(ins.sha256.len())], ins.file_name));
    if dest.is_file() && sha256_file(&dest)? == ins.sha256 {
        log(&format!("{} {} from cache", ins.name, ins.version));
        return Ok(dest);
    }
    log(&format!("downloading {} {} ({})", ins.name, ins.version, ins.url));
    let mut resp = agent(1800).get(&ins.url).call().with_context(|| format!("cannot download {}", ins.url))?;
    if resp.status() != 200 {
        bail!("{} answered HTTP {}", ins.url, resp.status());
    }
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!(".download.{}.{}.part", std::process::id(), uuid::Uuid::new_v4().simple()));
    let r: Result<()> = (|| {
        let mut f = File::create_new(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
        let mut reader = resp.body_mut().as_reader();
        let mut hash = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = reader.read(&mut buf).with_context(|| format!("cannot read {}", ins.url))?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > (2u64 << 30) {
                bail!("{} exceeds the installer download size limit", ins.url);
            }
            hash.update(&buf[..n]);
            f.write_all(&buf[..n]).with_context(|| format!("cannot write {}", tmp.display()))?;
        }
        let got = hex::encode(hash.finalize());
        if got != ins.sha256 {
            bail!("{} {}: the download has SHA-256 {got}, the winget manifest names {} ({})", ins.name, ins.version, ins.sha256, ins.url);
        }
        f.sync_all().with_context(|| format!("cannot sync {}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, &dest).with_context(|| format!("cannot store {}", dest.display()))?;
        Ok(())
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mszip_roundtrip_of_a_stored_sample() {
        // header + one block: "CK" + deflate of "hello hello hello"
        let payload = b"hello hello hello";
        let deflated = miniz_oxide::deflate::compress_to_vec(payload, 6);
        let mut d = vec![0x0A, 0x51, 0xE5, 0xC0, 24, 0, 0xB2, 0x02];
        d.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        d.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        d.extend_from_slice(&((deflated.len() + 2) as u32).to_le_bytes());
        d.extend_from_slice(b"CK");
        d.extend_from_slice(&deflated);
        assert_eq!(mszip(&d).unwrap(), payload);
    }

    #[test]
    fn locale_preference() {
        assert!(locale_rank(Some("de"), "de-DE") < locale_rank(Some("en-US"), "de-DE"));
        assert!(locale_rank(Some("de-DE"), "de-DE") < locale_rank(Some("de"), "de-DE"));
        assert!(locale_rank(None, "de-DE") < locale_rank(Some("fr"), "de-DE"));
    }
}
