//! Official Windows 11 ISO download from Microsoft.
//!
//! Follows the same public flow as Microsoft's download page:
//! product id from the page, a fingerprinting session on vlscppe/ov-df, then the
//! software-download-connector API for languages (SKUs) and the signed ISO link.
//! Only Microsoft hosts are contacted. Links expire after 24 hours.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod openssh;
pub mod winget;

const PROFILE: &str = "606624d44113";
const INSTANCE: &str = "560dc9f3-1aa5-4a2f-b63c-9e18f8d0e175";
const PAGE_X64: &str = "https://www.microsoft.com/en-us/software-download/windows11";
const PAGE_ARM64: &str = "https://www.microsoft.com/en-us/software-download/windows11arm64";
const REFERER: &str = "https://www.microsoft.com/software-download/windows11";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
const CATALOG_HOSTS: &[&str] = &["www.microsoft.com", "vlscppe.microsoft.com", "ov-df.microsoft.com"];
const MAX_CATALOG_RESPONSE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X64,
    Arm64,
}

impl Arch {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => Ok(Arch::X64),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            _ => bail!("unsupported architecture {s:?} (x64 or arm64)"),
        }
    }
    pub fn host() -> Self {
        if cfg!(target_arch = "aarch64") { Arch::Arm64 } else { Arch::X64 }
    }
    fn download_type(self) -> i64 {
        match self {
            Arch::X64 => 1,
            Arch::Arm64 => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialMedia {
    pub url: String,
    pub file_name: String,
    pub description: String,
    pub language: String,
    pub arch: Arch,
    pub sha256: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sku {
    #[serde(rename = "Id")]
    pub id: serde_json::Value,
    #[serde(rename = "Language")]
    pub language: String,
    #[serde(rename = "LocalizedLanguage", default)]
    pub localized: String,
}

/// One catalog session. The session id ties the fingerprint requests to the API calls.
pub struct Catalog {
    agent: ureq::Agent,
    session: String,
    product: String,
    arch: Arch,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(USER_AGENT)
        .http_status_as_error(false)
        .build()
        .into()
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', ':']).unwrap_or(rest.len());
    Some(&rest[..end])
}

impl Catalog {
    /// Opens a session: reads the product id and completes Microsoft's session handshake.
    pub fn open(arch: Arch) -> Result<Self> {
        let agent = agent();
        let page = match arch {
            Arch::X64 => PAGE_X64,
            Arch::Arm64 => PAGE_ARM64,
        };
        let html = read(&agent, page)?;
        let product = parse_product_id(&html)?;
        let session = uuid::Uuid::new_v4().to_string();
        read(&agent, &format!("https://vlscppe.microsoft.com/tags?org_id=y6jn8c31&session_id={session}"))?;
        let js = read(&agent, &format!("https://ov-df.microsoft.com/mdt.js?instanceId={INSTANCE}&PageId=si&session_id={session}"))?;
        let w = Regex::new(r"[?&]w=([A-F0-9]+)").unwrap().captures(&js).map(|c| c[1].to_string());
        let ticks = Regex::new(r#"rticks=\\?"\+?(\d+)"#).unwrap().captures(&js).map(|c| c[1].to_string());
        let (Some(w), Some(ticks)) = (w, ticks) else {
            bail!("Microsoft did not provide a download session; retry later or use a local ISO");
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        read(&agent, &format!(
            "https://ov-df.microsoft.com/?session_id={session}&CustomerId={INSTANCE}&PageId=si&w={w}&mdt={now}&rticks={ticks}"
        ))?;
        Ok(Catalog { agent, session, product, arch })
    }

    fn api(&self, action: &str, product: &str, sku: &str) -> String {
        format!(
            "https://www.microsoft.com/software-download-connector/api/{action}?profile={PROFILE}&productEditionId={product}\
             &SKU={sku}&friendlyFileName=undefined&Locale=en-US&sessionID={}",
            self.session
        )
    }

    pub fn languages(&self) -> Result<Vec<Sku>> {
        let body = read(&self.agent, &self.api("getskuinformationbyproductedition", &self.product, "undefined"))?;
        let v: serde_json::Value = serde_json::from_str(&body).context("language list is not JSON")?;
        check_errors(&v)?;
        Ok(serde_json::from_value(v["Skus"].clone()).context("unexpected language list")?)
    }

    /// Resolves the ISO link for a language. `wanted` is a Microsoft language name ("German")
    /// or a locale ("de-DE"); unknown values fall back to "English" only if `fallback` is set.
    pub fn resolve(&self, wanted: &str, fallback: bool) -> Result<OfficialMedia> {
        let skus = self.languages()?;
        let (sku, language) = select_sku(&skus, wanted, fallback)?;
        let id = match &sku.id {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let body = read(&self.agent, &self.api("GetProductDownloadLinksBySku", "undefined", &id))?;
        let v: serde_json::Value = serde_json::from_str(&body).context("download links are not JSON")?;
        check_errors(&v)?;
        let expires = v["DownloadExpirationDatetime"].as_str().map(str::to_string);
        for item in v["ProductDownloadOptions"].as_array().into_iter().flatten() {
            if item["DownloadType"].as_i64() != Some(self.arch.download_type()) {
                continue;
            }
            let url = item["Uri"].as_str().ok_or_else(|| anyhow!("download option without URI"))?.to_string();
            validate_iso_url(&url)?;
            let path = url.split('?').next().unwrap_or_default();
            let file_name = path.rsplit('/').next().unwrap_or("windows11.iso").to_string();
            if file_name.contains(['/', '\\', '\0']) || !file_name.to_ascii_lowercase().ends_with(".iso") {
                bail!("Microsoft returned an unexpected file name {file_name:?}");
            }
            let sha256 = item["Sha256"].as_str().map(|s| s.to_ascii_lowercase());
            return Ok(OfficialMedia {
                url,
                file_name,
                description: item["LocalizedProductDisplayName"].as_str().unwrap_or_default().to_string(),
                language,
                arch: self.arch,
                sha256,
                expires,
            });
        }
        bail!("Microsoft did not return an ISO for this architecture")
    }
}

fn read(agent: &ureq::Agent, url: &str) -> Result<String> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let host = host_of(&url).ok_or_else(|| anyhow!("refusing non-https catalog URL"))?;
        if !CATALOG_HOSTS.contains(&host) {
            bail!("catalog request left Microsoft's hosts ({host})");
        }
        let mut resp = retry(|| agent.get(&url).header("Referer", REFERER).call().map_err(anyhow::Error::from))?;
        let status = resp.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = resp
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| anyhow!("empty redirect"))?;
            url = if loc.starts_with("https://") { loc.to_string() } else { format!("https://{host}{loc}") };
            continue;
        }
        if !(200..300).contains(&status) {
            bail!("Microsoft ({host}) answered HTTP {status}");
        }
        let body = resp.body_mut().with_config().limit(MAX_CATALOG_RESPONSE).read_to_string()?;
        return Ok(body);
    }
    bail!("too many catalog redirects")
}

fn retry<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let mut wait = 1;
    for attempt in 1.. {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if attempt < 4 => {
                log::warn!("Microsoft request failed ({e}), retry in {wait} s");
                std::thread::sleep(Duration::from_secs(wait));
                wait *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Picks the SKU for a language name or locale. With `fallback`, a language Microsoft has no ISO for
/// falls back to English and the returned label says so.
pub fn select_sku<'s>(skus: &'s [Sku], wanted: &str, fallback: bool) -> Result<(&'s Sku, String)> {
    let target = language_name(wanted);
    let norm = |s: &str| s.chars().filter(|c| c.is_alphabetic()).collect::<String>().to_lowercase();
    // non-US English: Microsoft lists "English (United Kingdom)", older lists "English International"
    let alt = if target == "English (United Kingdom)" { "English International" } else { target.as_str() };
    let exact = skus.iter().find(|s| norm(&s.language) == norm(&target) || norm(&s.language) == norm(alt));
    let sku = exact
        .or_else(|| if fallback { skus.iter().find(|s| s.language == "English") } else { None })
        .ok_or_else(|| anyhow!("Microsoft has no ISO in {target:?}; see `lean11 download --list-languages`"))?;
    let language = if exact.is_some() { sku.language.clone() } else { format!("English (Microsoft has no {target} ISO)") };
    Ok((sku, language))
}

pub fn parse_product_id(html: &str) -> Result<String> {
    let select = Regex::new(r#"(?is)<select\b[^>]*\bid=["']product-edition["'][^>]*>(.*?)</select>"#).unwrap();
    let option = Regex::new(r#"(?is)<option\b[^>]*\bvalue=["'](\d+)["']"#).unwrap();
    select
        .captures(html)
        .and_then(|c| option.captures(&c[1]).map(|o| o[1].to_string()))
        .ok_or_else(|| anyhow!("Microsoft's download page changed (no product edition); use a local ISO"))
}

fn check_errors(v: &serde_json::Value) -> Result<()> {
    if let Some(errors) = v["Errors"].as_array().filter(|e| !e.is_empty()) {
        let msg = errors[0]["Value"].as_str().unwrap_or("unknown error");
        bail!("Microsoft refused the download request: {msg}");
    }
    Ok(())
}

/// Maps a locale ("de-DE") to Microsoft's language name; other input is returned unchanged.
pub fn language_name(input: &str) -> String {
    let l = input.to_ascii_lowercase().replace('_', "-");
    let name = match l.as_str() {
        "en-us" | "en" => "English",
        "en-gb" => "English (United Kingdom)",
        x if x.starts_with("en-") => "English (United Kingdom)",
        "pt-br" => "Brazilian Portuguese",
        "pt-pt" | "pt" => "Portuguese",
        "zh-cn" | "zh-sg" => "Chinese (Simplified)",
        "zh-tw" | "zh-hk" => "Chinese (Traditional)",
        "fr-ca" => "French Canadian",
        "es-mx" => "Spanish (Mexico)",
        "sr-latn-rs" | "sr" => "Serbian Latin",
        x => match x.split('-').next().unwrap_or("") {
            "ar" => "Arabic", "bg" => "Bulgarian", "hr" => "Croatian", "cs" => "Czech", "da" => "Danish",
            "nl" => "Dutch", "et" => "Estonian", "fi" => "Finnish", "fr" => "French", "de" => "German",
            "el" => "Greek", "he" => "Hebrew", "hu" => "Hungarian", "it" => "Italian", "ja" => "Japanese",
            "ko" => "Korean", "lv" => "Latvian", "lt" => "Lithuanian", "nb" | "no" => "Norwegian",
            "pl" => "Polish", "ro" => "Romanian", "ru" => "Russian", "sk" => "Slovak", "sl" => "Slovenian",
            "es" => "Spanish", "sv" => "Swedish", "th" => "Thai", "tr" => "Turkish", "uk" => "Ukrainian",
            _ => return input.to_string(),
        },
    };
    name.to_string()
}

/// A manual official link.
/// Only https links on Microsoft's hosts that name an .iso are accepted; every redirect is checked again.
pub fn manual(url: &str, sha256: Option<&str>) -> Result<OfficialMedia> {
    validate_iso_url(url)?;
    let path = url.split('?').next().unwrap_or_default();
    let file_name = path.rsplit('/').next().unwrap_or_default().to_string();
    if file_name.is_empty() || file_name.contains(['\\', '\0']) || file_name.starts_with('.') || !file_name.to_ascii_lowercase().ends_with(".iso") {
        bail!("the link does not name an .iso file");
    }
    if let Some(h) = sha256
        && (h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        bail!("the SHA-256 must be 64 hex digits");
    }
    Ok(OfficialMedia {
        url: url.to_string(),
        file_name,
        description: "Official Microsoft download (manual link)".into(),
        language: String::new(),
        arch: Arch::host(),
        sha256: sha256.map(|h| h.to_ascii_lowercase()),
        expires: None,
    })
}

fn validate_iso_url(url: &str) -> Result<()> {
    let host = host_of(url).ok_or_else(|| anyhow!("ISO link is not https"))?;
    let ok = host == "software.download.prss.microsoft.com"
        || host.ends_with(".download.prss.microsoft.com")
        || host.ends_with(".microsoft.com");
    if !ok {
        bail!("ISO link points outside Microsoft ({host})");
    }
    Ok(())
}

/// Progress callback: (bytes done, total bytes if known).
pub type Progress<'a> = &'a mut dyn FnMut(u64, Option<u64>);

/// Resume metadata of a partial download.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PartMeta {
    host: String,
    path: String,
    etag: String,
    length: u64,
}

fn host_path(url: &str) -> (String, String) {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    (host.to_string(), format!("/{}", path.split('?').next().unwrap_or("")))
}

/// ISO structure check: ISO-sized and an ISO/UDF volume descriptor from sector 16.
pub fn validate_iso_file(p: &Path) -> Result<()> {
    let len = std::fs::metadata(p)?.len();
    if len < 34816 || len % 2048 != 0 {
        bail!("The file is not a valid ISO-sized image.");
    }
    let mut f = File::open(p)?;
    f.seek(SeekFrom::Start(2048 * 16))?;
    let mut buf = vec![0u8; 2048 * 16];
    let n = f.read(&mut buf)?;
    if !(0..n / 2048).any(|i| matches!(&buf[i * 2048 + 1..i * 2048 + 6], b"CD001" | b"BEA01" | b"NSR02" | b"NSR03")) {
        bail!("The file has no recognized ISO/UDF volume descriptor.");
    }
    Ok(())
}

/// Downloads the ISO to `dest`, resuming a `.part` file when its strong ETag still matches, then checks
/// the ISO structure and the published SHA-256 (if Microsoft supplied one). Every redirect must stay on
/// Microsoft's hosts. Returns the final path and its SHA-256.
pub fn download(media: &OfficialMedia, dest: &Path, progress: Progress) -> Result<(PathBuf, String)> {
    download_cancellable(media, dest, progress, None)
}

/// Like [`download`]; setting `cancel` stops the transfer and keeps the partial file for a later resume.
pub fn download_cancellable(
    media: &OfficialMedia,
    dest: &Path,
    progress: Progress,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(PathBuf, String)> {
    let cancelled = || cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst));
    if dest.exists() {
        bail!("{} already exists", dest.display());
    }
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let part = dest.with_extension("iso.part");
    let meta_path = dest.with_extension("iso.part.json");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_body(None)
        .user_agent(USER_AGENT)
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let mut meta: Option<PartMeta> = std::fs::read(&meta_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut done = part.metadata().map(|m| m.len()).unwrap_or(0);
    if done > 0 && meta.is_none() {
        // a partial without resume metadata cannot be validated: start over
        done = 0;
        let _ = std::fs::remove_file(&part);
    }
    let mut total: Option<u64> = meta.as_ref().map(|m| m.length);
    let mut failures = 0;
    loop {
        let result = (|| -> Result<bool> {
            // follow redirects by hand so every hop is checked
            let mut url = media.url.clone();
            let mut resp = None;
            for _ in 0..10 {
                validate_iso_url(&url)?;
                let mut req = agent.get(&url);
                if done > 0 {
                    req = req.header("Range", &format!("bytes={done}-"));
                    if let Some(m) = &meta {
                        req = req.header("If-Range", &m.etag);
                    }
                }
                let r = req.call()?;
                if matches!(r.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                    let loc = r.headers().get("location").and_then(|h| h.to_str().ok()).ok_or_else(|| anyhow!("redirect without a location"))?;
                    url = if loc.starts_with("https://") { loc.to_string() } else { bail!("redirect to a non-https location") };
                    continue;
                }
                resp = Some((r, url.clone()));
                break;
            }
            let (mut resp, final_url) = resp.ok_or_else(|| anyhow!("too many redirects"))?;
            let status = resp.status().as_u16();
            let etag = resp.headers().get("etag").and_then(|h| h.to_str().ok()).map(str::to_string);
            let mut file = OpenOptions::new().create(true).append(true).open(&part)?;
            // some CDNs ignore If-Range: a partial response must carry the saved strong ETag and length
            let range_total = resp
                .headers()
                .get("content-range")
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.rsplit('/').next())
                .and_then(|t| t.parse::<u64>().ok());
            if status == 206
                && let Some(m) = &meta
                && (etag.as_deref() != Some(m.etag.as_str()) || range_total.is_some_and(|t| t != m.length))
            {
                log::warn!("the file on the server changed since the partial download; starting over");
                drop(resp);
                file.set_len(0)?;
                let _ = std::fs::remove_file(&meta_path);
                meta = None;
                total = None;
                done = 0;
                return Ok(false);
            }
            match status {
                206 => {}
                200 => {
                    // full body (server ignored the range or the ETag changed): start over
                    file.set_len(0)?;
                    file.seek(SeekFrom::Start(0))?;
                    done = 0;
                }
                416 if total == Some(done) => return Ok(true),
                403 | 410 => bail!("the download link expired; resolve a new one"),
                s => bail!("ISO download answered HTTP {s}"),
            }
            if let Some(len) = resp.headers().get("content-length").and_then(|h| h.to_str().ok()?.parse::<u64>().ok()) {
                total = Some(done + len);
            }
            // only a strong ETag allows a later resume
            match (&etag, total) {
                (Some(e), Some(t)) if !e.starts_with("W/") => {
                    let (host, path) = host_path(&final_url);
                    let m = PartMeta { host, path, etag: e.clone(), length: t };
                    std::fs::write(&meta_path, serde_json::to_vec(&m)?)?;
                    meta = Some(m);
                }
                _ => {
                    let _ = std::fs::remove_file(&meta_path);
                    meta = None;
                }
            }
            let mut body = resp.body_mut().with_config().limit(u64::MAX).reader();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                if cancelled() {
                    file.sync_all()?;
                    bail!("download cancelled");
                }
                let n = body.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                file.write_all(&buf[..n])?;
                done += n as u64;
                progress(done, total);
            }
            file.sync_all()?;
            Ok(total.is_none_or(|t| t == done))
        })();
        match result {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) if failures < 5 && !cancelled() && !e.to_string().contains("expired") && !e.to_string().contains("outside Microsoft") => {
                failures += 1;
                log::warn!("download interrupted at {done} bytes ({e}), resuming");
                std::thread::sleep(Duration::from_secs(2 << failures));
            }
            Err(e) => return Err(e.context(format!("partial file kept at {}", part.display()))),
        }
    }
    validate_iso_file(&part).with_context(|| format!("the download is not an ISO (kept {})", part.display()))?;
    let hash = sha256_file(&part, progress)?;
    if let Some(expected) = &media.sha256
        && !expected.eq_ignore_ascii_case(&hash)
    {
        bail!("SHA-256 mismatch: expected {expected}, got {hash} (kept {})", part.display());
    }
    std::fs::rename(&part, dest)?;
    let _ = std::fs::remove_file(&meta_path);
    Ok((dest.to_path_buf(), hash))
}

pub fn sha256_file(path: &Path, progress: Progress) -> Result<String> {
    let mut f = File::open(path)?;
    let total = f.metadata()?.len();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut done = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        done += n as u64;
        progress(done, Some(total));
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_id_from_page() {
        let html = r#"<select id="product-edition"><option value="" selected>x</option><option value="3813">Windows 11</option></select>"#;
        assert_eq!(parse_product_id(html).unwrap(), "3813");
    }

    #[test]
    fn locale_mapping() {
        assert_eq!(language_name("de-DE"), "German");
        assert_eq!(language_name("en-US"), "English");
        assert_eq!(language_name("pt-BR"), "Brazilian Portuguese");
        assert_eq!(language_name("Japanese"), "Japanese");
    }

    #[test]
    fn host_checks() {
        assert_eq!(host_of("https://www.microsoft.com/x?y"), Some("www.microsoft.com"));
        assert!(validate_iso_url("https://software.download.prss.microsoft.com/dbazure/a.iso?t=1").is_ok());
        assert!(validate_iso_url("https://evil.example/a.iso").is_err());
        assert!(validate_iso_url("http://software.download.prss.microsoft.com/a.iso").is_err());
        assert!(manual("https://software.download.prss.microsoft.com/db/Win11_x64.iso?t=1", None).is_ok());
        assert!(manual("https://software.download.prss.microsoft.com/db/setup.exe", None).is_err());
        assert!(manual("https://evil.example/Win11.iso", None).is_err());
        // the language list Microsoft returned on 23.10.2026
        let skus: Vec<Sku> = ["English", "English (United Kingdom)", "German", "Chinese (Simplified)", "Brazilian Portuguese"]
            .iter()
            .enumerate()
            .map(|(i, l)| Sku { id: serde_json::json!(i), language: l.to_string(), localized: String::new() })
            .collect();
        assert_eq!(select_sku(&skus, "de-DE", false).unwrap().1, "German");
        assert_eq!(select_sku(&skus, "en-GB", false).unwrap().1, "English (United Kingdom)");
        assert_eq!(select_sku(&skus, "zh-CN", false).unwrap().1, "Chinese (Simplified)");
        assert_eq!(select_sku(&skus, "pt_BR", false).unwrap().1, "Brazilian Portuguese");
        assert!(select_sku(&skus, "ca-ES", false).is_err());
        let (sku, label) = select_sku(&skus, "ca-ES", true).unwrap();
        assert_eq!(sku.language, "English");
        assert_eq!(label, "English (Microsoft has no ca-ES ISO)");
    }
}
