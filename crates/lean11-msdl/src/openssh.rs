//! Downloads the Win32-OpenSSH installer (Microsoft's official build) and caches it.
//!
//! Pinned to one release with known SHA-256 digests. `LEAN11_OPENSSH_MSI` points at a local MSI for
//! offline builds (its hash is still checked against the pinned digest unless the file is a different
//! version, in which case only its existence is required).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Pinned Win32-OpenSSH release (github.com/PowerShell/Win32-OpenSSH/releases).
pub const VERSION: &str = "10.4.0.0p1";
const BASE: &str = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview";

/// (installer file name, SHA-256) for a Windows architecture.
fn asset(arch: &str) -> Result<(&'static str, &'static str)> {
    Ok(match arch {
        "x64" | "amd64" | "x86_64" => ("OpenSSH-Win64-v10.4.0.0.msi", "788d8643464a01eb63640a2fd746f9ed23d106b5a901a35f88dc8cd40e446ac9"),
        "arm64" | "ARM64" | "aarch64" => ("OpenSSH-ARM64-v10.4.0.0.msi", "75fa139d8975eedb706d9180f454e2148af09d417692825f383fe00610b00e21"),
        "x86" => ("OpenSSH-Win32-v10.4.0.0.msi", "cc16bb7be31ce517887864dfecfe12fed8355959e28f9c2075c39f6311b53a51"),
        other => bail!("no OpenSSH build for architecture {other}"),
    })
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub(crate) fn cache_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(x) = std::env::var("LOCALAPPDATA").ok().filter(|v| !v.is_empty())
    {
        return PathBuf::from(x).join("lean11").join("cache");
    }
    if let Some(x) = std::env::var("XDG_CACHE_HOME").ok().filter(|v| !v.is_empty()) {
        return PathBuf::from(x).join("lean11");
    }
    if let Some(home) = std::env::var("HOME").ok().filter(|v| !v.is_empty()) {
        // macOS keeps caches under ~/Library/Caches
        if cfg!(target_os = "macos") {
            return PathBuf::from(home).join("Library/Caches/lean11");
        }
        return PathBuf::from(home).join(".cache/lean11");
    }
    std::env::temp_dir().join("lean11-cache")
}

/// Returns the OpenSSH MSI for `arch`, downloading it into the cache once (hash verified).
/// Honours `LEAN11_OPENSSH_MSI` for offline builds.
pub fn msi(arch: &str, log: &mut dyn FnMut(&str)) -> Result<PathBuf> {
    let (name, want) = asset(arch)?;
    if let Some(local) = std::env::var("LEAN11_OPENSSH_MSI").ok().filter(|v| !v.is_empty()) {
        let p = PathBuf::from(local);
        if !p.is_file() {
            bail!("LEAN11_OPENSSH_MSI={} is not a file", p.display());
        }
        let got = sha256_file(&p)?;
        if got != want && std::env::var("LEAN11_OPENSSH_UNVERIFIED").map_or(true, |v| v != "1") {
            bail!("LEAN11_OPENSSH_MSI {} has SHA-256 {got}, expected {want} ({name}); set LEAN11_OPENSSH_UNVERIFIED=1 to use another build", p.display());
        }
        log(&format!("using OpenSSH installer {}", p.display()));
        return Ok(p);
    }
    let dir = cache_dir();
    fs::create_dir_all(&dir).with_context(|| format!("cannot create the cache {}", dir.display()))?;
    let dest = dir.join(name);
    if dest.is_file() && sha256_file(&dest)? == want {
        log(&format!("OpenSSH installer from cache: {}", dest.display()));
        return Ok(dest);
    }
    let url = format!("{BASE}/{name}");
    log(&format!("downloading OpenSSH {VERSION} ({name})"));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .user_agent("lean11")
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into();
    let mut resp = agent.get(&url).call().with_context(|| format!("cannot download {url}"))?;
    if resp.status() != 200 {
        bail!("{url} answered HTTP {}", resp.status());
    }
    let bytes = resp.body_mut().with_config().limit(64 << 20).read_to_vec().context("cannot read the OpenSSH download")?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != want {
        bail!("OpenSSH {name} has SHA-256 {got}, expected {want}");
    }
    // unique temporary name: parallel builds must not write the same file
    let tmp = dir.join(format!(".{name}.{}.{}.part", std::process::id(), uuid::Uuid::new_v4().simple()));
    let r = File::create_new(&tmp).and_then(|mut f| f.write_all(&bytes).and_then(|()| f.sync_all())).and_then(|()| fs::rename(&tmp, &dest));
    if let Err(e) = r {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot store {}", dest.display()));
    }
    log(&format!("OpenSSH installer cached: {}", dest.display()));
    Ok(dest)
}
