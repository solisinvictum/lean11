//! Installers published as GitHub release assets (programs that are not in the winget catalog).
//!
//! The latest stable release (`/releases/latest`, no pre-releases) of the repository is read from the GitHub
//! API without a token; the asset whose name matches the pattern is taken with the SHA-256 GitHub records
//! for it (`digest`), so the download is verified like a winget installer.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::winget::Installer;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

/// `pattern` with one `*`: the asset name starts with the part before it and ends with the part after it
/// (case-insensitive). Without `*` the name must match exactly.
pub fn matches(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.to_ascii_lowercase(), name.to_ascii_lowercase());
    match p.split_once('*') {
        Some((head, tail)) => n.len() >= head.len() + tail.len() && n.starts_with(head) && n.ends_with(tail),
        None => p == n,
    }
}

fn pick(json: &str, repo: &str, pattern: &str) -> Result<(String, Asset)> {
    let r: Release = serde_json::from_str(json).with_context(|| format!("unexpected answer for {repo}'s latest release"))?;
    if r.prerelease {
        bail!("{repo}: the latest release {} is a pre-release", r.tag_name);
    }
    let mut found: Vec<Asset> = r.assets.into_iter().filter(|a| matches(pattern, &a.name)).collect();
    match found.len() {
        0 => bail!("{repo} {}: no release file matches {pattern}", r.tag_name),
        1 => Ok((r.tag_name, found.remove(0))),
        _ => bail!("{repo} {}: several release files match {pattern}", r.tag_name),
    }
}

/// Resolves the installer `pattern` of `repo`'s (owner/name) latest release. `args` are the silent install
/// arguments; the installer type (exe or msi) follows the file's extension.
pub fn resolve(repo: &str, pattern: &str, name: &str, args: &str) -> Result<Installer> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let json = crate::winget::fetch_text(&url)?;
    let (tag, a) = pick(&json, repo, pattern)?;
    let sha = a
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("{repo} {tag}: GitHub records no SHA-256 for {}, so it cannot be verified", a.name))?
        .to_ascii_lowercase();
    if !a.browser_download_url.starts_with(&format!("https://github.com/{repo}/releases/download/")) {
        bail!("{repo} {tag}: unexpected download URL {}", a.browser_download_url);
    }
    let version = tag.trim_start_matches('v').to_string();
    let safe: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let ext = a.name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    let kind = match ext.as_str() {
        "exe" | "msi" => ext.clone(),
        _ => bail!("{repo} {tag}: {} is neither an .exe nor an .msi installer", a.name),
    };
    Ok(Installer {
        id: repo.to_string(),
        name: name.to_string(),
        publisher: repo.split('/').next().unwrap_or(repo).to_string(),
        license: String::new(),
        version: version.clone(),
        architecture: "x64".into(),
        kind,
        url: a.browser_download_url,
        sha256: sha,
        args: args.to_string(),
        file_name: format!("{safe}-{}.{ext}", version.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert!(matches("VibepolloSetup-*.exe", "VibepolloSetup-v2.18.9.exe"));
        assert!(matches("vibepollosetup-*.EXE", "VibepolloSetup-v2.18.9.exe"));
        assert!(!matches("VibepolloSetup-*.exe", "vibepollo-2.18.9-1-x86_64.pkg.tar.zst"));
        assert!(!matches("a*a", "a"));
        assert!(matches("Setup.exe", "setup.exe"));
    }

    #[test]
    fn picks_the_matching_asset() {
        let j = r#"{"tag_name":"2.18.9","prerelease":false,"assets":[
            {"name":"vibepollo-2.18.9-1-x86_64.pkg.tar.zst","browser_download_url":"https://github.com/N/V/releases/download/2.18.9/x.zst","digest":"sha256:d4"},
            {"name":"VibepolloSetup-v2.18.9.exe","browser_download_url":"https://github.com/N/V/releases/download/2.18.9/VibepolloSetup-v2.18.9.exe","digest":"sha256:cc"}]}"#;
        let (tag, a) = pick(j, "N/V", "VibepolloSetup-*.exe").unwrap();
        assert_eq!(tag, "2.18.9");
        assert_eq!(a.name, "VibepolloSetup-v2.18.9.exe");
        assert!(pick(j, "N/V", "*.msi").is_err());
        assert!(pick(&j.replace("\"prerelease\":false", "\"prerelease\":true"), "N/V", "VibepolloSetup-*.exe").is_err());
    }
}
