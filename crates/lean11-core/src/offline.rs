//! Offline housekeeping: the pending-operations check before Core prunes component payloads and the
//! optional "redundant data" cleanup.

use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};
use lean11_hive::Hive;

use crate::cbs::CBS_KEY;

/// Files whose presence means servicing operations wait for the first boot.
const MARKER_FILES: &[&str] = &["Windows/WinSxS/pending.xml", "Windows/WinSxS/reboot.xml"];

/// CBS `CurrentState` values DISM reports as "... Pending" (uninstall pending, install pending).
const PENDING_STATES: &[u32] = &[0x05, 0x60];

/// Evidence of pending servicing operations (empty = none). Marker files first,
/// then every package whose state ends with "Pending".
pub fn pending_operations(root: &Path) -> Result<Vec<String>> {
    let markers: Vec<String> =
        MARKER_FILES.iter().filter(|f| lean11_wim::resolve_ci(root, f).is_some()).map(|f| format!("{f} exists")).collect();
    if !markers.is_empty() {
        return Ok(markers);
    }
    let hive = lean11_wim::resolve_ci(root, "Windows/System32/config/SOFTWARE").ok_or_else(|| anyhow!("image has no SOFTWARE hive"))?;
    let h = Hive::open(&hive, false)?;
    let pk = h.key(&format!(r"{CBS_KEY}\Packages"))?.ok_or_else(|| anyhow!("the image has no servicing inventory"))?;
    let packages = h.children(pk);
    if packages.is_empty() {
        return Err(anyhow!("the package inventory is empty, so pending operations cannot be ruled out"));
    }
    // Feature states ("Enable Pending") follow from the states of their content packages, so the package
    // states cover them.
    let mut out = Vec::new();
    for (name, node) in packages {
        let state = h
            .value(node, "CurrentState")?
            .and_then(|d| d.as_dword())
            .ok_or_else(|| anyhow!("package {name} has no readable state, so pending operations cannot be ruled out"))?;
        if PENDING_STATES.contains(&state) {
            out.push(format!("package {name}: state 0x{state:02x}"));
        }
    }
    Ok(out)
}

enum Assessment {
    Clear,
    Pending(String),
    Unknown(String),
}

/// Registry assessment for the cleanup: pending markers in SOFTWARE. A missing hive, a missing
/// inventory or a hive with an unreplayed transaction log is "unknown"; other errors stop the cleanup.
fn registry_pending(root: &Path) -> Result<Assessment> {
    let Some(hive) = lean11_wim::resolve_ci(root, "Windows/System32/config/SOFTWARE") else {
        return Ok(Assessment::Unknown("The SOFTWARE hive is missing.".into()));
    };
    let h = match Hive::open(&hive, false) {
        Ok(h) => h,
        Err(e) if e.to_string().contains("is dirty") => return Ok(Assessment::Unknown(format!("{e:#}"))),
        Err(e) => return Err(e),
    };
    if h.key(CBS_KEY)?.is_none() {
        return Ok(Assessment::Unknown("The SOFTWARE hive has no servicing inventory.".into()));
    }
    for k in [
        format!(r"{CBS_KEY}\RebootPending"),
        format!(r"{CBS_KEY}\PackagesPending"),
        format!(r"{CBS_KEY}\RebootInProgress"),
        r"Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired".to_string(),
    ] {
        if h.key(&k)?.is_some() {
            return Ok(Assessment::Pending(k));
        }
    }
    Ok(Assessment::Clear)
}

/// Rejects a path if it or any ancestor below `root` is a symbolic link (reparse point in the image).
fn reject_links(root: &Path, path: &Path) -> Result<()> {
    let rel = path.strip_prefix(root).map_err(|_| anyhow!("{} is outside the image", path.display()))?;
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if cur.symlink_metadata()?.file_type().is_symlink() {
            return Err(anyhow!("{} is a reparse point; refusing to clean through it", cur.display()));
        }
    }
    Ok(())
}

struct Target {
    path: &'static str,
    servicing_sensitive: bool,
    children_only: bool,
    prefix: Option<&'static str>,
    extensions: Option<&'static [&'static str]>,
}

const fn t(path: &'static str, servicing_sensitive: bool) -> Target {
    Target { path, servicing_sensitive, children_only: true, prefix: None, extensions: None }
}

/// Redundant-data targets, in cleanup order.
const TARGETS: &[Target] = &[
    t("Windows/SoftwareDistribution/Download", true),
    t("Windows/Temp", true),
    t("Users/Default/AppData/Local/Temp", true),
    Target { path: "Windows/Logs/CBS", servicing_sensitive: false, children_only: true, prefix: Some("CbsPersist_"), extensions: Some(&[".cab", ".log"]) },
    Target { path: "Windows/Logs/DISM", servicing_sensitive: false, children_only: true, prefix: None, extensions: Some(&[".bak"]) },
    Target { path: "Windows/MEMORY.DMP", servicing_sensitive: false, children_only: false, prefix: None, extensions: None },
    Target { path: "Windows/Minidump", servicing_sensitive: false, children_only: true, prefix: None, extensions: Some(&[".dmp"]) },
    t("ProgramData/Microsoft/Windows/WER/ReportArchive", false),
    t("ProgramData/Microsoft/Windows/WER/ReportQueue", false),
];

fn measure(p: &Path, files: &mut u64, bytes: &mut u64) -> Result<()> {
    let m = p.symlink_metadata()?;
    if m.file_type().is_symlink() {
        return Err(anyhow!("{} is a reparse point; refusing to clean through it", p.display()));
    }
    if m.is_dir() {
        for e in fs::read_dir(p)? {
            measure(&e?.path(), files, bytes)?;
        }
    } else {
        *files += 1;
        *bytes += m.len();
    }
    Ok(())
}

/// Outcome of one redundant-data target.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CleanupResult {
    pub path: String,
    /// `Completed` or `Skipped`
    pub state: String,
    pub files: u64,
    pub logical_bytes: u64,
    pub detail: String,
}

/// Removes offline caches, archived logs and crash reports (the "Redundant data" stage).
pub fn clean_redundant_data(root: &Path, log: &mut dyn FnMut(&str)) -> Result<Vec<CleanupResult>> {
    let marker = MARKER_FILES.iter().find(|f| lean11_wim::resolve_ci(root, f).is_some());
    // Some(true) = pending, Some(false) = clear, None = unknown
    let pending: (Option<bool>, String) = match marker {
        Some(m) => (Some(true), m.to_string()),
        None => match registry_pending(root)? {
            Assessment::Pending(k) => (Some(true), k),
            Assessment::Clear => (Some(false), String::new()),
            Assessment::Unknown(why) => (None, why),
        },
    };
    if pending.0.is_none() {
        log(&format!("Warning: pending servicing state could not be verified: {}. Temporary/update payloads are retained.", pending.1));
    }
    let mut results = Vec::new();
    fn skip(results: &mut Vec<CleanupResult>, path: &str, detail: String, log: &mut dyn FnMut(&str)) {
        log(&format!("Skipped cleanup: {path}: {detail}"));
        results.push(CleanupResult { path: path.to_string(), state: "Skipped".into(), files: 0, logical_bytes: 0, detail });
    }
    for target in TARGETS {
        if pending.0 != Some(false) && target.servicing_sensitive {
            let reason = if pending.0 == Some(true) {
                "Retained because this image has pending servicing operations.".to_string()
            } else {
                format!("Retained because pending servicing state could not be verified: {}", pending.1)
            };
            skip(&mut results, target.path, reason, log);
            continue;
        }
        let Some(path) = lean11_wim::resolve_ci(root, target.path) else {
            skip(&mut results, target.path, "Not present.".into(), log);
            continue;
        };
        reject_links(root, &path)?;
        let entries: Vec<std::path::PathBuf> = if target.children_only {
            if !path.is_dir() {
                return Err(anyhow!("Expected an offline cleanup directory: {}", target.path));
            }
            fs::read_dir(&path)?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .filter(|e| {
                    let name = e.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    let prefix_ok = target.prefix.is_none_or(|p| name.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase()));
                    let ext_ok = target.extensions.is_none_or(|exts| {
                        e.is_file() && exts.iter().any(|x| name.to_ascii_lowercase().ends_with(&x.to_ascii_lowercase()))
                    });
                    prefix_ok && ext_ok
                })
                .collect()
        } else {
            vec![path]
        };
        let (mut files, mut bytes) = (0u64, 0u64);
        for e in &entries {
            measure(e, &mut files, &mut bytes)?;
        }
        if entries.is_empty() {
            skip(&mut results, target.path, "No redundant files.".into(), log);
            continue;
        }
        log(&format!("Plan payload: {}", target.path));
        log(&format!("Removing payload: {}", target.path));
        for e in &entries {
            let m = e.symlink_metadata()?;
            if m.is_dir() { fs::remove_dir_all(e)? } else { fs::remove_file(e)? }
        }
        log(&format!("Payload removed: {}", target.path));
        let detail = format!("Cleanup removed {files} files and {bytes} logical bytes from {}.", target.path);
        log(&detail);
        results.push(CleanupResult { path: target.path.to_string(), state: "Completed".into(), files, logical_bytes: bytes, detail });
    }
    Ok(results)
}
