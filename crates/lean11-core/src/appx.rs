//! Provisioned Appx packages in an offline image (DISM /Get-ProvisionedAppxPackages and
//! /Remove-ProvisionedAppxPackage), reimplemented from DISM's behaviour; see docs/re/appx.md.
//!
//! Removing a provisioned package (verified against DISM 26100 on a 26300 image):
//! - SOFTWARE `AppxAllUserStore\Applications\<package>` is deleted with its dependency subkeys,
//! - `AppxAllUserStore\Staged\<family>` is deleted (every staged version, bundle member and resource),
//! - an empty `AppxAllUserStore\Deprovisioned\<family>` key is created,
//! - `Program Files\WindowsApps\<name>` is deleted for the package and every staged member,
//! - the license `ProgramData\Microsoft\Windows\ClipSVC\Install\Apps\<family>.xml` is deleted,
//! - the `<Package FullName=…/>` entries are removed from `ProgramData\Microsoft\Windows\AppxProvisioning.xml`,
//! - dependency (framework) packages that no other provisioned app depends on are destaged too.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use lean11_hive::Hive;

use crate::catalog::{self, CleanupOption};

pub const STORE: &str = r"Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
const WINDOWSAPPS: &str = "Program Files/WindowsApps";
const LICENSES: &str = "ProgramData/Microsoft/Windows/ClipSVC/Install/Apps";
const PROVISION_XML: &str = "ProgramData/Microsoft/Windows/AppxProvisioning.xml";

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvisionedApp {
    /// Package (or bundle) full name, the key below `AppxAllUserStore\Applications`.
    pub package_name: String,
    /// Name part of the identity, e.g. `Microsoft.BingWeather`.
    pub display_name: String,
    pub version: String,
    pub architecture: String,
    pub resource_id: String,
    pub publisher_id: String,
    /// Manifest path as stored (`%SYSTEMDRIVE%\Program Files\WindowsApps\...\AppxManifest.xml`).
    pub path: String,
    /// Dependency package full names (subkeys).
    pub dependencies: Vec<String>,
}

impl ProvisionedApp {
    pub fn family(&self) -> String {
        format!("{}_{}", self.display_name, self.publisher_id)
    }
}

/// Splits a package full name `Name_Version_Arch_ResourceId_PublisherId`.
pub fn split_full_name(full: &str) -> Option<(String, String, String, String, String)> {
    let p: Vec<&str> = full.split('_').collect();
    if p.len() != 5 {
        return None;
    }
    Some((p[0].into(), p[1].into(), p[2].into(), p[3].into(), p[4].into()))
}

/// Package family name (`Name_PublisherId`) of a full name.
pub fn family_of(full: &str) -> Option<String> {
    split_full_name(full).map(|(n, _, _, _, p)| format!("{n}_{p}"))
}

/// Lists provisioned packages from an offline SOFTWARE hive.
pub fn list_from_hive(software: &Hive) -> Result<Vec<ProvisionedApp>> {
    let key = software.key(&format!(r"{STORE}\Applications"))?.ok_or_else(|| anyhow!("image has no provisioned app store"))?;
    let mut out = Vec::new();
    for (name, node) in software.children(key) {
        let Some((display, version, arch, res, publisher)) = split_full_name(&name) else { continue };
        let path = software.value(node, "Path")?.and_then(|d| d.as_string()).unwrap_or_default();
        let dependencies = software.children(node).into_iter().map(|(n, _)| n).collect();
        out.push(ProvisionedApp {
            package_name: name,
            display_name: display,
            version,
            architecture: arch,
            resource_id: res,
            publisher_id: publisher,
            path,
            dependencies,
        });
    }
    out.sort_by(|a, b| a.package_name.to_lowercase().cmp(&b.package_name.to_lowercase()));
    Ok(out)
}

pub fn list(root: &Path) -> Result<Vec<ProvisionedApp>> {
    let p = lean11_wim::resolve_ci(root, "Windows/System32/config/SOFTWARE").ok_or_else(|| anyhow!("image has no SOFTWARE hive"))?;
    list_from_hive(&Hive::open(&p, false)?)
}

/// Provisioned packages matched by the selected app options.
pub fn matching<'a>(apps: &'a [ProvisionedApp], options: &[&CleanupOption]) -> Vec<&'a ProvisionedApp> {
    apps.iter().filter(|a| options.iter().any(|o| catalog::matches_app(o, &a.display_name, &a.package_name))).collect()
}

/// Removes all provisioned packages matched by `options`; returns the removed package full names.
pub fn remove_provisioned(root: &Path, options: &[&CleanupOption], log: &mut dyn FnMut(&str)) -> Result<Vec<String>> {
    let apps = list(root)?;
    let wanted: BTreeSet<String> = matching(&apps, options).into_iter().map(|a| a.package_name.clone()).collect();
    remove_packages(root, &wanted, log)
}

/// Removes provisioned packages by exact package name (DISM /Remove-ProvisionedAppxPackage /PackageName:).
pub fn remove_packages(root: &Path, package_names: &BTreeSet<String>, log: &mut dyn FnMut(&str)) -> Result<Vec<String>> {
    let hive_path = lean11_wim::resolve_ci(root, "Windows/System32/config/SOFTWARE").ok_or_else(|| anyhow!("image has no SOFTWARE hive"))?;
    let mut hive = Hive::open(&hive_path, true)?;
    let apps = list_from_hive(&hive)?;
    let targets: Vec<ProvisionedApp> = apps.iter().filter(|a| package_names.contains(&a.package_name)).cloned().collect();
    if targets.is_empty() {
        log("no matching provisioned apps in this image");
        return Ok(Vec::new());
    }
    let removing: BTreeSet<String> = targets.iter().map(|t| t.package_name.to_lowercase()).collect();
    // dependencies still needed by apps that stay
    let kept_deps: BTreeSet<String> = apps
        .iter()
        .filter(|a| !removing.contains(&a.package_name.to_lowercase()))
        .flat_map(|a| a.dependencies.iter().map(|d| d.to_lowercase()))
        .collect();

    let mut folders: BTreeSet<String> = BTreeSet::new();
    let mut xml_entries: BTreeSet<String> = BTreeSet::new();
    let mut licenses: BTreeSet<String> = BTreeSet::new();
    let mut orphans: BTreeSet<String> = BTreeSet::new();
    let mut removed = Vec::new();

    for t in &targets {
        let family = t.family();
        let staged_key = format!(r"{STORE}\Staged\{family}");
        let members: Vec<String> = match hive.key(&staged_key)? {
            Some(n) => hive.children(n).into_iter().map(|(m, _)| m).collect(),
            None => Vec::new(),
        };
        hive.delete_key(&format!(r"{STORE}\Applications\{}", t.package_name))?;
        hive.delete_key(&staged_key)?;
        hive.create_key(&format!(r"{STORE}\Deprovisioned\{family}"))?;
        folders.insert(t.package_name.clone());
        xml_entries.insert(t.package_name.clone());
        for m in &members {
            folders.insert(m.clone());
            xml_entries.insert(m.clone());
        }
        licenses.insert(family.to_lowercase());
        for d in &t.dependencies {
            if !kept_deps.contains(&d.to_lowercase()) {
                orphans.insert(d.clone());
            }
        }
        log(&format!("removed provisioned app {} ({} staged packages)", t.package_name, members.len()));
        removed.push(t.package_name.clone());
    }

    // dependencies no remaining app needs: destage them as well
    for d in &orphans {
        if let Some(fam) = family_of(d) {
            let key = format!(r"{STORE}\Staged\{fam}");
            if hive.delete_key(&format!(r"{key}\{d}"))? {
                log(&format!("destaged unused dependency {d}"));
            }
            if let Some(n) = hive.key(&key)?
                && hive.children(n).is_empty()
            {
                hive.delete_key(&key)?;
            }
        }
        folders.insert(d.clone());
        xml_entries.insert(d.clone());
    }
    hive.commit()?;
    drop(hive);

    // files
    if let Some(apps_dir) = lean11_wim::resolve_ci(root, WINDOWSAPPS) {
        for f in &folders {
            if let Some(p) = lean11_wim::resolve_ci(&apps_dir, f) {
                fs::remove_dir_all(&p).with_context(|| format!("cannot delete {}", p.display()))?;
            }
        }
    }
    if let Some(lic_dir) = lean11_wim::resolve_ci(root, LICENSES) {
        for e in fs::read_dir(&lic_dir)?.flatten() {
            let n = e.file_name().to_string_lossy().to_lowercase();
            if let Some(stem) = n.strip_suffix(".xml")
                && licenses.contains(stem)
            {
                fs::remove_file(e.path())?;
            }
        }
    }
    if let Some(xml_path) = lean11_wim::resolve_ci(root, PROVISION_XML) {
        let raw = fs::read(&xml_path)?;
        let (bom, text) = match raw.strip_prefix(b"\xEF\xBB\xBF") {
            Some(rest) => (true, String::from_utf8_lossy(rest).into_owned()),
            None => (false, String::from_utf8_lossy(&raw).into_owned()),
        };
        let (new, n) = remove_xml_packages(&text, &xml_entries);
        if n > 0 {
            let mut out = if bom { b"\xEF\xBB\xBF".to_vec() } else { Vec::new() };
            out.extend_from_slice(new.as_bytes());
            fs::write(&xml_path, out)?;
            log(&format!("AppxProvisioning.xml: {n} entries removed"));
        }
    }
    Ok(removed)
}

/// Removes `<Package FullName="X" …/>` elements (case-insensitive full names) from the provisioning list.
pub fn remove_xml_packages(xml: &str, names: &BTreeSet<String>) -> (String, usize) {
    let lower: BTreeSet<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let re = regex::Regex::new(r#"<Package\s+FullName="([^"]+)"[^>]*/>"#).unwrap();
    let mut count = 0;
    let out = re.replace_all(xml, |c: &regex::Captures| {
        if lower.contains(&c[1].to_lowercase()) {
            count += 1;
            String::new()
        } else {
            c[0].to_string()
        }
    });
    (out.into_owned(), count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(family_of("Microsoft.BingWeather_4.54.63038.0_neutral_~_8wekyb3d8bbwe").unwrap(), "Microsoft.BingWeather_8wekyb3d8bbwe");
        assert_eq!(family_of("Microsoft.OutlookForWindows_1.0.0.0_neutral__8wekyb3d8bbwe").unwrap(), "Microsoft.OutlookForWindows_8wekyb3d8bbwe");
        assert!(family_of("nonsense").is_none());
    }

    #[test]
    fn xml_entries() {
        let xml = r#"<Provisioned><Package FullName="A_1_x64__p" PackageType="framework"/><Package FullName="Microsoft.BingWeather_4.54.63038.0_neutral_~_8wekyb3d8bbwe" PackageType="bundle"/><Package FullName="Microsoft.BingWeather_3.2.11.0_x64__8wekyb3d8bbwe" ProvisionSourceIsBundle="true"/></Provisioned>"#;
        let names: BTreeSet<String> =
            ["microsoft.bingweather_4.54.63038.0_neutral_~_8wekyb3d8bbwe", "Microsoft.BingWeather_3.2.11.0_x64__8wekyb3d8bbwe"].iter().map(|s| s.to_string()).collect();
        let (out, n) = remove_xml_packages(xml, &names);
        assert_eq!(n, 2);
        assert_eq!(out, r#"<Provisioned><Package FullName="A_1_x64__p" PackageType="framework"/></Provisioned>"#);
    }
}
