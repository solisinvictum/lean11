//! Image inventory and expert actions of the Custom mode.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use lean11_hive::{Hive, RegData};

use crate::{appx, catalog, cbs, names, pe};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    #[default]
    ProvisionedApp,
    SystemApp,
    Feature,
    Capability,
    Package,
    Service,
    ComponentPayload,
}

impl std::str::FromStr for Kind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "provisionedapp" | "app" => Kind::ProvisionedApp,
            "systemapp" => Kind::SystemApp,
            "feature" => Kind::Feature,
            "capability" => Kind::Capability,
            "package" => Kind::Package,
            "service" => Kind::Service,
            "componentpayload" | "payload" => Kind::ComponentPayload,
            _ => bail!("unknown item kind {s:?}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Disable,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: Kind,
    pub identity: String,
    pub mode: Mode,
}

impl std::str::FromStr for Action {
    type Err = anyhow::Error;
    /// `kind:identity[:disable|remove]` (identity may contain ':' only for the last form)
    fn from_str(s: &str) -> Result<Self> {
        let (kind, rest) = s.split_once(':').ok_or_else(|| anyhow!("expected kind:identity[:mode], got {s:?}"))?;
        let (identity, mode) = match rest.rsplit_once(':') {
            Some((i, m)) if m.eq_ignore_ascii_case("disable") => (i, Mode::Disable),
            Some((i, m)) if m.eq_ignore_ascii_case("remove") => (i, Mode::Remove),
            _ => (rest, Mode::Remove),
        };
        let kind: Kind = kind.parse()?;
        if mode == Mode::Disable && !matches!(kind, Kind::Feature | Kind::Service) {
            bail!("{kind:?} items can only be removed");
        }
        Ok(Action { kind, identity: identity.to_string(), mode })
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Item {
    pub kind: Kind,
    pub identity: String,
    pub detail: String,
    /// Everything except catalog apps is protected: removal may break the image.
    pub protected: bool,
    /// Human-readable name (manifest, registry or names.rs); actions still use `identity`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// What the item is, where the image says so (manifest description, service type and start).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// WinSxS components: the CBS packages that own them (lower case identities, from the COMPONENTS hive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<String>,
}

impl Item {
    /// Name to show: the readable name, else the identity.
    pub fn label(&self) -> &str {
        if self.name.is_empty() { &self.identity } else { &self.name }
    }
}

/// Reads the inventory of a mounted image, sorted by kind and identity.
pub fn read(root: &Path) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for app in appx::list(root)? {
        let catalog_app = catalog::OPTIONS.iter().any(|o| catalog::matches_app(o, &app.display_name, &app.package_name));
        items.push(Item {
            kind: Kind::ProvisionedApp,
            name: names::app(&app.display_name),
            identity: app.package_name,
            detail: app.display_name,
            protected: !catalog_app,
            ..Default::default()
        });
    }
    let store = cbs::Store::open(root)?;
    let text = |s: &str| {
        if s.is_empty() || s.starts_with('$') || s.starts_with('@') || names::looks_pseudo(s) { String::new() } else { s.trim().to_string() }
    };
    // Language satellites carry unreliable texts (some ship Microsoft's pseudo-localization, e.g.
    // "VβŞÇЃĪΡŦ"): they take name and description from the language-neutral package of the same name
    // and architecture, newest version first.
    let mut neutral: HashMap<(String, String), Vec<(Vec<u32>, &cbs::Mum)>> = HashMap::new();
    for (id, m) in &store.mums {
        if let [name, _, arch, "", ver] = id.split('~').collect::<Vec<_>>().as_slice() {
            neutral.entry((name.to_ascii_lowercase(), arch.to_ascii_lowercase())).or_default().push((version_key(ver), m));
        }
    }
    for v in neutral.values_mut() {
        v.sort_by(|a, b| b.0.cmp(&a.0));
    }
    let texts = |identity: &str| -> (String, String) {
        let f: Vec<&str> = identity.split('~').collect();
        let own = store.mums.get(identity);
        let mut cands: Vec<&cbs::Mum> = Vec::new();
        if let [name, _, arch, lang, _] = f.as_slice() {
            if !lang.is_empty() {
                if let Some(v) = neutral.get(&(name.to_ascii_lowercase(), arch.to_ascii_lowercase())) {
                    cands.extend(v.iter().map(|(_, m)| *m));
                }
            }
        }
        cands.extend(own);
        let name = cands.iter().map(|m| text(&m.display_name)).find(|n| !n.is_empty() && n != "default").unwrap_or_default();
        let desc = cands.iter().map(|m| text(&m.description)).find(|d| !d.is_empty()).unwrap_or_default();
        (name, desc)
    };
    // "Name (de-DE, 32-bit)": language and architecture tell same-named packages apart
    let qualify = |name: String, identity: &str| -> String {
        let f: Vec<&str> = identity.split('~').collect();
        let mut q = Vec::new();
        if let Some(l) = f.get(3).filter(|l| !l.is_empty() && !name.contains(**l)) {
            q.push(l.to_string());
        }
        if f.get(2).is_some_and(|a| a.eq_ignore_ascii_case("wow64") || a.eq_ignore_ascii_case("x86")) {
            q.push("32-bit".into());
        }
        if q.is_empty() || name.is_empty() { name } else { format!("{name} ({})", q.join(", ")) }
    };
    for f in store.features() {
        items.push(Item {
            kind: Kind::Feature,
            name: text(&f.display_name),
            description: text(&f.description),
            identity: f.name,
            detail: f.state.to_string(),
            protected: true,
            owners: Vec::new(),
        });
    }
    // capability identity -> member package (for its manifest's name)
    let cap_pkg: HashMap<&str, &str> = store.capability_index.values().flatten().map(|(p, id)| (id.as_str(), p.as_str())).collect();
    for c in dism_capabilities(&store) {
        let (mut name, desc) = cap_pkg.get(c.as_str()).map(|p| texts(p)).unwrap_or_default();
        let lang = c.split('~').nth(3).filter(|l| !l.is_empty());
        if name.is_empty() {
            name = names::humanize(c.split('~').next().unwrap_or(&c));
        }
        if let Some(l) = lang.filter(|l| !name.contains(*l)) {
            name = format!("{name} ({l})");
        }
        items.push(Item {
            kind: Kind::Capability,
            name,
            description: desc,
            identity: c,
            detail: "Installed".into(),
            protected: true,
            owners: Vec::new(),
        });
    }
    for p in store.dism_packages() {
        let (name, description) = texts(&p.identity);
        items.push(Item {
            kind: Kind::Package,
            name: qualify(name, &p.identity),
            description,
            identity: p.identity.clone(),
            detail: cbs::state_name(p.state).into(),
            protected: true,
            owners: Vec::new(),
        });
    }
    items.extend(native(root)?);
    // WinSxS components: which packages (and features) own them
    let owners = cbs::component_owners(root);
    let mums_lc: HashMap<String, &str> = store.mums.keys().map(|k| (k.to_ascii_lowercase(), k.as_str())).collect();
    let label = |pkg: &str, update: &str| -> String {
        let orig = mums_lc.get(pkg).copied();
        let feature = orig
            .and_then(|o| store.mums.get(o))
            .and_then(|m| m.updates.iter().find(|u| u.name.eq_ignore_ascii_case(update)))
            .map(|u| text(&u.display_name))
            .filter(|n| !n.is_empty());
        let name = orig.map(|o| texts(o).0).filter(|n| !n.is_empty());
        let base = pkg.split('~').next().unwrap_or(pkg);
        let fallback = if base.starts_with("package_for_rollupfix") || base.starts_with("cbs_package_") || base.contains("_for_kb") {
            "Windows cumulative update (base system)".to_string()
        } else if base.starts_with("package_for_servicingstack") {
            "Servicing stack".to_string()
        } else if base == "microsoft-windows-foundation-package" {
            "Windows foundation (base system)".to_string()
        } else if base.starts_with("microsoft-windows-client-languagepack-package") {
            "Display language pack".to_string()
        } else if base.contains("edition") || base.starts_with("microsoft-windows-licenses-") {
            "Edition and license".to_string()
        } else if base.contains("-client-desktop-required-") {
            "Windows base system (required part)".to_string()
        } else if base.contains("-client-features-") {
            "Windows base system (optional features part)".to_string()
        } else if base.contains("-client-languagepack-") || base.contains("-languagefeatures-") {
            "Language resources".to_string()
        } else {
            // e.g. microsoft-windows-grouppolicy-clienttools-merged-package -> "Grouppolicy clienttools"
            let mut t = base;
            for pre in ["microsoft-windows-", "microsoft-onecore-"] {
                t = t.strip_prefix(pre).unwrap_or(t);
            }
            for suf in ["-package", "-merged", "-opt", "-wow64", "-core"] {
                t = t.strip_suffix(suf).unwrap_or(t);
            }
            let h = names::humanize(t);
            let mut c = h.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or(h)
        };
        // internal sub-packages exist per architecture: 32-bit (WOW64) parts say so
        let fallback = if base.contains("-wow64-") && !fallback.contains("32-bit") { format!("{fallback}, 32-bit") } else { fallback };
        feature.or(name).unwrap_or(fallback)
    };
    for it in items.iter_mut().filter(|i| i.kind == Kind::ComponentPayload) {
        let Some(pairs) = owners.get(&it.identity.to_ascii_lowercase()) else {
            it.description = "No package owns it any more (a superseded version kept for rollback).".into();
            continue;
        };
        let mut labels: Vec<String> = Vec::new();
        let mut pkgs: Vec<String> = Vec::new();
        for p in pairs {
            let (pkg, update) = cbs::split_owner_pair(p);
            let l = label(&pkg, &update);
            if !labels.contains(&l) {
                labels.push(l);
            }
            if !pkgs.contains(&pkg) {
                pkgs.push(pkg);
            }
        }
        let shown = labels.iter().take(4).cloned().collect::<Vec<_>>().join("; ");
        it.description = if labels.len() > 4 { format!("Part of: {shown} and {} more.", labels.len() - 4) } else { format!("Part of: {shown}.") };
        it.owners = pkgs;
    }
    items.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.identity.to_ascii_lowercase().cmp(&b.identity.to_ascii_lowercase())));
    Ok(items)
}

/// Inventory of an edition of an ISO, media directory, WIM/ESD or an already mounted image. The install
/// image is extracted (ISO) or exported (ESD) into a fresh directory below `work`, mounted read-only and
/// removed afterwards.
pub fn read_source(source: &Path, edition: Option<&str>, work: &Path, log: &mut dyn FnMut(&str)) -> Result<Vec<Item>> {
    if source.join("Windows/System32/config").is_dir() {
        return read(source);
    }
    fs::create_dir_all(work)?;
    let dir = work.join(format!("lean11-inventory-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&dir)?;
    // held while the inventory runs, so `lean11 recover` leaves this folder alone
    let _lock = crate::build::lock_dir(&dir).ok_or_else(|| anyhow!("cannot lock the inventory folder"))?;
    let result = (|| -> Result<Vec<Item>> {
        let wim = if source.is_dir() {
            lean11_wim::resolve_ci(source, "sources/install.wim")
                .or_else(|| lean11_wim::resolve_ci(source, "sources/install.esd"))
                .ok_or_else(|| anyhow!("no sources/install.wim|esd"))?
        } else if source.extension().is_some_and(|e| e.eq_ignore_ascii_case("iso")) {
            let r = lean11_iso::UdfReader::open(source)?;
            let inst = r.walk()?.into_iter().map(|e| e.path).find(|p| {
                let l = p.to_ascii_lowercase();
                l == "sources/install.wim" || l == "sources/install.esd"
            });
            let inst = inst.ok_or_else(|| anyhow!("no install image in the ISO"))?;
            log(&format!("extracting {inst} for the inventory"));
            r.extract(&dir.join("iso"), &|p: &str| !p.eq_ignore_ascii_case(&inst), &mut |_, _| {})?;
            lean11_wim::resolve_ci(&dir.join("iso"), &inst).ok_or_else(|| anyhow!("extraction failed"))?
        } else {
            source.to_path_buf()
        };
        let images = lean11_wim::info(&wim)?;
        let img = lean11_wim::select(&images, edition)?;
        log(&format!("inventory of [{}] {}", img.index, img.name));
        // solid ESD: export the edition to a plain WIM first
        let (wim, index) = if wim.extension().is_some_and(|e| e.eq_ignore_ascii_case("esd")) {
            let w = dir.join("inventory.wim");
            lean11_wim::export(&wim, img.index, &w, lean11_wim::Compression::Fast, log)?;
            (w, 1)
        } else {
            (wim, img.index)
        };
        let m = lean11_wim::Mount::ro(&wim, index, &dir.join("mount"), log)?;
        let items = read(&m.dir);
        m.discard(log)?;
        items
    })();
    if lean11_wim::is_mountpoint(&dir.join("mount")) {
        log(&format!("warning: {} is still mounted; working directory {} kept", dir.join("mount").display(), dir.display()));
    } else if let Err(e) = fs::remove_dir_all(&dir) {
        log(&format!("warning: could not remove the working directory {}: {e}", dir.display()));
    }
    result
}

/// Installed capabilities as DISM names them: the neutral identity when there is one (language satellites
/// fold into it), else the language identities; capabilities of DISM-hidden FODs are not listed.
fn dism_capabilities(store: &cbs::Store) -> Vec<String> {
    let mut out = BTreeSet::new();
    for members in store.capability_index.values() {
        let installed: Vec<&(String, String)> = members
            .iter()
            .filter(|(p, _)| store.packages.get(p).is_some_and(|q| q.state >= cbs::STATE_INSTALLED))
            .filter(|(p, _)| !store.mums.get(p).is_some_and(|m| m.dism_hidden))
            .collect();
        let neutral: Vec<&String> = installed.iter().map(|(_, id)| id).filter(|id| id.split('~').nth(3).is_some_and(str::is_empty)).collect();
        if neutral.is_empty() {
            out.extend(installed.iter().map(|(_, id)| id.clone()));
        } else {
            out.extend(neutral.into_iter().cloned());
        }
    }
    out.into_iter().collect()
}

fn control_sets(sys: &Hive) -> Vec<String> {
    sys.children(sys.root()).into_iter().map(|(n, _)| n).filter(|n| n.len() == 13 && n.starts_with("ControlSet") && n.as_bytes()[10..].iter().all(|b| b.is_ascii_digit())).collect()
}

/// Services of the current control set, system apps and WinSxS payload directories.
/// "10.0.26100.1742" → [10, 0, 26100, 1742] for ordering.
fn version_key(v: &str) -> Vec<u32> {
    v.split('.').map(|x| x.parse().unwrap_or(0)).collect()
}

/// Service type and start mode in words (registry `Type` and `Start`).
fn service_description(start: i64, ty: u32) -> String {
    let what = match ty {
        1 => "Kernel driver",
        2 => "File system driver",
        8 => "Recognizer driver",
        16 => "Service (own process)",
        32 => "Service (shared process)",
        t if t & 0x40 != 0 => "Per-user service",
        t if t & 0x30 != 0 => "Service",
        _ => "Registry entry without a service type",
    };
    let when = match start {
        0 => "starts at boot",
        1 => "starts with the system",
        2 => "starts automatically",
        3 => "starts on demand",
        4 => "disabled",
        _ => "",
    };
    if when.is_empty() { what.to_string() } else { format!("{what}, {when}") }
}

fn native(root: &Path) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    let sys_path = lean11_wim::resolve_ci(root, "Windows/System32/config/SYSTEM").ok_or_else(|| anyhow!("image has no SYSTEM hive"))?;
    let sys = Hive::open(&sys_path, false)?;
    let current = sys.get("Select", "Current")?.and_then(|d| d.as_dword()).unwrap_or(1);
    let services = sys.key(&format!(r"ControlSet{current:03}\Services"))?.ok_or_else(|| anyhow!("The image has no service inventory."))?;
    let mut res = pe::Resolver::new(root);
    for (name, node) in sys.children(services) {
        let dw = |v: &str| sys.value(node, v).ok().flatten().and_then(|d| d.as_dword());
        let start = dw("Start").map(|v| v as i64).unwrap_or(-1);
        let ty = dw("Type").unwrap_or(0);
        let display = sys.value(node, "DisplayName").ok().flatten().and_then(|d| d.as_string()).unwrap_or_else(|| name.clone());
        let readable = if display.starts_with('@') { res.resolve(&display).unwrap_or_default() } else { display.clone() };
        items.push(Item {
            kind: Kind::Service,
            name: if readable.is_empty() || readable == name { String::new() } else { readable },
            description: service_description(start, ty),
            detail: format!("Start={start}; type={ty}; {display}"),
            identity: name,
            protected: true,
            owners: Vec::new(),
        });
    }
    const PAYLOAD: &str = "Protected payload. Removal can break boot, servicing, security or the shell.";
    if let Some(dir) = lean11_wim::resolve_ci(root, "Windows/SystemApps") {
        for e in fs::read_dir(&dir)?.flatten().filter(|e| e.path().is_dir()) {
            let id = e.file_name().to_string_lossy().into_owned();
            items.push(Item { kind: Kind::SystemApp, name: names::system_app(&id), identity: id, detail: PAYLOAD.into(), protected: true, ..Default::default() });
        }
    }
    if let Some(dir) = lean11_wim::resolve_ci(root, "Windows/WinSxS") {
        let folders: Vec<String> = fs::read_dir(&dir)?.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        let short: Vec<&str> = folders.iter().map(String::as_str).filter(|f| f.contains("..")).collect();
        let full = cbs::component_names(root, &short);
        for id in folders {
            let name = names::payload(&id, full.get(&id).map(|(n, c)| (n.as_str(), c.as_str())));
            items.push(Item { kind: Kind::ComponentPayload, name, identity: id, detail: PAYLOAD.into(), protected: true, ..Default::default() });
        }
    }
    Ok(items)
}

/// Per-action rule: a non-empty identity without path separators, and Disable only for
/// features and services.
pub fn check_action(a: &Action) -> Result<()> {
    if a.identity.trim().is_empty()
        || a.identity.contains(['\\', '/'])
        || (a.mode == Mode::Disable && !matches!(a.kind, Kind::Feature | Kind::Service))
    {
        bail!("Invalid custom image action: {:?} {} {:?}", a.kind, a.identity, a.mode);
    }
    Ok(())
}

/// Every action must name an item of the image's current inventory (exact identity).
/// Version-free key of an inventory identity, so an action chosen on one image finds the same item in a
/// newer one (templates): apps by name and publisher, packages and capabilities without their version,
/// WinSxS payloads by architecture, name, token and language; the rest by identity.
pub fn match_key(kind: Kind, identity: &str) -> String {
    let id = identity.to_ascii_lowercase();
    match kind {
        // Name_Version_Arch_ResourceId_PublisherId
        Kind::ProvisionedApp => {
            let f: Vec<&str> = id.split('_').collect();
            if f.len() >= 2 { format!("{}_{}", f[0], f[f.len() - 1]) } else { id }
        }
        // Name~Token~Arch~Lang~Version
        Kind::Package | Kind::Capability => match id.rsplit_once('~') {
            Some((head, _version)) => head.to_string(),
            None => id,
        },
        // arch_name_token_version_lang_hash
        Kind::ComponentPayload => {
            let parts: Vec<&str> = id.rsplitn(5, '_').collect();
            if parts.len() == 5 { format!("{}_{}_{}", parts[4], parts[3], parts[1]) } else { id }
        }
        Kind::SystemApp | Kind::Feature | Kind::Service => id,
    }
}

/// Maps actions onto an image's inventory: an exact identity stays, otherwise the one item with the same
/// [`match_key`] takes its place. Actions without a match (or with several) are dropped; the notes say so.
pub fn adapt(actions: &[Action], items: &[Item]) -> (Vec<Action>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for a in actions {
        if items.iter().any(|i| i.kind == a.kind && i.identity == a.identity) {
            out.push(a.clone());
            continue;
        }
        let key = match_key(a.kind, &a.identity);
        let found: Vec<&Item> = items.iter().filter(|i| i.kind == a.kind && match_key(i.kind, &i.identity) == key).collect();
        match found.as_slice() {
            [one] => {
                notes.push(format!("{:?} {} → {}", a.kind, a.identity, one.identity));
                out.push(Action { kind: a.kind, identity: one.identity.clone(), mode: a.mode });
            }
            [] => notes.push(format!("{:?} {} is not in this image; skipped", a.kind, a.identity)),
            _ => notes.push(format!("{:?} {} matches {} items in this image; skipped", a.kind, a.identity, found.len())),
        }
    }
    // two template actions can land on the same item
    let mut seen = BTreeSet::new();
    out.retain(|a| seen.insert((a.kind, a.identity.clone())));
    (out, notes)
}

pub fn validate(actions: &[Action], items: &[Item]) -> Result<()> {
    for a in actions {
        check_action(a)?;
        if !items.iter().any(|i| i.kind == a.kind && i.identity == a.identity) {
            bail!("The custom action is not in the selected image's current inventory: {:?} / {}", a.kind, a.identity);
        }
    }
    Ok(())
}

/// Servicing outcome of expert actions: count plus the verified feature and capability states.
#[derive(Default)]
pub struct ServicingResult {
    pub done: usize,
    pub features: Vec<cbs::FeatureCheck>,
    pub capabilities: Vec<cbs::CapabilityCheck>,
}

/// Servicing actions, the "Custom servicing" stage: apps in the given order, then packages, capabilities and
/// features together as one servicing plan.
pub fn apply_servicing(root: &Path, actions: &[Action], log: &mut dyn FnMut(&str)) -> Result<ServicingResult> {
    let mut out = ServicingResult::default();
    // servicing targets with the action they come from
    let mut targets: Vec<(cbs::Target, &Action)> = Vec::new();
    for a in actions {
        check_action(a)?;
        match a.kind {
            Kind::ProvisionedApp => {
                let removed = appx::remove_packages(root, &BTreeSet::from([a.identity.clone()]), log)?;
                if removed.is_empty() {
                    bail!("provisioned app {} was not removed", a.identity);
                }
                log(&format!("Expert {:?}: {:?} {}", a.mode, a.kind, a.identity));
                out.done += 1;
            }
            Kind::Package | Kind::Capability | Kind::Feature => {
                let t = match (a.kind, a.mode) {
                    (Kind::Package, _) => cbs::Target::Package(a.identity.clone()),
                    (Kind::Capability, _) => cbs::Target::Capability(a.identity.clone()),
                    (_, Mode::Remove) => cbs::Target::Feature(a.identity.clone()),
                    (_, Mode::Disable) => cbs::Target::DisableFeature(a.identity.clone()),
                };
                targets.push((t, a));
            }
            _ => continue,
        }
    }
    if targets.is_empty() {
        return Ok(out);
    }
    // Removals first, then disables, each as one plan: features that share packages are removed together,
    // and the check against retained packages knows every feature of the request. Two passes because a
    // package can be content of a feature that is removed and of one that is only disabled.
    let (disables, removals): (Vec<_>, Vec<_>) = targets.into_iter().partition(|(t, _)| matches!(t, cbs::Target::DisableFeature(_)));
    let mut later = disables;
    let mut pass = removals;
    loop {
        if !pass.is_empty() {
            let store = cbs::Store::open(root)?;
            let disable_pass = pass.iter().all(|(t, _)| matches!(t, cbs::Target::DisableFeature(_)));
            if disable_pass {
                // a feature whose content went with a removal in the first pass has nothing left to disable
                pass.retain(|(t, a)| {
                    let gone = store.plan(std::slice::from_ref(t)).is_ok_and(|p| !p.missing.is_empty());
                    if gone {
                        log(&format!("Feature {}: nothing left to disable, its content was removed with another feature.", a.identity));
                    }
                    !gone
                });
            }
            if let Some((plan, done)) = plan_with_fallback(&store, pass, &mut later, log)? {
                if !plan.missing.is_empty() {
                    bail!("these servicing actions matched nothing in the servicing store: {}", plan.missing.join(", "));
                }
                cbs::remove(&store, &plan, log)?;
                let (f, c) = cbs::verify(root, &plan)?;
                for x in &f {
                    log(&format!("Feature removal outcome: {} => {}.", x.name, x.describe()));
                }
                for x in &c {
                    log(&format!("Capability removal outcome: {} => {}.", x.name, x.describe()));
                }
                out.features.extend(f);
                out.capabilities.extend(c);
                for (t, a) in &done {
                    let mode = if matches!(t, cbs::Target::DisableFeature(_)) { Mode::Disable } else { a.mode };
                    log(&format!("Expert {:?}: {:?} {}", mode, a.kind, a.identity));
                    out.done += 1;
                }
            }
        }
        if later.is_empty() {
            break;
        }
        pass = std::mem::take(&mut later);
    }
    Ok(out)
}

/// Plans `targets` as one request. A feature whose payload is shared with packages that stay cannot lose its
/// payload: DISM then only disables it (verified on 26H2: /Remove of WindowsMediaPlayer leaves the shared
/// Payload packages installed and reports "Disabled"). Such features are moved to `later` as disables (run
/// in the next pass); features that cannot be disabled either are left unchanged with a log line. Returns
/// the plan with the targets it covers, or None when nothing is left.
fn plan_with_fallback<'a>(
    store: &cbs::Store,
    mut targets: Vec<(cbs::Target, &'a Action)>,
    later: &mut Vec<(cbs::Target, &'a Action)>,
    log: &mut dyn FnMut(&str),
) -> Result<Option<(cbs::Plan, Vec<(cbs::Target, &'a Action)>)>> {
    let shared = |e: &anyhow::Error| e.to_string().contains("removal would take");
    loop {
        if targets.is_empty() {
            return Ok(None);
        }
        let list: Vec<cbs::Target> = targets.iter().map(|(t, _)| t.clone()).collect();
        match store.plan(&list) {
            Ok(plan) => return Ok(Some((plan, targets))),
            Err(e) if shared(&e) => {
                let mut changed = false;
                let mut keep = Vec::new();
                for (t, a) in targets.drain(..) {
                    let single = store.plan(std::slice::from_ref(&t));
                    match (&t, single) {
                        (cbs::Target::Feature(f), Err(se)) if shared(&se) => {
                            let d = cbs::Target::DisableFeature(f.clone());
                            match store.plan(std::slice::from_ref(&d)) {
                                Ok(_) => {
                                    log(&format!("Feature {f}: its payload is shared with packages that stay; it will be disabled without removing the payload (as DISM does)."));
                                    later.push((d, a));
                                }
                                Err(de) => log(&format!("Feature {f}: left unchanged, it can be neither removed nor disabled here ({de:#}).")),
                            }
                            changed = true;
                        }
                        (cbs::Target::DisableFeature(f), Err(de)) => {
                            log(&format!("Feature {f}: left unchanged, it cannot be disabled here ({de:#})."));
                            changed = true;
                        }
                        _ => keep.push((t, a)),
                    }
                }
                targets = keep;
                if !changed {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Native actions: system app and WinSxS directories (deleted as files), services (`Start=4` or the key
/// deleted) in every control set; shared executables are not deleted.
pub fn apply_native(root: &Path, actions: &[Action], log: &mut dyn FnMut(&str)) -> Result<usize> {
    let mut done = 0;
    for a in actions.iter().filter(|a| matches!(a.kind, Kind::SystemApp | Kind::ComponentPayload)) {
        check_action(a)?;
        if a.identity == ".." || a.identity == "." {
            bail!("invalid directory name {:?}", a.identity);
        }
        let rel = if a.kind == Kind::SystemApp { "Windows/SystemApps" } else { "Windows/WinSxS" };
        let dir = lean11_wim::resolve_ci(root, rel).ok_or_else(|| anyhow!("image has no {rel}"))?;
        match lean11_wim::resolve_ci(&dir, &a.identity) {
            Some(p) => {
                fs::remove_dir_all(&p)?;
                log(&format!("Expert Remove: {rel}/{}", a.identity));
                done += 1;
            }
            None => log(&format!("Not present: {rel}/{}", a.identity)),
        }
    }
    let services: Vec<&Action> = actions.iter().filter(|a| a.kind == Kind::Service).collect();
    if services.is_empty() {
        return Ok(done);
    }
    let sys_path = lean11_wim::resolve_ci(root, "Windows/System32/config/SYSTEM").ok_or_else(|| anyhow!("image has no SYSTEM hive"))?;
    let mut sys = Hive::open(&sys_path, true)?;
    let mut changed = BTreeSet::new();
    for cs in control_sets(&sys) {
        for a in &services {
            check_action(a)?;
            let path = format!(r"{cs}\Services\{}", a.identity);
            if sys.key(&path)?.is_none() {
                log(&format!("Not present in {cs}: service {}", a.identity));
                continue;
            }
            match a.mode {
                Mode::Disable => sys.set(&path, "Start", &RegData::dword(4))?,
                Mode::Remove => {
                    sys.delete_key(&path)?;
                }
            }
            log(&format!("Expert {:?}: {cs}\\Services\\{}. Shared executable files are not deleted.", a.mode, a.identity));
            changed.insert(a.identity.clone());
        }
    }
    sys.commit()?;
    done += changed.len();
    Ok(done)
}

#[cfg(test)]
mod tests {

    #[test]
    fn template_actions_follow_new_versions() {
        let item = |kind, id: &str| Item { kind, identity: id.into(), ..Default::default() };
        let new = vec![
            item(Kind::ProvisionedApp, "Microsoft.BingNews_4.2.0.0_x64__8wekyb3d8bbwe"),
            item(Kind::Package, "Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~~10.0.26300.9000"),
            item(Kind::Capability, "Browser.InternetExplorer~~~~0.0.11.0"),
            item(Kind::ComponentPayload, "amd64_microsoft-windows-foo_31bf3856ad364e35_10.0.26300.9000_none_0123456789abcdef"),
            item(Kind::Service, "DiagTrack"),
        ];
        let act = |kind, id: &str| Action { kind, identity: id.into(), mode: Mode::Remove };
        let old = vec![
            act(Kind::ProvisionedApp, "Microsoft.BingNews_4.1.0.0_x64__8wekyb3d8bbwe"),
            act(Kind::Package, "Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~~10.0.26100.1"),
            act(Kind::Capability, "Browser.InternetExplorer~~~~0.0.11.0"),
            act(Kind::ComponentPayload, "amd64_microsoft-windows-foo_31bf3856ad364e35_10.0.26100.1_none_fedcba9876543210"),
            act(Kind::Service, "DiagTrack"),
            act(Kind::Service, "NoSuchService"),
        ];
        let (out, notes) = adapt(&old, &new);
        assert_eq!(out.len(), 5, "{notes:?}");
        assert!(out.iter().all(|a| new.iter().any(|i| i.identity == a.identity)));
        assert_eq!(notes.iter().filter(|n| n.contains("skipped")).count(), 1, "{notes:?}");
        validate(&out, &new).unwrap();
    }

    use super::*;

    #[test]
    fn parse_actions() {
        let a: Action = "feature:WorkFolders-Client:disable".parse().unwrap();
        assert_eq!((a.kind, a.identity.as_str(), a.mode), (Kind::Feature, "WorkFolders-Client", Mode::Disable));
        let b: Action = "capability:App.StepsRecorder~~~~0.0.1.0".parse().unwrap();
        assert_eq!((b.kind, b.mode), (Kind::Capability, Mode::Remove));
        assert!("package:x:disable".parse::<Action>().is_err());
        assert!("bogus:x".parse::<Action>().is_err());
    }
}
