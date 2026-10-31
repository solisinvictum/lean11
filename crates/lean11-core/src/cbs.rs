//! Component Based Servicing in an offline image: inventory (packages, optional features,
//! capabilities) and removal (DISM /Remove-Package, /Remove-Capability, /Disable-Feature /Remove),
//! reimplemented from DISM's observable behaviour; see docs/re/cbs.md.
//!
//! Data model (build 26100/26300):
//! - SOFTWARE `Component Based Servicing\Packages\<identity>`: installed packages with `CurrentState`
//!   (0x70 installed, 0x40 staged). The package manifests are `Windows\servicing\Packages\<identity>.mum`.
//! - An optional feature is a selectable `<update name=…>` of a package. Its content is the packages
//!   in that update, the packages holding an update with `<detectUpdate><parent name=feature/>`, and the
//!   members of the capabilities the update names. Enabled = content installed, disabled = staged,
//!   removed = absent.
//! - `CapabilityIndex\<name>`: one value per member package, data = capability identity.
//! - COMPONENTS `CanonicalData\Deployments\<deployment>`: owner values `p!`/`s!`/`i!CBS_…` whose data is
//!   8 flag bytes plus `<package identity>.<update name>`; `i!` = installed (projected).
//!   `DerivedData\Components\<component>`: `c!<deployment>` references; the key name is also the
//!   payload directory `WinSxS\<component>` and the manifest `WinSxS\Manifests\<component>.manifest`.
//! - Projected files are hard links of the payload files, projected registry data is listed in the
//!   (DCM/PA30 compressed) component manifest.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lean11_hive::{Hive, NodeH, RegData};

pub const CBS_KEY: &str = r"Microsoft\Windows\CurrentVersion\Component Based Servicing";
const WINNERS_KEY: &str = r"Microsoft\Windows\CurrentVersion\SideBySide\Winners";
const WINEVT_KEY: &str = r"Microsoft\Windows\CurrentVersion\WINEVT";
const TASKCACHE_KEY: &str = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
const PACKAGES_DIR: &str = "Windows/servicing/Packages";
const CATROOT: &str = "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";
const WINSXS: &str = "Windows/WinSxS";

pub const STATE_STAGED: u32 = 0x40;

/// DISM's name for a CBS package state.
pub fn state_name(state: u32) -> &'static str {
    match state {
        0x00 => "Not Present",
        0x05 => "Uninstall Pending",
        0x20 | 0x30 | 0x40 => "Staged",
        0x50 => "Superseded",
        0x60 => "Install Pending",
        0x65 => "Partially Installed",
        0x70 | 0x80 => "Installed",
        _ => "Unknown",
    }
}
pub const STATE_INSTALLED: u32 = 0x70;

/// Packages that a removal must never touch (it would take the whole OS with it).
const PROTECTED: &[&str] = &[
    "Microsoft-Windows-Foundation-Package",
    "Microsoft-Windows-Client-Features-Package",
    "Microsoft-Windows-Client-Desktop-Required-Package",
    "Microsoft-Windows-ServicingStack",
    "Package_for_RollupFix",
    "Package_for_ServicingStack",
    "Microsoft-Windows-Client-LanguagePack-Package",
];
/// Upper bound for one removal; a larger closure means the dependency walk went astray.
const MAX_REMOVAL: usize = 400;

pub type Log<'a> = &'a mut dyn FnMut(&str);

// ---------------------------------------------------------------------------------------------
// identities and manifests

/// `Name~PublicKeyToken~Arch~Language~Version`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageId {
    pub name: String,
    pub token: String,
    pub arch: String,
    pub lang: String,
    pub version: String,
}

impl PackageId {
    pub fn parse(s: &str) -> Option<Self> {
        let p: Vec<&str> = s.split('~').collect();
        (p.len() == 5).then(|| PackageId {
            name: p[0].into(),
            token: p[1].into(),
            arch: p[2].into(),
            lang: p[3].into(),
            version: p[4].into(),
        })
    }
    /// Name and architecture, lower case: all versions and languages of one package.
    pub fn family(&self) -> (String, String) {
        (self.name.to_ascii_lowercase(), self.arch.to_ascii_lowercase())
    }
}

/// An `<assemblyIdentity>` reference inside a manifest.
#[derive(Debug, Clone, Default)]
pub struct AsmRef {
    pub name: String,
    pub arch: String,
    pub lang: String,
    pub version: String,
}

impl AsmRef {
    fn family(&self) -> (String, String) {
        (self.name.to_ascii_lowercase(), self.arch.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Update {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub selectable: bool,
    /// `<selectable disposition=…>`: staged, absent, ...
    pub disposition: String,
    /// `EnableSelectabilityForEdition` names: the feature is only selectable in these editions.
    pub editions: Vec<String>,
    /// `<applicable><detectUpdate><update name=…/>`: child feature of that update.
    pub detect_updates: Vec<String>,
    /// `<applicable><detectUpdate><parent name=…/>`: the update is content of that feature.
    pub detect_parents: Vec<String>,
    pub packages: Vec<AsmRef>,
    pub components: Vec<AsmRef>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Mum {
    /// `<assembly displayName=… description=…>` of the package manifest.
    pub display_name: String,
    pub description: String,
    /// `<mum2:DismOptions Visibility="hidden"/>`: DISM does not list the package (or its capability).
    pub dism_hidden: bool,
    pub parents: Vec<AsmRef>,
    pub updates: Vec<Update>,
    pub declared_capabilities: Vec<String>,
}

fn asm_ref(n: roxmltree::Node) -> Option<AsmRef> {
    let a = n.children().find(|c| c.has_tag_name("assemblyIdentity"))?;
    let lang = a.attribute("language").unwrap_or("neutral");
    Some(AsmRef {
        name: a.attribute("name")?.to_string(),
        arch: a.attribute("processorArchitecture").unwrap_or("").to_string(),
        lang: if lang.eq_ignore_ascii_case("neutral") { String::new() } else { lang.to_string() },
        version: a.attribute("version").unwrap_or("").to_string(),
    })
}

pub fn parse_mum(xml: &str) -> Result<Mum> {
    let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}'))?;
    let mut mum = Mum::default();
    let asm = doc.root_element();
    mum.display_name = asm.attribute("displayName").unwrap_or("").to_string();
    mum.description = asm.attribute("description").unwrap_or("").to_string();
    let pkg = doc.root_element().children().find(|c| c.has_tag_name("package")).ok_or_else(|| anyhow!("package manifest without <package>"))?;
    mum.dism_hidden = pkg
        .children()
        .filter(|c| c.has_tag_name("customInformation"))
        .flat_map(|c| c.descendants())
        .any(|d| d.tag_name().name() == "DismOptions" && d.attribute("Visibility").is_some_and(|v| v.eq_ignore_ascii_case("hidden")));
    for c in pkg.children().filter(|c| c.is_element()) {
        match c.tag_name().name() {
            "parent" => mum.parents.extend(asm_ref(c)),
            "declareCapability" => mum.declared_capabilities.extend(
                c.descendants().filter(|d| d.has_tag_name("capabilityIdentity")).filter_map(|d| d.attribute("name")).map(str::to_string),
            ),
            "update" => {
                let mut u = Update {
                    name: c.attribute("name").unwrap_or("").to_string(),
                    display_name: c.attribute("displayName").unwrap_or("").to_string(),
                    description: c.attribute("description").unwrap_or("").to_string(),
                    ..Default::default()
                };
                for e in c.children().filter(|e| e.is_element()) {
                    match e.tag_name().name() {
                        "selectable" => {
                            u.selectable = true;
                            u.disposition = e.attribute("disposition").unwrap_or("").to_string();
                            u.editions.extend(
                                e.descendants()
                                    .filter(|d| d.has_tag_name("EnableSelectabilityForEdition"))
                                    .filter_map(|d| d.attribute("name"))
                                    .map(str::to_string),
                            );
                        }
                        "applicable" => {
                            let in_detect = |d: &roxmltree::Node| d.parent().is_some_and(|p| p.has_tag_name("detectUpdate"));
                            for d in e.descendants().filter(in_detect) {
                                if let Some(n) = d.attribute("name") {
                                    if d.has_tag_name("parent") {
                                        u.detect_parents.push(n.to_string());
                                    } else if d.has_tag_name("update") {
                                        u.detect_updates.push(n.to_string());
                                    }
                                }
                            }
                        }
                        "package" => u.packages.extend(asm_ref(e)),
                        "component" => u.components.extend(asm_ref(e)),
                        "capability" => u.capabilities.extend(
                            e.children().filter(|d| d.has_tag_name("capabilityIdentity")).filter_map(|d| d.attribute("name")).map(str::to_string),
                        ),
                        _ => {}
                    }
                }
                mum.updates.push(u);
            }
            _ => {}
        }
    }
    Ok(mum)
}

// ---------------------------------------------------------------------------------------------
// store

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub identity: String,
    pub id: PackageId,
    pub state: u32,
    pub visibility: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum FeatureState {
    Enabled,
    Disabled,
    /// Disabled with payload removed.
    Removed,
}

impl std::fmt::Display for FeatureState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            FeatureState::Enabled => "Enabled",
            FeatureState::Disabled => "Disabled",
            FeatureState::Removed => "Disabled with Payload Removed",
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Feature {
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// Package that declares the feature.
    pub package: String,
    pub state: FeatureState,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Capability {
    /// Capability identity, e.g. `App.StepsRecorder~~~~0.0.1.0`.
    pub name: String,
    pub installed: bool,
    pub packages: Vec<String>,
}

#[derive(Debug, Default)]
struct FeatureContent {
    packages: BTreeSet<String>,
    pairs: BTreeSet<String>,
    capability_packages: BTreeSet<String>,
    /// The manifests name some content (packages, components or capabilities).
    declared: bool,
}

/// Read-only view of the servicing store of a mounted image.
pub struct Store {
    pub root: PathBuf,
    pub packages: BTreeMap<String, PackageInfo>,
    pub mums: HashMap<String, Mum>,
    /// CapabilityIndex: base name -> (member package, capability identity)
    pub capability_index: BTreeMap<String, Vec<(String, String)>>,
    /// Deployment owner pairs `<package>.<update>` (lower case) with `i!` values.
    installed_pairs: HashSet<String>,
    /// Deployment owner pairs with any owner value.
    present_pairs: HashSet<String>,
}

fn hive_path(root: &Path, name: &str) -> Result<PathBuf> {
    lean11_wim::resolve_ci(root, &format!("Windows/System32/config/{name}")).ok_or_else(|| anyhow!("image has no {name} hive"))
}

fn dword(h: &Hive, node: NodeH, name: &str) -> u32 {
    h.value(node, name).ok().flatten().and_then(|d| d.as_dword()).unwrap_or(0)
}

/// `<package identity>.<update>` from the data of a deployment owner value.
fn owner_pair(d: &RegData) -> Option<String> {
    if d.data.len() <= 8 {
        return None;
    }
    let s = String::from_utf8_lossy(&d.data[8..]);
    Some(s.trim_end_matches('\0').to_ascii_lowercase())
}

fn is_owner_value(name: &str) -> bool {
    let n = name.as_bytes();
    n.len() > 2 && n[1] == b'!' && matches!(n[0].to_ascii_lowercase(), b'p' | b's' | b'i')
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let sw = Hive::open(&hive_path(root, "SOFTWARE")?, false)?;
        let mut packages = BTreeMap::new();
        if let Some(pk) = sw.key(&format!(r"{CBS_KEY}\Packages"))? {
            for (name, node) in sw.children(pk) {
                let Some(id) = PackageId::parse(&name) else { continue };
                let state = dword(&sw, node, "CurrentState");
                let visibility = dword(&sw, node, "Visibility");
                packages.insert(name.clone(), PackageInfo { identity: name, id, state, visibility });
            }
        }
        let mut capability_index: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        if let Some(ci) = sw.key(&format!(r"{CBS_KEY}\CapabilityIndex"))? {
            for (name, node) in sw.children(ci) {
                let members = sw.values(node).into_iter().map(|(k, d)| (k, lean11_hive::from_utf16(&d.data))).collect();
                capability_index.insert(name, members);
            }
        }
        // manifests of all registered packages (file names may differ in case)
        let mut mums = HashMap::new();
        if let Some(dir) = lean11_wim::resolve_ci(root, PACKAGES_DIR) {
            let files: HashMap<String, PathBuf> = fs::read_dir(&dir)?
                .flatten()
                .map(|e| (e.file_name().to_string_lossy().to_ascii_lowercase(), e.path()))
                .collect();
            for identity in packages.keys() {
                if let Some(p) = files.get(&format!("{}.mum", identity.to_ascii_lowercase())) {
                    let xml = fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
                    match parse_mum(&xml) {
                        Ok(m) => {
                            mums.insert(identity.clone(), m);
                        }
                        Err(e) => log::warn!("{}: {e}", p.display()),
                    }
                }
            }
        }
        let (mut installed_pairs, mut present_pairs) = (HashSet::new(), HashSet::new());
        if let Ok(p) = hive_path(root, "COMPONENTS") {
            let co = Hive::open(&p, false)?;
            if let Some(deps) = co.key(r"CanonicalData\Deployments")? {
                for (_, node) in co.children(deps) {
                    for (k, d) in co.values(node) {
                        if !is_owner_value(&k) {
                            continue;
                        }
                        if let Some(pair) = owner_pair(&d) {
                            if strip_ci(&k, "i!").is_some() {
                                installed_pairs.insert(pair.clone());
                            }
                            present_pairs.insert(pair);
                        }
                    }
                }
            }
        }
        Ok(Store { root: root.to_path_buf(), packages, mums, capability_index, installed_pairs, present_pairs })
    }

    fn by_family(&self, fam: &(String, String)) -> impl Iterator<Item = &PackageInfo> {
        self.packages.values().filter(move |p| &p.id.family() == fam)
    }

    /// Selectable updates (optional features) declared by installed packages.
    fn feature_decls(&self) -> Vec<(&PackageInfo, &Update)> {
        let mut out = Vec::new();
        for p in self.packages.values().filter(|p| p.state >= STATE_INSTALLED) {
            if let Some(m) = self.mums.get(&p.identity) {
                out.extend(m.updates.iter().filter(|u| u.selectable && !u.name.is_empty()).map(|u| (p, u)));
            }
        }
        out
    }

    /// Content of a feature: packages and component-only owner pairs that make it enabled, plus the
    /// members of the capabilities it names (they provide the payload but do not enable it).
    fn feature_content(&self, feature: &str) -> FeatureContent {
        let mut c = FeatureContent::default();
        for (p, u) in self.feature_decls().into_iter().filter(|(_, u)| u.name.eq_ignore_ascii_case(feature)) {
            for r in &u.packages {
                c.declared = true;
                c.packages.extend(self.by_family(&r.family()).map(|q| q.identity.clone()));
            }
            if !u.components.is_empty() {
                c.declared = true;
                c.pairs.insert(format!("{}.{}", p.identity, u.name).to_ascii_lowercase());
            }
            for cap in &u.capabilities {
                c.declared = true;
                if let Some(members) = self.capability_index.get(cap) {
                    c.capability_packages.extend(members.iter().map(|(m, _)| m.clone()).filter(|m| self.packages.contains_key(m)));
                }
            }
        }
        // Updates of other packages that detect this feature as parent: only that update is content
        // (its components via the deployment owner pair, its packages), not the holding package, which
        // is often a shared base package (e.g. IIS ServerCommon).
        // Detection chains: an update can detect another content update as its parent (the wow64 FOD's
        // update detects `WorkFolders-Client-Content` of the amd64 FOD), so follow them transitively.
        let mut names: HashSet<String> = HashSet::from([feature.to_ascii_lowercase()]);
        let mut seen: HashSet<(String, String)> = HashSet::new();
        loop {
            let mut grew = false;
            let mut new_names = Vec::new();
            for (identity, m) in &self.mums {
                for u in m.updates.iter().filter(|u| u.detect_parents.iter().any(|d| names.contains(&d.to_ascii_lowercase()))) {
                    if !seen.insert((identity.clone(), u.name.to_ascii_lowercase())) {
                        continue;
                    }
                    grew = true;
                    new_names.push(u.name.to_ascii_lowercase());
                    if !u.components.is_empty() {
                        c.declared = true;
                        c.pairs.insert(format!("{identity}.{}", u.name).to_ascii_lowercase());
                    }
                    for r in &u.packages {
                        c.declared = true;
                        c.packages.extend(self.by_family(&r.family()).map(|q| q.identity.clone()));
                    }
                }
            }
            names.extend(new_names);
            if !grew {
                break;
            }
        }
        c
    }

    fn feature_state(&self, feature: &str, c: &FeatureContent, depth: u32) -> FeatureState {
        if !c.declared {
            // parent feature without own content (Hyper-V-All, Printing-Foundation-Features):
            // enabled when a child feature is enabled
            let enabled_child = depth < 8
                && self.feature_decls().into_iter().any(|(_, u)| {
                    u.detect_updates.iter().any(|d| d.eq_ignore_ascii_case(feature))
                        && self.feature_state(&u.name, &self.feature_content(&u.name), depth + 1) == FeatureState::Enabled
                });
            return if enabled_child { FeatureState::Enabled } else { FeatureState::Disabled };
        }
        let states: Vec<u32> = c.packages.iter().filter_map(|i| self.packages.get(i)).map(|q| q.state).collect();
        if states.iter().any(|&s| s >= STATE_INSTALLED) || c.pairs.iter().any(|x| self.installed_pairs.contains(x)) {
            FeatureState::Enabled
        } else if !states.is_empty()
            || !c.capability_packages.is_empty()
            || c.pairs.iter().any(|x| self.present_pairs.contains(x))
        {
            FeatureState::Disabled
        } else {
            FeatureState::Removed
        }
    }

    /// False for features reserved for other editions (`EnableSelectabilityForEdition` without an
    /// installed edition package of that name).
    fn selectable_here(&self, u: &Update) -> bool {
        u.editions.is_empty()
            || u.editions.iter().any(|ed| self.packages.values().any(|p| p.state >= STATE_INSTALLED && p.id.name.eq_ignore_ascii_case(ed)))
    }

    /// Optional features as DISM /Get-Features lists them.
    pub fn features(&self) -> Vec<Feature> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (p, u) in self.feature_decls() {
            if !self.selectable_here(u) || !seen.insert(u.name.to_ascii_lowercase()) {
                continue;
            }
            let state = self.feature_state(&u.name, &self.feature_content(&u.name), 0);
            out.push(Feature {
                name: u.name.clone(),
                display_name: u.display_name.clone(),
                description: u.description.clone(),
                package: p.identity.clone(),
                state,
            });
        }
        out.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
        out
    }

    /// Packages as `DISM /Get-Packages` lists them: visibility 1 and not hidden by `DismOptions`.
    pub fn dism_packages(&self) -> Vec<&PackageInfo> {
        self.packages.values().filter(|p| p.visibility == 1 && !self.mums.get(&p.identity).is_some_and(|m| m.dism_hidden)).collect()
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        let mut by_identity: BTreeMap<String, Capability> = BTreeMap::new();
        for members in self.capability_index.values() {
            for (pkg, cap) in members {
                let c = by_identity.entry(cap.clone()).or_insert_with(|| Capability { name: cap.clone(), installed: false, packages: vec![] });
                if let Some(p) = self.packages.get(pkg) {
                    c.installed |= p.state >= STATE_INSTALLED;
                    c.packages.push(pkg.clone());
                }
            }
        }
        by_identity.into_values().collect()
    }

    /// Adds everything that cannot stay once `set` is gone: other versions and languages of the same
    /// packages, packages whose `<parent>` is removed (wrappers, satellites) and child packages that
    /// only removed packages include.
    pub fn closure(&self, mut set: BTreeSet<String>) -> BTreeSet<String> {
        // child family -> identities of the packages including it
        let mut includers: HashMap<(String, String), Vec<&str>> = HashMap::new();
        for (identity, m) in &self.mums {
            for u in &m.updates {
                for r in &u.packages {
                    includers.entry(r.family()).or_default().push(identity);
                }
            }
        }
        loop {
            let fams: HashSet<(String, String)> = set.iter().filter_map(|i| self.packages.get(i)).map(|p| p.id.family()).collect();
            let mut add: Vec<String> = Vec::new();
            for p in self.packages.values().filter(|p| !set.contains(&p.identity)) {
                let fam = p.id.family();
                if fams.contains(&fam) {
                    add.push(p.identity.clone());
                    continue;
                }
                let m = self.mums.get(&p.identity);
                if m.is_some_and(|m| m.parents.iter().any(|r| fams.contains(&r.family()))) {
                    add.push(p.identity.clone());
                    continue;
                }
                if let Some(inc) = includers.get(&fam)
                    && inc.iter().any(|i| set.contains(*i))
                    && inc.iter().all(|i| set.contains(*i) || !self.packages.get(*i).is_some_and(|q| q.state >= STATE_STAGED))
                {
                    add.push(p.identity.clone());
                }
            }
            if add.is_empty() {
                return set;
            }
            set.extend(add);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// removal

/// Post-removal state of a feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FeatureCheck {
    pub name: String,
    pub state: Option<String>,
    /// PayloadRemoved, DisabledPayloadRetained, DisablePending, Enabled, Unknown
    pub outcome: String,
}

impl FeatureCheck {
    pub fn accepted(&self) -> bool {
        matches!(self.outcome.as_str(), "PayloadRemoved" | "DisabledPayloadRetained" | "DisablePending")
    }
    pub fn describe(&self) -> String {
        let st = self.state.clone().unwrap_or_default();
        match self.outcome.as_str() {
            "PayloadRemoved" => "disabled and its payload removed".into(),
            "DisabledPayloadRetained" => format!("disabled; its payload stays in the image (state '{st}')"),
            "Enabled" => format!("still enabled (state '{st}')"),
            _ if self.state.is_none() => "missing from the post-removal inventory".into(),
            _ => format!("unrecognised state '{st}'"),
        }
    }
}

/// Post-removal state of a capability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CapabilityCheck {
    pub name: String,
    pub state: Option<String>,
    /// Absent, Pending, Present, Unknown
    pub proof: String,
}

impl CapabilityCheck {
    pub fn accepted(&self) -> bool {
        self.proof == "Absent"
    }
    pub fn describe(&self) -> String {
        let st = self.state.clone().unwrap_or_default();
        match self.proof.as_str() {
            "Absent" => format!("absent (state '{st}')"),
            "Present" => format!("still present (state '{st}')"),
            _ => format!("unrecognised state '{st}'"),
        }
    }
}

/// Re-reads the store after `remove` and proves every planned feature is disabled and every planned
/// capability absent, as DISM checks after `/Disable-Feature` and `/Remove-Capability`.
pub fn verify(root: &Path, plan: &Plan) -> Result<(Vec<FeatureCheck>, Vec<CapabilityCheck>)> {
    let store = Store::open(root)?;
    let states: HashMap<String, FeatureState> = store.features().into_iter().map(|f| (f.name.to_ascii_lowercase(), f.state)).collect();
    let features: Vec<FeatureCheck> = plan
        .features
        .iter()
        .chain(&plan.disabled_features)
        .map(|name| {
            let st = states.get(&name.to_ascii_lowercase()).copied();
            let outcome = match st {
                Some(FeatureState::Removed) => "PayloadRemoved",
                Some(FeatureState::Disabled) => "DisabledPayloadRetained",
                Some(FeatureState::Enabled) => "Enabled",
                None => "Unknown",
            };
            FeatureCheck { name: name.clone(), state: st.map(|s| s.to_string()), outcome: outcome.into() }
        })
        .collect();
    let caps: HashMap<String, Capability> = store.capabilities().into_iter().map(|c| (c.name.to_ascii_lowercase(), c)).collect();
    let capabilities: Vec<CapabilityCheck> = plan
        .capabilities
        .iter()
        .map(|name| {
            // a removed capability has no packages left and is listed by DISM as "Not Present" (FOD marker)
            let (state, proof) = match caps.get(&name.to_ascii_lowercase()) {
                Some(c) if c.installed => ("Installed", "Present"),
                Some(c) if !c.packages.is_empty() => ("Staged", "Present"),
                _ => ("Not Present", "Absent"),
            };
            CapabilityCheck { name: name.clone(), state: Some(state.into()), proof: proof.into() }
        })
        .collect();
    let rejected: Vec<String> = features.iter().filter(|f| !f.accepted()).map(|f| format!("{} => {}", f.name, f.describe())).collect();
    if !rejected.is_empty() {
        bail!("Feature batch did not disable every requested feature: {}.", rejected.join("; "));
    }
    let unproven: Vec<String> = capabilities.iter().filter(|c| !c.accepted()).map(|c| format!("{} => {}", c.name, c.describe())).collect();
    if !unproven.is_empty() {
        bail!("Capability batch did not prove removal: {}.", unproven.join("; "));
    }
    Ok((features, capabilities))
}

#[derive(Debug, Clone)]
pub enum Target {
    /// Capability base name or prefix, e.g. `App.StepsRecorder` or `Language.Speech`.
    Capability(String),
    /// Optional feature name (`Disable-Feature /Remove`).
    Feature(String),
    /// Optional feature name (`Disable-Feature` without /Remove: payload stays, content is staged).
    DisableFeature(String),
    /// Package name (all versions, architectures and languages) or full identity.
    Package(String),
}

#[derive(Debug, Default)]
pub struct Plan {
    pub packages: BTreeSet<String>,
    /// Component-only feature content: `<package identity>.<update>` (lower case).
    pub pairs: BTreeSet<String>,
    pub features: Vec<String>,
    /// Removed capability identities, recorded as `Features on Demand\Removed FOD Markers`.
    pub capabilities: BTreeSet<String>,
    /// Packages that stay with their payload but are no longer installed (0x70 -> 0x40).
    pub stage: BTreeSet<String>,
    /// Features disabled without /Remove (notification `Selection=0`, no `Removed`).
    pub disabled_features: Vec<String>,
    /// Owner pairs (`<package>.<update>`, lower case) that lose only their installed (`i!`) values.
    pub stage_pairs: BTreeSet<String>,
    /// Targets that matched nothing.
    pub missing: Vec<String>,
}

impl Store {
    pub fn plan(&self, targets: &[Target]) -> Result<Plan> {
        let mut plan = Plan::default();
        let mut initial = BTreeSet::new();
        // wrappers of disabled features: removed as they are, without the closure (which would also take
        // the content they include, but that content stays staged)
        let mut wrappers = BTreeSet::new();
        for t in targets {
            match t {
                Target::Capability(c) => {
                    let lc = c.to_ascii_lowercase();
                    if c.contains('~') {
                        // exact capability identity (DISM /CapabilityName:App.StepsRecorder~~~~0.0.1.0)
                        for members in self.capability_index.values() {
                            if members.iter().any(|(_, id)| id.eq_ignore_ascii_case(c)) {
                                initial.extend(
                                    members.iter().filter(|(m, id)| id.eq_ignore_ascii_case(c) && self.packages.contains_key(m)).map(|(m, _)| m.clone()),
                                );
                                plan.capabilities.insert(c.clone());
                            }
                        }
                    } else {
                    for (name, members) in &self.capability_index {
                        let ln = name.to_ascii_lowercase();
                        if ln == lc || ln.starts_with(&format!("{lc}.")) || (lc.ends_with('*') && ln.starts_with(lc.trim_end_matches('*'))) {
                            initial.extend(members.iter().map(|(m, _)| m.clone()).filter(|m| self.packages.contains_key(m)));
                            // DISM marks the identity it was given: the neutral one if there is one
                            let ids: BTreeSet<&String> = members.iter().map(|(_, id)| id).collect();
                            let neutral: Vec<&&String> = ids.iter().filter(|id| id.split('~').nth(3).is_some_and(str::is_empty)).collect();
                            if neutral.is_empty() {
                                plan.capabilities.extend(ids.iter().map(|id| id.to_string()));
                            } else {
                                plan.capabilities.extend(neutral.iter().map(|id| id.to_string()));
                            }
                        }
                    }
                    }
                }
                Target::Feature(f) => {
                    let c = self.feature_content(f);
                    if !c.packages.is_empty() || !c.pairs.is_empty() || !c.capability_packages.is_empty() {
                        plan.features.push(f.clone());
                    }
                    // with /Remove the payload goes too: the capability packages are removed as well
                    initial.extend(c.packages);
                    initial.extend(c.capability_packages);
                    plan.pairs.extend(c.pairs);
                }
                Target::DisableFeature(f) => {
                    let c = self.feature_content(f);
                    if !c.packages.is_empty() || !c.pairs.is_empty() || !c.capability_packages.is_empty() {
                        plan.disabled_features.push(f.clone());
                    }
                    // content is staged (installed versions go to 0x40), component-only content loses its
                    // installed owner values; wrapper packages whose parent is staged content are removed
                    let staged: BTreeSet<String> = c.packages.into_iter().chain(c.capability_packages).collect();
                    let fams: HashSet<(String, String)> = staged.iter().filter_map(|i| self.packages.get(i)).map(|p| p.id.family()).collect();
                    for (identity, m) in &self.mums {
                        if !staged.contains(identity) && m.parents.iter().any(|r| fams.contains(&r.family())) {
                            wrappers.insert(identity.clone());
                        }
                    }
                    for p in &staged {
                        if let Some(m) = self.mums.get(p) {
                            for u in m.updates.iter().filter(|u| !u.components.is_empty()) {
                                plan.stage_pairs.insert(format!("{p}.{}", u.name).to_ascii_lowercase());
                            }
                        }
                    }
                    plan.stage_pairs.extend(c.pairs);
                    if staged.is_empty() && plan.stage_pairs.is_empty() {
                        plan.missing.push(format!("{t:?}"));
                    }
                    plan.stage.extend(staged);
                    continue;
                }
                Target::Package(p) => {
                    if self.packages.contains_key(p) {
                        initial.insert(p.clone());
                    } else {
                        initial.extend(self.packages.values().filter(|q| q.id.name.eq_ignore_ascii_case(p)).map(|q| q.identity.clone()));
                    }
                }
            }
            // per target, not by growth: targets of one request may share packages
            if !self.target_matches(t) {
                plan.missing.push(format!("{t:?}"));
            }
        }
        plan.packages = if initial.is_empty() { initial } else { self.closure(initial) };
        plan.packages.extend(wrappers);
        if let Some(p) = plan.packages.iter().find(|p| plan.stage.contains(*p)) {
            bail!("{p} would be both removed and kept staged; split the request");
        }
        self.check_plan(&plan)?;
        for p in &plan.packages {
            let name = &self.packages[p].id.name;
            if PROTECTED.iter().any(|x| name.eq_ignore_ascii_case(x)) {
                bail!("removal would include the protected package {p}");
            }
        }
        if plan.packages.len() > MAX_REMOVAL {
            bail!("removal grew to {} packages; refusing", plan.packages.len());
        }
        Ok(plan)
    }
}

impl Store {
    /// True if a removal target names something in the store (same matching rules as [`Store::plan`]).
    fn target_matches(&self, t: &Target) -> bool {
        match t {
            Target::Capability(c) if c.contains('~') => {
                self.capability_index.values().flatten().any(|(m, id)| id.eq_ignore_ascii_case(c) && self.packages.contains_key(m))
            }
            Target::Capability(c) => {
                let lc = c.to_ascii_lowercase();
                self.capability_index.iter().any(|(name, members)| {
                    let ln = name.to_ascii_lowercase();
                    (ln == lc || ln.starts_with(&format!("{lc}.")) || (lc.ends_with('*') && ln.starts_with(lc.trim_end_matches('*'))))
                        && members.iter().any(|(m, _)| self.packages.contains_key(m))
                })
            }
            Target::Feature(f) | Target::DisableFeature(f) => {
                let c = self.feature_content(f);
                // a parent feature without content of its own (e.g. IIS-WebServerRole) exists but has nothing
                // to remove: a no-op, not a miss
                !c.packages.is_empty()
                    || !c.pairs.is_empty()
                    || !c.capability_packages.is_empty()
                    || self.feature_decls().iter().any(|(_, u)| u.name.eq_ignore_ascii_case(f) && self.selectable_here(u))
            }
            Target::Package(p) => self.packages.contains_key(p) || self.packages.values().any(|q| q.id.name.eq_ignore_ascii_case(p)),
        }
    }

    /// Refuses plans that would leave a retained package without a package it includes, and plans
    /// made on an incomplete manifest graph.
    fn check_plan(&self, plan: &Plan) -> Result<()> {
        if plan.packages.is_empty() {
            return Ok(());
        }
        if let Some(p) = self.packages.values().find(|p| p.state >= STATE_STAGED && !self.mums.contains_key(&p.identity)) {
            bail!("no readable manifest for {}; refusing to plan a removal", p.identity);
        }
        let removed: HashSet<(String, String)> = plan.packages.iter().map(|i| self.packages[i].id.family()).collect();
        let selected =
            |name: &str| plan.features.iter().chain(&plan.disabled_features).any(|f| f.eq_ignore_ascii_case(name));
        // Rollups (`Package_for_RollupFix`, `Package_for_KB…`) list every optional package as a
        // conditional child; DISM removes those children anyway.
        let rollup = |p: &PackageInfo| p.id.name.to_ascii_lowercase().starts_with("package_for_");
        for p in self.packages.values().filter(|p| p.state >= STATE_STAGED && !plan.packages.contains(&p.identity) && !rollup(p)) {
            for u in &self.mums[&p.identity].updates {
                // the removed features themselves (also in language satellites, where they are not
                // selectable) and their content updates may lose their packages
                if selected(&u.name) || (!u.detect_parents.is_empty() && u.detect_parents.iter().all(|d| selected(d))) {
                    continue;
                }
                if let Some(r) = u.packages.iter().find(|r| removed.contains(&r.family())) {
                    bail!("removal would take {} from the retained package {} (update {})", r.name, p.identity, u.name);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub packages: usize,
    pub deployments: usize,
    pub components: usize,
    pub unprojected: usize,
    pub files: usize,
    pub dirs: usize,
    pub registry_keys: usize,
    pub staged: usize,
    pub catalogs: usize,
    /// Driver packages dropped from the driver database because their DriverStore copy went with the payload.
    pub driver_packages: usize,
}

/// Registry data a component manifest projects.
#[derive(Debug, Default)]
struct Projection {
    /// (hive, key path inside the hive, value names)
    keys: Vec<(HiveSel, String, Vec<String>)>,
    services: Vec<String>,
    /// Destination directories of the projected files (image-relative, `/` separated).
    dirs: Vec<String>,
    /// `<firewallRule InternalName=…>`: value names below the FirewallRules keys.
    firewall_rules: Vec<String>,
    /// `<instrumentation>` event providers: (provider GUID, channels the provider declares).
    event_providers: Vec<(String, Vec<String>)>,
    /// `<taskScheduler>` task URIs (`\Microsoft\Windows\Work Folders\…`).
    tasks: Vec<String>,
}

/// Maps a manifest destination like `$(runtime.system32)\Microsoft-Edge-WebView\` to an image path.
fn map_destination(dest: &str, wow64: bool) -> Option<String> {
    let dest = dest.trim_end_matches('\\');
    let (var, rest) = match dest.strip_prefix("$(") {
        Some(r) => r.split_once(')')?,
        None => return None,
    };
    let base = match var.to_ascii_lowercase().as_str() {
        "runtime.windows" => "Windows",
        "runtime.system32" if wow64 => "Windows/SysWOW64",
        "runtime.system32" => "Windows/System32",
        "runtime.drivers" => "Windows/System32/drivers",
        "runtime.wbem" if wow64 => "Windows/SysWOW64/wbem",
        "runtime.wbem" => "Windows/System32/wbem",
        "runtime.fonts" => "Windows/Fonts",
        "runtime.inf" => "Windows/INF",
        "runtime.programfiles" if wow64 => "Program Files (x86)",
        "runtime.programfiles" | "runtime.programfilesx64" => "Program Files",
        "runtime.programfilesx86" => "Program Files (x86)",
        _ => return None,
    };
    let rest = rest.trim_matches('\\').replace('\\', "/");
    Some(if rest.is_empty() { base.to_string() } else { format!("{base}/{rest}") })
}

/// `WinSxS\FileMaps` name prefix of a directory below `Windows` (`$$_system32_microsoft-edge-webview`).
fn filemap_prefix(dir: &str) -> Option<String> {
    let rest = strip_ci(dir, "Windows/")?;
    // separators and blanks become '_', runs collapse (`WidevineCdm\_platform_specific` -> `widevinecdm_platform_specific`)
    let mut out = String::from("$$");
    for c in format!("/{rest}").to_ascii_lowercase().chars() {
        let c = if c == '/' || c == ' ' { '_' } else { c };
        if !(c == '_' && out.ends_with('_')) {
            out.push(c);
        }
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HiveSel {
    Software,
    System,
}

fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// Placeholder for the control set in mapped SYSTEM paths, replaced by the image's current one.
const CURRENT_CONTROL_SET: &str = "{CurrentControlSet}";

/// Maps a manifest key name to a hive and path; wow64 components write to the 32-bit views.
fn map_key(key: &str, wow64: bool) -> Option<(HiveSel, String)> {
    let key = key.trim_end_matches('\\');
    let wow = |rest: &str| if wow64 { format!(r"WOW6432Node\{rest}") } else { rest.to_string() };
    if let Some(r) = strip_ci(key, r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\") {
        return Some((HiveSel::System, format!(r"{CURRENT_CONTROL_SET}\{r}")));
    }
    if let Some(r) = strip_ci(key, r"HKEY_LOCAL_MACHINE\SYSTEM\") {
        return Some((HiveSel::System, r.to_string()));
    }
    if let Some(r) = strip_ci(key, r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\") {
        return Some((HiveSel::Software, format!(r"Classes\{}", wow(r))));
    }
    if let Some(r) = strip_ci(key, r"HKEY_LOCAL_MACHINE\SOFTWARE\") {
        return Some((HiveSel::Software, wow(r)));
    }
    if let Some(r) = strip_ci(key, r"HKEY_CLASSES_ROOT\") {
        return Some((HiveSel::Software, format!(r"Classes\{}", wow(r))));
    }
    None
}

fn valid_registry_guid(guid: &str) -> bool {
    let body = if guid.starts_with('{') || guid.ends_with('}') {
        let Some(body) = guid.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else { return false };
        body
    } else {
        guid
    };
    body.len() == 36
        && body.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn parse_projection(xml: &str) -> Result<Projection> {
    let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}'))?;
    let root = doc.root_element();
    let wow64 = root
        .children()
        .find(|c| c.has_tag_name("assemblyIdentity"))
        .and_then(|a| a.attribute("processorArchitecture"))
        .is_some_and(|a| a.eq_ignore_ascii_case("wow64") || a.eq_ignore_ascii_case("x86"));
    let mut pr = Projection::default();
    for k in root.descendants().filter(|d| d.has_tag_name("registryKey")) {
        let Some(name) = k.attribute("keyName") else { continue };
        let Some((hive, path)) = map_key(name, wow64) else { continue };
        let values = k.children().filter(|v| v.has_tag_name("registryValue")).filter_map(|v| v.attribute("name")).map(str::to_string).collect();
        pr.keys.push((hive, path, values));
    }
    pr.services = root.descendants().filter(|d| d.has_tag_name("serviceData")).filter_map(|d| d.attribute("name")).map(str::to_string).collect();
    let mut dirs: Vec<String> = root
        .children()
        .filter(|d| d.has_tag_name("file"))
        .filter_map(|d| d.attribute("destinationPath"))
        .filter_map(|d| map_destination(d, wow64))
        .collect();
    dirs.sort();
    dirs.dedup();
    pr.dirs = dirs;
    pr.firewall_rules =
        root.descendants().filter(|d| d.has_tag_name("firewallRule")).filter_map(|d| d.attribute("InternalName")).map(str::to_string).collect();
    // data the events and task-scheduler advanced installers register (removed by DISM on uninstall)
    for inst in root.descendants().filter(|d| d.has_tag_name("instrumentation")) {
        for prov in inst.descendants().filter(|d| d.has_tag_name("provider")) {
            let Some(guid) = prov.attribute("guid") else { continue };
            let channels = prov
                .descendants()
                .filter(|d| d.has_tag_name("channel"))
                .filter_map(|c| c.attribute("name"))
                .map(str::to_string)
                .collect();
            pr.event_providers.push((guid.to_string(), channels));
        }
    }
    for ts in root.descendants().filter(|d| d.has_tag_name("taskScheduler")) {
        pr.tasks.extend(
            ts.descendants()
                .filter(|d| d.has_tag_name("URI"))
                .filter_map(|u| u.text())
                .map(|t| t.trim().trim_start_matches('\\').to_string())
                .filter(|t| !t.is_empty() && !t.contains(".."))
                .map(|t| format!("\\{t}")),
        );
    }
    Ok(pr)
}

/// Loads the DCM base manifest from the newest servicing stack's wcp.dll in the image.
fn manifest_base(root: &Path) -> Result<Vec<u8>> {
    let sxs = lean11_wim::resolve_ci(root, WINSXS).ok_or_else(|| anyhow!("image has no WinSxS"))?;
    let mut stacks: Vec<(Vec<u32>, PathBuf)> = fs::read_dir(&sxs)?
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            let rest = n.split_once("_microsoft-windows-servicingstack_")?.1;
            let ver = rest.split('_').nth(1)?;
            let v: Vec<u32> = ver.split('.').map(|x| x.parse().unwrap_or(0)).collect();
            Some((v, e.path()))
        })
        .collect();
    stacks.sort();
    let (_, dir) = stacks.pop().ok_or_else(|| anyhow!("no servicing stack in WinSxS"))?;
    let wcp = lean11_wim::resolve_ci(&dir, "wcp.dll").ok_or_else(|| anyhow!("no wcp.dll in {}", dir.display()))?;
    msdelta::winsxs::extract_base(&fs::read(&wcp)?).map_err(|e| anyhow!("base manifest from {}: {e}", wcp.display()))
}

/// Decoded manifest of a WinSxS component, by full name or unique name prefix (developer tool).
pub fn manifest_text(root: &Path, component: &str) -> Result<String> {
    let dir = lean11_wim::resolve_ci(root, "Windows/WinSxS/Manifests").ok_or_else(|| anyhow!("image has no WinSxS manifests"))?;
    let want = component.to_ascii_lowercase();
    let hits: Vec<PathBuf> = fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().starts_with(&want)))
        .collect();
    match hits.as_slice() {
        [one] => read_manifest(one, &manifest_base(root)?),
        [] => bail!("no manifest starts with {component}"),
        many => bail!("{} manifests start with {component}", many.len()),
    }
}

/// Owners of WinSxS components from the COMPONENTS hive: component folder (lower case) -> owner pairs
/// `<package identity>.<update>` (lower case). A component's `c!<deployment>` values name the deployments that
/// carry it; a deployment's `p!`/`s!`/`i!` values name the package updates that own it.
pub fn component_owners(root: &Path) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    let Ok(p) = hive_path(root, "COMPONENTS") else { return out };
    let Ok(co) = Hive::open(&p, false) else { return out };
    let (Ok(Some(comps)), Ok(Some(deps))) = (co.key(r"DerivedData\Components"), co.key(r"CanonicalData\Deployments")) else { return out };
    let deployments: HashMap<String, Vec<String>> = co
        .children(deps)
        .into_iter()
        .map(|(n, h)| {
            let mut owners: Vec<String> =
                co.values(h).into_iter().filter(|(v, _)| is_owner_value(v)).filter_map(|(_, d)| owner_pair(&d)).collect();
            owners.sort_unstable();
            owners.dedup();
            (n.to_ascii_lowercase(), owners)
        })
        .collect();
    for (name, h) in co.children(comps) {
        let mut owners: Vec<String> = co
            .values(h)
            .into_iter()
            .filter_map(|(v, _)| v.strip_prefix("c!").map(|d| d.to_ascii_lowercase()))
            .filter_map(|d| deployments.get(&d))
            .flatten()
            .cloned()
            .collect();
        owners.sort_unstable();
        owners.dedup();
        if !owners.is_empty() {
            out.insert(name.to_ascii_lowercase(), owners);
        }
    }
    out
}

/// Splits an owner pair `<package identity>.<update>` into package identity and update name.
pub fn split_owner_pair(pair: &str) -> (String, String) {
    // the version is the last `~` field's first four dot-separated parts; the rest is the update
    if let Some((head, tail)) = pair.rsplit_once('~') {
        let parts: Vec<&str> = tail.splitn(5, '.').collect();
        if parts.len() == 5 {
            return (format!("{head}~{}", parts[..4].join(".")), parts[4].to_string());
        }
        return (pair.to_string(), String::new());
    }
    (pair.to_string(), String::new())
}

/// Full component names of WinSxS folders from the COMPONENTS hive (`DerivedData\Components\<folder>`
/// value `identity` = "Name, Culture=…, Version=…"); used for folder names shortened with "..".
/// Returns folder -> (name, culture; culture empty for neutral).
pub fn component_names(root: &Path, folders: &[&str]) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    let Ok(p) = hive_path(root, "COMPONENTS") else { return out };
    let Ok(co) = Hive::open(&p, false) else { return out };
    let Ok(Some(comps)) = co.key(r"DerivedData\Components") else { return out };
    // one pass over the key list instead of a linear child lookup per folder (19k+ keys)
    let keys: HashMap<String, NodeH> = co.children(comps).into_iter().map(|(n, h)| (n.to_ascii_lowercase(), h)).collect();
    let mut missing = Vec::new();
    for f in folders {
        let id = keys
            .get(&f.to_ascii_lowercase())
            .and_then(|h| co.value(*h, "identity").ok().flatten())
            .map(|d| String::from_utf8_lossy(&d.data).trim_end_matches('\0').to_string());
        match id.as_deref().and_then(|i| i.split(',').next()).map(str::trim).filter(|n| !n.is_empty()) {
            Some(name) => {
                let culture = id
                    .as_deref()
                    .and_then(|i| i.split(',').map(str::trim).find_map(|p| p.strip_prefix("Culture=")))
                    .map(|c| c.trim_matches('"'))
                    .filter(|c| !c.eq_ignore_ascii_case("neutral"))
                    .unwrap_or("");
                out.insert(f.to_string(), (name.to_string(), culture.to_string()));
            }
            None => missing.push(*f),
        }
    }
    // components without a hive entry (superseded versions): the manifest's assemblyIdentity
    if let (false, Some(dir), Ok(base)) = (missing.is_empty(), lean11_wim::resolve_ci(root, "Windows/WinSxS/Manifests"), manifest_base(root)) {
        for f in missing {
            let Ok(xml) = read_manifest(&dir.join(format!("{f}.manifest")), &base) else { continue };
            let Some(i) = xml.find("<assemblyIdentity") else { continue };
            let tag = &xml[i..i + xml[i..].find('>').unwrap_or(xml.len() - i)];
            let attr = |a: &str| -> Option<String> {
                let n = tag.find(&format!(" {a}=\""))? + a.len() + 3;
                Some(tag[n..n + tag[n..].find('"')?].to_string())
            };
            if let Some(n) = attr("name") {
                let lang = attr("language").filter(|l| !l.eq_ignore_ascii_case("neutral") && l != "*").unwrap_or_default();
                out.insert(f.to_string(), (n, lang));
            }
        }
    }
    out
}

fn read_manifest(path: &Path, base: &[u8]) -> Result<String> {
    let raw = fs::read(path)?;
    let xml = if msdelta::dcm::is_dcm(&raw) {
        msdelta::winsxs::decompress(base, &raw).map_err(|e| anyhow!("{}: {e}", path.display()))?
    } else {
        raw
    };
    Ok(String::from_utf8_lossy(&xml).into_owned())
}

/// wcp's key-form string hash (`RtlHashEncodedLBlob`): UTF-16 code units, ASCII lower-cased, four
/// interleaved accumulators (docs/re/cbs.md).
fn lblob_hash(s: &str) -> u64 {
    let mut h = [0u32; 4];
    for (i, c) in s.encode_utf16().enumerate() {
        let c = if (0x41..=0x5a).contains(&c) { c + 0x20 } else { c };
        h[i % 4] = h[i % 4].wrapping_mul(0x1003F).wrapping_add(u32::from(c));
    }
    (h[0] as u64)
        .wrapping_mul(0x1E5_FFFF_FD27)
        .wrapping_add((h[1] as u64).wrapping_mul((-0x23_FFFF_FFAF_i64) as u64))
        .wrapping_add((h[2] as u64).wrapping_mul(0x1_FFFF_FFF7))
        .wrapping_add(h[3] as u64)
}

/// Key-form hash of a component identity (`Name, Culture=…, Version=…, PublicKeyToken=…, …`): the
/// attributes in identity order, a neutral culture is not hashed. Without the version it is the hash of
/// the version-independent family (`VersionedIndex\…\ComponentFamilies`, `SideBySide\Winners`).
/// Verified against all 30750 component keys of a 26300 image.
pub fn identity_hash(identity: &str, with_version: bool) -> Option<u64> {
    const K: u64 = 0x1_FFFF_FFF7;
    let mut parts = identity.split(',').map(str::trim);
    let name = parts.next().filter(|n| !n.is_empty())?;
    let mut acc = lblob_hash("name").wrapping_mul(K).wrapping_add(lblob_hash(name));
    for p in parts {
        let (k, v) = p.split_once('=')?;
        let (k, v) = (k.trim(), v.trim());
        if (k.eq_ignore_ascii_case("Culture") && v.eq_ignore_ascii_case("neutral")) || (!with_version && k.eq_ignore_ascii_case("Version")) {
            continue;
        }
        acc = acc.wrapping_mul(K).wrapping_add(lblob_hash(k).wrapping_mul(K).wrapping_add(lblob_hash(v)));
    }
    Some(acc)
}

/// Exact family key name of a component (`arch_name_token_lang_<family hash>`) from its identity value.
fn family_key(component: &str, identity: &str) -> Option<String> {
    let (prefix, _) = family_prefix(component)?;
    Some(format!("{prefix}{:016x}", identity_hash(identity, false)?))
}

/// The `identity` value of a component key (UTF-8 text in a binary value).
fn component_identity(co: &Hive, comps_key: NodeH, component: &str) -> Result<Option<String>> {
    let Some(node) = co.child(comps_key, component)? else { return Ok(None) };
    Ok(co.value(node, "identity")?.map(|d| String::from_utf8_lossy(&d.data).trim_end_matches('\0').to_string()))
}

/// Splits `arch_name_token_version_lang_hash` into (family prefix `arch_name_token_lang_`, version).
fn family_prefix(component: &str) -> Option<(String, String)> {
    let p: Vec<&str> = component.split('_').collect();
    if p.len() < 6 {
        return None;
    }
    let n = p.len();
    let (hash, lang, version, token) = (p[n - 1], p[n - 2], p[n - 3], p[n - 4]);
    let _ = hash;
    let head = p[..n - 4].join("_");
    Some((format!("{head}_{token}_{lang}_").to_ascii_lowercase(), version.to_string()))
}

fn remove_path(p: &Path) -> Result<bool> {
    match p.symlink_metadata() {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p).with_context(|| format!("removing {}", p.display()))?,
        Ok(_) => fs::remove_file(p).with_context(|| format!("removing {}", p.display()))?,
        Err(_) => return Ok(false),
    }
    Ok(true)
}

/// Deletes the listed values of a key, then the key itself if nothing is left in it.
fn unproject_key(h: &mut Hive, path: &str, values: &[String]) -> Result<bool> {
    let Some(node) = h.key(path)? else { return Ok(false) };
    if !values.is_empty() {
        h.retain_values(node, |k, _| !values.iter().any(|v| v.eq_ignore_ascii_case(k)))?;
    }
    if h.is_empty_key(node)? {
        h.delete_node(node)?;
        return Ok(true);
    }
    Ok(false)
}

/// Walks the image outside WinSxS and returns every path whose (device, inode) is in `inodes`.
fn find_links(root: &Path, inodes: &HashSet<(u64, u64)>) -> Vec<((u64, u64), PathBuf)> {
    let skip = lean11_wim::resolve_ci(root, WINSXS);
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = p.symlink_metadata() else { continue };
            if m.is_dir() {
                if Some(&p) != skip.as_ref() {
                    stack.push(p);
                }
            } else if let Ok(s) = lean11_wim::platform::stat_of(&p, &m)
                && s.nlink > 1
                && inodes.contains(&(s.dev, s.ino))
            {
                out.push(((s.dev, s.ino), p));
            }
        }
    }
    out
}

/// Removes the packages of `plan` from the mounted image like DISM's offline removal with /Remove.
///
/// Order: hive edits happen in memory, every manifest needed for unprojection is read before the first
/// file is deleted, and the hives are written at the end. A failure before that point leaves the image
/// untouched; a failure later leaves it inconsistent, so callers must discard the mount on error.
pub fn remove(store: &Store, plan: &Plan, log: Log) -> Result<Report> {
    let root = &store.root;
    let mut rep = Report::default();
    if plan.packages.is_empty() && plan.pairs.is_empty() && plan.stage.is_empty() && plan.stage_pairs.is_empty() {
        return Ok(rep);
    }
    let staged_lc: HashSet<String> = plan.stage.iter().map(|p| p.to_ascii_lowercase()).collect();
    let removed_lc: HashSet<String> = plan.packages.iter().map(|p| p.to_ascii_lowercase()).collect();
    let owned_by_removed = |pair: &str| -> bool {
        plan.pairs.contains(pair) || pair.rsplit_once('.').is_some_and(|(pkg, _)| removed_lc.contains(pkg))
    };

    // 1. deployments: drop the owner values of the removed packages
    let mut co = Hive::open(&hive_path(root, "COMPONENTS")?, true)?;
    let deps_key = co.key(r"CanonicalData\Deployments")?.ok_or_else(|| anyhow!("COMPONENTS has no deployments"))?;
    let mut installed_before = HashSet::new();
    let mut installed_after = HashSet::new();
    let mut removed_deps: HashSet<String> = HashSet::new();
    let mut dep_catalogs: Vec<(String, String)> = Vec::new();
    for (dname, node) in co.children(deps_key) {
        let vals = co.values_strict(node)?;
        let owners: Vec<(String, String)> =
            vals.iter().filter(|(k, _)| is_owner_value(k)).filter_map(|(k, d)| owner_pair(d).map(|p| (k.to_ascii_lowercase(), p))).collect();
        let dl = dname.to_ascii_lowercase();
        if owners.iter().any(|(k, _)| k.starts_with("i!")) {
            installed_before.insert(dl.clone());
        }
        // removed packages lose every owner value, staged ones only the installed (i!) value
        let staged_pair =
            |pair: &str| plan.stage_pairs.contains(pair) || pair.rsplit_once('.').is_some_and(|(pkg, _)| staged_lc.contains(pkg));
        let doomed: HashSet<String> = owners
            .iter()
            .filter(|(k, p)| owned_by_removed(p) || (k.starts_with("i!") && staged_pair(p)))
            .map(|(k, _)| k.clone())
            .collect();
        if doomed.is_empty() {
            if installed_before.contains(&dl) {
                installed_after.insert(dl);
            }
            continue;
        }
        if owners.iter().all(|(k, _)| doomed.contains(k)) {
            if let Some(t) = vals.iter().find(|(k, _)| k.eq_ignore_ascii_case("CatalogThumbprint")) {
                dep_catalogs.push((lean11_hive::from_utf16(&t.1.data), dname.clone()));
            }
            co.delete_node(node)?;
            removed_deps.insert(dl);
            rep.deployments += 1;
        } else {
            co.retain_values(node, |k, _| !doomed.contains(&k.to_ascii_lowercase()))?;
            if owners.iter().any(|(k, _)| k.starts_with("i!") && !doomed.contains(k)) {
                installed_after.insert(dl);
            }
        }
    }
    log(&format!("deployments: {} removed", rep.deployments));

    // 2. components: which lose their projection, which become orphans, which families stay alive
    let comps_key = co.key(r"DerivedData\Components")?.ok_or_else(|| anyhow!("COMPONENTS has no components"))?;
    let mut orphans: Vec<String> = Vec::new();
    let mut unproject: Vec<String> = Vec::new();
    // family prefixes of components that stay projected; their members may share projections with a
    // removed version, so such components are not unprojected (conservative: prefixes are abbreviated)
    let mut alive_families: HashSet<String> = HashSet::new();
    // exact families (key-form hash of the identity) of components that stay projected
    let mut alive_exact: HashSet<String> = HashSet::new();
    let mut exact_of: HashMap<String, String> = HashMap::new();
    let mut prune_refs: Vec<String> = Vec::new();
    for (cname, node) in co.children(comps_key) {
        let refs: Vec<String> =
            co.values_strict(node)?.into_iter().filter_map(|(k, _)| strip_ci(&k, "c!").map(str::to_ascii_lowercase)).collect();
        let has = refs.iter().any(|r| installed_after.contains(r));
        let exact = co
            .value(node, "identity")?
            .and_then(|d| family_key(&cname, String::from_utf8_lossy(&d.data).trim_end_matches('\0')));
        if has {
            match &exact {
                Some(f) => {
                    alive_exact.insert(f.clone());
                }
                None => {
                    if let Some((f, _)) = family_prefix(&cname) {
                        alive_families.insert(f);
                    }
                }
            }
        }
        if let Some(f) = exact {
            exact_of.insert(cname.clone(), f);
        }
        if refs.is_empty() || !refs.iter().any(|r| removed_deps.contains(r) || installed_before.contains(r) && !installed_after.contains(r)) {
            continue;
        }
        if refs.iter().any(|r| installed_before.contains(r)) && !has {
            unproject.push(cname.clone());
        }
        if refs.iter().all(|r| removed_deps.contains(r)) {
            orphans.push(cname);
        } else if refs.iter().any(|r| removed_deps.contains(r)) {
            prune_refs.push(cname);
        }
    }
    for cname in &prune_refs {
        let node = co.child(comps_key, cname)?.ok_or_else(|| anyhow!("component {cname} vanished"))?;
        co.retain_values(node, |k, _| !strip_ci(k, "c!").is_some_and(|d| removed_deps.contains(&d.to_ascii_lowercase())))?;
    }
    // a component shares projections with a retained one of its exact family; components without an
    // identity fall back to the abbreviated prefix (conservative)
    let (shared, unproject): (Vec<String>, Vec<String>) = unproject.into_iter().partition(|c| match exact_of.get(c) {
        Some(f) => alive_exact.contains(f) || family_prefix(c).is_some_and(|(p, _)| alive_families.contains(&p)),
        None => family_prefix(c).is_some_and(|(p, _)| alive_families.contains(&p) || alive_exact.iter().any(|e| e.starts_with(&p))),
    });
    for c in &shared {
        log(&format!("note: {c} shares its family with a projected component; projections kept"));
    }

    // 3. read every manifest needed for unprojection before anything is deleted
    let sxs = lean11_wim::resolve_ci(root, WINSXS).ok_or_else(|| anyhow!("image has no WinSxS"))?;
    let manifests = lean11_wim::resolve_ci(&sxs, "Manifests").ok_or_else(|| anyhow!("image has no WinSxS\\Manifests"))?;
    let base = if unproject.is_empty() { Vec::new() } else { manifest_base(root)? };
    let mut projections = Vec::with_capacity(unproject.len());
    for c in &unproject {
        let mf = lean11_wim::resolve_ci(&manifests, &format!("{c}.manifest")).ok_or_else(|| anyhow!("no manifest for {c}"))?;
        let pr = read_manifest(&mf, &base).and_then(|x| parse_projection(&x)).with_context(|| format!("manifest of {c}"))?;
        projections.push(pr);
    }

    // payload hard links: (dev, inode) -> (link count, links known to belong to removed components)
    let mut links: HashMap<(u64, u64), (u64, u64)> = HashMap::new();
    let count_dir = |name: &str, unproj: bool, links: &mut HashMap<(u64, u64), (u64, u64)>| {
        let Some(dir) = lean11_wim::resolve_ci(&sxs, name) else { return };
        // payload directories mirror subfolders of the destination (Locales\, WidevineCdm\…)
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let Ok(m) = e.path().symlink_metadata() else { continue };
                if m.is_dir() {
                    stack.push(e.path());
                } else if m.is_file()
                    && let Ok(s) = lean11_wim::platform::stat_of(&e.path(), &m)
                    && s.nlink > 1
                {
                    let key = (s.dev, s.ino);
                    if unproj || links.contains_key(&key) {
                        links.entry(key).or_insert((s.nlink, 0)).1 += 1;
                    }
                }
            }
        }
    };
    for c in &unproject {
        count_dir(c, true, &mut links);
    }
    for c in orphans.iter().filter(|c| !unproject.contains(c)) {
        count_dir(c, false, &mut links);
    }

    // 4. unprojection: registry data and projected files
    let mut sw = Hive::open(&hive_path(root, "SOFTWARE")?, true)?;
    let mut sys = Hive::open(&hive_path(root, "SYSTEM")?, true)?;
    let control_set = current_control_set(&sys)?;
    let mut dirs: Vec<String> = Vec::new();
    for pr in &projections {
        dirs.extend(pr.dirs.iter().cloned());
    }
    // components that are no longer installed lose their SideBySide winner entries (orphans are handled
    // with their version families below)
    {
        let names: Vec<String> = sw.key(WINNERS_KEY)?.map(|w| sw.children(w).into_iter().map(|(n, _)| n).collect()).unwrap_or_default();
        // shared components keep their projections, but their own version is no longer installed either
        for c in unproject.iter().chain(shared.iter()).filter(|c| !orphans.contains(c)) {
            let exact = component_identity(&co, comps_key, c)?.and_then(|id| family_key(c, &id));
            let target = match (exact, family_prefix(c)) {
                (Some(f), Some((_, version))) => names.iter().find(|n| n.eq_ignore_ascii_case(&f)).map(|n| (n.clone(), version)),
                _ => winner_family(&sw, &names, c)?,
            };
            if let Some((family, version)) = target {
                drop_winner(&mut sw, &family, &version, false)?;
            }
        }
    }
    for pr in projections {
        // deepest keys first so parents can become empty
        let mut keys = pr.keys;
        keys.sort_by_key(|(_, p, _)| std::cmp::Reverse(p.matches('\\').count()));
        for (hive, path, values) in keys {
            let (h, path) = match hive {
                HiveSel::Software => (&mut sw, path),
                HiveSel::System => (&mut sys, path.replace(CURRENT_CONTROL_SET, &control_set)),
            };
            if unproject_key(h, &path, &values)? {
                rep.registry_keys += 1;
            }
        }
        for s in pr.services {
            if sys.delete_key(&format!(r"{control_set}\Services\{s}"))? {
                rep.registry_keys += 1;
            }
        }
        if !pr.firewall_rules.is_empty() {
            for k in ["Parameters", "Defaults"] {
                let path = format!(r"{control_set}\Services\SharedAccess\{k}\FirewallPolicy\FirewallRules");
                if let Some(node) = sys.key(&path)? {
                    sys.retain_values(node, |n, _| !pr.firewall_rules.iter().any(|r| r.eq_ignore_ascii_case(n)))?;
                }
            }
        }
        // events advanced installer: publisher, its own channels and EventLog autologger entries
        for (guid, channels) in &pr.event_providers {
            if !valid_registry_guid(guid) {
                continue;
            }
            let guid = if guid.starts_with('{') { guid.clone() } else { format!("{{{guid}}}") };
            if sw.delete_key(&format!(r"{WINEVT_KEY}\Publishers\{guid}"))? {
                rep.registry_keys += 1;
            }
            for c in channels {
                if c.is_empty() || c.contains('\\') || c.contains('\0') {
                    continue;
                }
                if sw.delete_key(&format!(r"{WINEVT_KEY}\Channels\{c}"))? {
                    rep.registry_keys += 1;
                }
            }
            let loggers = format!(r"{control_set}\Control\WMI\Autologger");
            if let Some(node) = sys.key(&loggers)? {
                for (l, _) in sys.children(node) {
                    if l.to_ascii_lowercase().starts_with("eventlog-") && sys.delete_key(&format!(r"{loggers}\{l}\{guid}"))? {
                        rep.registry_keys += 1;
                    }
                }
            }
        }
        // task-scheduler advanced installer: the task's TaskCache entries
        for uri in &pr.tasks {
            if uri.contains('\0') || uri.trim_start_matches('\\').split('\\').any(str::is_empty) {
                continue;
            }
            let tree = format!(r"{TASKCACHE_KEY}\Tree{uri}");
            let Some(node) = sw.key(&tree)? else { continue };
            if !sw.children(node).is_empty() { continue; }
            let id = sw.get(&tree, "Id")?.and_then(|d| d.as_string());
            let Some(id) = id.filter(|i| i.starts_with('{') && i.ends_with('}') && valid_registry_guid(i)) else { continue };
            if sw.delete_key(&tree)? {
                rep.registry_keys += 1;
            }
            for sub in ["Tasks", "Boot", "Logon", "Maintenance", "Plain"] {
                if sw.delete_key(&format!(r"{TASKCACHE_KEY}\{sub}\{id}"))? {
                    rep.registry_keys += 1;
                }
            }
        }
        rep.unprojected += 1;
    }
    if !links.is_empty() {
        let outside = find_links(root, &links.keys().copied().collect());
        let mut found: HashMap<(u64, u64), Vec<PathBuf>> = HashMap::new();
        for (k, p) in outside {
            found.entry(k).or_default().push(p);
        }
        for (k, paths) in found {
            let (nlink, known) = links[&k];
            if nlink > known + paths.len() as u64 {
                // another (retained) component's payload links the same file
                continue;
            }
            for p in paths {
                if remove_path(&p)? {
                    rep.files += 1;
                }
            }
        }
    }
    // destination directories that are empty now, deepest first, with their FileMaps entries; also
    // intermediate directories (EBWebView\ above EBWebView\x64\) as long as they lie inside a destination
    let dests: Vec<String> = dirs.iter().map(|d| d.to_ascii_lowercase()).collect();
    let inside = |a: &str| {
        let a = a.to_ascii_lowercase();
        dests.iter().any(|e| a == *e || a.starts_with(&format!("{e}/")))
    };
    let mut extra = Vec::new();
    for d in &dirs {
        let mut cur = d.as_str();
        while let Some((parent, _)) = cur.rsplit_once('/') {
            if !inside(parent) {
                break;
            }
            extra.push(parent.to_string());
            cur = parent;
        }
    }
    dirs.extend(extra);
    dirs.sort_by_key(|d| (std::cmp::Reverse(d.matches('/').count()), d.to_ascii_lowercase()));
    dirs.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    let filemaps = lean11_wim::resolve_ci(&sxs, "FileMaps");
    let filemap_names: Vec<String> = filemaps
        .as_ref()
        .and_then(|d| fs::read_dir(d).ok())
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    for d in &dirs {
        let Some(p) = lean11_wim::resolve_ci(root, d) else { continue };
        if !p.is_dir() || fs::read_dir(&p)?.next().is_some() {
            continue;
        }
        fs::remove_dir(&p).with_context(|| format!("removing {}", p.display()))?;
        rep.dirs += 1;
        if let (Some(fm), Some(prefix)) = (&filemaps, filemap_prefix(d)) {
            for n in &filemap_names {
                let ln = n.to_ascii_lowercase();
                if let Some(rest) = ln.strip_prefix(&prefix).and_then(|r| r.strip_prefix('_')).and_then(|r| r.strip_suffix(".cdf-ms"))
                    && rest.len() == 16
                    && rest.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    remove_path(&fm.join(n))?;
                }
            }
        }
    }
    log(&format!(
        "unprojected {} components ({} files, {} directories, {} registry keys)",
        rep.unprojected, rep.files, rep.dirs, rep.registry_keys
    ));

    // 5. orphaned components: payload, manifest, store keys and version families
    let families_path: Option<String> = match co.key(r"DerivedData\VersionedIndex")? {
        Some(vi) => co.children(vi).first().map(|(n, _)| format!(r"DerivedData\VersionedIndex\{n}\ComponentFamilies")),
        None => None,
    };
    let family_names: Vec<String> = match &families_path {
        Some(p) => co.key(p)?.map(|f| co.children(f).into_iter().map(|(n, _)| n).collect()).unwrap_or_default(),
        None => Vec::new(),
    };
    for cname in &orphans {
        // exact family from the identity (read before the component key goes)
        let exact_family = component_identity(&co, comps_key, cname)?.and_then(|id| family_key(cname, &id));
        if let Some(dir) = lean11_wim::resolve_ci(&sxs, cname) {
            remove_path(&dir)?;
        }
        if let Some(mf) = lean11_wim::resolve_ci(&manifests, &format!("{cname}.manifest")) {
            remove_path(&mf)?;
        }
        if let Some(node) = co.child(comps_key, cname)? {
            co.delete_node(node)?;
        }
        rep.components += 1;
        let (Some((prefix, version)), Some(fpath)) = (family_prefix(cname), &families_path) else { continue };
        let mut candidates: Vec<&String> = Vec::new();
        if let Some(f) = &exact_family {
            // key-form hash of the identity without its version names the family exactly
            candidates.extend(family_names.iter().filter(|n| n.eq_ignore_ascii_case(f)));
        } else {
            // no identity: only when the abbreviated prefix and the version identify exactly one
            for n in &family_names {
                if n.to_ascii_lowercase().strip_prefix(&prefix).is_some_and(|rest| !rest.contains('_'))
                    && co.key(&format!(r"{fpath}\{n}\v!{version}"))?.is_some()
                {
                    candidates.push(n);
                }
            }
        }
        if candidates.len() > 1 {
            log(&format!("note: version family of {cname} is ambiguous, left in place"));
            continue;
        }
        for fname in candidates {
            if co.key(&format!(r"{fpath}\{fname}\v!{version}"))?.is_none() {
                continue;
            }
            co.delete_key(&format!(r"{fpath}\{fname}\v!{version}"))?;
            // a family without version subkeys goes (its only value is SomeUnparsedVersionsExist)
            if let Some(f) = co.key(&format!(r"{fpath}\{fname}"))?
                && co.children(f).is_empty()
            {
                co.delete_node(f)?;
            }
            // the pre-pass skipped orphans, so their winners go here
            drop_winner(&mut sw, fname, &version, true)?;
        }
    }
    log(&format!("components: {} removed from WinSxS", rep.components));

    // 6. catalogs no deployment references any more
    if co.key(r"CanonicalData\Catalogs")?.is_some() {
        let cat_dir = lean11_wim::resolve_ci(&sxs, "Catalogs");
        for (thumb, dep) in &dep_catalogs {
            let path = format!(r"CanonicalData\Catalogs\{thumb}");
            let Some(node) = co.key(&path)? else { continue };
            co.retain_values(node, |k, _| !strip_ci(k, "c!").is_some_and(|d| d.eq_ignore_ascii_case(dep)))?;
            if !co.values_strict(node)?.iter().any(|(k, _)| strip_ci(k, "c!").is_some()) {
                co.delete_node(node)?;
                if let Some(f) = cat_dir.as_ref().and_then(|d| lean11_wim::resolve_ci(d, &format!("{thumb}.cat"))) {
                    remove_path(&f)?;
                }
                rep.catalogs += 1;
            }
        }
    }

    // 7. CBS package records, indexes and manifests
    let cbs = sw.key(CBS_KEY)?.ok_or_else(|| anyhow!("SOFTWARE has no CBS key"))?;
    if let Some(pk) = sw.child(cbs, "Packages")? {
        for (name, node) in sw.children(pk) {
            if removed_lc.contains(&name.to_ascii_lowercase()) {
                sw.delete_node(node)?;
                rep.packages += 1;
                continue;
            }
            let lname = name.to_ascii_lowercase();
            let staged = staged_lc.contains(&lname);
            let Some(owners) = sw.child(node, "Owners")? else { continue };
            let mut lost_wrapper = false;
            sw.retain_values(owners, |k, _| {
                let gone = removed_lc.contains(&k.to_ascii_lowercase());
                lost_wrapper |= gone;
                !gone
            })?;
            if staged {
                // owner value = kind << 16 | requested state; owners that are staged now request 0x40
                for (k, d) in sw.values_strict(owners)? {
                    if let Some(v) = d.as_dword()
                        && v & 0xff == STATE_INSTALLED
                        && staged_lc.contains(&k.to_ascii_lowercase())
                    {
                        sw.set(&format!(r"{CBS_KEY}\Packages\{name}\Owners"), &k, &RegData::dword(v & !0xff | STATE_STAGED))?;
                    }
                }
                // a package that lost its wrapper owns itself (standalone)
                if lost_wrapper && sw.value(owners, &name)?.is_none() {
                    sw.set(&format!(r"{CBS_KEY}\Packages\{name}\Owners"), &name, &RegData::dword(0x0002_0000 | STATE_STAGED))?;
                }
                if sw.value(node, "CurrentState")?.and_then(|d| d.as_dword()) == Some(STATE_INSTALLED) {
                    sw.set(&format!(r"{CBS_KEY}\Packages\{name}"), "CurrentState", &RegData::dword(STATE_STAGED))?;
                    rep.staged += 1;
                }
            }
        }
    }
    for index in ["PackageIndex", "PackageDetect", "CapabilityIndex", "UpdateDetect", "ComponentDetect"] {
        let Some(ix) = sw.child(cbs, index)? else { continue };
        for (_, node) in sw.children(ix) {
            if sw.retain_values(node, |k, _| !removed_lc.contains(&k.to_ascii_lowercase()))? > 0 && sw.is_empty_key(node)? {
                sw.delete_node(node)?;
            }
        }
    }
    for c in &plan.capabilities {
        sw.set(&format!(r"{CBS_KEY}\Features on Demand\Removed FOD Markers"), c, &RegData::dword(1))?;
    }
    let now = chrono_like_now();
    for f in &plan.disabled_features {
        let key = format!(r"{CBS_KEY}\Notifications\OptionalFeatures\{f}");
        sw.set(&format!(r"{CBS_KEY}\Notifications\OptionalFeatures"), "LastModified", &RegData::sz(&now))?;
        sw.set(&key, "LastModified", &RegData::sz(&now))?;
        sw.set(&key, "Selection", &RegData::dword(0))?;
    }
    for f in &plan.features {
        let key = format!(r"{CBS_KEY}\Notifications\OptionalFeatures\{f}");
        sw.set(&format!(r"{CBS_KEY}\Notifications\OptionalFeatures"), "LastModified", &RegData::sz(&now))?;
        sw.set(&key, "LastModified", &RegData::sz(&now))?;
        sw.set(&key, "Removed", &RegData::dword(1))?;
        sw.set(&key, "Selection", &RegData::dword(0))?;
    }
    let pkg_dir = lean11_wim::resolve_ci(root, PACKAGES_DIR);
    let catroot = lean11_wim::resolve_ci(root, CATROOT);
    for p in &plan.packages {
        for (dir, ext) in [(&pkg_dir, "mum"), (&pkg_dir, "cat"), (&catroot, "cat")] {
            if let Some(f) = dir.as_ref().and_then(|d| lean11_wim::resolve_ci(d, &format!("{p}.{ext}"))) {
                remove_path(&f)?;
            }
        }
    }
    co.commit()?;
    sw.commit()?;
    sys.commit()?;
    rep.driver_packages = prune_driver_database(root)?;
    log(&format!("packages: {} removed, {} catalogs, {} driver packages", rep.packages, rep.catalogs, rep.driver_packages));
    Ok(rep)
}

const FILE_REPOSITORY: &str = "Windows/System32/DriverStore/FileRepository";

fn multi_sz(items: &[String]) -> RegData {
    let mut data: Vec<u8> = items.iter().flat_map(|s| lean11_hive::utf16z(s)).collect();
    data.extend([0, 0]);
    RegData { kind: lean11_hive::REG_MULTI_SZ, data }
}

/// Drops driver packages whose DriverStore copy (`FileRepository\<package>\<inf>`) went with the removed payload
/// from the driver database (`DRIVERS` hive), as `pnputil /delete-driver` does: the package record, its entry
/// in `DriverInfFiles`, and, once no package of that INF is left, the INF's device ID ranks and driver file
/// references. Left in place, Plug and Play keeps selecting the missing package for matching devices
/// ("Cannot find driver package") instead of another driver.
fn prune_driver_database(root: &Path) -> Result<usize> {
    let (Some(path), Some(repo)) = (lean11_wim::resolve_ci(root, "Windows/System32/config/DRIVERS"), lean11_wim::resolve_ci(root, FILE_REPOSITORY))
    else {
        return Ok(0);
    };
    let mut h = Hive::open(&path, true)?;
    let Some(pk) = h.key(r"DriverDatabase\DriverPackages")? else { return Ok(0) };
    // INF name (lower case) -> its packages that lost their files
    let mut stale: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, node) in h.children(pk) {
        let Some(p) = name.to_ascii_lowercase().find(".inf_") else { continue };
        let file_inf = &name[..p + 4];
        let inf = match h.value(node, "")?.and_then(|d| d.as_string()) {
            Some(i) if !i.is_empty() => i,
            _ => file_inf.to_string(),
        };
        if lean11_wim::resolve_ci(&repo, &format!("{name}/{file_inf}")).is_none() {
            stale.entry(inf.to_ascii_lowercase()).or_default().insert(name.to_ascii_lowercase());
        }
    }
    if stale.is_empty() {
        return Ok(0);
    }
    let mut dropped = 0;
    for (name, node) in h.children(pk) {
        if stale.values().any(|s| s.contains(&name.to_ascii_lowercase())) {
            h.delete_node(node)?;
            dropped += 1;
        }
    }
    // INFs without any package left
    let mut dead: BTreeSet<String> = BTreeSet::new();
    let infs = h.key(r"DriverDatabase\DriverInfFiles")?;
    for (inf, pkgs) in &stale {
        let node = match infs {
            Some(n) => h.child(n, inf)?,
            None => None,
        };
        let Some(node) = node else {
            dead.insert(inf.clone());
            continue;
        };
        let key = format!(r"DriverDatabase\DriverInfFiles\{}", h.name(node));
        let rest: Vec<String> = h
            .value(node, "")?
            .and_then(|d| d.as_multi())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| !pkgs.contains(&p.to_ascii_lowercase()))
            .collect();
        if rest.is_empty() {
            h.delete_node(node)?;
            dead.insert(inf.clone());
            continue;
        }
        h.set(&key, "", &multi_sz(&rest))?;
        let active = h.value(node, "Active")?.and_then(|d| d.as_string()).unwrap_or_default();
        if pkgs.contains(&active.to_ascii_lowercase()) {
            h.set(&key, "Active", &RegData::sz(&rest[rest.len() - 1]))?;
        }
    }
    if !dead.is_empty() {
        if let Some(ids) = h.key(r"DriverDatabase\DeviceIds")? {
            let _ = prune_device_ids(&mut h, ids, &dead, true)?;
        }
        if let Some(files) = h.key(r"DriverDatabase\DriverFiles")? {
            for (name, node) in h.children(files) {
                let Some(d) = h.value(node, "")? else { continue };
                let refs = d.as_multi().or_else(|| d.as_string().map(|s| vec![s])).unwrap_or_default();
                let rest: Vec<String> = refs.iter().filter(|i| !dead.contains(&i.to_ascii_lowercase())).cloned().collect();
                if rest.len() == refs.len() {
                    continue;
                }
                if rest.is_empty() {
                    h.delete_node(node)?;
                } else {
                    let data = if d.as_multi().is_some() { multi_sz(&rest) } else { RegData::sz(&rest[0]) };
                    h.set(&format!(r"DriverDatabase\DriverFiles\{name}"), "", &data)?;
                }
            }
        }
    }
    h.commit()?;
    Ok(dropped)
}

/// Removes the rank values named after a dead INF below `DeviceIds` and the keys this leaves empty (keys that
/// were empty before stay). Returns true if the key was deleted.
fn prune_device_ids(h: &mut Hive, node: NodeH, dead: &BTreeSet<String>, top: bool) -> Result<bool> {
    let mut changed = false;
    for (_, c) in h.children(node) {
        changed |= prune_device_ids(h, c, dead, false)?;
    }
    changed |= h.retain_values(node, |k, _| !dead.contains(&k.to_ascii_lowercase()))? > 0;
    if changed && !top && h.is_empty_key(node)? {
        h.delete_node(node)?;
        return Ok(true);
    }
    Ok(false)
}

/// `SideBySide\Winners\<family>\<major.minor>` has one value per installed version, the default value names
/// the winner. Removes `version` and re-elects the winner. Emptied keys are deleted when the component is
/// removed (`delete_keys`); when it is only uninstalled (feature disabled) DISM keeps them without values.
fn drop_winner(sw: &mut Hive, family: &str, version: &str, delete_keys: bool) -> Result<()> {
    let wpath = format!(r"{WINNERS_KEY}\{family}");
    let Some(w) = sw.key(&wpath)? else { return Ok(()) };
    for mm in sw.children(w).into_iter().map(|(n, _)| n).collect::<Vec<_>>() {
        let mpath = format!(r"{wpath}\{mm}");
        let Some(node) = sw.key(&mpath)? else { continue };
        sw.retain_values(node, |k, _| !k.eq_ignore_ascii_case(version))?;
        let left: Vec<String> = sw.values_strict(node)?.into_iter().map(|(k, _)| k).filter(|k| !k.is_empty()).collect();
        if left.is_empty() && delete_keys {
            sw.delete_node(node)?;
        } else if left.is_empty() {
            sw.retain_values(node, |_, _| false)?;
        } else if let Some(best) = left.iter().max_by_key(|v| v.split('.').map(|x| x.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>()) {
            let best = best.clone();
            sw.set(&mpath, "", &RegData::sz(&best))?;
        }
    }
    let Some(w) = sw.key(&wpath)? else { return Ok(()) };
    if delete_keys {
        if sw.children(w).is_empty() {
            sw.delete_node(w)?;
        }
    } else {
        let mut any = false;
        for (_, mm) in sw.children(w) {
            any |= !sw.values_strict(mm)?.is_empty();
        }
        if !any {
            sw.retain_values(w, |_, _| false)?;
        }
    }
    Ok(())
}

/// Winners family of an (abbreviated) component name: unique prefix match with a value for its version.
fn winner_family(sw: &Hive, names: &[String], component: &str) -> Result<Option<(String, String)>> {
    let Some((prefix, version)) = family_prefix(component) else { return Ok(None) };
    let mut found = Vec::new();
    for n in names {
        if !n.to_ascii_lowercase().strip_prefix(&prefix).is_some_and(|rest| !rest.contains('_')) {
            continue;
        }
        let Some(w) = sw.key(&format!(r"{WINNERS_KEY}\{n}"))? else { continue };
        for (_, mm) in sw.children(w) {
            if sw.value(mm, &version)?.is_some() {
                found.push(n.clone());
                break;
            }
        }
    }
    Ok(if found.len() == 1 { Some((found.remove(0), version)) } else { None })
}

/// `ControlSetNNN` the offline SYSTEM hive boots with (`Select\Current`, default 001).
fn current_control_set(sys: &Hive) -> Result<String> {
    let n = sys.get("Select", "Current")?.and_then(|d| d.as_dword()).unwrap_or(1);
    Ok(format!("ControlSet{n:03}"))
}

/// UTC time as CBS writes it (`2026/10/23/05:39:27`).
fn chrono_like_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86400, secs % 86400);
    // civil from days (Howard Hinnant)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}/{m:02}/{d:02}/{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    #[test]
    fn owner_pairs_split() {
        assert_eq!(
            super::split_owner_pair("microsoft-windows-foundation-package~31bf3856ad364e35~amd64~~10.0.26100.1.foundation"),
            ("microsoft-windows-foundation-package~31bf3856ad364e35~amd64~~10.0.26100.1".to_string(), "foundation".to_string())
        );
        assert_eq!(super::split_owner_pair("odd"), ("odd".to_string(), String::new()));
    }

    #[test]
    fn key_form_hash() {
        let id = "Microsoft-Windows-EnterpriseClientSync-Host-GPExtension.Resources, Culture=de-DE, Version=10.0.26100.1, \
                  PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS";
        assert_eq!(format!("{:016x}", identity_hash(id, true).unwrap()), "4021578c0740da34");
        assert_eq!(format!("{:016x}", identity_hash(id, false).unwrap()), "0bd137ff2f5bb269");
        let neutral = "0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, \
                       PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS";
        assert_eq!(format!("{:016x}", identity_hash(neutral, true).unwrap()), "3fb84cbf20555c08");
        assert_eq!(
            family_key("amd64_microsoft-windows-e..extension.resources_31bf3856ad364e35_10.0.26100.1_de-de_4021578c0740da34", id).unwrap(),
            "amd64_microsoft-windows-e..extension.resources_31bf3856ad364e35_de-de_0bd137ff2f5bb269"
        );
    }

    use super::*;

    #[test]
    fn identities() {
        let p = PackageId::parse("Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~de-DE~10.0.26100.9457").unwrap();
        assert_eq!(p.lang, "de-DE");
        assert_eq!(p.family(), ("microsoft-windows-stepsrecorder-package".into(), "amd64".into()));
        let (prefix, v) =
            family_prefix("amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.26100.9444_none_76b725a4fafd35a9").unwrap();
        assert_eq!(prefix, "amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_none_");
        assert_eq!(v, "10.0.26100.9444");
        assert_eq!(chrono_like_now().len(), 19);
    }

    #[test]
    fn mum_feature() {
        let xml = r#"<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v3">
<assemblyIdentity name="X-Package" version="1.0" processorArchitecture="amd64" language="neutral"/>
<package identifier="x"><parent><assemblyIdentity name="Host" version="1" processorArchitecture="amd64" language="neutral"/></parent>
<update name="Feat" displayName="F"><selectable disposition="staged"><detectNone default="false"/></selectable>
<package contained="false" integrate="hidden"><assemblyIdentity name="Opt" version="1" processorArchitecture="amd64" language="neutral"/></package>
<capability><capabilityIdentity name="Cap.X"/></capability></update>
<update name="Content"><applicable disposition="detect"><detectUpdate><parent name="Feat"/></detectUpdate></applicable>
<component><assemblyIdentity name="Dep" version="1" processorArchitecture="amd64" language="neutral"/></component></update>
</package></assembly>"#;
        let m = parse_mum(xml).unwrap();
        assert_eq!(m.parents[0].name, "Host");
        assert!(m.updates[0].selectable);
        assert_eq!(m.updates[0].packages[0].name, "Opt");
        assert_eq!(m.updates[0].capabilities, vec!["Cap.X"]);
        assert_eq!(m.updates[1].detect_parents, vec!["Feat"]);
        assert_eq!(m.updates[1].components[0].name, "Dep");
    }

    #[test]
    fn destinations() {
        assert_eq!(map_destination(r"$(runtime.system32)\Microsoft-Edge-WebView\Locales\", false).unwrap(), "Windows/System32/Microsoft-Edge-WebView/Locales");
        assert_eq!(map_destination(r"$(runtime.system32)\", true).unwrap(), "Windows/SysWOW64");
        assert_eq!(map_destination(r"$(runtime.unknown)\x", false), None);
        assert_eq!(
            filemap_prefix("Windows/System32/Microsoft-Edge-WebView/Trust Protection Lists/Mu").unwrap(),
            "$$_system32_microsoft-edge-webview_trust_protection_lists_mu"
        );
        assert_eq!(
            filemap_prefix("Windows/System32/Microsoft-Edge-WebView/WidevineCdm/_platform_specific/win_x64").unwrap(),
            "$$_system32_microsoft-edge-webview_widevinecdm_platform_specific_win_x64"
        );
    }

    #[test]
    fn key_mapping() {
        assert_eq!(
            map_key(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\x\Parameters", false),
            Some((HiveSel::System, r"{CurrentControlSet}\Services\x\Parameters".into()))
        );
        assert_eq!(map_key(r"HKEY_CLASSES_ROOT\CLSID\{1}", true), Some((HiveSel::Software, r"Classes\WOW6432Node\CLSID\{1}".into())));
        assert_eq!(map_key(r"HKEY_LOCAL_MACHINE\Software\Microsoft\X", false), Some((HiveSel::Software, r"Microsoft\X".into())));
    }

    /// Needs a real DRIVERS hive: LEAN11_DRIVERS_HIVE=<image>/Windows/System32/config/DRIVERS cargo test -- --ignored
    #[test]
    #[ignore]
    fn prune_driver_database_on_a_real_hive() {
        use super::*;
        let Ok(src) = std::env::var("LEAN11_DRIVERS_HIVE") else { return };
        let dir = std::env::temp_dir().join(format!("lean11-drv-{}", std::process::id()));
        let cfg = dir.join("Windows/System32/config");
        fs::create_dir_all(&cfg).unwrap();
        fs::copy(&src, cfg.join("DRIVERS")).unwrap();
        let repo = dir.join(FILE_REPOSITORY);
        let h = Hive::open(&cfg.join("DRIVERS"), false).unwrap();
        let pk = h.key(r"DriverDatabase\DriverPackages").unwrap().unwrap();
        let infs_before = h.children(h.key(r"DriverDatabase\DriverInfFiles").unwrap().unwrap()).len();
        let mut total = 0;
        for (name, _) in h.children(pk) {
            total += 1;
            if name.to_ascii_lowercase().starts_with("net1ic64.inf_") {
                continue;
            }
            // the folder holds the original INF name (an OEM package is published as oemNN.inf)
            let inf = &name[..name.to_ascii_lowercase().find(".inf_").unwrap() + 4];
            fs::create_dir_all(repo.join(&name)).unwrap();
            fs::write(repo.join(&name).join(inf), b"").unwrap();
        }
        drop(h);
        assert_eq!(prune_driver_database(&dir).unwrap(), 1);
        let h = Hive::open(&cfg.join("DRIVERS"), false).unwrap();
        let pk = h.key(r"DriverDatabase\DriverPackages").unwrap().unwrap();
        assert_eq!(h.children(pk).len(), total - 1);
        assert!(h.key(r"DriverDatabase\DriverInfFiles\net1ic64.inf").unwrap().is_none());
        assert!(h.key(r"DriverDatabase\DriverFiles\e1i68x64.sys").unwrap().is_none());
        let id = h.key(r"DriverDatabase\DeviceIds\PCI\VEN_8086&DEV_10D3").unwrap();
        assert!(id.is_none_or(|n| h.value(n, "net1ic64.inf").unwrap().is_none()));
        // other drivers are untouched, and a second run finds nothing
        assert_eq!(h.children(h.key(r"DriverDatabase\DriverInfFiles").unwrap().unwrap()).len(), infs_before - 1);
        drop(h);
        assert_eq!(prune_driver_database(&dir).unwrap(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}
