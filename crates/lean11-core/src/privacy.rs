//! Privacy settings catalog: lean11's curated list of privacy and telemetry settings. Every setting names
//! how it was verified for the current Windows 11 release (`data/privacy.toml`).
//!
//! Settings are applied offline to the image: registry values (HKLM to the SOFTWARE/SYSTEM hives, HKCU
//! to the default user profile, so every account created later gets them), service start types,
//! scheduled tasks and hosts file entries. Removing apps, capabilities and features stays with the
//! Components and Custom steps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use lean11_hive::{Hive, RegData};

use crate::build::Recipe;
use crate::catalog;

const CATALOG: &str = include_str!("../data/privacy.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Safe for everyone: no visible feature is lost.
    Recommended,
    /// Costs a feature or convenience (named in the description).
    Strict,
    /// Only on request (special cases, side effects).
    Optional,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    pub id: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub level: Level,
    /// Conditions under which the setting makes no sense (see [`Condition`]).
    #[serde(default)]
    pub hidden_if: Vec<String>,
    /// Settings that contradict this one.
    #[serde(default)]
    pub conflicts: Vec<String>,
    /// References (documentation the setting is based on).
    #[serde(default)]
    pub sources: Vec<String>,
    /// How the setting was verified for the current Windows release.
    pub verified: String,
    #[serde(default)]
    pub note: String,
    /// Evidence for values no ADMX policy defines: `doc` (Microsoft documents the value, named in
    /// `verified`), `vm` (read back on a fresh installation after setup).
    #[serde(default)]
    pub evidence: Vec<String>,
    pub ops: Vec<Op>,
}

/// One change. Exactly one of `reg`, `service`, `task`, `hosts` is set.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Op {
    /// Registry key with root: `HKLM\SOFTWARE\…`, `HKLM\SYSTEM\CurrentControlSet\…`, `HKCU\…`.
    pub reg: Option<String>,
    /// Value name (empty = default value).
    pub name: Option<String>,
    pub dword: Option<u32>,
    pub qword: Option<u64>,
    pub sz: Option<String>,
    pub expand_sz: Option<String>,
    pub multi_sz: Option<Vec<String>>,
    /// Hex bytes.
    pub binary: Option<String>,
    /// Delete the value `name`.
    #[serde(default)]
    pub delete: bool,
    /// Delete the key with all subkeys.
    #[serde(default)]
    pub delete_key: bool,
    /// Service name; with `start` (0-4).
    pub service: Option<String>,
    pub start: Option<u32>,
    /// Scheduled task path (`\Microsoft\Windows\…\Name`), disabled.
    pub task: Option<String>,
    /// Host names resolved to 0.0.0.0 in the hosts file.
    pub hosts: Option<Vec<String>>,
    /// Program (`%SystemRoot%\…`) whose outgoing traffic a Windows Firewall rule blocks.
    pub firewall_block: Option<String>,
    /// Windows setup resets this value (security template, language settings): it is written offline
    /// and again by `SetupComplete.cmd` at the end of setup.
    #[serde(default)]
    pub after_setup: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub category: Vec<Category>,
    pub setting: Vec<Setting>,
}

/// Parses and validates a catalog file (the embedded one or a draft for `lean11 privacy verify --catalog`).
pub fn parse_catalog(text: &str) -> Result<Catalog> {
    let c: Catalog = toml::from_str(text)?;
    validate_catalog(&c)?;
    Ok(c)
}

/// The embedded catalog (validated by the tests).
pub fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| toml::from_str(CATALOG).expect("data/privacy.toml is valid (checked by the tests)"))
}

pub fn setting(id: &str) -> Option<&'static Setting> {
    catalog().setting.iter().find(|s| s.id == id)
}

// ---------------------------------------------------------------------------------------------------
// registry paths

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Root {
    Software,
    System,
    DefaultUser,
    DotDefault,
    /// HKU\S-1-5-19 (Windows/ServiceProfiles/LocalService/NTUSER.DAT)
    LocalService,
    /// HKU\S-1-5-20 (Windows/ServiceProfiles/NetworkService/NTUSER.DAT)
    NetworkService,
}

impl Root {
    /// Image-relative hive file of the service profiles (the others are opened by the build).
    pub fn profile_file(self) -> Option<&'static str> {
        match self {
            Root::LocalService => Some("Windows/ServiceProfiles/LocalService/NTUSER.DAT"),
            Root::NetworkService => Some("Windows/ServiceProfiles/NetworkService/NTUSER.DAT"),
            _ => None,
        }
    }
}

/// Splits a full registry path into the offline hive and the path inside it. `CurrentControlSet` stays
/// as `{ControlSet}` and is resolved against the image.
pub fn split_reg(path: &str) -> Result<(Root, String)> {
    let p = path.trim_matches('\\');
    let (root, rest) = p.split_once('\\').unwrap_or((p, ""));
    let up = root.to_ascii_uppercase();
    let (hive_name, rest) = match up.as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => {
            let (h, r) = rest.split_once('\\').unwrap_or((rest, ""));
            (h.to_ascii_uppercase(), r.to_string())
        }
        "HKCU" | "HKEY_CURRENT_USER" => return Ok((Root::DefaultUser, rest.to_string())),
        "HKCR" | "HKEY_CLASSES_ROOT" => return Ok((Root::Software, format!(r"Classes\{rest}").trim_end_matches('\\').to_string())),
        "HKU" | "HKEY_USERS" => {
            let (u, r) = rest.split_once('\\').unwrap_or((rest, ""));
            if u.eq_ignore_ascii_case(".DEFAULT") || u == "S-1-5-18" {
                return Ok((Root::DotDefault, r.to_string()));
            }
            if u == "S-1-5-19" {
                return Ok((Root::LocalService, r.to_string()));
            }
            if u == "S-1-5-20" {
                return Ok((Root::NetworkService, r.to_string()));
            }
            bail!("unsupported user hive in {path}");
        }
        _ => bail!("unsupported registry root in {path}"),
    };
    match hive_name.as_str() {
        "SOFTWARE" => Ok((Root::Software, rest)),
        "SYSTEM" => {
            let (cs, r) = rest.split_once('\\').unwrap_or((&rest, ""));
            if cs.eq_ignore_ascii_case("CurrentControlSet") {
                Ok((Root::System, if r.is_empty() { "{ControlSet}".into() } else { format!(r"{{ControlSet}}\{r}") }))
            } else {
                Ok((Root::System, rest.clone()))
            }
        }
        _ => bail!("unsupported HKLM hive in {path}"),
    }
}

impl Op {
    pub fn kind(&self) -> &'static str {
        match () {
            _ if self.reg.is_some() => "reg",
            _ if self.service.is_some() => "service",
            _ if self.task.is_some() => "task",
            _ if self.hosts.is_some() => "hosts",
            _ if self.firewall_block.is_some() => "firewall",
            _ => "none",
        }
    }

    /// Registry data to write (None for deletions).
    pub fn data(&self) -> Result<Option<RegData>> {
        use lean11_hive::{REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, utf16z};
        let mut v: Vec<RegData> = Vec::new();
        if let Some(d) = self.dword {
            v.push(RegData::dword(d));
        }
        if let Some(q) = self.qword {
            v.push(RegData { kind: REG_QWORD, data: q.to_le_bytes().to_vec() });
        }
        if let Some(s) = &self.sz {
            v.push(RegData::sz(s));
        }
        if let Some(s) = &self.expand_sz {
            v.push(RegData { kind: REG_EXPAND_SZ, data: utf16z(s) });
        }
        if let Some(m) = &self.multi_sz {
            let mut data = Vec::new();
            for s in m {
                data.extend(utf16z(s));
            }
            data.extend([0, 0]);
            v.push(RegData { kind: REG_MULTI_SZ, data });
        }
        if let Some(b) = &self.binary {
            if let Some(c) = b.chars().find(|c| !c.is_ascii_hexdigit() && !c.is_ascii_whitespace() && *c != ',' && *c != ':') {
                bail!("binary {b}: unexpected character {c:?}");
            }
            let clean: String = b.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            v.push(RegData { kind: REG_BINARY, data: hex::decode(&clean).with_context(|| format!("binary {b}"))? });
        }
        match (v.len(), self.delete || self.delete_key) {
            (0, true) => Ok(None),
            (1, false) => Ok(v.pop()),
            (0, false) => bail!("registry op without data"),
            _ => bail!("registry op with more than one data kind or data plus delete"),
        }
    }

    fn validate(&self) -> Result<()> {
        let kinds = [self.reg.is_some(), self.service.is_some(), self.task.is_some(), self.hosts.is_some(), self.firewall_block.is_some()];
        if kinds.iter().filter(|k| **k).count() != 1 {
            bail!("op needs exactly one of reg, service, task, hosts, firewall_block: {self:?}");
        }
        if let Some(p) = &self.firewall_block {
            if !p.starts_with("%SystemRoot%\\") || p.contains(['|', '\r', '\n']) || !p.to_ascii_lowercase().ends_with(".exe") {
                bail!("firewall_block needs a %SystemRoot%\\…\\name.exe path: {p}");
            }
        }
        if let Some(r) = &self.reg {
            split_reg(r)?;
            if self.delete_key && (self.name.is_some() || self.delete) {
                bail!("delete_key takes no value name: {r}");
            }
            if !self.delete_key && self.name.is_none() {
                bail!("registry op without value name: {r}");
            }
            self.data()?;
            if self.after_setup {
                let (root, _) = split_reg(r)?;
                // passed quoted to reg.exe in a batch file: no cmd metacharacters, no trailing backslash
                let plain = |v: &str| !v.contains(['%', '"', '\r', '\n', '&', '|', '<', '>', '^', '!', '(', ')']) && !v.ends_with('\\');
                let ok_root = matches!(root, Root::Software | Root::System | Root::DefaultUser);
                let ok_data = self.dword.is_some() || self.qword.is_some() || self.sz.as_deref().is_some_and(plain);
                if !ok_root || !ok_data || self.delete || !plain(r) || !plain(self.name.as_deref().unwrap_or_default()) {
                    bail!("after_setup needs an HKLM or HKCU value set to dword, qword or plain sz: {r}");
                }
            }
        } else if self.after_setup {
            bail!("after_setup is for registry values: {self:?}");
        } else if self.service.is_some() {
            if !matches!(self.start, Some(0..=4)) {
                bail!("service op needs start 0-4: {self:?}");
            }
        } else if self.start.is_some() || self.name.is_some() || self.delete || self.delete_key {
            bail!("fields of another op kind: {self:?}");
        }
        if let Some(h) = &self.hosts {
            if h.is_empty() || h.iter().any(|x| x.is_empty() || x.contains(char::is_whitespace)) {
                bail!("bad hosts list: {h:?}");
            }
        }
        if let Some(t) = &self.task {
            if !t.starts_with('\\') || t.ends_with('\\') {
                bail!("task path must be \\Folder\\Name: {t}");
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------
// conditions and selection

/// When a setting is pointless because the component it configures is gone or switched off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Defender switched off (disable-defender or Core).
    DefenderOff,
    /// Windows Update switched off (disable-windows-update or Core).
    UpdatesOff,
    /// Edge files removed.
    EdgeRemoved,
    /// OneDrive setup removed.
    OneDriveRemoved,
    /// A Components option is selected.
    Option(String),
    /// A provisioned app (family name prefix) is removed by a Components option or a Custom action.
    AppRemoved(String),
}

impl Condition {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "defender-off" => Condition::DefenderOff,
            "updates-off" => Condition::UpdatesOff,
            "edge-removed" => Condition::EdgeRemoved,
            "onedrive-removed" => Condition::OneDriveRemoved,
            _ => match s.split_once(':') {
                Some(("option", id)) => {
                    catalog::option(id).ok_or_else(|| anyhow!("unknown option in condition {s}"))?;
                    Condition::Option(id.into())
                }
                Some(("app-removed", fam)) if !fam.is_empty() => Condition::AppRemoved(fam.into()),
                _ => bail!("unknown condition {s}"),
            },
        })
    }

    pub fn holds(&self, r: &Recipe) -> bool {
        let has = |id: &str| r.options.iter().any(|o| o == id);
        match self {
            Condition::DefenderOff => r.disables_defender(),
            Condition::UpdatesOff => r.disables_updates(),
            Condition::EdgeRemoved => has("edge-files"),
            Condition::OneDriveRemoved => has("onedrive-files"),
            Condition::Option(id) => has(id),
            Condition::AppRemoved(fam) => {
                let f = fam.to_ascii_lowercase();
                r.options.iter().filter_map(|o| catalog::option(o)).filter(|o| o.kind == catalog::Kind::App).any(|o| {
                    o.targets.iter().any(|t| t.to_ascii_lowercase() == f || f.starts_with(&t.to_ascii_lowercase()))
                }) || r.actions.iter().any(|a| {
                    a.kind == crate::inventory::Kind::ProvisionedApp && a.mode == crate::inventory::Mode::Remove && a.identity.to_ascii_lowercase().starts_with(&format!("{f}_"))
                })
            }
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Condition::DefenderOff => "Defender is switched off".into(),
            Condition::UpdatesOff => "Windows Update is switched off".into(),
            Condition::EdgeRemoved => "Edge is removed".into(),
            Condition::OneDriveRemoved => "OneDrive is removed".into(),
            Condition::Option(id) => format!("set by Components: {}", catalog::option(id).map(|o| o.title).unwrap_or(id)),
            Condition::AppRemoved(f) => format!("{} is removed", crate::names::app(f)),
        }
    }
}

/// State of a setting for a recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Available,
    /// Hidden with the reason (component gone, already covered by a Components option).
    Hidden(String),
}

/// Normalized registry write (root, lower-case key, lower-case name, data) for duplicate detection.
type RegKey = (Root, String, String);

fn components_regs(r: &Recipe) -> HashMap<RegKey, RegData> {
    let mut m = HashMap::new();
    let mut ops = Vec::new();
    for id in &r.options {
        ops.extend(catalog::registry_ops(id));
    }
    for op in ops {
        if let catalog::RegOp::Set(v) = op {
            let root = match v.hive {
                catalog::Hive::Software => Root::Software,
                catalog::Hive::System => Root::System,
                catalog::Hive::DefaultUser => Root::DefaultUser,
                catalog::Hive::DotDefault => Root::DotDefault,
            };
            let data = match v.value {
                catalog::Value::Dword(d) => RegData::dword(d),
                catalog::Value::Sz(s) => RegData::sz(s),
            };
            m.insert((root, v.key.to_ascii_lowercase(), v.name.to_ascii_lowercase()), data);
        }
    }
    m
}

pub fn status(s: &Setting, r: &Recipe) -> Status {
    for c in &s.hidden_if {
        if let Ok(c) = Condition::parse(c) {
            if c.holds(r) {
                return Status::Hidden(c.reason());
            }
        }
    }
    // every registry write already done identically by the selected Components options
    let comp = components_regs(r);
    let regs: Vec<&Op> = s.ops.iter().filter(|o| o.reg.is_some()).collect();
    if !regs.is_empty() && regs.len() == s.ops.len() {
        let covered = regs.iter().all(|o| {
            let Ok((root, key)) = split_reg(o.reg.as_deref().unwrap_or_default()) else { return false };
            let Ok(Some(data)) = o.data() else { return false };
            comp.get(&(root, key.to_ascii_lowercase(), o.name.clone().unwrap_or_default().to_ascii_lowercase())) == Some(&data)
        });
        if covered {
            return Status::Hidden("already set by the selected Components options".into());
        }
    }
    Status::Available
}

/// Preset ids: `recommended` = level recommended, `strict` = recommended + strict.
pub fn preset(name: &str) -> Result<Vec<String>> {
    let max = match name {
        "none" => return Ok(Vec::new()),
        "recommended" => Level::Recommended,
        "strict" => Level::Strict,
        _ => bail!("unknown privacy preset {name} (recommended, strict, none)"),
    };
    Ok(catalog().setting.iter().filter(|s| s.level <= max).map(|s| s.id.clone()).collect())
}

/// Final selection of a recipe: hidden settings dropped (with a note), unknown ids and conflicts are
/// errors.
pub fn resolve<'a>(r: &Recipe, log: &mut dyn FnMut(&str)) -> Result<Vec<&'a Setting>> {
    let mut out: Vec<&Setting> = Vec::new();
    for id in &r.privacy {
        let s = setting(id).ok_or_else(|| anyhow!("unknown privacy setting {id} (see `lean11 privacy list`)"))?;
        match status(s, r) {
            Status::Available => out.push(s),
            Status::Hidden(why) => log(&format!("privacy: {id} skipped ({why})")),
        }
    }
    for s in &out {
        for c in &s.conflicts {
            if out.iter().any(|o| &o.id == c) {
                bail!("privacy settings {} and {c} contradict each other; select only one", s.id);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------
// offline application

/// Offline hives of the image, opened for writing by the caller.
pub struct Hives<'h> {
    pub software: &'h mut Hive,
    pub system: &'h mut Hive,
    pub user: &'h mut Hive,
    pub dot_default: &'h mut Hive,
}

#[derive(Debug, Default)]
pub struct Applied {
    pub registry: usize,
    pub services: usize,
    pub hosts: BTreeSet<String>,
    pub tasks: Vec<String>,
    /// Ops that did not apply (service or key not in this image), for the log.
    pub skipped: Vec<String>,
}

/// Registry and service changes of the selected settings. Services are set in every control set; a
/// service that does not exist in the image is skipped, never created.
pub fn apply_registry(image: &std::path::Path, settings: &[&Setting], h: &mut Hives, control_sets: &[String], current: &str) -> Result<Applied> {
    let mut a = Applied::default();
    let mut profiles: HashMap<Root, Hive> = HashMap::new();
    for s in settings {
        for op in &s.ops {
            if let Some(path) = &op.reg {
                let (root, key) = split_reg(path)?;
                let key = key.replace("{ControlSet}", current);
                if let (Some(file), false) = (root.profile_file(), profiles.contains_key(&root)) {
                    // created by Windows on first boot; the catalog uses policies instead (checked by verify)
                    let p = lean11_wim::resolve_ci(image, file).ok_or_else(|| anyhow!("{}: {file} does not exist in the install image", s.id))?;
                    profiles.insert(root, Hive::open(&p, true)?);
                }
                let hive: &mut Hive = match root {
                    Root::Software => h.software,
                    Root::System => h.system,
                    Root::DefaultUser => h.user,
                    Root::DotDefault => h.dot_default,
                    _ => profiles.get_mut(&root).expect("opened above"),
                };
                if op.delete_key {
                    hive.delete_key(&key)?;
                } else if op.delete {
                    hive.delete_value(&key, op.name.as_deref().unwrap_or_default())?;
                } else {
                    let data = op.data()?.ok_or_else(|| anyhow!("{}: no data", s.id))?;
                    hive.set(&key, op.name.as_deref().unwrap_or_default(), &data)?;
                }
                a.registry += 1;
            } else if let Some(svc) = &op.service {
                let mut found = false;
                for cs in control_sets {
                    let key = format!(r"{cs}\Services\{svc}");
                    if h.system.key(&key)?.is_some() {
                        h.system.set(&key, "Start", &RegData::dword(op.start.unwrap_or(4)))?;
                        found = true;
                    }
                }
                if found {
                    a.services += 1;
                } else {
                    a.skipped.push(format!("{}: service {svc} not in the image", s.id));
                }
            } else if let Some(prog) = &op.firewall_block {
                let (id, rule) = firewall_rule(s, prog);
                for cs in control_sets {
                    let key = format!(r"{cs}\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                    if h.system.key(&key)?.is_some() {
                        h.system.set(&key, &id, &RegData::sz(&rule))?;
                    }
                }
                a.registry += 1;
            } else if let Some(hosts) = &op.hosts {
                a.hosts.extend(hosts.iter().map(|x| x.to_ascii_lowercase()));
            } else if let Some(t) = &op.task {
                a.tasks.push(t.clone());
            }
        }
    }
    for h in profiles.values_mut() {
        h.commit()?;
    }
    Ok(a)
}

/// Rule id and rule text (Windows Firewall's registry format, as in the image's own rules) for a program
/// whose outgoing traffic is blocked; the user can switch it off in Windows Defender Firewall.
pub fn firewall_rule(s: &Setting, prog: &str) -> (String, String) {
    let exe = prog.rsplit('\\').next().unwrap_or(prog);
    // the path below %SystemRoot%, so System32 and SysWOW64 copies get rules of their own
    let rel = prog.strip_prefix("%SystemRoot%\\").unwrap_or(prog).to_ascii_lowercase();
    let rel = rel.strip_suffix(".exe").unwrap_or(&rel);
    let slug: String = rel.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let id = format!("lean11-{}-{slug}", s.id);
    let rule = format!("v2.33|Action=Block|Active=TRUE|Dir=Out|App={prog}|Name=lean11: block {exe}|Desc=lean11 privacy setting {}|", s.id);
    (id, rule)
}

const TASKCACHE: &str = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

/// CRC-32 (IEEE) without the final inversion, as the Task Scheduler stores it in the JobBucket.
fn crc32_raw(data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

/// `<Enabled>false</Enabled>` as a direct child of `<Settings>` (replacing an `<Enabled>` there, else
/// inserted right after the `<Settings>` tag, on its own line when the XML is indented).
fn disable_in_xml(xml: &str) -> Result<String> {
    let start = xml.find("<Settings>").ok_or_else(|| anyhow!("task XML without <Settings>"))?;
    let end = xml[start..].find("</Settings>").map(|e| start + e).ok_or_else(|| anyhow!("task XML without </Settings>"))?;
    let block = &xml[start..end];
    // nested elements of Settings (IdleSettings, ...) have no <Enabled>; triggers are outside the block
    if let Some(i) = block.find("<Enabled>") {
        let j = block[i..].find("</Enabled>").ok_or_else(|| anyhow!("broken <Enabled> in task XML"))? + i + "</Enabled>".len();
        return Ok(format!("{}<Enabled>false</Enabled>{}", &xml[..start + i], &xml[start + j..]));
    }
    let tag_end = start + "<Settings>".len();
    let rest = &xml[tag_end..];
    // indented XML: keep the layout (newline and the indentation of the next line)
    let nl = if rest.starts_with("\r\n") { "\r\n" } else if rest.starts_with('\n') { "\n" } else { "" };
    if nl.is_empty() {
        return Ok(format!("{}<Enabled>false</Enabled>{rest}", &xml[..tag_end]));
    }
    let indent: String = rest[nl.len()..].chars().take_while(|c| *c == ' ' || *c == '\t').collect();
    Ok(format!("{}{nl}{indent}<Enabled>false</Enabled>{rest}", &xml[..tag_end]))
}

/// Disables a scheduled task in an offline image the way the Task Scheduler does (verified on 26H2 by
/// diffing `Disable-ScheduledTask`): `<Enabled>false</Enabled>` in the task XML, `Hash` = SHA-256 of the
/// XML without BOM, and in the `Triggers` blob the JobBucket flag 0x400000 cleared and its CRC-32 of the
/// XML updated.
///
/// A fresh install image has no task XML files: the tasks exist only in the TaskCache and setup writes
/// the files from it. There only the enabled flag is cleared. Returns false when the task is not in the
/// image.
pub fn disable_task(root: &std::path::Path, software: &mut Hive, task: &str) -> Result<bool> {
    use sha2::Digest;
    let Some(id) = software.get(&format!(r"{TASKCACHE}\Tree{task}"), "Id")?.and_then(|d| d.as_string()) else { return Ok(false) };
    let tkey = format!(r"{TASKCACHE}\Tasks\{id}");
    let triggers = software.get(&tkey, "Triggers")?.ok_or_else(|| anyhow!("task {task}: no Triggers value"))?;
    let hash = software.get(&tkey, "Hash")?.ok_or_else(|| anyhow!("task {task}: no Hash value"))?;
    if hash.data.len() != 32 {
        bail!("task {task}: unexpected Hash format ({} bytes)", hash.data.len());
    }
    let mut trig = triggers.data.clone();
    let version = trig.get(0..2).map(|v| u16::from_le_bytes([v[0], v[1]])).unwrap_or(0);
    if trig.len() < 0x34 || !(0x15..=0x20).contains(&version) {
        bail!("task {task}: unknown Triggers layout (version {version:#x}, {} bytes)", trig.len());
    }
    let rel = task.trim_start_matches('\\').replace('\\', "/");
    let file = lean11_wim::resolve_ci(root, "Windows/System32/Tasks").and_then(|d| lean11_wim::resolve_ci(&d, &rel));
    let Some(file) = file else {
        let flags = u32::from_le_bytes(trig[0x28..0x2c].try_into().unwrap()) & !0x0040_0000;
        trig[0x28..0x2c].copy_from_slice(&flags.to_le_bytes());
        software.set(&tkey, "Triggers", &RegData { kind: triggers.kind, data: trig })?;
        return Ok(true);
    };
    let raw = std::fs::read(&file)?;
    let body = raw.strip_prefix(&[0xff, 0xfe]).ok_or_else(|| anyhow!("task {task}: XML is not UTF-16 with BOM"))?;
    // the stored hash must match the file, else the image is already inconsistent and we stop
    if sha2::Sha256::digest(body).as_slice() != hash.data.as_slice() {
        bail!("task {task}: the image's task hash does not match its XML; left unchanged");
    }
    if body.len() % 2 != 0 {
        bail!("task {task}: XML has an odd byte length; left unchanged");
    }
    let units: Vec<u16> = body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let xml = String::from_utf16(&units).map_err(|_| anyhow!("task {task}: XML is not valid UTF-16"))?;
    let new = disable_in_xml(&xml)?;
    let mut bytes = vec![0xff, 0xfe];
    for u in new.encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    let new_body = &bytes[2..];
    let flags = u32::from_le_bytes(trig[0x28..0x2c].try_into().unwrap()) & !0x0040_0000;
    trig[0x28..0x2c].copy_from_slice(&flags.to_le_bytes());
    trig[0x30..0x34].copy_from_slice(&crc32_raw(new_body).to_le_bytes());
    std::fs::write(&file, &bytes)?;
    software.set(&tkey, "Hash", &RegData { kind: hash.kind, data: sha2::Sha256::digest(new_body).to_vec() })?;
    software.set(&tkey, "Triggers", &RegData { kind: triggers.kind, data: trig })?;
    Ok(true)
}

/// The hosts file with the blocked names appended in a marked block (replacing an earlier block).
pub fn hosts_file(existing: &str, names: &BTreeSet<String>) -> String {
    const BEGIN: &str = "# >>> lean11 privacy";
    const END: &str = "# <<< lean11 privacy";
    let mut out = String::new();
    // lines of a block since its BEGIN marker; dropped only when the matching END follows, so an
    // unterminated block (or a stray marker) never takes other entries with it
    let mut pending: Option<String> = None;
    for line in existing.lines() {
        let t = line.trim();
        if t == BEGIN {
            if let Some(p) = pending.take() {
                out.push_str(&p);
            }
            pending = Some(String::new());
            continue;
        }
        if t == END && pending.is_some() {
            pending = None;
            continue;
        }
        let target = pending.as_mut().unwrap_or(&mut out);
        target.push_str(line);
        target.push_str("\r\n");
    }
    if let Some(p) = pending {
        out.push_str(&p);
    }
    if !names.is_empty() {
        out.push_str(BEGIN);
        out.push_str("\r\n");
        for n in names {
            out.push_str(&format!("0.0.0.0 {n}\r\n"));
        }
        out.push_str(END);
        out.push_str("\r\n");
    }
    out
}

// ---------------------------------------------------------------------------------------------------
// listing and checks

/// Category path titles ("Data collection > Telemetry").
pub fn category_path(id: &str) -> String {
    let cats: BTreeMap<&str, &Category> = catalog().category.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut parts = Vec::new();
    let mut cur = cats.get(id).copied();
    let mut guard = 0;
    while let Some(c) = cur {
        parts.push(c.title.as_str());
        cur = c.parent.as_deref().and_then(|p| cats.get(p).copied());
        guard += 1;
        if guard > 8 {
            break;
        }
    }
    parts.reverse();
    parts.join(" > ")
}

/// PowerShell that reads every op of the given settings back on the installed system and prints one line
/// per mismatch (`FAIL <setting> <what>`), then `CHECKED <n> FAILED <m>`. Used by the VM tests.
pub fn check_script(settings: &[&Setting]) -> String {
    let mut s = String::from(
        "$ErrorActionPreference='SilentlyContinue'\n$ProgressPreference='SilentlyContinue'\n$n=0;$f=0\nfunction Fail($id,$w){$script:f++;Write-Output \"FAIL $id $w\"}\n\
         $users=@(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-[0-9-]+$' } | ForEach-Object { $_.PSChildName })\n\
         if(-not $users){$users=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)}\n\
         Write-Output ('ACCOUNTS ' + (($users | ForEach-Object { $sid=$_; try { (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { $sid } }) -join ', '))\n",
    );
    // catalog text goes only into single-quoted literals (PowerShell also treats the typographic quotes
    // as single quotes); runtime values are concatenated, never interpolated
    let q = |x: &str| x.replace('\'', "''").replace('\u{2018}', "\u{2018}\u{2018}").replace('\u{2019}', "\u{2019}\u{2019}").replace('\u{201a}', "\u{201a}\u{201a}").replace('\u{201b}', "\u{201b}\u{201b}");
    for st in settings {
        let id = q(&st.id);
        for op in &st.ops {
            if let Some(path) = &op.reg {
                // HKCU values are checked in every loaded account hive (each signed-in account was created
                // from the default profile), HKLM / HKU paths directly
                let user = path.strip_prefix("HKCU\\");
                let lit = match user {
                    Some(rest) => format!("('Registry::HKEY_USERS\\'+$u+'\\{}')", q(rest)),
                    None => format!("'{}'", q(&format!("Registry::{}", path.replace("HKLM\\", "HKEY_LOCAL_MACHINE\\").replace("HKU\\", "HKEY_USERS\\")))),
                };
                let who = if user.is_some() { " + ' [' + $u + ']'" } else { "" };
                let name = q(op.name.as_deref().unwrap_or_default());
                let check = if op.delete_key {
                    format!("$n++;if(Test-Path -LiteralPath {lit}){{Fail '{id}' ('key still present: {}'{who})}}", q(path))
                } else if op.delete {
                    format!(
                        "$n++;if($null -ne (Get-ItemProperty -LiteralPath {lit} -Name '{name}').'{name}'){{Fail '{id}' ('value still present: {}!{name}'{who})}}",
                        q(path)
                    )
                } else {
                    let want = if let Some(d) = op.dword {
                        d.to_string()
                    } else if let Some(v) = op.qword {
                        v.to_string()
                    } else if let Some(v) = op.sz.as_ref().or(op.expand_sz.as_ref()) {
                        v.clone()
                    } else if let Some(m) = &op.multi_sz {
                        m.join(" ")
                    } else {
                        continue;
                    };
                    format!(
                        "$n++;$v=(Get-ItemProperty -LiteralPath {lit} -Name '{name}').'{name}';if(\"$v\" -ne '{}'){{Fail '{id}' ('{}!{name} = ' + $v + ', want {}'{who})}}",
                        q(&want), q(path), q(&want)
                    )
                };
                if user.is_some() {
                    s.push_str(&format!("foreach($u in $users){{{check}}}\n"));
                } else {
                    s.push_str(&check);
                    s.push('\n');
                }
            } else if let Some(svc) = &op.service {
                s.push_str(&format!(
                    "$n++;$k=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{svc}';if($k -and $k.Start -ne {}){{Fail '{id}' ('service {svc} Start=' + $k.Start)}}\n",
                    op.start.unwrap_or(4),
                    svc = q(svc)
                ));
            } else if let Some(t) = &op.task {
                let (dir, name) = t.rsplit_once('\\').unwrap_or(("", t));
                s.push_str(&format!(
                    "$n++;$t=Get-ScheduledTask -TaskPath '{}\\' -TaskName '{}';if(-not $t){{Write-Output 'INFO {id} task {t} not present'}}elseif($t.State -ne 'Disabled'){{Fail '{id}' ('task {t} ' + $t.State)}}\n",
                    q(dir), q(name),
                    t = q(t)
                ));
            } else if let Some(prog) = &op.firewall_block {
                let (rid, _) = firewall_rule(st, prog);
                s.push_str(&format!(
                    "$n++;$r=Get-NetFirewallRule -Name '{}';if(-not $r -or \"$($r.Enabled)\" -ne 'True' -or \"$($r.Action)\" -ne 'Block' -or \"$($r.Direction)\" -ne 'Outbound' -or ($r | Get-NetFirewallApplicationFilter).Program -ne '{}'){{Fail '{id}' 'firewall rule {}'}}\n",
                    q(&rid), q(prog), q(&rid)
                ));
            } else if let Some(hs) = &op.hosts {
                for hname in hs {
                    s.push_str(&format!(
                        "$n++;if(-not (Select-String -Path \"$env:SystemRoot\\System32\\drivers\\etc\\hosts\" -Pattern '^0\\.0\\.0\\.0 {}$' -Quiet)){{Fail '{id}' 'hosts: {}'}}\n",
                        q(&regex::escape(hname)), q(hname)
                    ));
                }
            }
        }
    }
    s.push_str("Write-Output \"CHECKED $n FAILED $f\"\n");
    s
}

/// Script run once by the answer file's `FirstLogonCommands` (elevated, first account): writes the
/// `after_setup` values again, HKCU ones into the default profile and for the signed-in account.
pub const AFTER_SETUP_SCRIPT: &str = "lean11-privacy.cmd";
/// Script run by Active Setup once per account at its first sign-in (HKCU `after_setup` values).
pub const AFTER_SETUP_USER_SCRIPT: &str = "lean11-privacy-user.cmd";
/// Active Setup component of the user script (`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`).
pub const ACTIVE_SETUP_ID: &str = "{6F1D5C2A-7B3E-4C11-9A1D-711CE0DE0011}";
/// `SetupComplete.cmd` line used when the build also has the SSH option (which runs from SetupComplete
/// anyway): accounts used over SSH before the first sign-in then already get the repaired default profile.
pub const SETUPCOMPLETE_COMMAND: &str = "if exist \"%SystemRoot%\\Setup\\Scripts\\lean11-privacy.cmd\" call \"%SystemRoot%\\Setup\\Scripts\\lean11-privacy.cmd\" setup >\"%SystemRoot%\\Temp\\lean11-privacy-setup.log\" 2>&1\r\n";
/// `FirstLogonCommands` command line for [`AFTER_SETUP_SCRIPT`].
pub const FIRST_LOGON_COMMAND: &str = r"cmd.exe /c call %SystemRoot%\Setup\Scripts\lean11-privacy.cmd >%SystemRoot%\Temp\lean11-privacy.log 2>&1";

/// One `after_setup` value: (`HKLM`/`HKCU` path, name, reg.exe type, data text, Registry.pol type, raw data).
struct AfterSetup<'a> {
    reg: &'a str,
    name: &'a str,
    ty: &'static str,
    text: String,
    data: RegData,
}

fn after_setup_values<'a>(settings: &[&'a Setting]) -> Vec<AfterSetup<'a>> {
    let mut v = Vec::new();
    for st in settings {
        for op in st.ops.iter().filter(|o| o.after_setup) {
            let (Some(reg), Some(name)) = (op.reg.as_deref(), op.name.as_deref()) else { continue };
            let (ty, text) = if let Some(d) = op.dword {
                ("REG_DWORD", d.to_string())
            } else if let Some(q) = op.qword {
                ("REG_QWORD", q.to_string())
            } else if let Some(x) = &op.sz {
                ("REG_SZ", x.clone())
            } else {
                continue;
            };
            let Ok(Some(data)) = op.data() else { continue };
            v.push(AfterSetup { reg, name, ty, text, data });
        }
    }
    v
}

/// True when the settings need the first-logon script (and the answer file's `FirstLogonCommands`).
pub fn needs_after_setup(settings: &[&Setting]) -> bool {
    settings.iter().any(|s| s.ops.iter().any(|o| o.after_setup))
}

fn reg_add(path: &str, v: &AfterSetup) -> String {
    format!("reg add \"{path}\" /v \"{}\" /t {} /d \"{}\" /f || set lean11fail=1\r\n", v.name, v.ty, v.text)
}

const SCRIPT_HEAD: &str = "@echo off\r\nsetlocal DisableDelayedExpansion\r\nset lean11fail=0\r\n";

/// [`AFTER_SETUP_SCRIPT`]: HKLM values, HKCU values into the default profile (so every account created
/// later starts with them) and for the account signing in first. `None` when no op needs it.
pub fn after_setup_script(settings: &[&Setting]) -> Option<String> {
    let vals = after_setup_values(settings);
    if vals.is_empty() {
        return None;
    }
    let mut s = format!("{SCRIPT_HEAD}rem lean11 privacy: values that Windows setup resets (security template, language settings)\r\n");
    let user: Vec<&AfterSetup> = vals.iter().filter(|v| v.reg.starts_with("HKCU\\")).collect();
    for v in vals.iter().filter(|v| !v.reg.starts_with("HKCU\\")) {
        s.push_str(&reg_add(v.reg, v));
    }
    if !user.is_empty() {
        // `setup` (from SetupComplete.cmd, as SYSTEM): no signed-in account, only the default profile
        s.push_str("if /i \"%~1\"==\"setup\" goto lean11default\r\n");
        for v in &user {
            s.push_str(&reg_add(v.reg, v));
        }
        s.push_str(":lean11default\r\n");
        // without the loaded default profile the HKU writes would land in a plain HKU key
        s.push_str("reg load HKU\\Lean11Default \"%SystemDrive%\\Users\\Default\\NTUSER.DAT\"\r\nif errorlevel 1 (set lean11fail=1& goto lean11done)\r\n");
        for v in &user {
            s.push_str(&reg_add(&format!("HKU\\Lean11Default\\{}", &v.reg["HKCU\\".len()..]), v));
        }
        s.push_str("reg unload HKU\\Lean11Default || set lean11fail=1\r\n:lean11done\r\n");
    }
    s.push_str("exit /b %lean11fail%\r\n");
    Some(s)
}

/// [`AFTER_SETUP_USER_SCRIPT`]: the HKCU `after_setup` values for the signed-in account. `None` when none.
pub fn after_setup_user_script(settings: &[&Setting]) -> Option<String> {
    let vals = after_setup_values(settings);
    let user: Vec<&AfterSetup> = vals.iter().filter(|v| v.reg.starts_with("HKCU\\")).collect();
    if user.is_empty() {
        return None;
    }
    let mut s = format!("{SCRIPT_HEAD}rem lean11 privacy: per-account values that Windows setup resets\r\n");
    for v in user {
        s.push_str(&reg_add(v.reg, v));
    }
    s.push_str("exit /b %lean11fail%\r\n");
    Some(s)
}

/// Machine `Registry.pol` entries (PReg) for the HKLM `after_setup` values: the local Group Policy
/// writes them on every start, also where the answer file did not run. `None` when none.
pub fn registry_pol_entries(settings: &[&Setting]) -> Option<Vec<u8>> {
    let u = |x: &str| x.encode_utf16().chain([0]).flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
    let sep = |out: &mut Vec<u8>, c: char| out.extend((c as u16).to_le_bytes());
    let mut out = Vec::new();
    for v in after_setup_values(settings).iter().filter(|v| v.reg.starts_with("HKLM\\")) {
        let key = v.reg["HKLM\\".len()..].to_string();
        sep(&mut out, '[');
        out.extend(u(&key));
        sep(&mut out, ';');
        out.extend(u(v.name));
        sep(&mut out, ';');
        out.extend(v.data.kind.to_le_bytes());
        sep(&mut out, ';');
        out.extend((v.data.data.len() as u32).to_le_bytes());
        sep(&mut out, ';');
        out.extend(&v.data.data);
        sep(&mut out, ']');
    }
    (!out.is_empty()).then_some(out)
}

/// `Registry.pol` with our entries: appended to an existing file (its own entries kept, a stale copy of
/// ours replaced by the new one through the later position), or a new file with the PReg header.
pub fn registry_pol(existing: Option<&[u8]>, entries: &[u8]) -> Result<Vec<u8>> {
    const HEAD: &[u8] = b"PReg\x01\x00\x00\x00";
    let mut out = match existing {
        Some(b) if b.is_empty() => HEAD.to_vec(),
        Some(b) if b.starts_with(HEAD) => {
            if b.ends_with(entries) {
                return Ok(b.to_vec());
            }
            b.to_vec()
        }
        Some(_) => bail!("the image's Registry.pol is not a PReg file; it was left unchanged"),
        None => HEAD.to_vec(),
    };
    out.extend_from_slice(entries);
    Ok(out)
}

/// `gpt.ini` of the local Group Policy with the registry extension for computer settings and the machine
/// version raised by one (the client only reapplies a changed version).
pub fn gpt_ini(existing: Option<&str>) -> String {
    const EXT: &str = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}";
    let mut lines: Vec<String> = Vec::new();
    let (mut have_ext, mut have_ver) = (false, false);
    let mut in_general = false;
    let mut general_end = None;
    for l in existing.unwrap_or("[General]").lines() {
        let t = l.trim();
        if t.starts_with('[') && t.ends_with(']') {
            in_general = t.eq_ignore_ascii_case("[General]");
        }
        let field = t.split_once('=').filter(|_| in_general);
        if let Some((_, v)) = field.filter(|(k, _)| k.trim().eq_ignore_ascii_case("gPCMachineExtensionNames")) {
            let v = v.trim();
            have_ext = true;
            if v.to_ascii_uppercase().contains(EXT) {
                lines.push(t.to_string());
            } else {
                lines.push(format!("gPCMachineExtensionNames=[{EXT}]{v}"));
            }
        } else if let Some((_, v)) = field.filter(|(k, _)| k.trim().eq_ignore_ascii_case("Version")) {
            have_ver = true;
            let n: u32 = v.trim().parse().unwrap_or(0);
            let machine = (n & 0xffff).wrapping_add(1) & 0xffff;
            lines.push(format!("Version={}", (n & 0xffff_0000) | machine.max(1)));
        } else if !t.is_empty() {
            lines.push(t.to_string());
        }
        if in_general {
            general_end = Some(lines.len());
        }
    }
    let mut insert_at = match general_end {
        Some(i) => i,
        None => {
            lines.insert(0, "[General]".into());
            1
        }
    };
    if !have_ext {
        lines.insert(insert_at, format!("gPCMachineExtensionNames=[{EXT}]"));
        insert_at += 1;
    }
    if !have_ver {
        lines.insert(insert_at, "Version=1".into());
    }
    lines.join("\r\n") + "\r\n"
}

/// Result of checking one op against an image.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub setting: String,
    pub op: String,
    /// ok, policy-value, policy-class, not-policy, missing, info
    pub status: &'static str,
    pub detail: String,
}

fn op_label(op: &Op) -> String {
    if let Some(r) = &op.reg {
        let what = if op.delete_key {
            "delete key".to_string()
        } else if op.delete {
            "delete".to_string()
        } else {
            op.data().ok().flatten().map(|d| reg_text(&d)).unwrap_or_default()
        };
        format!("{r}!{} = {what}", op.name.as_deref().unwrap_or(""))
    } else if let Some(s) = &op.service {
        format!("service {s} start={}", op.start.unwrap_or(4))
    } else if let Some(t) = &op.task {
        format!("task {t}")
    } else if let Some(p) = &op.firewall_block {
        format!("firewall block {p}")
    } else if let Some(h) = &op.hosts {
        format!("hosts {}", h.join(" "))
    } else {
        String::new()
    }
}

fn reg_text(d: &RegData) -> String {
    use lean11_hive::REG_QWORD;
    if let Some(v) = d.as_dword() {
        v.to_string()
    } else if d.kind == REG_QWORD && d.data.len() >= 8 {
        u64::from_le_bytes(d.data[..8].try_into().unwrap()).to_string()
    } else if let Some(s) = d.as_string() {
        s
    } else if let Some(m) = d.as_multi() {
        m.join("|")
    } else {
        hex::encode(&d.data)
    }
}

/// Checks the ops of `settings` against an extracted image (root = image root):
/// - values below a `Policies` key must match a policy of the image's ADMX templates (key, value name,
///   class, allowed value);
/// - other registry values: the key, and for deletions the value, should exist in the offline hives
///   (a missing key is reported, it may still be valid when Windows creates it on first use);
/// - services and scheduled tasks must exist in the image.
pub fn verify(root: &std::path::Path, settings: &[&Setting], extra_admx: &[std::path::PathBuf]) -> Result<Vec<Finding>> {
    let mut pol = crate::admx::Policies::load(root)?;
    for d in extra_admx {
        pol.add_dir(d)?;
    }
    let open = |rel: &str| -> Result<Hive> {
        Hive::open(&lean11_wim::resolve_ci(root, rel).ok_or_else(|| anyhow!("image has no {rel}"))?, false)
    };
    let software = open("Windows/System32/config/SOFTWARE")?;
    let system = open("Windows/System32/config/SYSTEM")?;
    let user = open("Users/Default/NTUSER.DAT")?;
    let dot_default = open("Windows/System32/config/DEFAULT")?;
    // service profile hives only exist after the first boot
    let local_service = open("Windows/ServiceProfiles/LocalService/NTUSER.DAT").ok();
    let network_service = open("Windows/ServiceProfiles/NetworkService/NTUSER.DAT").ok();
    let current = system.get("Select", "Current")?.and_then(|d| d.as_dword()).unwrap_or(1);
    let cs = format!("ControlSet{current:03}");
    let tasks_dir = lean11_wim::resolve_ci(root, "Windows/System32/Tasks");
    let mut out = Vec::new();
    for s in settings {
        for op in &s.ops {
            // values outside the ADMX templates count as backed when the setting names its evidence
            let evidence = s.evidence.join("+");
            let not_policy = |f: &mut dyn FnMut(&'static str, String), detail: String| {
                if evidence.is_empty() {
                    f("not-policy", detail);
                } else {
                    f("evidence", format!("{evidence}; {detail}"));
                }
            };
            let mut f = |status: &'static str, detail: String| {
                out.push(Finding { setting: s.id.clone(), op: op_label(op), status, detail });
            };
            if let Some(path) = &op.reg {
                let (root_kind, key) = split_reg(path)?;
                let key = key.replace("{ControlSet}", &cs);
                let hive = match root_kind {
                    Root::Software => &software,
                    Root::System => &system,
                    Root::DefaultUser => &user,
                    Root::DotDefault => &dot_default,
                    Root::LocalService | Root::NetworkService => {
                        match if root_kind == Root::LocalService { &local_service } else { &network_service } {
                            Some(h) => h,
                            None => {
                                f("offline-impossible", "service profile hive does not exist in the install image".into());
                                continue;
                            }
                        }
                    }
                };
                let name = op.name.clone().unwrap_or_default();
                let current = hive.get(&key, &name).ok().flatten();
                let now = match (&current, hive.key(&key)?.is_some()) {
                    (Some(d), _) => format!("image: {}", reg_text(d)),
                    (None, true) => "image: key present, value absent".into(),
                    (None, false) => "image: key absent".into(),
                };
                let lower = path.to_ascii_lowercase();
                // ADMX keys are relative to HKLM / HKCU; a few policies live outside a Policies key
                let rel_for_admx = match root_kind {
                    Root::Software => format!(r"Software\{key}"),
                    Root::System => format!(r"System\{}", key.replacen(&cs, "CurrentControlSet", 1)),
                    _ => key.clone(),
                };
                let admx_hit = !op.delete_key && !pol.lookup(&rel_for_admx, op.name.as_deref().unwrap_or_default()).is_empty();
                if (lower.contains("\\policies\\") || admx_hit) && !op.delete_key {
                    // ADMX keys are relative to HKLM / HKCU
                    let rel = match root_kind {
                        Root::Software => format!(r"Software\{key}"),
                        Root::System => format!(r"System\{}", key.replacen(&cs, "CurrentControlSet", 1)),
                        _ => key.clone(),
                    };
                    let want_class = if matches!(root_kind, Root::Software | Root::System) { "Machine" } else { "User" };
                    let value = if op.delete { "<delete>".to_string() } else { op.data()?.map(|d| reg_text(&d)).unwrap_or_default() };
                    let hits = pol.lookup(&rel, &name);
                    if hits.is_empty() {
                        not_policy(&mut f, format!("no ADMX policy writes this value; {now}"));
                    } else if hits.iter().any(|h| (h.class == want_class || h.class == "Both") && crate::admx::fits(&h.allowed, &value)) {
                        let all: Vec<String> = hits
                            .iter()
                            .filter(|h| (h.class == want_class || h.class == "Both") && crate::admx::fits(&h.allowed, &value))
                            .map(|h| format!("{} \"{}\"", h.policy, h.display))
                            .collect();
                        f("ok", format!("ADMX {}; {now}", all.join(", ")));
                    } else if hits.iter().any(|h| crate::admx::fits(&h.allowed, &value)) {
                        let h = hits[0];
                        f("policy-class", format!("ADMX {} is class {}, op writes {want_class}; {now}", h.policy, h.class));
                    } else {
                        let h = hits[0];
                        f("policy-value", format!("ADMX {} allows {:?}, op writes {value}; {now}", h.policy, h.allowed));
                    }
                } else if op.delete_key {
                    f(if hive.key(&key)?.is_some() { "ok" } else { "info" }, now);
                } else if op.delete {
                    f(if current.is_some() { "ok" } else { "info" }, now);
                } else {
                    let want = op.data()?.map(|d| reg_text(&d)).unwrap_or_default();
                    if current.as_ref().map(reg_text).as_deref() == Some(want.as_str()) {
                        f("info", format!("already the image default; {now}"));
                    } else {
                        not_policy(&mut f, now);
                    }
                }
            } else if let Some(svc) = &op.service {
                match system.key(&format!(r"{cs}\Services\{svc}"))? {
                    Some(_) => {
                        let start = system.get(&format!(r"{cs}\Services\{svc}"), "Start")?.and_then(|d| d.as_dword());
                        f("ok", format!("image: Start={start:?}"));
                    }
                    None => f("missing", "service not in the image".into()),
                }
            } else if let Some(t) = &op.task {
                let rel = t.trim_start_matches('\\').replace('\\', "/");
                let file = tasks_dir.as_ref().and_then(|d| lean11_wim::resolve_ci(d, &rel));
                let tree = software.key(&format!(r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree{t}"))?;
                match tree {
                    None => f("missing", if file.is_some() { "task XML without TaskCache entry".into() } else { "task not in the image".into() }),
                    Some(node) => {
                        let id = software.value(node, "Id")?.and_then(|d| d.as_string()).unwrap_or_default();
                        let trig = software.get(&format!(r"{TASKCACHE}\Tasks\{id}"), "Triggers")?;
                        let enabled = trig.as_ref().and_then(|t| t.data.get(0x28..0x2c)).map(|b| u32::from_le_bytes(b.try_into().unwrap()) & 0x0040_0000 != 0);
                        match enabled {
                            Some(true) => f("ok", format!("task present, enabled{}", if file.is_some() { ", XML present" } else { "" })),
                            Some(false) => f("info", "task already disabled in the image".into()),
                            None => f("missing", "task without Triggers blob".into()),
                        }
                    }
                }
            } else if let Some(prog) = &op.firewall_block {
                let rel = prog.replacen("%SystemRoot%", "Windows", 1).replace('\\', "/");
                let rules = system.key(&format!(r"{cs}\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"))?.is_some();
                match (lean11_wim::resolve_ci(root, &rel).is_some_and(|p| p.is_file()), rules) {
                    (true, true) => f("ok", "program present in the image".into()),
                    (false, _) => f("missing", "program not in the image".into()),
                    (true, false) => f("missing", "image has no firewall rule store".into()),
                }
            } else if op.hosts.is_some() {
                f("ok", String::new());
            }
        }
    }
    Ok(out)
}

/// Validates the embedded catalog: unique ids, known categories, conditions and conflicts, well-formed ops.
pub fn validate_catalog(c: &Catalog) -> Result<()> {
    let mut cats = BTreeSet::new();
    for cat in &c.category {
        if !cats.insert(cat.id.as_str()) {
            bail!("duplicate category {}", cat.id);
        }
    }
    for cat in &c.category {
        if let Some(p) = &cat.parent {
            if !cats.contains(p.as_str()) {
                bail!("category {} has unknown parent {p}", cat.id);
            }
        }
    }
    let ids: BTreeSet<&str> = c.setting.iter().map(|s| s.id.as_str()).collect();
    if ids.len() != c.setting.len() {
        let mut seen = BTreeSet::new();
        let dup = c.setting.iter().find(|s| !seen.insert(s.id.as_str())).map(|s| s.id.as_str());
        bail!("duplicate setting id {dup:?}");
    }
    for s in &c.setting {
        let ctx = || format!("setting {}", s.id);
        if !s.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            bail!("setting id {} must be lower-case kebab-case", s.id);
        }
        if !cats.contains(s.category.as_str()) {
            bail!("setting {} has unknown category {}", s.id, s.category);
        }
        if s.title.trim().is_empty() || s.description.trim().is_empty() || s.verified.trim().is_empty() {
            bail!("setting {} needs title, description and verified", s.id);
        }
        if s.ops.is_empty() {
            bail!("setting {} has no ops", s.id);
        }
        for c in &s.hidden_if {
            Condition::parse(c).with_context(ctx)?;
        }
        if let Some(e) = s.evidence.iter().find(|e| !matches!(e.as_str(), "doc" | "vm")) {
            bail!("setting {} has unknown evidence {e} (doc, vm)", s.id);
        }
        for x in &s.conflicts {
            if !ids.contains(x.as_str()) || x == &s.id {
                bail!("setting {} conflicts with unknown {x}", s.id);
            }
        }
        for op in &s.ops {
            op.validate().with_context(ctx)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_is_valid() {
        let c: Catalog = toml::from_str(CATALOG).expect("parse");
        validate_catalog(&c).unwrap();
        // conflicts are mutual
        for s in &c.setting {
            for x in &s.conflicts {
                let o = c.setting.iter().find(|o| &o.id == x).unwrap();
                assert!(o.conflicts.contains(&s.id), "{} conflicts with {x} but not back", s.id);
            }
        }
    }

    #[test]
    fn registry_paths() {
        assert_eq!(split_reg(r"HKLM\SOFTWARE\Policies\X").unwrap(), (Root::Software, r"Policies\X".into()));
        assert_eq!(split_reg(r"HKLM\SYSTEM\CurrentControlSet\Services\X").unwrap(), (Root::System, r"{ControlSet}\Services\X".into()));
        assert_eq!(split_reg(r"HKCU\Software\X").unwrap(), (Root::DefaultUser, r"Software\X".into()));
        assert_eq!(split_reg(r"HKEY_USERS\.DEFAULT\Control Panel").unwrap(), (Root::DotDefault, "Control Panel".into()));
        assert!(split_reg(r"HKLM\SAM\X").is_err());
    }

    #[test]
    fn task_crc_matches_windows() {
        // CRC-32 as found in a 26H2 JobBucket: plain IEEE CRC without the final inversion
        assert_eq!(crc32_raw(b"123456789"), !0xCBF4_3926);
    }

    #[test]
    fn task_xml_disable() {
        let x = "<Task>\r\n  <Settings>\r\n    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n  </Settings>\r\n  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>\r\n</Task>";
        let d = disable_in_xml(x).unwrap();
        assert!(d.contains("<Settings>\r\n    <Enabled>false</Enabled>\r\n    <StopIf"));
        assert!(d.contains("<BootTrigger><Enabled>true</Enabled>"), "trigger untouched");
        assert_eq!(disable_in_xml(&d).unwrap(), d, "idempotent");
        let e = x.replace("<Settings>\r\n", "<Settings>\r\n    <Enabled>true</Enabled>\r\n");
        assert!(disable_in_xml(&e).unwrap().contains("<Enabled>false</Enabled>\r\n    <StopIf"));
        // compact XML: inserted inside Settings, not after it
        assert_eq!(disable_in_xml("<Task><Settings></Settings></Task>").unwrap(), "<Task><Settings><Enabled>false</Enabled></Settings></Task>");
    }

    #[test]
    fn after_setup_script_lines() {
        let list: Vec<&Setting> = catalog().setting.iter().filter(|s| s.ops.iter().any(|o| o.after_setup)).collect();
        assert!(!list.is_empty());
        let s = after_setup_script(&list).unwrap();
        assert!(s.contains("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v \"RestrictAnonymous\" /t REG_DWORD /d \"1\" /f"), "{s}");
        assert!(s.contains("reg load HKU\\Lean11Default") && s.contains("HKU\\Lean11Default\\Control Panel\\International\\User Profile"), "{s}");
        assert!(s.contains("reg add \"HKCU\\Control Panel\\International\\User Profile\""), "first account too: {s}");
        assert!(s.find("goto lean11default").unwrap() < s.find("reg add \"HKCU").unwrap() && s.find(":lean11default").unwrap() < s.find("reg load").unwrap(), "{s}");
        assert!(after_setup_script(&[]).is_none());
        let u = after_setup_user_script(&list).unwrap();
        assert!(u.contains("HKCU\\Control Panel") && !u.contains("HKLM"), "{u}");
        // Registry.pol: header + machine entries only, idempotent append
        let e = registry_pol_entries(&list).unwrap();
        let pol = registry_pol(None, &e).unwrap();
        assert!(pol.starts_with(b"PReg\x01\x00\x00\x00"));
        let key: Vec<u8> = "SYSTEM\\CurrentControlSet\\Control\\Lsa".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(pol.windows(key.len()).any(|w| w == key.as_slice()));
        let hkcu: Vec<u8> = "International".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(!pol.windows(hkcu.len()).any(|w| w == hkcu.as_slice()), "no HKCU values in the machine policy");
        assert_eq!(registry_pol(Some(&pol), &e).unwrap(), pol);
        assert!(registry_pol(Some(b"junk"), &e).is_err());
        // gpt.ini: extension added once, machine version raised
        let g = gpt_ini(None);
        assert!(g.contains("gPCMachineExtensionNames=[{35378EAC") && g.contains("Version=1"), "{g}");
        let g2 = gpt_ini(Some("[General]\r\ngPCUserExtensionNames=[{A}{B}]\r\nVersion=65538\r\n"));
        assert!(g2.contains("Version=65539") && g2.contains("gPCUserExtensionNames=[{A}{B}]"), "{g2}");
        assert_eq!(gpt_ini(Some(&g)).matches("35378EAC").count(), 1);
        // only the [General] section counts, keys in any case
        let g3 = gpt_ini(Some("[General]\r\nversion=3\r\n[Other]\r\nVersion=9\r\n"));
        assert!(g3.starts_with("[General]\r\nVersion=4\r\ngPCMachineExtensionNames=") || g3.contains("[General]\r\nVersion=4"), "{g3}");
        assert!(g3.contains("[Other]\r\nVersion=9"), "{g3}");
        // a stale copy of our entries earlier in the file does not count: they are appended again
        let mixed = registry_pol(Some(&registry_pol(Some(&pol), &[0x5b, 0x00, 0x5d, 0x00]).unwrap()), &e).unwrap();
        assert!(mixed.ends_with(&e));

    }

    #[test]
    fn hosts_unterminated_block_keeps_entries() {
        let names: BTreeSet<String> = ["a.example".to_string()].into();
        let broken = "# >>> lean11 privacy\r\n0.0.0.0 old.example\r\n10.0.0.1 nas\r\n";
        let out = hosts_file(broken, &names);
        assert!(out.contains("10.0.0.1 nas\r\n") && out.contains("0.0.0.0 a.example\r\n"));
        assert_eq!(hosts_file(&out, &names), out, "idempotent after repair");
    }

    #[test]
    fn check_script_quotes_catalog_text() {
        let c = parse_catalog(
            r#"
[[category]]
id = "x"
title = "X"
[[setting]]
id = "q"
category = "x"
title = "t"
description = "d"
level = "optional"
verified = "v"
ops = [{ reg = 'HKLM\SOFTWARE\Policies\A', name = "N", sz = "$(evil) it's" }]
"#,
        )
        .unwrap();
        let s = check_script(&[&c.setting[0]]);
        assert!(s.contains("'$(evil) it''s'"), "{s}");
        assert!(!s.contains("\"$(evil)"), "no catalog text in double quotes: {s}");
    }

    #[test]
    fn hosts_block_is_replaced() {
        let names: BTreeSet<String> = ["a.example".to_string(), "b.example".to_string()].into();
        let once = hosts_file("# default\r\n127.0.0.1 localhost\r\n", &names);
        let twice = hosts_file(&once, &names);
        assert_eq!(once, twice);
        assert!(once.contains("0.0.0.0 a.example\r\n"));
        assert_eq!(hosts_file(&once, &BTreeSet::new()), "# default\r\n127.0.0.1 localhost\r\n");
    }
}
