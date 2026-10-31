//! Group Policy templates (ADMX/ADML) of an image, used to verify the privacy catalog: every value a
//! setting writes below a Policies key must be a value that a policy of this Windows release defines.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};

/// Values a policy element accepts.
#[derive(Debug, Clone, PartialEq)]
pub enum Allowed {
    /// Exact values (decimal as text, strings as is).
    Values(Vec<String>),
    /// Decimal range (inclusive).
    Range(u64, u64),
    /// Free text or list.
    Any,
}

#[derive(Debug, Clone)]
pub struct PolicyValue {
    /// Policy name and file ("AllowTelemetry (DataCollection.admx)").
    pub policy: String,
    /// Display name from the en-US ADML when present.
    pub display: String,
    /// Machine, User or Both.
    pub class: String,
    pub allowed: Allowed,
}

/// (lower-case key relative to HKLM/HKCU, lower-case value name) → policies that write it.
#[derive(Debug, Default)]
pub struct Policies {
    pub values: HashMap<(String, String), Vec<PolicyValue>>,
    pub files: usize,
}

fn val_of(n: roxmltree::Node) -> Option<String> {
    let v = n.children().find(|c| c.is_element())?;
    match v.tag_name().name() {
        "decimal" => v.attribute("value").map(str::to_string),
        "string" => Some(v.text().unwrap_or("").to_string()),
        "delete" => Some("<delete>".into()),
        _ => None,
    }
}

impl Policies {
    pub fn load(root: &Path) -> Result<Self> {
        let dir = lean11_wim::resolve_ci(root, "Windows/PolicyDefinitions").ok_or_else(|| anyhow!("image has no PolicyDefinitions"))?;
        let mut p = Policies::default();
        p.add_dir(&dir)?;
        Ok(p)
    }

    /// Adds the ADMX files of a folder (with its language subfolders), e.g. the Edge, Chrome or Firefox
    /// policy templates for settings of browsers that are not part of the image.
    pub fn add_dir(&mut self, dir: &Path) -> Result<()> {
        let p = self;
        // language folders, en-US first (per file: a localized image has only a few en-US files)
        let mut adml_dirs: Vec<std::path::PathBuf> = fs::read_dir(dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.file_name().is_some_and(|n| n.len() == 5 && n.to_string_lossy().as_bytes()[2] == b'-'))
            .collect();
        adml_dirs.sort_by_key(|p| !p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("en-US")));
        for e in fs::read_dir(dir)?.flatten() {
            let path = e.path();
            if !path.extension().is_some_and(|x| x.eq_ignore_ascii_case("admx")) {
                continue;
            }
            let Ok(raw) = fs::read(&path) else { continue };
            let text = decode(&raw);
            let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
            p.files += 1;
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            // display strings
            let adml_name = format!("{}.adml", file.rsplit_once('.').map(|(b, _)| b).unwrap_or(&file));
            let strings: HashMap<String, String> = adml_dirs
                .iter()
                .find_map(|d| lean11_wim::resolve_ci(d, &adml_name))
                .and_then(|a| fs::read(a).ok())
                .map(|b| decode(&b))
                .and_then(|t| {
                    let d = roxmltree::Document::parse(&t).ok()?;
                    Some(d.descendants().filter(|n| n.has_tag_name("string")).filter_map(|n| Some((n.attribute("id")?.to_string(), n.text().unwrap_or("").to_string()))).collect())
                })
                .unwrap_or_default();
            for pol in doc.descendants().filter(|n| n.has_tag_name("policy")) {
                let name = pol.attribute("name").unwrap_or("");
                let class = pol.attribute("class").unwrap_or("").to_string();
                let key = pol.attribute("key").unwrap_or("");
                let disp = pol
                    .attribute("displayName")
                    .and_then(|d| d.strip_prefix("$(string.")?.strip_suffix(')'))
                    .and_then(|id| strings.get(id).cloned())
                    .unwrap_or_default();
                let mk = |allowed: Allowed| PolicyValue { policy: format!("{name} ({file})"), display: disp.clone(), class: class.clone(), allowed };
                let mut add = |key: &str, vname: &str, allowed: Allowed| {
                    if key.is_empty() {
                        return;
                    }
                    let k = (key.to_ascii_lowercase(), vname.to_ascii_lowercase());
                    let entry = p.values.entry(k).or_default();
                    // merge exact values of the same policy (enabled + disabled value)
                    if let (Some(last), Allowed::Values(v)) = (entry.last_mut(), &allowed) {
                        if last.policy == format!("{name} ({file})") {
                            if let Allowed::Values(lv) = &mut last.allowed {
                                lv.extend(v.iter().cloned());
                                return;
                            }
                        }
                    }
                    entry.push(mk(allowed));
                };
                if let Some(vn) = pol.attribute("valueName") {
                    let mut vals = Vec::new();
                    for tag in ["enabledValue", "disabledValue"] {
                        if let Some(n) = pol.children().find(|c| c.has_tag_name(tag)) {
                            vals.extend(val_of(n));
                        }
                    }
                    if vals.is_empty() {
                        // no explicit values: enabled = 1, disabled = deleted (ADMX default)
                        vals = vec!["1".into(), "0".into(), "<delete>".into()];
                    }
                    add(key, vn, Allowed::Values(vals));
                }
                for list in ["enabledList", "disabledList"] {
                    for item in pol.children().filter(|c| c.has_tag_name(list)).flat_map(|l| l.children().filter(|c| c.has_tag_name("item"))) {
                        let k = item.attribute("key").unwrap_or(key);
                        if let (Some(vn), Some(v)) = (item.attribute("valueName"), item.children().find(|c| c.has_tag_name("value")).and_then(val_of)) {
                            add(k, vn, Allowed::Values(vec![v]));
                        }
                    }
                }
                for el in pol.children().filter(|c| c.has_tag_name("elements")).flat_map(|e| e.children().filter(|c| c.is_element())) {
                    let k = el.attribute("key").unwrap_or(key);
                    let vn = el.attribute("valueName").unwrap_or("");
                    match el.tag_name().name() {
                        "decimal" | "longDecimal" => {
                            let min = el.attribute("minValue").and_then(|v| v.parse().ok()).unwrap_or(0);
                            let max = el.attribute("maxValue").and_then(|v| v.parse().ok()).unwrap_or(u32::MAX as u64);
                            add(k, vn, Allowed::Range(min, max));
                        }
                        "enum" => {
                            let vals: Vec<String> = el.children().filter(|c| c.has_tag_name("item")).filter_map(|i| i.children().find(|c| c.has_tag_name("value")).and_then(val_of)).collect();
                            add(k, vn, Allowed::Values(vals));
                        }
                        "boolean" => {
                            let mut vals = Vec::new();
                            for t in ["trueValue", "falseValue"] {
                                if let Some(n) = el.children().find(|c| c.has_tag_name(t)) {
                                    vals.extend(val_of(n));
                                }
                            }
                            if vals.is_empty() {
                                vals = vec!["1".into(), "0".into()];
                            }
                            add(k, vn, Allowed::Values(vals));
                        }
                        "text" | "multiText" => add(k, vn, Allowed::Any),
                        "list" => add(k, "*", Allowed::Any),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Policies that write `key`/`name` (key relative to HKLM or HKCU). A list policy matches any name.
    pub fn lookup(&self, key: &str, name: &str) -> Vec<&PolicyValue> {
        let k = key.to_ascii_lowercase();
        let mut v: Vec<&PolicyValue> = self.values.get(&(k.clone(), name.to_ascii_lowercase())).map(|x| x.iter().collect()).unwrap_or_default();
        v.extend(self.values.get(&(k, "*".into())).into_iter().flatten());
        v
    }
}

/// ADMX/ADML files are UTF-8 or UTF-16 with BOM.
fn decode(raw: &[u8]) -> String {
    if raw.starts_with(&[0xff, 0xfe]) {
        let u: Vec<u16> = raw[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw)).into_owned()
    }
}

/// Does `value` fit `allowed`? `value` is the decimal or string form, `<delete>` for a deletion.
pub fn fits(allowed: &Allowed, value: &str) -> bool {
    match allowed {
        Allowed::Any => true,
        Allowed::Values(v) => v.iter().any(|x| x.eq_ignore_ascii_case(value)),
        Allowed::Range(lo, hi) => value.parse::<u64>().is_ok_and(|n| n >= *lo && n <= *hi),
    }
}
