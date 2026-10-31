//! Knowledge base: a safety rating and a precise description for catalog options, privacy settings and
//! inventory items (`data/knowledge.toml`, compiled into the binary).
//!
//! Ratings: safe = Windows and its setup keep working and nothing visible is lost; limited = Windows keeps
//! working, but the item's function (or functions depending on it) is gone or impaired; breaks = setup or
//! Windows itself fails (proven by a test install or documented). Items without an entry are unrated.

use crate::inventory::Kind;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const DATA: &str = include_str!("../data/knowledge.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rating {
    Safe,
    Limited,
    Breaks,
}

impl Rating {
    pub fn label(self) -> &'static str {
        match self {
            Rating::Safe => "safe",
            Rating::Limited => "limited",
            Rating::Breaks => "breaks",
        }
    }
}

/// What an entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Subject {
    /// A catalog option (Components step), matched by its id.
    Option,
    /// A privacy setting, matched by its id.
    Privacy,
    ProvisionedApp,
    SystemApp,
    Feature,
    Capability,
    Package,
    Service,
    ComponentPayload,
}

impl From<Kind> for Subject {
    fn from(k: Kind) -> Self {
        match k {
            Kind::ProvisionedApp => Subject::ProvisionedApp,
            Kind::SystemApp => Subject::SystemApp,
            Kind::Feature => Subject::Feature,
            Kind::Capability => Subject::Capability,
            Kind::Package => Subject::Package,
            Kind::Service => Subject::Service,
            Kind::ComponentPayload => Subject::ComponentPayload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub kind: Subject,
    /// Case-insensitive patterns (`*` = any text) tested against the identity and the readable name.
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    pub rating: Rating,
    /// What the item is.
    pub what: String,
    /// What removing or disabling it does.
    pub effect: String,
    /// Evidence for the rating (documentation, analysis of the image, test install).
    pub verified: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    entry: Vec<Entry>,
}

/// The knowledge base compiled into the binary.
pub fn entries() -> &'static [Entry] {
    static K: OnceLock<Vec<Entry>> = OnceLock::new();
    K.get_or_init(|| parse(DATA).expect("data/knowledge.toml is invalid"))
}

pub fn parse(text: &str) -> Result<Vec<Entry>> {
    let f: File = toml::from_str(text).context("knowledge base")?;
    for e in &f.entry {
        if e.patterns.is_empty() || e.patterns.iter().any(|p| p.trim().is_empty()) {
            bail!("knowledge entry without pattern ({:?})", e.what);
        }
        if e.what.trim().is_empty() || e.effect.trim().is_empty() || e.verified.trim().is_empty() {
            bail!("knowledge entry {:?}: what, effect and verified are required", e.patterns);
        }
    }
    Ok(f.entry)
}

/// Case-insensitive (Unicode) glob match with `*` only.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 {
        return p == t;
    }
    let mut rest = t.as_str();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(pos) => rest = &rest[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Specificity of a pattern: an exact pattern beats any glob, a longer literal part beats a shorter one.
fn specificity(pattern: &str) -> usize {
    if pattern.contains('*') { pattern.len() - pattern.matches('*').count() } else { usize::MAX }
}

/// The most specific entry for a subject whose pattern matches one of `keys` (identity, readable name).
pub fn lookup_in<'a>(entries: &'a [Entry], kind: Subject, keys: &[&str]) -> Option<&'a Entry> {
    entries
        .iter()
        .filter(|e| e.kind == kind)
        .filter_map(|e| {
            e.patterns
                .iter()
                .filter(|p| keys.iter().any(|k| !k.is_empty() && glob(p, k)))
                .map(|p| specificity(p))
                .max()
                .map(|s| (s, e))
        })
        .max_by_key(|(s, _)| *s)
        .map(|(_, e)| e)
}

pub fn lookup(kind: Subject, keys: &[&str]) -> Option<&'static Entry> {
    lookup_in(entries(), kind, keys)
}

/// Rating of a catalog option (every option has an entry, see the tests).
pub fn option_rating(id: &str) -> Option<Rating> {
    lookup(Subject::Option, &[id]).map(|e| e.rating)
}

/// Rating of a privacy setting: its own entry, else from its level (recommended loses nothing visible,
/// strict and optional cost a feature by definition of the levels).
pub fn privacy_rating(s: &crate::privacy::Setting) -> Rating {
    match lookup(Subject::Privacy, &[&s.id]) {
        Some(e) => e.rating,
        None if s.level == crate::privacy::Level::Recommended => Rating::Safe,
        None => Rating::Limited,
    }
}

/// The chosen options, privacy settings and custom actions rated `breaks`, as readable names. With the image's
/// inventory the actions are looked up by identity and readable name, without it by identity only.
pub fn breaking_choices(r: &crate::build::Recipe, items: Option<&[crate::inventory::Item]>) -> Vec<String> {
    let mut out = Vec::new();
    for id in &r.options {
        if option_rating(id) == Some(Rating::Breaks) {
            out.push(crate::catalog::option(id).map_or(id.clone(), |o| o.title.to_string()));
        }
    }
    for id in &r.privacy {
        if let Some(s) = crate::privacy::setting(id)
            && privacy_rating(s) == Rating::Breaks
        {
            out.push(s.title.clone());
        }
    }
    for a in &r.actions {
        let item = items.and_then(|items| items.iter().find(|i| i.kind == a.kind && i.identity == a.identity));
        let e = match item {
            Some(i) => self::item(i),
            None => lookup(a.kind.into(), &[&a.identity]),
        };
        if e.is_some_and(|e| e.rating == Rating::Breaks) {
            out.push(item.map_or(a.identity.clone(), |i| i.label().to_string()));
        }
    }
    out
}

/// Rating and entry of an inventory item, if known. A WinSxS component without an entry of its own takes the
/// entry of the packages that own it, when every owner is rated (the most severe one counts).
pub fn item(i: &crate::inventory::Item) -> Option<&'static Entry> {
    if let Some(e) = lookup(i.kind.into(), &[&i.identity, &i.name]) {
        return Some(e);
    }
    if i.kind != crate::inventory::Kind::ComponentPayload || i.owners.is_empty() {
        return None;
    }
    let owners: Vec<&'static Entry> = i.owners.iter().map(|o| lookup(Subject::Package, &[o])).collect::<Option<_>>()?;
    owners.into_iter().max_by_key(|e| e.rating)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_knowledge_parses() {
        assert!(!entries().is_empty());
    }

    #[test]
    fn every_catalog_option_is_rated() {
        let missing: Vec<&str> =
            crate::catalog::OPTIONS.iter().map(|o| o.id).filter(|id| lookup(Subject::Option, &[id]).is_none()).collect();
        assert!(missing.is_empty(), "options without knowledge entry: {missing:?}");
    }

    #[test]
    fn globs() {
        assert!(glob("microsoft.bingnews_*", "Microsoft.BingNews_4.1.2_x64__8wekyb3d8bbwe"));
        assert!(glob("*servicingstack*", "amd64_microsoft-windows-servicingstack_31bf"));
        assert!(glob("diagtrack", "DiagTrack"));
        assert!(!glob("diagtrack", "DiagTrack2"));
        assert!(!glob("a*b*c", "ab"));
        assert!(glob("a*b*c", "axbyc"));
        assert!(glob("*änderung*", "Änderungsdienst"));
    }

    #[test]
    fn most_specific_wins() {
        let e = parse(
            r#"
[[entry]]
kind = "service"
match = ["*"]
rating = "limited"
what = "any"
effect = "x"
verified = "x"
[[entry]]
kind = "service"
match = ["diag*"]
rating = "safe"
what = "diag"
effect = "x"
verified = "x"
[[entry]]
kind = "service"
match = ["diagtrack"]
rating = "safe"
what = "exact"
effect = "x"
verified = "x"
"#,
        )
        .unwrap();
        assert_eq!(lookup_in(&e, Subject::Service, &["DiagTrack"]).unwrap().what, "exact");
        assert_eq!(lookup_in(&e, Subject::Service, &["diagsvc"]).unwrap().what, "diag");
        assert_eq!(lookup_in(&e, Subject::Service, &["wuauserv"]).unwrap().what, "any");
        assert!(lookup_in(&e, Subject::Feature, &["DiagTrack"]).is_none());
    }
}
