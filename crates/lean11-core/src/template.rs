//! Templates: everything chosen for a build (mode, Components options, privacy settings, custom actions
//! and settings) without the source, edition and output, so the same choice can be applied to another
//! ISO. Recipes stay the full, image-bound record of one build.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::build::Recipe;
use crate::catalog::{self, Mode};
use crate::inventory::Action;
use lean11_wim::Compression;

/// Format version written into every template.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Marks the file as a lean11 template (format version).
    pub lean11_template: u32,
    pub mode: Mode,
    /// Core's removals in a Custom build.
    #[serde(default)]
    pub core: bool,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub privacy: Vec<String>,
    /// Additional programs (ids of `data/software.toml`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub software: Vec<String>,
    /// Custom actions; on another image they are matched by name without version (see
    /// `inventory::adapt`).
    #[serde(default)]
    pub actions: Vec<Action>,
    pub compression: Compression,
    pub local_account: bool,
    pub compact: bool,
    #[serde(default)]
    pub no_prompt: bool,
    #[serde(default)]
    pub omit_sxs: bool,
    #[serde(default)]
    pub remove_redundant_data: bool,
    #[serde(default)]
    pub turbo: bool,
    #[serde(default)]
    pub ssh_authorized_key: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// The acknowledgements given when the template was made (Core, custom actions).
    #[serde(default)]
    pub core_acknowledged: bool,
    #[serde(default)]
    pub expert_acknowledged: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub breaking_acknowledged: bool,
}

impl Template {
    pub fn from_recipe(r: &Recipe) -> Self {
        // a changed preset is saved as what it builds (Custom), like a build would treat it
        let mut n = r.clone();
        n.normalize_mode();
        let r = &n;
        Template {
            lean11_template: VERSION,
            mode: r.mode,
            core: r.core,
            options: r.options.clone(),
            privacy: r.privacy.clone(),
            software: r.software.clone(),
            actions: r.actions.clone(),
            compression: r.compression,
            local_account: r.local_account,
            compact: r.compact,
            no_prompt: r.no_prompt,
            omit_sxs: r.omit_sxs,
            remove_redundant_data: r.remove_redundant_data,
            turbo: r.turbo,
            ssh_authorized_key: r.ssh_authorized_key.clone(),
            label: r.label.clone(),
            core_acknowledged: r.core_acknowledged,
            expert_acknowledged: r.expert_acknowledged,
            breaking_acknowledged: r.breaking_acknowledged,
        }
    }

    /// Puts the template's choice into a recipe (source, edition, output and working options stay).
    /// Ids this version does not know are left out and named in the returned notes; custom actions are
    /// marked for matching against the image the build uses.
    pub fn apply(&self, r: &mut Recipe) -> Vec<String> {
        let mut notes = Vec::new();
        r.mode = self.mode;
        r.core = self.core;
        r.options = self
            .options
            .iter()
            .filter(|id| {
                let known = catalog::option(id).is_some();
                if !known {
                    notes.push(format!("unknown Components option {id} left out"));
                }
                known
            })
            .cloned()
            .collect();
        r.privacy = self
            .privacy
            .iter()
            .filter(|id| {
                let known = crate::privacy::setting(id).is_some();
                if !known {
                    notes.push(format!("unknown privacy setting {id} left out"));
                }
                known
            })
            .cloned()
            .collect();
        r.software = self
            .software
            .iter()
            .filter(|id| {
                let known = crate::software::program(id).is_some();
                if !known {
                    notes.push(format!("unknown software {id} left out"));
                }
                known
            })
            .cloned()
            .collect();
        r.actions = self.actions.clone();
        r.adapt_actions = !self.actions.is_empty();
        r.compression = self.compression;
        r.local_account = self.local_account;
        r.compact = self.compact;
        r.no_prompt = self.no_prompt;
        r.omit_sxs = self.omit_sxs;
        r.remove_redundant_data = self.remove_redundant_data;
        r.turbo = self.turbo;
        r.ssh_authorized_key = self.ssh_authorized_key.clone();
        r.label = self.label.clone();
        r.core_acknowledged = self.core_acknowledged;
        r.expert_acknowledged = self.expert_acknowledged;
        r.breaking_acknowledged = self.breaking_acknowledged;
        r.normalize_mode();
        notes
    }

    /// Reads a template; a saved recipe is accepted too (its source, edition and output are ignored).
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| format!("{} is not JSON", path.display()))?;
        if v.get("lean11_template").is_some() {
            let t: Template = serde_json::from_value(v).with_context(|| format!("{} is not a valid lean11 template", path.display()))?;
            if t.lean11_template > VERSION {
                bail!("{} is a template of a newer lean11 (format {}); update lean11", path.display(), t.lean11_template);
            }
            Ok(t)
        } else if v.get("source").is_some() {
            let r: Recipe = serde_json::from_value(v).with_context(|| format!("{} is neither a template nor a recipe", path.display()))?;
            Ok(Template::from_recipe(&r))
        } else {
            bail!("{} is not a lean11 template", path.display())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?).with_context(|| format!("cannot write {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::recipe_for;
    use crate::inventory::{Kind, Mode as ActMode};
    use std::path::PathBuf;

    #[test]
    fn round_trip_keeps_the_choice_not_the_image() {
        let mut r = recipe_for(Mode::Lean, PathBuf::from("/a/old.iso"), PathBuf::from("/a/old-out.iso"));
        r.options.push("disable-defender".into());
        r.privacy = vec!["diagnostic-data-off".into()];
        r.actions = vec![Action { kind: Kind::Service, identity: "DiagTrack".into(), mode: ActMode::Disable }];
        r.expert_acknowledged = true;
        let t = Template::from_recipe(&r);
        assert_eq!(t.mode, Mode::Custom);
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("old.iso") && !json.contains("old-out"));
        let mut n = recipe_for(Mode::Lean, PathBuf::from("/b/new.iso"), PathBuf::from("/b/out.iso"));
        let back: Template = serde_json::from_str(&json).unwrap();
        let notes = back.apply(&mut n);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(n.source, PathBuf::from("/b/new.iso"));
        assert_eq!(n.mode, Mode::Custom);
        assert_eq!(n.privacy, r.privacy);
        assert_eq!(n.actions, r.actions);
        assert!(n.adapt_actions && n.expert_acknowledged);
        n.validate().unwrap();
    }

    #[test]
    fn label_follows_the_template() {
        let mut r = recipe_for(Mode::Custom, PathBuf::from("x.iso"), PathBuf::from("y.iso"));
        r.label = Some("OLD".into());
        let mut t = Template::from_recipe(&r);
        t.label = None;
        t.apply(&mut r);
        assert_eq!(r.label, None);
    }

    #[test]
    fn unknown_ids_are_reported() {
        let mut r = recipe_for(Mode::Custom, PathBuf::from("x.iso"), PathBuf::from("y.iso"));
        let mut t = Template::from_recipe(&r);
        t.options.push("no-such-option".into());
        t.privacy.push("no-such-setting".into());
        let notes = t.apply(&mut r);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(!r.options.iter().any(|o| o == "no-such-option"));
    }
}
