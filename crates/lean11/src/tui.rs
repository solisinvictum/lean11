//! Terminal wizard: mode → source → edition → components → privacy → custom (inventory) → settings → review → build.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use lean11_core::build::{Builder, Recipe, recipe_for};
use lean11_core::catalog::{self, CleanupOption, Kind, Mode};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use lean11_core::inventory::{self, Action, Item, Kind as ItemKind, Mode as ActMode};
use lean11_core::knowledge::{self, Rating};
use lean11_wim::{Compression, ImageInfo};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Step {
    Mode,
    Source,
    Edition,
    Components,
    Privacy,
    Custom,
    Software,
    Settings,
    Review,
    Build,
}

const STEPS: [(Step, &str); 10] = [
    (Step::Mode, "Mode"),
    (Step::Source, "Source"),
    (Step::Edition, "Edition"),
    (Step::Components, "Components"),
    (Step::Privacy, "Privacy"),
    (Step::Custom, "Custom"),
    (Step::Software, "Software"),
    (Step::Settings, "Settings"),
    (Step::Review, "Review"),
    (Step::Build, "Build"),
];

const MODES: [(Mode, &str, &str); 3] = [
    (Mode::Lean, "Lean11", "Removes bundled apps and unwanted features while keeping updates, Defender and recovery."),
    (Mode::Core, "Lean11 Core", "Trims further: removes the component store and recovery, disables Windows Update and Defender. Not serviceable, for test VMs only."),
    (Mode::Custom, "Custom", "Starts with nothing selected; choose individual apps, features and settings."),
];

enum Msg {
    Line(String),
    Progress(u64, Option<u64>),
    Done(std::result::Result<PathBuf, String>),
}

struct Task {
    rx: Receiver<Msg>,
    /// Stop request for a build (checked at stage boundaries).
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    lines: Vec<String>,
    progress: Option<(u64, Option<u64>)>,
    result: Option<std::result::Result<PathBuf, String>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Field {
    Source,
    Output,
    Work,
    Language,
    Filter,
    SaveRecipe,
    LoadRecipe,
    SshKey,
    PrivacyFilter,
    SaveTemplate,
    LoadTemplate,
}

/// A row of the privacy step: a category heading or a setting with its state for the current recipe.
enum PrivRow {
    Head(&'static lean11_core::privacy::Category, String),
    Item(&'static lean11_core::privacy::Setting, lean11_core::privacy::Status),
}

const ITEM_KINDS: [(ItemKind, &str); 7] = [
    (ItemKind::ProvisionedApp, "Apps"),
    (ItemKind::Feature, "Features"),
    (ItemKind::Capability, "Capabilities"),
    (ItemKind::Package, "Packages"),
    (ItemKind::Service, "Services"),
    (ItemKind::SystemApp, "System apps"),
    (ItemKind::ComponentPayload, "WinSxS payloads"),
];

struct App {
    step: Step,
    mode: Mode,
    mode_state: ListState,
    core_ack: bool,
    confirm_core: bool,
    /// Index of an irreversible option waiting for confirmation
    confirm_option: Option<usize>,
    /// Core's removals added to a Custom build.
    core_removals: bool,
    source: String,
    language: String,
    editions: Vec<ImageInfo>,
    ed_state: ListState,
    options: Vec<(&'static CleanupOption, bool)>,
    opt_state: ListState,
    compression: Compression,
    local_account: bool,
    compact: bool,
    no_prompt: bool,
    omit_sxs: bool,
    remove_redundant_data: bool,
    /// Public key file for the OpenSSH option (Custom); empty = off
    ssh_key: String,
    /// Key text from a loaded recipe (when no file is chosen)
    ssh_key_text: Option<String>,
    turbo: bool,
    keep_work: bool,
    output: String,
    work: String,
    set_state: ListState,
    inv: Vec<Item>,
    inv_task: Option<Receiver<(ImageKey, std::result::Result<Vec<Item>, String>)>>,
    /// Source and edition the inventory and custom actions belong to.
    inv_key: Option<ImageKey>,
    inv_kind: usize,
    inv_filter: String,
    inv_state: ListState,
    actions: Vec<Action>,
    /// Custom actions of an imported template: matched to the image's inventory once it is read (and
    /// again after the image changes)
    template_actions: Option<Vec<Action>>,
    /// `actions` still hold the template's identities (no inventory to match them yet)
    actions_pending: bool,
    /// Chosen privacy setting ids; settings hidden by the current Components choice stay chosen
    /// but are left out of the recipe
    privacy: Vec<String>,
    priv_filter: String,
    priv_state: ListState,
    /// Chosen additional programs (ids of the software catalog)
    software: Vec<String>,
    sw_state: ListState,
    expert_ack: bool,
    confirm_expert: bool,
    /// Red choices were accepted (popup before the build).
    breaking_ack: bool,
    confirm_breaking: bool,
    editing: Option<(Field, String)>,
    /// File browser for a path field
    picker: Option<(Field, crate::picker::Picker)>,
    message: Option<String>,
    download: Option<Task>,
    build: Option<Task>,
    quit: bool,
}

impl App {
    fn new(source: Option<PathBuf>) -> Self {
        let lang = std::env::var("LANG").ok().and_then(|l| l.split('.').next().map(|s| s.replace('_', "-"))).unwrap_or_else(|| "en-US".into());
        let mut a = App {
            step: Step::Mode,
            mode: Mode::Lean,
            mode_state: ListState::default().with_selected(Some(0)),
            core_ack: false,
            confirm_core: false,
            confirm_option: None,
            core_removals: false,
            source: source.map(|p| p.display().to_string()).unwrap_or_default(),
            language: lang,
            editions: Vec::new(),
            ed_state: ListState::default(),
            options: catalog::OPTIONS.iter().map(|o| (o, false)).collect(),
            opt_state: ListState::default().with_selected(Some(0)),
            compression: Compression::Recovery,
            local_account: true,
            compact: true,
            no_prompt: false,
            omit_sxs: false,
            remove_redundant_data: false,
            ssh_key: String::new(),
            ssh_key_text: None,
            turbo: false,
            keep_work: false,
            output: "lean11.iso".into(),
            work: String::new(),
            set_state: ListState::default().with_selected(Some(0)),
            inv: Vec::new(),
            inv_task: None,
            inv_key: None,
            inv_kind: 0,
            inv_filter: String::new(),
            inv_state: ListState::default().with_selected(Some(0)),
            actions: Vec::new(),
            template_actions: None,
            actions_pending: false,
            privacy: Vec::new(),
            priv_filter: String::new(),
            priv_state: ListState::default().with_selected(Some(0)),
            software: Vec::new(),
            sw_state: ListState::default().with_selected(Some(0)),
            expert_ack: false,
            confirm_expert: false,
            breaking_ack: false,
            confirm_breaking: false,
            editing: None,
            picker: None,
            message: None,
            download: None,
            build: None,
            quit: false,
        };
        a.apply_mode(Mode::Lean);
        a
    }

    fn apply_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.core_removals = false;
        let sel = catalog::for_mode(mode);
        for (o, on) in self.options.iter_mut() {
            *on = sel.contains(&o.id);
        }
        self.output = if mode == Mode::Core { "lean11-core.iso".into() } else { "lean11.iso".into() };
    }

    fn recipe(&self) -> Recipe {
        self.recipe_with(true)
    }

    /// `read_key = false` skips reading the SSH key file (privacy status checks run on every frame and do
    /// not depend on it).
    fn recipe_with(&self, read_key: bool) -> Recipe {
        let mut r = recipe_for(self.mode, PathBuf::from(&self.source), PathBuf::from(&self.output));
        r.options = self.options.iter().filter(|(_, on)| *on).map(|(o, _)| o.id.to_string()).collect();
        r.edition = self.ed_state.selected().and_then(|i| self.editions.get(i)).map(|e| e.index.to_string());
        r.compression = self.compression;
        r.local_account = self.local_account;
        r.compact = self.compact;
        r.no_prompt = self.no_prompt;
        r.omit_sxs = self.omit_sxs;
        r.remove_redundant_data = self.remove_redundant_data;
        if self.mode == Mode::Custom && read_key {
            if !self.ssh_key.trim().is_empty() {
                // an unreadable file shows up as an invalid key in validation
                r.ssh_authorized_key = Some(std::fs::read_to_string(self.ssh_key.trim()).map(|k| k.trim().to_string()).unwrap_or_default());
            } else {
                r.ssh_authorized_key = self.ssh_key_text.clone();
            }
        }
        r.core_acknowledged = self.core_ack;
        r.core = self.mode == Mode::Core || (self.mode == Mode::Custom && self.core_removals);
        r.turbo = self.turbo;
        r.actions = self.actions.clone();
        // template actions not yet matched to an inventory are matched by the build
        r.adapt_actions = self.actions_pending;
        r.expert_acknowledged = self.expert_ack;
        r.breaking_acknowledged = self.breaking_ack;
        r.keep_work = self.keep_work;
        // catalog order; settings pointless for this recipe (component gone, already set) are left out
        r.privacy = lean11_core::privacy::catalog()
            .setting
            .iter()
            .filter(|s| self.privacy.contains(&s.id) && lean11_core::privacy::status(s, &r) == lean11_core::privacy::Status::Available)
            .map(|s| s.id.clone())
            .collect();
        // catalog order
        r.software = lean11_core::software::catalog().iter().filter(|p| self.software.contains(&p.id)).map(|p| p.id.clone()).collect();
        r
    }

    /// Space in the Software step: adds or removes the program under the cursor (a preset becomes Custom).
    fn toggle_software(&mut self) {
        let Some(p) = self.sw_state.selected().and_then(|i| lean11_core::software::catalog().get(i)) else { return };
        self.make_custom();
        if self.software.contains(&p.id) {
            self.software.retain(|x| x != &p.id);
        } else {
            self.software.push(p.id.clone());
        }
    }

    /// A changed preset becomes Custom and keeps Core's removals if they were on.
    fn make_custom(&mut self) {
        if self.mode != Mode::Custom {
            self.core_removals = self.mode == Mode::Core;
            self.mode = Mode::Custom;
            self.mode_state.select(MODES.iter().position(|(m, ..)| *m == Mode::Custom));
            self.message = Some("Changed selection: building as Custom.".into());
        }
    }

    fn privacy_rows(&self) -> Vec<PrivRow> {
        use lean11_core::privacy;
        let r = self.recipe_with(false);
        let f = self.priv_filter.trim().to_lowercase();
        let mut rows = Vec::new();
        for c in &privacy::catalog().category {
            let path = privacy::category_path(&c.id);
            let items: Vec<PrivRow> = privacy::catalog()
                .setting
                .iter()
                .filter(|s| s.category == c.id)
                .filter(|s| {
                    f.is_empty() || [&s.id, &s.title, &s.description, &path].iter().any(|t| t.to_lowercase().contains(&f))
                })
                .map(|s| PrivRow::Item(s, privacy::status(s, &r)))
                .collect();
            if !items.is_empty() {
                rows.push(PrivRow::Head(c, path));
                rows.extend(items);
            }
        }
        rows
    }

    /// Selects one setting and drops the ones it contradicts.
    fn privacy_on(&mut self, s: &lean11_core::privacy::Setting) {
        if self.privacy.contains(&s.id) {
            return;
        }
        let dropped: Vec<String> = self.privacy.iter().filter(|o| s.conflicts.contains(*o) || lean11_core::privacy::setting(o).is_some_and(|x| x.conflicts.contains(&s.id))).cloned().collect();
        self.privacy.retain(|o| !dropped.contains(o));
        self.privacy.push(s.id.clone());
        if !dropped.is_empty() {
            self.message = Some(format!("Turned off {} (contradicts {}).", dropped.join(", "), s.id));
        }
    }

    fn toggle_privacy(&mut self) {
        use lean11_core::privacy::Status;
        let rows = self.privacy_rows();
        let Some(i) = self.priv_state.selected() else { return };
        match rows.get(i) {
            Some(PrivRow::Item(_, Status::Hidden(why))) => self.message = Some(format!("Not available: {why}.")),
            Some(PrivRow::Item(s, Status::Available)) => {
                self.make_custom();
                if self.privacy.contains(&s.id) {
                    self.privacy.retain(|o| o != &s.id);
                } else {
                    self.privacy_on(s);
                }
            }
            Some(PrivRow::Head(c, _)) => {
                // the category's visible, available settings: all off when any is on, else the
                // recommended and strict ones on (optional ones only one by one)
                let ids: Vec<&lean11_core::privacy::Setting> = rows
                    .iter()
                    .filter_map(|r| match r {
                        PrivRow::Item(s, Status::Available) if s.category == c.id => Some(*s),
                        _ => None,
                    })
                    .collect();
                if ids.is_empty() {
                    return;
                }
                self.make_custom();
                if ids.iter().any(|s| self.privacy.contains(&s.id)) {
                    self.privacy.retain(|o| !ids.iter().any(|s| &s.id == o));
                } else {
                    for s in ids.into_iter().filter(|s| s.level != lean11_core::privacy::Level::Optional) {
                        self.privacy_on(s);
                    }
                }
            }
            None => {}
        }
    }

    fn privacy_preset(&mut self, name: &str) {
        let ids = lean11_core::privacy::preset(name).unwrap_or_default();
        if ids.is_empty() && self.privacy.is_empty() {
            return;
        }
        if !ids.is_empty() {
            self.make_custom();
        }
        self.privacy = ids;
        let n = self.recipe().privacy.len();
        self.message = Some(format!("Privacy preset {name}: {n} settings apply to this build."));
    }

    /// Restores a saved recipe into the wizard and opens the review.
    fn apply_recipe(&mut self, mut r: Recipe) -> Result<()> {
        // everything fallible first, so a failed import leaves the wizard unchanged; a modified
        // preset loads as Custom with Core's removals kept
        r.normalize_mode();
        r.validate()?;
        let source = r.source.display().to_string();
        let editions = read_editions(&source)?;
        // a saved edition that no longer exists falls back to the default
        let pick = lean11_wim::select(&editions, r.edition.as_deref()).or_else(|_| lean11_wim::select(&editions, None))?.index;
        self.mode = r.mode;
        self.mode_state.select(MODES.iter().position(|(m, ..)| *m == r.mode));
        self.core_ack = r.core_acknowledged;
        self.core_removals = r.mode == Mode::Custom && r.core;
        self.source = source;
        self.ed_state.select(editions.iter().position(|i| i.index == pick));
        self.editions = editions;
        self.inv.clear();
        self.inv_key = Some(self.image_key());
        for (o, on) in self.options.iter_mut() {
            *on = r.options.iter().any(|id| id == o.id);
        }
        self.compression = r.compression;
        self.local_account = r.local_account;
        self.compact = r.compact;
        self.no_prompt = r.no_prompt;
        self.omit_sxs = r.omit_sxs;
        self.remove_redundant_data = r.remove_redundant_data;
        self.turbo = r.turbo;
        self.keep_work = r.keep_work;
        self.ssh_key.clear();
        self.ssh_key_text = r.ssh_authorized_key.clone();
        self.output = r.output.display().to_string();
        self.actions = r.actions;
        self.actions_pending = r.adapt_actions;
        self.template_actions = None;
        self.privacy = r.privacy;
        self.software = r.software;
        self.expert_ack = r.expert_acknowledged;
        self.step = Step::Review;
        self.auto_inventory();
        Ok(())
    }

    /// Takes over a template's choice (source, edition and output stay).
    fn apply_template(&mut self, t: lean11_core::template::Template) {
        let mut r = self.recipe();
        let mut notes = t.apply(&mut r);
        self.mode = r.mode;
        self.mode_state.select(MODES.iter().position(|(m, ..)| *m == r.mode));
        self.core_ack = r.core_acknowledged;
        self.core_removals = r.mode == Mode::Custom && r.core;
        for (o, on) in self.options.iter_mut() {
            *on = r.options.iter().any(|id| id == o.id);
        }
        self.privacy = r.privacy;
        self.software = r.software.clone();
        self.compression = r.compression;
        self.local_account = r.local_account;
        self.compact = r.compact;
        self.no_prompt = r.no_prompt;
        self.omit_sxs = r.omit_sxs;
        self.remove_redundant_data = r.remove_redundant_data;
        self.turbo = r.turbo;
        self.ssh_key.clear();
        self.ssh_key_text = r.ssh_authorized_key;
        self.expert_ack = r.expert_acknowledged;
        self.template_actions = (!r.actions.is_empty()).then(|| r.actions.clone());
        self.actions = r.actions;
        self.actions_pending = self.template_actions.is_some();
        if self.actions_pending && !self.inv.is_empty() {
            notes.extend(self.match_template_actions());
        }
        let skipped = notes.iter().filter(|n| n.contains("skipped") || n.contains("left out")).count();
        self.message = Some(if notes.is_empty() {
            "Template loaded.".into()
        } else if skipped > 0 {
            format!("Template loaded; {skipped} entries do not fit this image or version (first: {}).", notes.iter().find(|n| n.contains("skipped") || n.contains("left out")).unwrap())
        } else {
            format!("Template loaded; {} custom actions matched to this image.", notes.len())
        });
    }

    /// Matches the imported template's actions to the loaded inventory; returns the notes.
    fn match_template_actions(&mut self) -> Vec<String> {
        let Some(t) = &self.template_actions else { return Vec::new() };
        let (adapted, notes) = inventory::adapt(t, &self.inv);
        self.actions = adapted;
        self.actions_pending = false;
        notes
    }

    /// Reads the inventory in the background as soon as source and edition are known.
    fn auto_inventory(&mut self) {
        if self.inv.is_empty() && self.inv_task.is_none() && self.ed_state.selected().is_some() && !self.editions.is_empty() {
            if lean11_core::build::lacks_privileges() {
                self.message = Some("With LEAN11_WIMLIB=1 the inventory needs root: start the wizard with sudo, or press l in Custom later.".into());
            } else {
                self.start_inventory();
            }
        }
    }

    fn load_source(&mut self) -> Result<()> {
        let images = read_editions(&self.source)?;
        let default = lean11_wim::select(&images, None).map(|i| i.index).unwrap_or(1);
        self.ed_state.select(images.iter().position(|i| i.index == default));
        self.editions = images;
        Ok(())
    }

    fn image_key(&self) -> ImageKey {
        let edition = self.ed_state.selected().and_then(|i| self.editions.get(i)).map(|e| e.index.to_string());
        (self.source.trim().to_string(), edition)
    }

    /// Inventory and custom actions chosen for another source or edition are dropped.
    fn check_image_key(&mut self) {
        if self.inv_key.as_ref().is_some_and(|k| *k != self.image_key()) {
            let had = !self.actions.is_empty();
            self.inv.clear();
            self.actions.clear();
            self.inv_key = None;
            // a running inventory keeps its receiver; its result is dropped because the key differs
            if let Some(t) = &self.template_actions {
                // a template's actions are matched to the new image once its inventory is read
                self.actions = t.clone();
                self.actions_pending = true;
            } else if had {
                self.message = Some("The image changed: its inventory and custom actions were cleared.".into());
            }
        }
    }
}

type ImageKey = (String, Option<String>);

fn read_editions(source: &str) -> Result<Vec<ImageInfo>> {
    lean11_core::build::source_images(&PathBuf::from(source.trim()))
}

impl App {
    fn start_inventory(&mut self) {
        let source = PathBuf::from(self.source.trim());
        let edition = self.ed_state.selected().and_then(|i| self.editions.get(i)).map(|e| e.index.to_string());
        let work = self.work_dir();
        let (tx, rx) = mpsc::channel();
        let key = self.image_key();
        self.inv_key = Some(key.clone());
        std::thread::spawn(move || {
            let r = inventory::read_source(&source, edition.as_deref(), &work, &mut |_| {}).map_err(|e| format!("{e:#}"));
            tx.send((key, r)).ok();
        });
        self.inv_task = Some(rx);
        self.message = Some("Reading the image inventory in the background (a few minutes); you can go on choosing…".into());
    }

    /// Items of the current kind matching the filter.
    fn inv_view(&self) -> Vec<&Item> {
        let kind = ITEM_KINDS[self.inv_kind].0;
        let f = self.inv_filter.to_lowercase();
        self.inv
            .iter()
            .filter(|i| {
                i.kind == kind
                    && (f.is_empty()
                        || i.name.to_lowercase().contains(&f)
                        || i.identity.to_lowercase().contains(&f)
                        || i.detail.to_lowercase().contains(&f))
            })
            .collect()
    }

    fn action_of(&self, i: &Item) -> Option<ActMode> {
        self.actions.iter().find(|a| a.kind == i.kind && a.identity == i.identity).map(|a| a.mode)
    }

    /// Space cycles none → remove → disable (features, services) → none.
    fn toggle_action(&mut self) {
        let Some(item) = self.inv_state.selected().and_then(|n| self.inv_view().get(n).map(|i| (*i).clone())) else { return };
        let next = match self.action_of(&item) {
            None => Some(ActMode::Remove),
            Some(ActMode::Remove) if matches!(item.kind, ItemKind::Feature | ItemKind::Service) => Some(ActMode::Disable),
            _ => None,
        };
        self.actions.retain(|a| !(a.kind == item.kind && a.identity == item.identity));
        if let Some(mode) = next {
            self.actions.push(Action { kind: item.kind, identity: item.identity.clone(), mode });
        }
    }

    fn start_download(&mut self) {
        let (tx, rx) = mpsc::channel();
        let lang = self.language.clone();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cancel.clone();
        // downloads go into the workspace's downloads directory
        let folder = self.work_dir().join("downloads");
        std::thread::spawn(move || {
            let r = (|| -> Result<PathBuf> {
                tx.send(Msg::Line("Contacting Microsoft…".into())).ok();
                // a link is a manual official download; otherwise resolve the language, and unsupported
                // languages fall back to English with an explicit status
                let media = if lang.trim().starts_with("https://") {
                    lean11_msdl::manual(lang.trim(), None)?
                } else {
                    lean11_msdl::Catalog::open(lean11_msdl::Arch::host())?.resolve(&lang, true)?
                };
                tx.send(Msg::Line(format!("{} ({})", media.description, media.language))).ok();
                let dest = folder.join(&media.file_name);
                let (p, hash) = lean11_msdl::download_cancellable(
                    &media,
                    &dest,
                    &mut |d, t| {
                        tx.send(Msg::Progress(d, t)).ok();
                    },
                    Some(&flag),
                )?;
                tx.send(Msg::Line(format!("SHA-256 {hash}"))).ok();
                Ok(std::path::absolute(p)?)
            })();
            tx.send(Msg::Done(r.map_err(|e| format!("{e:#}")))).ok();
        });
        self.download = Some(Task { rx, cancel: Some(cancel), lines: Vec::new(), progress: None, result: None });
    }

    /// Working directory: the chosen one, else `lean11-work` next to the output ISO.
    fn work_dir(&self) -> PathBuf {
        if self.work.trim().is_empty() {
            std::path::absolute(&self.output).ok().and_then(|p| p.parent().map(|d| d.join("lean11-work"))).unwrap_or_else(|| "lean11-work".into())
        } else {
            PathBuf::from(self.work.trim())
        }
    }

    fn start_build(&mut self) {
        let recipe = self.recipe();
        let work = self.work_dir();
        let (tx, rx) = mpsc::channel();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cancel.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let mut sink = move |m: &str| {
                tx2.send(Msg::Line(m.to_string())).ok();
            };
            let r = Builder::new(&work, recipe, &mut sink).and_then(|mut b| {
                b.cancel = Some(flag);
                b.run()
            });
            tx.send(Msg::Done(r.map_err(|e| format!("{e:#}")))).ok();
        });
        self.build = Some(Task { rx, cancel: Some(cancel), lines: Vec::new(), progress: None, result: None });
        self.step = Step::Build;
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.inv_task
            && let Ok((key, r)) = rx.try_recv()
        {
            let stale = key != self.image_key();
            match r {
                // a result for an image that is no longer selected is dropped
                _ if stale => {}
                Ok(items) => {
                    let mut items = items;
                    // readable order: by kind, then by the name shown
                    items.sort_by_cached_key(|i| (i.kind, i.label().to_lowercase()));
                    self.inv = items;
                    self.inv_state.select(Some(0));
                    let mut msg = format!("Inventory read: {} items", self.inv.len());
                    if self.actions_pending {
                        let notes = self.match_template_actions();
                        let skipped = notes.iter().filter(|n| n.contains("skipped")).count();
                        msg.push_str(&format!("; template actions: {} matched, {skipped} not in this image", self.actions.len()));
                    }
                    self.message = Some(msg);
                }
                Err(e) => self.message = Some(format!("Inventory failed (press l in Custom to retry): {e}")),
            }
            self.inv_task = None;
            // the image changed while reading: read the new one (failures wait for l)
            if stale && self.step != Step::Build {
                self.auto_inventory();
            }
        }
        for t in [&mut self.download, &mut self.build].into_iter().flatten() {
            while let Ok(m) = t.rx.try_recv() {
                match m {
                    Msg::Line(l) => t.lines.push(l),
                    Msg::Progress(d, total) => t.progress = Some((d, total)),
                    Msg::Done(r) => t.result = Some(r),
                }
            }
        }
        if let Some(d) = &self.download
            && let Some(r) = &d.result
        {
            match r {
                Ok(p) => {
                    self.source = p.display().to_string();
                    self.message = Some(format!("Downloaded {}", self.source));
                }
                Err(e) if e.contains("download cancelled") => {
                    self.message = Some("Download cancelled; the partial file is kept and resumes on the next download.".into())
                }
                Err(e) => self.message = Some(format!("Download failed: {e}")),
            }
            self.download = None;
        }
    }

    fn settings_rows(&self) -> Vec<(String, String)> {
        let yn = |b: bool| if b { "yes" } else { "no" }.to_string();
        vec![
            ("Output ISO".into(), self.output.clone()),
            ("Working directory".into(), if self.work.is_empty() { "(next to the output)".into() } else { self.work.clone() }),
            ("Turbo mode".into(), yn(self.turbo)),
            ("Compression".into(), match self.compression {
                Compression::Recovery => "recovery (install.esd, smallest, slowest)".into(),
                Compression::Maximum => "maximum (install.wim LZX)".into(),
                _ => "fast (install.wim XPRESS)".into(),
            }),
            ("Prefer local account".into(), yn(self.local_account)),
            ("Compact installation".into(), yn(self.compact)),
            ("UEFI boot without key press".into(), yn(self.no_prompt)),
            ("Omit .NET 3.5 payload (sources\\sxs)".into(), yn(self.omit_sxs)),
            ("Remove redundant data (caches, logs, crash reports)".into(), yn(self.remove_redundant_data)),
            ("Keep working files".into(), yn(self.keep_work)),
            ("SSH access (key, Administrator)".into(), if self.mode != Mode::Custom {
                "(Custom only)".into()
            } else if self.ssh_key.is_empty() {
                if self.ssh_key_text.is_some() { "(key from the loaded recipe)".into() } else { "off".into() }
            } else {
                self.ssh_key.clone()
            }),
        ]
    }

    /// Takes over a typed or picked value.
    fn commit_field(&mut self, field: Field, text: String) {
        // typed paths may start with ~ like in a shell
        let text = match field {
            Field::Source | Field::Output | Field::Work | Field::SshKey | Field::SaveTemplate | Field::LoadTemplate => expand_home(&text),
            _ => text,
        };
        match field {
            Field::Source => self.source = text,
            Field::Output => self.output = text,
            Field::Work => self.work = text,
            Field::SshKey => {
                let t = text.trim().to_string();
                if t.is_empty() {
                    self.ssh_key.clear();
                    self.ssh_key_text = None;
                } else {
                    match std::fs::read_to_string(&t) {
                        Ok(k) if lean11_core::ssh::valid_authorized_key(&k) => self.ssh_key = t,
                        Ok(_) => self.message = Some(format!("{t} is not an OpenSSH public key (.pub)")),
                        Err(e) => self.message = Some(format!("Cannot read {t}: {e}")),
                    }
                }
            }
            Field::Language => {
                self.language = text;
                self.start_download();
            }
            Field::Filter => {
                self.inv_filter = text;
                self.inv_state.select(Some(0));
            }
            Field::PrivacyFilter => {
                self.priv_filter = text;
                self.priv_state.select(Some(0));
            }
            Field::SaveTemplate => {
                // the whole privacy choice, also settings the current Components choice hides
                let mut t = lean11_core::template::Template::from_recipe(&self.recipe());
                t.privacy = lean11_core::privacy::catalog().setting.iter().filter(|s| self.privacy.contains(&s.id)).map(|s| s.id.clone()).collect();
                if let Some(ta) = &self.template_actions
                    && self.actions_pending
                {
                    t.actions = ta.clone();
                }
                let r = t.save(std::path::Path::new(text.trim()));
                self.message = Some(match r {
                    Ok(()) => format!("Template saved to {}", text.trim()),
                    Err(e) => format!("Cannot save the template: {e:#}"),
                });
            }
            Field::LoadTemplate => match lean11_core::template::Template::load(std::path::Path::new(text.trim())) {
                Ok(t) => {
                    self.apply_template(t);
                    if self.step == Step::Mode {
                        self.step = Step::Source;
                    }
                }
                Err(e) => self.message = Some(format!("Cannot load the template: {e:#}")),
            },
            Field::SaveRecipe => {
                let recipe = self.recipe();
                let r = recipe
                    .validate()
                    .and_then(|()| Ok(serde_json::to_vec_pretty(&recipe)?))
                    .and_then(|j| Ok(std::fs::write(&text, j)?));
                self.message = Some(match r {
                    Ok(()) => format!("Recipe saved to {text}"),
                    Err(e) => format!("Cannot save the recipe: {e:#}"),
                });
            }
            Field::LoadRecipe => {
                let r = std::fs::read(&text)
                    .map_err(anyhow::Error::from)
                    .and_then(|b| Ok(serde_json::from_slice::<Recipe>(&b)?))
                    .and_then(|r| self.apply_recipe(r));
                self.message = Some(match r {
                    Ok(()) => format!("Recipe loaded from {text}"),
                    Err(e) => format!("Cannot load the recipe: {e:#}"),
                });
            }
        }
    }

    /// Opens the file browser for a path field.
    fn browse(&mut self, field: Field) {
        use crate::picker::{Kind, Picker};
        let p = match field {
            Field::Source => Picker::new(Kind::Source, "Choose a Windows 11 ISO or media folder", &self.source, &["Downloads", "Desktop"]),
            Field::SshKey => Picker::new(Kind::PubKey, "Choose the public SSH key (.pub)", &self.ssh_key, &[".ssh"]),
            Field::LoadRecipe => Picker::new(Kind::Recipe, "Choose a recipe (.json)", "", &["Downloads", "Desktop"]),
            Field::LoadTemplate => Picker::new(Kind::Recipe, "Choose a template (.json)", "", &["Downloads", "Desktop"]),
            Field::SaveTemplate => {
                let mut p = Picker::new(Kind::SaveIn, "Choose where to save the template", "", &["Downloads", "Desktop"]);
                p.save_name = "lean11-template.json".into();
                p
            }
            Field::Work => Picker::new(Kind::Dir, "Choose the working directory", &self.work, &[]),
            Field::Output => {
                let mut p = Picker::new(Kind::SaveIn, "Choose where to save the ISO", &self.output, &["Downloads", "Desktop"]);
                p.save_name = PathBuf::from(&self.output).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "lean11.iso".into());
                p
            }
            _ => return,
        };
        self.picker = Some((field, p));
    }

    fn key(&mut self, code: KeyCode, mods: KeyModifiers) {
        self.message = None;
        if code == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL) {
            if self.build.as_ref().is_some_and(|b| b.result.is_none()) {
                self.message = Some("A build is running: press s to stop it after the current stage.".into());
            } else if self.inv_task.is_some() {
                self.message = Some("The inventory is reading a mounted image; wait until it finishes.".into());
            } else {
                self.quit = true;
            }
            return;
        }
        if let Some((field, mut p)) = self.picker.take() {
            use crate::picker::Outcome;
            match p.key(code) {
                Outcome::Stay => self.picker = Some((field, p)),
                Outcome::Cancel => {}
                Outcome::Pick(path) => self.commit_field(field, path.display().to_string()),
                Outcome::Type(text) => self.editing = Some((field, text)),
                Outcome::Clear => self.commit_field(field, String::new()),
            }
            return;
        }
        if let Some((field, mut text)) = self.editing.take() {
            match code {
                KeyCode::Enter => {
                    self.commit_field(field, text);
                    return;
                }
                KeyCode::Esc => return,
                KeyCode::Backspace => {
                    text.pop();
                }
                KeyCode::Char(c) => text.push(c),
                _ => {}
            }
            self.editing = Some((field, text));
            return;
        }
        if self.confirm_breaking {
            if code == KeyCode::Char('y') {
                self.breaking_ack = true;
                self.confirm_breaking = false;
                self.start_build();
            } else if matches!(code, KeyCode::Char('n') | KeyCode::Esc) {
                self.confirm_breaking = false;
            }
            return;
        }
        if self.confirm_expert {
            if code == KeyCode::Char('y') {
                self.expert_ack = true;
                self.confirm_expert = false;
                self.step = Step::Software;
            } else if matches!(code, KeyCode::Char('n') | KeyCode::Esc) {
                self.confirm_expert = false;
            }
            return;
        }
        if let Some(i) = self.confirm_option {
            if code == KeyCode::Char('y') {
                self.core_ack = true;
                self.options[i].1 = true;
                self.confirm_option = None;
            } else if matches!(code, KeyCode::Char('n') | KeyCode::Esc) {
                self.confirm_option = None;
            }
            return;
        }
        if self.confirm_core {
            if code == KeyCode::Char('y') {
                self.core_ack = true;
                self.confirm_core = false;
                if self.step == Step::Components {
                    self.core_removals = true;
                } else {
                    self.apply_mode(Mode::Core);
                    self.step = Step::Source;
                }
            } else if matches!(code, KeyCode::Char('n') | KeyCode::Esc) {
                self.confirm_core = false;
            }
            return;
        }
        let back = matches!(code, KeyCode::Esc | KeyCode::Left);
        if back && self.step != Step::Build && self.step != Step::Mode {
            self.step = STEPS[STEPS.iter().position(|s| s.0 == self.step).unwrap() - 1].0;
            return;
        }
        if code == KeyCode::Char('q') && self.step != Step::Build {
            if self.inv_task.is_some() {
                // quitting would leave the inventory's mount and extracted image behind
                self.message = Some("The inventory is reading a mounted image; wait until it finishes.".into());
            } else {
                self.quit = true;
            }
            return;
        }
        // templates: import (t) and export (x) wherever the choice is made
        if matches!(self.step, Step::Mode | Step::Components | Step::Privacy | Step::Software | Step::Settings | Step::Review) {
            match code {
                KeyCode::Char('t') => return self.browse(Field::LoadTemplate),
                KeyCode::Char('x') => return self.browse(Field::SaveTemplate),
                _ => {}
            }
        }
        match self.step {
            Step::Mode => match code {
                KeyCode::Char('r') if self.download.is_some() => {
                    self.message = Some("A download is running; import the recipe after it finished.".into());
                }
                KeyCode::Char('r') => self.browse(Field::LoadRecipe),
                KeyCode::Up => self.mode_state.select_previous(),
                KeyCode::Down => self.mode_state.select_next(),
                KeyCode::Enter | KeyCode::Right => {
                    let m = MODES[self.mode_state.selected().unwrap_or(0).min(2)].0;
                    if m == Mode::Core && !self.core_ack {
                        self.confirm_core = true;
                    } else {
                        self.apply_mode(m);
                        self.step = Step::Source;
                    }
                }
                _ => {}
            },
            Step::Source => match code {
                KeyCode::Char('b') | KeyCode::Char('e') => self.browse(Field::Source),
                KeyCode::Char('t') | KeyCode::Char('i') => self.editing = Some((Field::Source, self.source.clone())),
                KeyCode::Char('d') if self.download.is_none() => self.editing = Some((Field::Language, self.language.clone())),
                KeyCode::Char('x') if self.download.is_some() => {
                    if let Some(c) = self.download.as_ref().and_then(|t| t.cancel.as_ref()) {
                        c.store(true, std::sync::atomic::Ordering::SeqCst);
                        self.message = Some("Cancelling the download; the partial file is kept for a later resume…".into());
                    }
                }
                KeyCode::Enter | KeyCode::Right if self.download.is_none() => match self.load_source() {
                    Ok(()) => self.step = Step::Edition,
                    Err(e) => self.message = Some(format!("{e:#}")),
                },
                _ => {}
            },
            Step::Edition => match code {
                KeyCode::Up => self.ed_state.select_previous(),
                KeyCode::Down => self.ed_state.select_next(),
                KeyCode::Enter | KeyCode::Right => {
                    self.check_image_key();
                    self.step = Step::Components;
                    self.auto_inventory();
                }
                _ => {}
            },
            Step::Components => match code {
                KeyCode::Up => self.opt_state.select_previous(),
                KeyCode::Down => self.opt_state.select_next(),
                KeyCode::Char(' ') => {
                    let to_custom = |app: &mut Self| app.make_custom();
                    match self.opt_state.selected() {
                        Some(i) if i < self.options.len() => {
                            to_custom(self);
                            let irreversible = lean11_core::catalog::IRREVERSIBLE.contains(&self.options[i].0.id);
                            if !self.options[i].1 && irreversible && !self.core_ack {
                                self.confirm_option = Some(i);
                            } else {
                                self.options[i].1 = !self.options[i].1;
                            }
                        }
                        Some(i) if i == self.options.len() => {
                            if self.core_removals || self.mode == Mode::Core {
                                to_custom(self);
                                self.core_removals = false;
                            } else if !self.core_ack {
                                to_custom(self);
                                self.confirm_core = true;
                            } else {
                                to_custom(self);
                                self.core_removals = true;
                            }
                        }
                        _ => {}
                    }
                }
                KeyCode::Enter | KeyCode::Right => {
                    self.check_image_key();
                    self.step = Step::Privacy;
                }
                _ => {}
            },
            Step::Privacy => match code {
                KeyCode::Up => self.priv_state.select_previous(),
                KeyCode::Down => self.priv_state.select_next(),
                KeyCode::PageUp => self.priv_state.scroll_up_by(20),
                KeyCode::PageDown => self.priv_state.scroll_down_by(20),
                KeyCode::Home => self.priv_state.select_first(),
                KeyCode::End => self.priv_state.select_last(),
                KeyCode::Char(' ') => self.toggle_privacy(),
                KeyCode::Char('r') => self.privacy_preset("recommended"),
                KeyCode::Char('s') => self.privacy_preset("strict"),
                KeyCode::Char('n') => self.privacy_preset("none"),
                KeyCode::Char('/') => self.editing = Some((Field::PrivacyFilter, self.priv_filter.clone())),
                KeyCode::Enter | KeyCode::Right => self.step = Step::Custom,
                _ => {}
            },
            Step::Custom => match code {
                KeyCode::Up => self.inv_state.select_previous(),
                KeyCode::Down => self.inv_state.select_next(),
                KeyCode::PageUp => self.inv_state.scroll_up_by(20),
                KeyCode::PageDown => self.inv_state.scroll_down_by(20),
                KeyCode::Tab => {
                    self.inv_kind = (self.inv_kind + 1) % ITEM_KINDS.len();
                    self.inv_state.select(Some(0));
                }
                KeyCode::BackTab => {
                    self.inv_kind = (self.inv_kind + ITEM_KINDS.len() - 1) % ITEM_KINDS.len();
                    self.inv_state.select(Some(0));
                }
                KeyCode::Char('l') if self.inv_task.is_none() => {
                    if lean11_core::build::lacks_privileges() {
                        self.message = Some("With LEAN11_WIMLIB=1 the inventory mounts the image and needs root: start the wizard with sudo.".into());
                    } else {
                        self.start_inventory();
                    }
                }
                KeyCode::Char('/') => self.editing = Some((Field::Filter, self.inv_filter.clone())),
                KeyCode::Char(' ') => self.toggle_action(),
                KeyCode::Enter | KeyCode::Right => {
                    if !self.actions.is_empty() && !self.expert_ack {
                        self.confirm_expert = true;
                    } else {
                        self.step = Step::Software;
                    }
                }
                _ => {}
            },
            Step::Software => match code {
                KeyCode::Up => self.sw_state.select_previous(),
                KeyCode::Down => self.sw_state.select_next(),
                KeyCode::Home => self.sw_state.select_first(),
                KeyCode::End => self.sw_state.select_last(),
                KeyCode::Char(' ') => self.toggle_software(),
                KeyCode::Enter | KeyCode::Right => self.step = Step::Settings,
                _ => {}
            },
            Step::Settings => match code {
                KeyCode::Up => self.set_state.select_previous(),
                KeyCode::Down => self.set_state.select_next(),
                KeyCode::Char(' ') | KeyCode::Char('e') => match self.set_state.selected().unwrap_or(0) {
                    0 => self.browse(Field::Output),
                    1 => self.browse(Field::Work),
                    2 => self.turbo = !self.turbo,
                    3 => {
                        self.compression = match self.compression {
                            Compression::Recovery => Compression::Maximum,
                            Compression::Maximum => Compression::Fast,
                            _ => Compression::Recovery,
                        }
                    }
                    4 => self.local_account = !self.local_account,
                    5 => self.compact = !self.compact,
                    6 => self.no_prompt = !self.no_prompt,
                    7 => self.omit_sxs = !self.omit_sxs,
                    8 => self.remove_redundant_data = !self.remove_redundant_data,
                    9 => self.keep_work = !self.keep_work,
                    10 if self.mode == Mode::Custom => self.browse(Field::SshKey),
                    _ => {}
                },
                KeyCode::Enter | KeyCode::Right => self.step = Step::Review,
                _ => {}
            },
            Step::Review => {
                if code == KeyCode::Char('s') {
                    self.editing = Some((Field::SaveRecipe, format!("{}.recipe.json", self.output.trim_end_matches(".iso"))));
                    return;
                }
                if matches!(code, KeyCode::Enter | KeyCode::Char('b')) {
                    if lean11_core::build::lacks_privileges() {
                        self.message = Some("With LEAN11_WIMLIB=1 building needs root: start the wizard with sudo.".into());
                    } else if PathBuf::from(&self.output).exists() {
                        self.message = Some(format!("{} exists; choose another output name in Settings.", self.output));
                    } else if !self.breaking_ack
                        && !lean11_core::knowledge::breaking_choices(&self.recipe(), (!self.inv.is_empty()).then_some(self.inv.as_slice())).is_empty()
                    {
                        self.confirm_breaking = true;
                    } else {
                        self.start_build();
                    }
                }
            }
            Step::Build => {
                let running = self.build.as_ref().is_some_and(|b| b.result.is_none());
                if !running && matches!(code, KeyCode::Char('q') | KeyCode::Enter | KeyCode::Esc) {
                    self.quit = true;
                } else if running && code == KeyCode::Char('s') {
                    if let Some(c) = self.build.as_ref().and_then(|b| b.cancel.as_ref()) {
                        c.store(true, std::sync::atomic::Ordering::SeqCst);
                        self.message = Some("Stopping after the current stage; the job stays resumable…".into());
                    }
                }
            }
        }
    }
}

fn render(f: &mut Frame, app: &mut App) {
    let [head, body, foot] = Layout::vertical([Constraint::Length(3), Constraint::Fill(1), Constraint::Length(2)]).areas(f.area());
    let crumbs: Vec<Span> = STEPS
        .iter()
        .enumerate()
        .flat_map(|(i, (s, name))| {
            let style = if *s == app.step {
                Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else if *s < app.step {
                Style::new().fg(Color::Green)
            } else {
                Style::new().fg(Color::DarkGray)
            };
            let mut v = vec![Span::styled(format!(" {} {} ", i + 1, name), style)];
            if i + 1 < STEPS.len() {
                v.push(Span::raw(" › ").dark_gray());
            }
            v
        })
        .collect();
    f.render_widget(Paragraph::new(Line::from(crumbs)).block(Block::bordered().title(" lean11 ".bold())), head);

    match app.step {
        Step::Mode => {
            let items: Vec<ListItem> = MODES
                .iter()
                .map(|(_, t, d)| ListItem::new(vec![Line::from(t.bold()), Line::from(format!("  {d}")).dark_gray(), Line::raw("")]))
                .collect();
            let list = List::new(items).block(Block::bordered().title(" Choose your build ")).highlight_symbol("▶ ").highlight_style(Style::new().fg(Color::Cyan));
            f.render_stateful_widget(list, body, &mut app.mode_state);
        }
        Step::Source => {
            let mut lines = vec![
                Line::from("Windows 11 ISO or extracted media directory:".bold()),
                Line::raw(""),
                Line::from(format!("  {}", if app.source.is_empty() { "(none)" } else { &app.source })).cyan(),
                Line::raw(""),
                Line::raw("b: browse for the ISO    t: type a path    d: download the latest ISO from Microsoft    Enter: continue"),
            ];
            if let Some(d) = &app.download {
                lines.push(Line::raw(""));
                lines.extend(d.lines.iter().map(|l| Line::raw(l.clone())));
            }
            let [top, bar] = Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(body);
            f.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Source ")).wrap(Wrap { trim: false }), top);
            if let Some((done, total)) = app.download.as_ref().and_then(|d| d.progress) {
                let ratio = total.map(|t| done as f64 / t.max(1) as f64).unwrap_or(0.0).clamp(0.0, 1.0);
                f.render_widget(
                    Gauge::default().block(Block::bordered().title(" Download ")).ratio(ratio).label(format!("{:.1} GiB", done as f64 / 1073741824.0)),
                    bar,
                );
            }
        }
        Step::Edition => {
            let items: Vec<ListItem> = app
                .editions
                .iter()
                .map(|i| ListItem::new(format!("[{}] {}  ({}, {}, {})", i.index, i.name, i.edition_id, i.arch(), i.version())))
                .collect();
            let list = List::new(items).block(Block::bordered().title(" Edition ")).highlight_symbol("▶ ").highlight_style(Style::new().fg(Color::Cyan));
            f.render_stateful_widget(list, body, &mut app.ed_state);
        }
        Step::Components => {
            let [list_area, desc] = Layout::vertical([Constraint::Fill(1), Constraint::Length(7)]).areas(body);
            let items: Vec<ListItem> = app
                .options
                .iter()
                .map(|(o, on)| {
                    let kind = match o.kind {
                        Kind::App => "app",
                        Kind::File => "files",
                        Kind::Capability => "capability",
                        Kind::Feature => "feature",
                        Kind::Policy => "setting",
                        Kind::System => "system",
                    };
                    let r = knowledge::option_rating(o.id);
                    let spans = vec![
                        Span::raw(if *on { "[x] " } else { "[ ] " }),
                        rating_dot(r),
                        Span::raw(format!("{:<11}", kind)).dark_gray(),
                        Span::styled(o.title, rating_style(r)),
                    ];
                    ListItem::new(Line::from(spans))
                })
                .chain(std::iter::once(ListItem::new(Line::from(vec![
                    Span::raw(if app.core_removals || app.mode == Mode::Core { "[x] " } else { "[ ] " }),
                    rating_dot(Some(Rating::Limited)),
                    Span::raw(format!("{:<11}", "core")).dark_gray(),
                    Span::styled(
                        "Core removals: component store, recovery, Windows Update and Defender (irreversible)",
                        rating_style(Some(Rating::Limited)),
                    ),
                ]))))
                .collect();
            let title = format!(" Components: {} ({} selected) ", mode_name(app.mode), app.options.iter().filter(|o| o.1).count());
            // reversed instead of a highlight color: the row keeps its traffic-light color when selected
            let list = List::new(items).block(Block::bordered().title(title)).highlight_symbol("▶ ").highlight_style(Style::new().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(list, list_area, &mut app.opt_state);
            let d: Vec<Line> = match app.opt_state.selected() {
                Some(i) if i == app.options.len() => vec![Line::raw(
                    "Deletes the WinSxS component folders except common controls, GDI+, CRT and servicing, removes WinRE and \
                     disables Windows Update and Defender. The image cannot be updated or repaired. Test VMs only.",
                )],
                i => match i.and_then(|i| app.options.get(i)) {
                    Some((o, _)) => match knowledge::lookup(knowledge::Subject::Option, &[o.id]) {
                        Some(e) => knowledge_lines(e),
                        None => vec![Line::raw(o.description)],
                    },
                    None => Vec::new(),
                },
            };
            f.render_widget(Paragraph::new(d).wrap(Wrap { trim: true }).block(Block::bordered().title(rating_legend())), desc);
        }
        Step::Privacy => {
            use lean11_core::privacy::{Level, Status};
            let [list_area, desc] = Layout::vertical([Constraint::Fill(1), Constraint::Length(7)]).areas(body);
            let rows = app.privacy_rows();
            let inner = list_area.width.saturating_sub(4) as usize;
            let items: Vec<ListItem> = rows
                .iter()
                .map(|row| match row {
                    PrivRow::Head(_, path) => ListItem::new(Line::from(path.clone().bold().cyan())),
                    PrivRow::Item(s, st) => {
                        let on = app.privacy.contains(&s.id);
                        let lvl = match s.level {
                            Level::Recommended => "recommended",
                            Level::Strict => "strict     ",
                            Level::Optional => "optional   ",
                        };
                        let lst = Style::new().fg(Color::DarkGray);
                        match st {
                            Status::Available => {
                                let r = Some(knowledge::privacy_rating(s));
                                ListItem::new(Line::from(vec![
                                    Span::raw(if on { "  [x] " } else { "  [ ] " }),
                                    rating_dot(r),
                                    Span::styled(lvl, lst),
                                    Span::raw("  "),
                                    Span::styled(fit(&s.title, inner.saturating_sub(23)), rating_style(r)),
                                ]))
                            }
                            Status::Hidden(why) => {
                                let t = format!("{}  ({why})", s.title);
                                ListItem::new(Line::from(vec![Span::raw("   -  "), Span::raw("  "), Span::raw(lvl), Span::raw("  "), Span::raw(fit(&t, inner.saturating_sub(23)))]).dark_gray())
                            }
                        }
                    }
                })
                .collect();
            let n = app.recipe_with(false).privacy.len();
            let title = format!(" Privacy settings: {n} apply, filter: {} ", if app.priv_filter.is_empty() { "-" } else { &app.priv_filter });
            let desc_block = Block::bordered().title(rating_legend());
            let list = List::new(items).block(Block::bordered().title(title)).highlight_symbol("▶ ").highlight_style(Style::new().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(list, list_area, &mut app.priv_state);
            let d: Vec<Line> = match app.priv_state.selected().and_then(|i| rows.get(i)) {
                Some(PrivRow::Head(c, path)) => vec![
                    Line::from(path.clone().bold()),
                    Line::raw(if c.description.is_empty() { String::new() } else { c.description.clone() }),
                    Line::from("Space: the category's recommended and strict settings on, or all off".dark_gray()),
                ],
                Some(PrivRow::Item(s, st)) => {
                    let pr = knowledge::privacy_rating(s);
                    let word = match pr {
                        Rating::Safe => "Safe: ",
                        Rating::Limited => "Limited: ",
                        Rating::Breaks => "Breaks Windows: ",
                    };
                    let rst = rating_style(Some(pr));
                    let mut l = vec![
                        Line::from(vec![Span::raw(s.title.clone()).bold(), Span::raw(format!("   {}", s.id)).dark_gray()]),
                        Line::from(vec![Span::styled(word, rst.add_modifier(Modifier::BOLD)), Span::raw(s.description.clone())]),
                    ];
                    if let Status::Hidden(why) = st {
                        l.push(Line::from(format!("Not available: {why}.").yellow()));
                    }
                    if !s.conflicts.is_empty() {
                        l.push(Line::from(format!("Contradicts: {}", s.conflicts.join(", ")).yellow()));
                    }
                    if !s.note.is_empty() {
                        l.push(Line::raw(format!("Note: {}", s.note)));
                    }
                    l.push(Line::from(format!("Verified: {}", s.verified).dark_gray()));
                    l
                }
                None => Vec::new(),
            };
            f.render_widget(Paragraph::new(d).wrap(Wrap { trim: true }).block(desc_block), desc);
        }
        Step::Custom => {
            let [tabs, list_area, desc] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(7)]).areas(body);
            let tab_spans: Vec<Span> = ITEM_KINDS
                .iter()
                .enumerate()
                .flat_map(|(n, (k, name))| {
                    let count = app.inv.iter().filter(|i| i.kind == *k).count();
                    let sel = app.actions.iter().filter(|a| a.kind == *k).count();
                    let label = if sel > 0 { format!(" {name} {count} ({sel}) ") } else { format!(" {name} {count} ") };
                    let st = if n == app.inv_kind { Style::new().fg(Color::Black).bg(Color::Cyan) } else { Style::new().fg(Color::Gray) };
                    [Span::styled(label, st), Span::raw(" ")]
                })
                .collect();
            f.render_widget(Paragraph::new(Line::from(tab_spans)), tabs);
            let view = app.inv_view();
            let kind = ITEM_KINDS[app.inv_kind].0;
            // only apps mix safe and protected entries; every other tab is protected as a whole
            let mark_protected = kind == ItemKind::ProvisionedApp;
            let d: Vec<Line> = app
                .inv_state
                .selected()
                .and_then(|n| view.get(n))
                .map(|i| {
                    let mut l = vec![Line::from(vec![Span::raw(i.label().to_string()).bold(), Span::raw(format!("   {}", i.identity)).dark_gray()])];
                    if let Some(e) = knowledge::item(i) {
                        l.extend(knowledge_lines(e));
                        if matches!(i.kind, ItemKind::Feature | ItemKind::Package) {
                            l.push(Line::from(format!("State: {}", i.detail).dark_gray()));
                        }
                        return l;
                    }
                    let mut text = i.description.clone();
                    if matches!(i.kind, ItemKind::Feature | ItemKind::Package) {
                        text = if text.is_empty() { format!("State: {}", i.detail) } else { format!("{text} (state: {})", i.detail) };
                    }
                    if i.protected {
                        text.push_str(if text.is_empty() { "" } else { "  " });
                        text.push_str("Protected: removal can break boot, servicing, security or the shell.");
                    }
                    l.push(Line::from(text));
                    l.push(Line::from("Not rated yet: no verified description of what removing it does.".dark_gray()));
                    l
                })
                .unwrap_or_default();
            let inner = list_area.width.saturating_sub(4) as usize;
            // column fits 95 % of the names; the few longer ones are cut with "…"
            // display cells, not chars: CJK names take two cells per character
            let mut lens: Vec<usize> = view.iter().map(|i| UnicodeWidthStr::width(i.label())).collect();
            lens.sort_unstable();
            let p95 = lens.get(lens.len().saturating_sub(1) * 95 / 100).copied().unwrap_or(0);
            let name_w = p95.min(inner.saturating_sub(18) * 3 / 5).max(10);
            let items: Vec<ListItem> = view
                .iter()
                .map(|i| {
                    let act = app.action_of(i);
                    // the chosen action is marked in bold magenta, so red, yellow and green stay the rating
                    let (mark, tag, style) = match act {
                        Some(ActMode::Remove) => ("[x] ", "remove  ", Style::new().fg(Color::Indexed(201)).add_modifier(Modifier::BOLD)),
                        Some(ActMode::Disable) => ("[-] ", "disable ", Style::new().fg(Color::Indexed(201)).add_modifier(Modifier::BOLD)),
                        None => ("[ ] ", "", Style::new()),
                    };
                    let r = knowledge::item(i).map(|e| e.rating);
                    let label = fit(i.label(), name_w);
                    let mut spans = vec![Span::styled(mark, style), rating_dot(r), Span::styled(label, rating_style(r)), Span::raw("  ")];
                    if !tag.is_empty() {
                        spans.push(Span::styled(tag, style.add_modifier(Modifier::BOLD)));
                    }
                    if mark_protected {
                        spans.push(Span::raw(if i.protected { "protected  " } else { "           " }).dark_gray().italic());
                    }
                    let id = lean11_core::names::short_id(i.kind, &i.identity);
                    if id != i.label() {
                        spans.push(Span::raw(id).dark_gray());
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let title = if app.inv.is_empty() {
                if app.inv_task.is_some() {
                    let pending = if app.actions_pending { format!(", {} template actions wait for it", app.actions.len()) } else { String::new() };
                    format!(" Custom actions: reading the inventory in the background{pending}… ")
                } else {
                    " Custom actions (optional): press l to read the image inventory ".to_string()
                }
            } else {
                format!(
                    " Custom actions: {} selected, filter: {}{} ",
                    app.actions.len(),
                    if app.inv_filter.is_empty() { "-" } else { &app.inv_filter },
                    if mark_protected { "" } else { "   (all protected: removal can break the image)" }
                )
            };
            let list = List::new(items).block(Block::bordered().title(title)).highlight_symbol("▶ ").highlight_style(Style::new().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(list, list_area, &mut app.inv_state);
            f.render_widget(Paragraph::new(d).wrap(Wrap { trim: true }).block(Block::bordered().title(rating_legend())), desc);
        }
        Step::Software => {
            let [list_area, desc] = Layout::vertical([Constraint::Fill(1), Constraint::Length(6)]).areas(body);
            let catalog = lean11_core::software::catalog();
            let items: Vec<ListItem> = catalog
                .iter()
                .map(|p| {
                    ListItem::new(Line::from(vec![
                        Span::raw(if app.software.contains(&p.id) { "[x] " } else { "[ ] " }),
                        Span::raw(format!("{:<20}", p.category)).dark_gray(),
                        Span::raw(p.name.clone()),
                    ]))
                })
                .collect();
            let title = format!(" Software: {} selected, installed at the end of setup ", app.software.len());
            let list = List::new(items).block(Block::bordered().title(title)).highlight_symbol("▶ ").highlight_style(Style::new().fg(Color::Cyan));
            f.render_stateful_widget(list, list_area, &mut app.sw_state);
            let d: Vec<Line> = match app.sw_state.selected().and_then(|i| catalog.get(i)) {
                Some(p) => vec![
                    Line::from(vec![Span::raw(p.name.clone()).bold(), Span::raw(format!("   {}", p.id)).dark_gray()]),
                    Line::raw(p.description.clone()),
                    Line::from(
                        if p.kind == lean11_core::software::ProgramKind::Scoop {
                            "Set up per account at sign-in (needs internet then).".to_string()
                        } else {
                            format!("Latest version from the winget catalog ({}), vendor download checked by SHA-256 at build time.", p.winget.join(" / "))
                        }
                        .dark_gray(),
                    ),
                ],
                None => Vec::new(),
            };
            f.render_widget(Paragraph::new(d).wrap(Wrap { trim: true }).block(Block::bordered()), desc);
        }
        Step::Settings => {
            let rows = app.settings_rows();
            let w = rows.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0) + 3;
            let items: Vec<ListItem> = rows.into_iter().map(|(k, v)| ListItem::new(Line::from(vec![Span::raw(format!("{k:<w$}")), Span::raw(v).cyan()]))).collect();
            let list = List::new(items).block(Block::bordered().title(" Settings ")).highlight_symbol("▶ ").highlight_style(Style::new().add_modifier(Modifier::BOLD));
            f.render_stateful_widget(list, body, &mut app.set_state);
        }
        Step::Review => {
            let r = app.recipe();
            let ed = app.ed_state.selected().and_then(|i| app.editions.get(i)).map(|e| format!("{} {} {}", e.name, e.arch(), e.version())).unwrap_or_default();
            let mut lines = vec![
                Line::from(vec!["Mode:        ".into(), mode_name(app.mode).bold()]),
                Line::from(format!("Source:      {}", app.source)),
                Line::from(format!("Edition:     {ed}")),
                Line::from(format!("Output:      {}", app.output)),
                Line::from(format!("Compression: {:?}", r.compression)),
            ];
            if let Some(k) = &r.ssh_authorized_key {
                let short = k.split_whitespace().take(1).chain(k.split_whitespace().nth(2)).collect::<Vec<_>>().join(" ");
                lines.push(Line::from(vec![
                    "Remote:      ".into(),
                    format!("OpenSSH on port 22, key {short} for the built-in Administrator (full rights)").bold(),
                ]));
            }
            if !r.software.is_empty() {
                let names: Vec<&str> = r.software.iter().filter_map(|id| lean11_core::software::program(id)).map(|p| p.name.as_str()).collect();
                lines.push(Line::from(vec!["Software:    ".into(), Span::raw(names.join(", "))]));
            }
            if !r.privacy.is_empty() {
                use lean11_core::privacy::Level;
                let count = |l: Level| r.privacy.iter().filter_map(|id| lean11_core::privacy::setting(id)).filter(|s| s.level == l).count();
                lines.push(Line::from(vec![
                    "Privacy:     ".into(),
                    Span::raw(format!(
                        "{} settings ({} recommended, {} strict, {} optional)",
                        r.privacy.len(),
                        count(Level::Recommended),
                        count(Level::Strict),
                        count(Level::Optional)
                    )),
                ]));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from("Selected:".bold()));
            for (o, on) in &app.options {
                if *on {
                    lines.push(Line::raw(format!("  • {}", o.title)));
                }
            }
            if !app.actions.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::from("Custom actions:".bold()));
                for a in &app.actions {
                    lines.push(Line::raw(format!("  • {:?} {:?}: {}", a.mode, a.kind, a.identity)));
                }
            }
            if app.mode == Mode::Core || app.core_removals {
                lines.push(Line::raw(""));
                if app.mode != Mode::Core {
                    lines.push(Line::styled("  • Core removals: component store, recovery, Windows Update and Defender", rating_style(Some(Rating::Breaks))));
                }
                lines.push(Line::styled("Core images cannot be updated or serviced. Use them only in test VMs.", rating_style(Some(Rating::Breaks)).add_modifier(Modifier::BOLD)));
            }
            let red = lean11_core::knowledge::breaking_choices(&r, (!app.inv.is_empty()).then_some(app.inv.as_slice()));
            if !red.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::styled(format!("Red (setup or Windows fails): {}", red.join(", ")), rating_style(Some(Rating::Breaks)).add_modifier(Modifier::BOLD)));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from("Enter: build".green().bold()));
            f.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Review ")).wrap(Wrap { trim: false }), body);
        }
        Step::Build => {
            let t = app.build.as_ref();
            let lines: Vec<Line> = t
                .map(|t| {
                    // a log entry may hold several lines
                    let all: Vec<&str> = t.lines.iter().flat_map(|l| l.lines()).collect();
                    let h = body.height.saturating_sub(2) as usize;
                    let skip = all.len().saturating_sub(h);
                    all[skip..]
                        .iter()
                        .map(|l| {
                            let l = l.to_string();
                            if l.starts_with("== ") {
                                Line::from(l.bold())
                            } else if l.starts_with("WARNING") {
                                Line::from(l.yellow())
                            } else {
                                Line::raw(l)
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let title = match t.and_then(|t| t.result.as_ref()) {
                None => Line::raw(" Building… "),
                Some(Ok(p)) => Line::styled(format!(" Done: {} (q to quit) ", p.display()), rating_style(Some(Rating::Safe)).add_modifier(Modifier::BOLD)),
                Some(Err(_)) => Line::styled(" Failed (q to quit) ", rating_style(Some(Rating::Breaks)).add_modifier(Modifier::BOLD)),
            };
            f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title)), body);
            if let Some(Err(e)) = t.and_then(|t| t.result.as_ref()) {
                popup(f, "Build failed", e);
            }
        }
    }

    let help = match app.step {
        Step::Mode => "↑↓ choose   Enter next   r load recipe   t load template   q quit",
        Step::Review => "Enter build   s save recipe   x save template   t load template   Esc back   q quit",
        Step::Source => "b browse   t type   d download (x cancels)   Enter next   Esc back",
        Step::Components => "↑↓ move   Space toggle   t/x load/save template   Enter next   Esc back",
        Step::Privacy => "↑↓ move   Space toggle   r recommended   s strict   n none   / filter   t/x template   Enter next   Esc back",
        Step::Custom => "l reload   Tab kind   / filter   Space remove/disable/none   Enter next   Esc back",
        Step::Software => "↑↓ move   Space toggle   t/x load/save template   Enter next   Esc back",
        Step::Settings => "↑↓ move   Space change/edit   t/x load/save template   Enter next   Esc back",
        Step::Build if app.build.as_ref().is_some_and(|b| b.result.is_some()) => "q quit",
        Step::Build => "s stop after the current stage (resumable)",
        _ => "↑↓ move   Enter next   Esc back   q quit",
    };
    let footer = match &app.message {
        Some(m) => Line::from(m.clone().yellow()),
        None => Line::from(help.dark_gray()),
    };
    f.render_widget(Paragraph::new(footer), foot);

    if let Some(i) = app.confirm_option {
        let o = app.options[i].0;
        popup(
            f,
            o.title,
            &format!("{}\n\nThis cannot be undone on the installed system. Use it only where you accept that.\n\nPress y to accept, n to go back.", o.description),
        );
    }
    if app.confirm_core {
        popup(
            f,
            "Lean11 Core",
            "Core removes the component store and Windows recovery and disables Windows Update and Defender. \
             The result cannot be updated, serviced or repaired, and features cannot be added later. \
             Use it only for test VMs.\n\nPress y to accept, n to go back.",
        );
    }
    if app.confirm_breaking {
        let names = lean11_core::knowledge::breaking_choices(&app.recipe(), (!app.inv.is_empty()).then_some(app.inv.as_slice()));
        popup(
            f,
            "Red choices",
            &format!(
                "These choices are rated red: setup or Windows fails with them.\n\n  {}\n\nBuild anyway? Press y to accept, n to go back.",
                names.join("\n  ")
            ),
        );
    }
    if app.confirm_expert {
        popup(
            f,
            "Custom actions",
            "Custom removals act on protected parts of the image. They can make it unbootable or unable to update, \
             recover or protect itself. Test the result in an isolated VM.\n\nPress y to accept, n to go back.",
        );
    }
    if let Some((field, text)) = &app.editing {
        let title = match field {
            Field::Source => "Path to ISO or media directory",
            Field::Output => "Output ISO",
            Field::Work => "Working directory (empty = next to the output)",
            Field::Language => "Download language (e.g. de-DE, English) or an official Microsoft ISO link",
            Field::Filter => "Filter (part of the name, empty = all)",
            Field::SaveRecipe => "Save the recipe as",
            Field::LoadRecipe => "Load a recipe from",
            Field::SshKey => "Public key file (.pub) for the built-in Administrator, empty = off",
            Field::PrivacyFilter => "Filter privacy settings (part of the title, id or category, empty = all)",
            Field::SaveTemplate => "Save the template (your choice without source and output) as",
            Field::LoadTemplate => "Load a template from",
        };
        popup(f, title, &format!("{text}▏\n\nEnter accept, Esc cancel"));
    }
    if let Some((_, p)) = &mut app.picker {
        p.render(f);
    }
}

/// Replaces a leading `~` (alone or followed by a path separator) with the home directory, as a shell would.
fn expand_home(text: &str) -> String {
    let t = text.trim();
    let rest = match t.strip_prefix('~') {
        Some(r) if r.is_empty() || r.starts_with('/') || r.starts_with('\\') => r,
        _ => return text.to_string(),
    };
    match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).filter(|h| !h.is_empty()) {
        Some(h) => format!("{}{rest}", h.to_string_lossy()),
        None => text.to_string(),
    }
}

/// Traffic-light color of a rating. Fixed colors of the 256-color palette (pure green, gold, pure red, grey):
/// terminal themes recolor the 16 named colors, often into pastels that are hard to tell apart.
fn rating_color(r: Option<Rating>) -> Color {
    match r {
        Some(Rating::Safe) => Color::Indexed(46),
        Some(Rating::Limited) => Color::Indexed(220),
        Some(Rating::Breaks) => Color::Indexed(196),
        None => Color::Indexed(244),
    }
}

/// Style for a rated row or word: its traffic-light color.
fn rating_style(r: Option<Rating>) -> Style {
    Style::new().fg(rating_color(r))
}

/// Colored dot for a rating (grey = not rated yet).
fn rating_dot(r: Option<Rating>) -> Span<'static> {
    Span::styled("● ", rating_style(r))
}

/// Legend for the description boxes.
fn rating_legend() -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled("● safe ", rating_style(Some(Rating::Safe))),
        Span::styled("● limited ", rating_style(Some(Rating::Limited))),
        Span::styled("● breaks Windows ", rating_style(Some(Rating::Breaks))),
        Span::styled("● not rated ", rating_style(None)),
    ])
}

/// Description lines of a knowledge entry: rating with what it is, the effect, the evidence.
fn knowledge_lines(e: &knowledge::Entry) -> Vec<Line<'static>> {
    let word = match e.rating {
        Rating::Safe => "Safe",
        Rating::Limited => "Limited",
        Rating::Breaks => "Breaks Windows",
    };
    let st = rating_style(Some(e.rating));
    vec![
        Line::from(vec![Span::styled(format!("{word}: "), st.add_modifier(Modifier::BOLD)), Span::raw(e.what.clone())]),
        Line::from(vec![Span::raw("If removed: ").bold(), Span::raw(e.effect.clone())]),
        Line::from(format!("Verified: {}", e.verified).dark_gray()),
    ]
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Lean => "Lean11",
        Mode::Core => "Lean11 Core",
        Mode::Custom => "Custom",
    }
}

/// `s` cut (with "…") or padded to exactly `w` display cells.
fn fit(s: &str, w: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    if UnicodeWidthStr::width(s) <= w {
        out.push_str(s);
        used = UnicodeWidthStr::width(s);
    } else {
        for c in s.chars() {
            let cw = UnicodeWidthChar::width(c).unwrap_or(0);
            if used + cw + 1 > w {
                break;
            }
            out.push(c);
            used += cw;
        }
        out.push('…');
        used += 1;
    }
    out.extend(std::iter::repeat_n(' ', w.saturating_sub(used)));
    out
}

fn popup(f: &mut Frame, title: &str, text: &str) {
    let a = f.area();
    let w = (a.width * 3 / 4).max(40).min(a.width);
    // height from the wrapped text (plus borders), so the y/n line is never cut off
    let inner = w.saturating_sub(2).max(1) as usize;
    let rows: usize = text.split('\n').map(|l| UnicodeWidthStr::width(l).div_ceil(inner).max(1)).sum();
    // +1: word wrapping can need a line more than the character count suggests
    let h = ((rows + 3).min(u16::MAX as usize) as u16).max(5).min(a.height);
    let r = Rect::new(a.x + (a.width - w) / 2, a.y + (a.height - h) / 2, w, h);
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(text.to_string()).wrap(Wrap { trim: false }).block(Block::bordered().title(format!(" {title} ")).yellow()), r);
}

fn run_app(terminal: &mut DefaultTerminal, mut app: App) -> Result<()> {
    while !app.quit {
        app.poll();
        terminal.draw(|f| render(f, &mut app))?;
        if event::poll(Duration::from_millis(200))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            app.key(k.code, k.modifiers);
        }
    }
    Ok(())
}

pub fn run(source: Option<PathBuf>) -> Result<()> {
    let mut terminal = ratatui::init();
    let r = run_app(&mut terminal, App::new(source));
    ratatui::restore();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_cells() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(UnicodeWidthStr::width(fit("服务主机本地系统", 7).as_str()), 7);
    }

    #[test]
    fn home_expansion() {
        assert_eq!(expand_home("/data/win.iso"), "/data/win.iso");
        assert_eq!(expand_home("~user/win.iso"), "~user/win.iso");
        if let Some(h) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let h = h.to_string_lossy().into_owned();
            assert_eq!(expand_home("~/Downloads/win.iso"), format!("{h}/Downloads/win.iso"));
            assert_eq!(expand_home(" ~ "), h);
        }
    }
}
