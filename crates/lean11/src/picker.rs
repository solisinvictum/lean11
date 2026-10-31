//! File and directory picker for the TUI: browse with the arrow keys instead of typing paths.

use std::path::{Path, PathBuf};

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;

/// What the picker looks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A Windows ISO, or an extracted media directory (has sources/install.wim|esd).
    Source,
    /// An OpenSSH public key (.pub).
    PubKey,
    /// A saved recipe (.json).
    Recipe,
    /// A directory.
    Dir,
    /// A directory to save a file in; the name is typed afterwards.
    SaveIn,
}

/// Result of a key press.
pub enum Outcome {
    Stay,
    Cancel,
    Pick(PathBuf),
    /// Switch to typing, prefilled with this text.
    Type(String),
    /// Clear the setting (SSH key).
    Clear,
}

struct Entry {
    name: String,
    path: PathBuf,
    dir: bool,
    size: u64,
    /// Directory with Windows installation media.
    media: bool,
}

pub struct Picker {
    pub kind: Kind,
    pub title: String,
    dir: PathBuf,
    entries: Vec<Entry>,
    state: ListState,
    hidden: bool,
    error: Option<String>,
    /// Default file name for `SaveIn`.
    pub save_name: String,
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" }))
}

fn is_media(dir: &Path) -> bool {
    ["sources/install.wim", "sources/install.esd"].iter().any(|p| lean11_wim::resolve_ci(dir, p).is_some_and(|f| f.is_file()))
}

fn wanted_file(kind: Kind, name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    match kind {
        Kind::Source => l.ends_with(".iso"),
        Kind::PubKey => l.ends_with(".pub"),
        Kind::Recipe => l.ends_with(".json"),
        Kind::Dir | Kind::SaveIn => false,
    }
}

impl Picker {
    /// Opens at the directory of `current` if it exists, else at the first existing `fallbacks`
    /// directory (relative to $HOME), else at $HOME.
    pub fn new(kind: Kind, title: &str, current: &str, fallbacks: &[&str]) -> Self {
        let cur = PathBuf::from(current.trim());
        let start = if !current.trim().is_empty() && cur.is_dir() && kind != Kind::Source {
            Some(cur.clone())
        } else {
            cur.parent().filter(|p| !p.as_os_str().is_empty() && p.is_dir()).map(Path::to_path_buf)
        };
        let dir = start
            .or_else(|| fallbacks.iter().map(|f| home().join(f)).find(|p| p.is_dir()))
            .unwrap_or_else(home);
        let mut p = Picker {
            kind,
            title: title.to_string(),
            dir: std::fs::canonicalize(&dir).unwrap_or(dir),
            entries: Vec::new(),
            state: ListState::default(),
            hidden: false,
            error: None,
            save_name: String::new(),
        };
        p.reload(cur.file_name().map(|n| n.to_string_lossy().into_owned()).as_deref());
        p
    }

    fn reload(&mut self, select: Option<&str>) {
        self.entries.clear();
        self.error = None;
        if let Some(parent) = self.dir.parent() {
            self.entries.push(Entry { name: "..".into(), path: parent.to_path_buf(), dir: true, size: 0, media: false });
        }
        let mut list = Vec::new();
        match std::fs::read_dir(&self.dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !self.hidden && name.starts_with('.') {
                        continue;
                    }
                    let path = e.path();
                    // follow symlinks (e.g. /Volumes, ~/Downloads links)
                    let Ok(md) = std::fs::metadata(&path) else { continue };
                    if md.is_dir() {
                        let media = self.kind == Kind::Source && is_media(&path);
                        list.push(Entry { name, path, dir: true, size: 0, media });
                    } else if wanted_file(self.kind, &name) {
                        list.push(Entry { name, path, dir: false, size: md.len(), media: false });
                    }
                }
            }
            Err(e) => self.error = Some(format!("cannot read {}: {e}", self.dir.display())),
        }
        list.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        self.entries.extend(list);
        let idx = select
            .and_then(|s| self.entries.iter().position(|e| e.name == s))
            .or_else(|| self.entries.iter().position(|e| !e.dir))
            .or_else(|| self.entries.iter().position(|e| e.media))
            .unwrap_or(usize::from(self.entries.len() > 1 && self.entries[0].name == ".."));
        self.state.select((!self.entries.is_empty()).then_some(idx.min(self.entries.len().saturating_sub(1))));
    }

    fn open(&mut self, dir: PathBuf) {
        let from = self.dir.file_name().map(|n| n.to_string_lossy().into_owned());
        let up = self.dir.parent() == Some(dir.as_path());
        self.dir = dir;
        self.reload(if up { from.as_deref() } else { None });
    }

    fn selected(&self) -> Option<&Entry> {
        self.state.selected().and_then(|i| self.entries.get(i))
    }

    pub fn key(&mut self, code: KeyCode) -> Outcome {
        let n = self.entries.len();
        match code {
            KeyCode::Esc => return Outcome::Cancel,
            KeyCode::Up => self.state.select_previous(),
            KeyCode::Down => self.state.select_next(),
            KeyCode::PageUp => self.state.select(Some(self.state.selected().unwrap_or(0).saturating_sub(15))),
            KeyCode::PageDown => self.state.select(Some((self.state.selected().unwrap_or(0) + 15).min(n.saturating_sub(1)))),
            KeyCode::Home => self.state.select(Some(0)),
            KeyCode::End => self.state.select(Some(n.saturating_sub(1))),
            KeyCode::Left | KeyCode::Backspace => {
                if let Some(p) = self.dir.parent().map(Path::to_path_buf) {
                    self.open(p);
                }
            }
            KeyCode::Right => {
                if let Some(e) = self.selected().filter(|e| e.dir) {
                    let p = e.path.clone();
                    self.open(p);
                }
            }
            KeyCode::Enter => {
                if let Some(e) = self.selected() {
                    let p = e.path.clone();
                    if !e.dir {
                        return Outcome::Pick(p);
                    }
                    self.open(p);
                }
            }
            // choose a directory: the shown one (working directory, save location) or, for the source,
            // the highlighted media folder
            KeyCode::Char(' ') | KeyCode::Char('s') => {
                let target = match (self.kind, self.selected()) {
                    (Kind::Source, Some(e)) if e.media => e.path.clone(),
                    _ => self.dir.clone(),
                };
                match self.kind {
                    Kind::Dir => return Outcome::Pick(target),
                    Kind::Source => {
                        if is_media(&target) {
                            return Outcome::Pick(target);
                        }
                        self.error = Some(format!("{} has no sources/install.wim or install.esd", target.display()));
                    }
                    Kind::SaveIn => return Outcome::Type(target.join(&self.save_name).display().to_string()),
                    Kind::PubKey | Kind::Recipe => {}
                }
            }
            KeyCode::Char('.') => {
                self.hidden = !self.hidden;
                let keep = self.selected().map(|e| e.name.clone());
                self.reload(keep.as_deref());
            }
            KeyCode::Char('~') => self.open(home()),
            // the root of the current drive on Windows
            KeyCode::Char('/') => self.open(self.dir.ancestors().last().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))),
            KeyCode::Char('t') => {
                let base = match (self.kind, self.selected()) {
                    (Kind::SaveIn, _) => self.dir.join(&self.save_name),
                    (_, Some(e)) if !e.dir => e.path.clone(),
                    _ => self.dir.join(""),
                };
                return Outcome::Type(base.display().to_string());
            }
            KeyCode::Delete | KeyCode::Char('x') if self.kind == Kind::PubKey => return Outcome::Clear,
            _ => {}
        }
        Outcome::Stay
    }

    fn help(&self) -> String {
        let pick = match self.kind {
            Kind::Source => "Enter open/choose ISO   s use media folder (highlighted or shown)",
            Kind::PubKey => "Enter choose key   x no key",
            Kind::Recipe => "Enter choose recipe",
            Kind::Dir => "Enter open folder   s use the folder shown above",
            Kind::SaveIn => "Enter open folder   s save in the folder shown above",
        };
        format!("↑↓ move   ←/Backspace up   {pick}   . hidden   ~ home   t type a path   Esc cancel")
    }

    pub fn render(&mut self, f: &mut Frame) {
        let a = f.area();
        let w = (a.width * 9 / 10).max(50).min(a.width);
        let h = (a.height * 8 / 10).max(12).min(a.height);
        let r = Rect::new(a.x + (a.width - w) / 2, a.y + (a.height - h) / 2, w, h);
        f.render_widget(Clear, r);
        let block = Block::bordered().title(format!(" {} ", self.title)).yellow();
        let inner = block.inner(r);
        f.render_widget(block, r);
        let foot_h = if inner.width < 110 { 3 } else { 2 };
        let [head, body, foot] = Layout::vertical([Constraint::Length(1), Constraint::Min(1), Constraint::Length(foot_h)]).areas(inner);
        f.render_widget(Paragraph::new(Line::from(vec![Span::raw("📂 "), self.dir.display().to_string().bold()])), head);
        let items: Vec<ListItem> = self
            .entries
            .iter()
            .map(|e| {
                if e.dir {
                    let mut spans = vec![Span::styled(format!("{}/", e.name), Style::default().fg(Color::Cyan))];
                    if e.media {
                        spans.push(Span::styled("   Windows media", Style::default().fg(Color::Green)));
                    }
                    ListItem::new(Line::from(spans))
                } else {
                    let size = if e.size >= 1 << 30 {
                        format!("{:.2} GiB", e.size as f64 / (1u64 << 30) as f64)
                    } else if e.size >= 1 << 20 {
                        format!("{:.1} MiB", e.size as f64 / (1u64 << 20) as f64)
                    } else {
                        format!("{} B", e.size)
                    };
                    ListItem::new(Line::from(vec![Span::raw(e.name.clone()), Span::styled(format!("   {size}"), Style::default().fg(Color::DarkGray))]))
                }
            })
            .collect();
        let empty = !self.entries.iter().any(|e| e.name != "..");
        let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED)).highlight_symbol("▶ ");
        f.render_stateful_widget(list, body, &mut self.state);
        if empty && self.error.is_none() {
            let what = match self.kind {
                Kind::Source => "no .iso files or folders here",
                Kind::PubKey => "no .pub files or folders here",
                Kind::Recipe => "no .json files or folders here",
                Kind::Dir | Kind::SaveIn => "no subfolders here",
            };
            let r2 = Rect::new(body.x + 2, body.y + 2.min(body.height.saturating_sub(1)), body.width.saturating_sub(4), 1);
            f.render_widget(Paragraph::new(what).dark_gray(), r2);
        }
        let mut lines = vec![Line::from(self.help()).dark_gray()];
        if let Some(e) = &self.error {
            lines.insert(0, Line::from(e.clone()).red());
        }
        f.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }), foot);
    }
}
