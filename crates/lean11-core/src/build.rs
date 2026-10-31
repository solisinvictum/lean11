//! The build pipeline: media → working image → removals and settings → compression → boot image → ISO.
//!
//! Each finished stage is recorded in `job.json`, so an interrupted build resumes after the last
//! completed stage (`lean11 build --resume <job dir>`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use lean11_hive::{Hive, RegData};
use lean11_wim::{Compression, ImageInfo, Mount};

use crate::catalog::{self, Hive as H, Kind, Mode, RegOp, Value};
use crate::ssh;
use crate::{appx, cbs, inventory, offline, unattend};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    /// Windows ISO or extracted media directory.
    pub source: PathBuf,
    /// Image index, name or edition id; default Professional.
    pub edition: Option<String>,
    pub mode: Mode,
    /// Core's irreversible removals; set by the Core preset or chosen in Custom.
    #[serde(default)]
    pub core: bool,
    /// Selected catalog option ids.
    pub options: Vec<String>,
    pub compression: Compression,
    pub local_account: bool,
    pub compact: bool,
    /// Add an OpenSSH server and this authorized key (built-in Administrator).
    #[serde(default)]
    pub ssh_authorized_key: Option<String>,
    pub output: PathBuf,
    pub label: Option<String>,
    /// UEFI boot without "press any key".
    pub no_prompt: bool,
    pub keep_work: bool,
    /// Do not stage sources\sxs (.NET 3.5 payload) into the output media.
    pub omit_sxs: bool,
    /// Remove offline caches, archived logs and crash reports.
    #[serde(default)]
    pub remove_redundant_data: bool,
    /// Custom-mode expert actions on inventory items.
    #[serde(default)]
    pub actions: Vec<inventory::Action>,
    /// Turbo mode: a fast-compressed working image for Core, fast output or WinSxS actions.
    #[serde(default)]
    pub turbo: bool,
    /// The user accepted Core's loss of updates, recovery and antivirus protection.
    #[serde(default)]
    pub core_acknowledged: bool,
    /// The user accepted that expert actions can make the image unbootable.
    #[serde(default)]
    pub expert_acknowledged: bool,
    /// Selected privacy settings (ids of `data/privacy.toml`).
    #[serde(default)]
    pub privacy: Vec<String>,
    /// The custom actions come from a template made on another image: they are matched to this image's
    /// inventory by name without version (unmatched ones are skipped) instead of requiring the exact
    /// identity.
    #[serde(default)]
    pub adapt_actions: bool,
    /// Additional programs (ids of `data/software.toml`), installed at the end of setup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub software: Vec<String>,
    /// The user accepted choices rated `breaks` (setup or Windows fails with them).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub breaking_acknowledged: bool,
}

impl Recipe {
    /// Core pruning, Core registry changes and the legacy installer apply.
    pub fn is_core(&self) -> bool {
        self.core || self.mode == Mode::Core
    }

    fn has(&self, id: &str) -> bool {
        self.options.iter().any(|o| o == id)
    }

    /// Core's four parts, each also selectable on its own in Custom.
    pub fn disables_defender(&self) -> bool {
        self.is_core() || self.has("disable-defender")
    }
    pub fn disables_updates(&self) -> bool {
        self.is_core() || self.has("disable-windows-update")
    }
    pub fn removes_winre(&self) -> bool {
        self.is_core() || self.has("remove-winre")
    }
    pub fn trims_winsxs(&self) -> bool {
        self.is_core() || self.has("trim-winsxs")
    }

    /// A preset whose removal set was changed becomes Custom, keeping Core's removals when they were on.
    pub fn normalize_mode(&mut self) {
        if self.mode == Mode::Custom {
            return;
        }
        let preset: std::collections::BTreeSet<&str> = catalog::for_mode(self.mode).into_iter().collect();
        let chosen: std::collections::BTreeSet<&str> = self.options.iter().map(String::as_str).collect();
        // remote access is a Custom addition too
        if preset != chosen
            || !self.actions.is_empty()
            || (self.mode == Mode::Lean && self.core)
            || self.ssh_authorized_key.is_some()
            || !self.privacy.is_empty()
            || !self.software.is_empty()
        {
            self.core = self.is_core();
            self.mode = Mode::Custom;
        }
    }

    /// Checks the recipe before a build.
    pub fn validate(&self) -> Result<()> {
        if self.mode != Mode::Custom {
            let preset: std::collections::BTreeSet<&str> = catalog::for_mode(self.mode).into_iter().collect();
            let chosen: std::collections::BTreeSet<&str> = self.options.iter().map(String::as_str).collect();
            if (self.mode == Mode::Lean && self.core) || !self.actions.is_empty() || preset != chosen {
                bail!("Use Custom for changes to the Lean11 or Lean11 Core removal sets.");
            }
            if self.ssh_authorized_key.is_some() {
                bail!("The SSH server option is part of Custom.");
            }
            if !self.privacy.is_empty() {
                bail!("Privacy settings are part of Custom.");
            }
            if !self.software.is_empty() {
                bail!("Additional software is part of Custom.");
            }
        }
        crate::software::validate(&self.software)?;
        let breaking = crate::knowledge::breaking_choices(self, None);
        if !breaking.is_empty() && !self.breaking_acknowledged {
            bail!("These choices break setup or Windows (red): {}. Accept with --accept-breaking.", breaking.join(", "));
        }
        if self.is_core() && !self.core_acknowledged {
            bail!("Core requires acknowledgement of the loss of updates, recovery and antivirus protection.");
        }
        crate::privacy::resolve(self, &mut |_| {})?;
        if (self.removes_winre() || self.trims_winsxs()) && !self.core_acknowledged {
            bail!("Removing WinRE or trimming WinSxS is irreversible and requires acknowledgement (--accept-core).");
        }
        if !self.actions.is_empty() && !self.expert_acknowledged {
            bail!("Custom removals require acknowledgement of the risk of an unbootable image.");
        }
        if let Some(k) = &self.ssh_authorized_key {
            if !ssh::valid_authorized_key(k) {
                bail!("The SSH key is not a valid OpenSSH public key (expected e.g. 'ssh-ed25519 AAAA... comment').");
            }
        }
        let mut seen = std::collections::HashSet::new();
        for a in &self.actions {
            if !seen.insert((a.kind, a.identity.clone())) {
                bail!("Duplicate custom image actions.");
            }
            inventory::check_action(a)?;
        }
        let mut ids = std::collections::HashSet::new();
        for id in &self.options {
            if !ids.insert(id) {
                bail!("Invalid image index or duplicate cleanup options.");
            }
            if catalog::option(id).is_none() {
                bail!("Unknown cleanup option: {id}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Start,
    Media,
    Exported,
    Serviced,
    Compressed,
    BootImage,
    Iso,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub recipe: Recipe,
    pub stage: Stage,
    pub image: Option<ImageInfo>,
    pub label: String,
    pub warnings: Vec<String>,
    pub removed: Vec<String>,
    pub registry_values: usize,
    pub sha256: Option<String>,
    pub timings: Vec<(String, f64)>,
    /// Saved progress that resume verifies.
    #[serde(default)]
    pub checkpoint: Checkpoint,
    /// Operation history.
    #[serde(default)]
    pub operations: Vec<Operation>,
    /// Redundant-data outcomes.
    #[serde(default)]
    pub cleanup: Vec<offline::CleanupResult>,
    #[serde(default)]
    pub features: Vec<cbs::FeatureCheck>,
    #[serde(default)]
    pub capabilities: Vec<cbs::CapabilityCheck>,
    /// Stage the job was resumed from.
    #[serde(default)]
    pub resumed_from: Option<String>,
    /// Setup files left out of the media by omit_sxs.
    #[serde(default)]
    pub omitted_setup_bytes: u64,
    /// The working copy was discarded by `recover --discard`; logs and reports stay.
    #[serde(default)]
    pub discarded: bool,
}

/// One entry of the operation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Operation {
    pub id: String,
    pub stage: String,
    pub title: String,
    /// Pending, Running, Completed, Skipped, Failed
    pub state: String,
    pub detail: Option<String>,
    pub duration_milliseconds: Option<f64>,
}

/// Unfinished jobs in a work directory: (job directory, stage). Their leftover mounts are released;
/// with `discard` the job directories are deleted.
pub fn recover(target: &Path, discard: bool, log: &mut dyn FnMut(&str)) -> Result<Vec<(PathBuf, String)>> {
    let is_owned = |name: &str| {
        name.strip_prefix("lean11-").is_some_and(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()))
            || name.starts_with("lean11-inventory-")
    };
    // a single job folder or a whole working directory
    let name_of = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let dirs: Vec<PathBuf> = if is_owned(&name_of(target)) {
        vec![target.to_path_buf()]
    } else {
        let mut v: Vec<PathBuf> = fs::read_dir(target)?.flatten().map(|e| e.path()).filter(|p| is_owned(&name_of(p))).collect();
        v.sort();
        v
    };
    let mut out = Vec::new();
    for dir in dirs {
        let name = name_of(&dir);
        if !dir.is_dir() || dir.symlink_metadata()?.file_type().is_symlink() {
            continue;
        }
        let inventory = name.starts_with("lean11-inventory-");
        // active jobs are refused: the owner holds the lock (taken before reading the saved state)
        let Some(_lock) = lock_dir(&dir) else {
            log(&format!("{} is in use by a running build or inventory; skipped", dir.display()));
            out.push((dir, "Active".into()));
            continue;
        };
        let mut job: Option<Job> = fs::read(dir.join("job.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
        if job.as_ref().is_some_and(|j| j.stage == Stage::Done || j.discarded) {
            continue;
        }
        for (wim, m) in [(dir.join("install-work.wim"), dir.join("mount")), (dir.join("setup/boot.wim"), dir.join("mount-boot")), (dir.join("inventory.wim"), dir.join("mount"))] {
            lean11_wim::release_stale(&wim, &m, log)?;
        }
        let stage = if inventory { "Inventory".to_string() } else { job.as_ref().map(|j| format!("{:?}", j.stage)).unwrap_or_else(|| "Start".into()) };
        if discard {
            if inventory {
                fs::remove_dir_all(&dir)?;
            } else {
                // only the working copy goes; source, logs, recipe, reports and any output stay
                for sub in ["media", "mount", "mount-boot", "setup", "compress", "install-work.wim", "source-install.wim", "source-install.esd"] {
                    let p = dir.join(sub);
                    if lean11_wim::is_mountpoint(&p) {
                        bail!("{} is still mounted", p.display());
                    }
                    if p.is_dir() {
                        fs::remove_dir_all(&p)?;
                    } else if p.exists() {
                        fs::remove_file(&p)?;
                    }
                }
                if let Some(j) = job.as_mut() {
                    j.discarded = true;
                    fs::write(dir.join("job.json"), serde_json::to_vec_pretty(j)?)?;
                }
            }
            log(&format!("discarded the working copy of {}", dir.display()));
        }
        out.push((dir, stage));
    }
    Ok(out)
}

/// Length and SHA-256 of the files a resumed job relies on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    /// SHA-256 of the recipe without its output path: resume refuses changed removal choices.
    #[serde(default)]
    pub recipe: Option<String>,
    /// Working image after export or commit.
    pub working: Option<(u64, String)>,
    /// Staged media files (relative path → length, SHA-256); nothing else may be present.
    pub media: std::collections::BTreeMap<String, (u64, String)>,
}

/// Windows 11 client, build 22621 or newer.
fn validate_image(img: &ImageInfo) -> Result<()> {
    let build: u32 = img.build.parse().unwrap_or(0);
    if build < 22621 {
        bail!("{} is build {build}; Windows 11 22H2 (22621) or newer is required", img.name);
    }
    if img.installation_type != "Client" && !img.installation_type.is_empty() {
        bail!("{} is a {} image; only Windows client images are supported", img.name, img.installation_type);
    }
    Ok(())
}

/// Editions of an ISO (read from the install image header, no extraction) or a media directory.
pub fn source_images(source: &Path) -> Result<Vec<ImageInfo>> {
    let images = if source.is_dir() {
        let wim = lean11_wim::resolve_ci(source, "sources/install.wim")
            .or_else(|| lean11_wim::resolve_ci(source, "sources/install.esd"))
            .ok_or_else(|| anyhow!("source has no sources/install.wim or install.esd"))?;
        lean11_wim::info(&wim)?
    } else if source.is_file() {
        let r = lean11_iso::UdfReader::open(source)?;
        let e = r
            .find("sources/install.wim")?
            .or(r.find("sources/install.esd")?)
            .ok_or_else(|| anyhow!("the ISO has no sources/install.wim or install.esd"))?;
        lean11_wim::info_from_header(&mut |o, l| r.read_range(&e, o, l))?
    } else {
        bail!("source {} not found", source.display());
    };
    if images.is_empty() {
        bail!("no images found in the source");
    }
    Ok(images)
}

/// Hash of the removal choices (everything but the output name, which a resume may change).
fn recipe_digest(r: &Recipe) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut r = r.clone();
    r.output = PathBuf::new();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&r)?)))
}

/// Exclusive lock on an owned folder (`job.lock`); `None` while another process holds it.
pub fn lock_dir(dir: &Path) -> Option<fs::File> {
    let lock = fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("job.lock")).ok()?;
    lock.try_lock().ok().map(|()| lock)
}

use lean11_wim::platform::FsKind;

/// (file-system kind, bytes available) of the file system holding `p`.
fn fs_info(p: &Path) -> Result<(FsKind, u64)> {
    lean11_wim::platform::fs_info(p).with_context(|| format!("cannot inspect {}", p.display()))
}

const GIB: u64 = 1 << 30;

/// Host checks: workspace on a file system that can hold WIM staging data and enough free
/// space, output not on FAT32 and at least 12 GiB free on another drive.
fn check_host(work: &Path, output: &Path, required: u64) -> Result<()> {
    let (wtype, wfree) = fs_info(work)?;
    if wtype != FsKind::Other {
        bail!("The workspace cannot be on FAT or exFAT: image extraction needs hard links and files over 4 GiB.");
    }
    if wfree < required {
        bail!("The workspace needs at least {} GiB free for this image.", required.div_ceil(GIB));
    }
    let out_dir = std::path::absolute(output)?.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let (otype, ofree) = fs_info(&out_dir)?;
    if otype == FsKind::Fat {
        bail!("The output drive cannot be FAT32; Windows ISOs commonly exceed its 4 GiB limit.");
    }
    let same = lean11_wim::platform::volume_id(work).is_some() && lean11_wim::platform::volume_id(work) == lean11_wim::platform::volume_id(&out_dir);
    if !same && ofree < 12 * GIB {
        bail!("The output drive needs at least 12 GiB free.");
    }
    Ok(())
}

fn file_digest(p: &Path) -> Result<(u64, String)> {
    Ok((fs::metadata(p)?.len(), sha256(p)?))
}

/// Relative paths of every file below `root` (`/` separated).
fn list_files(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let e = e?;
            let t = e.file_type()?;
            if t.is_dir() {
                stack.push(e.path());
            } else if t.is_symlink() {
                bail!("the staged media contains a symbolic link: {}", e.path().display());
            } else {
                out.push(e.path().strip_prefix(root)?.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

pub struct Builder<'a> {
    pub dir: PathBuf,
    pub job: Job,
    /// Exclusive lock on the job directory while this process owns it.
    _lock: fs::File,
    /// Set from another thread to stop at the next stage boundary; the job stays resumable.
    pub cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    current_stage: String,
    log_file: std::cell::RefCell<fs::File>,
    sink: std::cell::RefCell<&'a mut dyn FnMut(&str)>,
}

pub fn is_root() -> bool {
    lean11_wim::platform::is_admin()
}

/// Only the wimlib fallback (`LEAN11_WIMLIB=1`) mounts images through FUSE and needs root.
pub fn lacks_privileges() -> bool {
    !lean11_wim::native() && !is_root()
}

impl<'a> Builder<'a> {
    pub fn new(work: &Path, recipe: Recipe, sink: &'a mut dyn FnMut(&str)) -> Result<Self> {
        recipe.validate()?;
        if recipe.output.exists() {
            bail!("{} already exists; choose another output name", recipe.output.display());
        }
        // preflight: the edition, its build and the room it needs
        fs::create_dir_all(work)?;
        let images = source_images(&recipe.source)?;
        let img = lean11_wim::select(&images, recipe.edition.as_deref())?;
        validate_image(img)?;
        check_host(work, &recipe.output, (40 * GIB).max(img.total_bytes.saturating_mul(3) + 10 * GIB))?;
        let digest = recipe_digest(&recipe)?;
        let dir = work.join(format!("lean11-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&dir)?;
        // locked before anything else is written, so `recover` never sees it unlocked
        let lock = lock_dir(&dir).ok_or_else(|| anyhow!("cannot lock the new job folder"))?;
        fs::write(dir.join("recipe.json"), serde_json::to_vec_pretty(&recipe)?)?;
        let job = Job {
            recipe,
            stage: Stage::Start,
            image: None,
            label: String::new(),
            warnings: Vec::new(),
            removed: Vec::new(),
            registry_values: 0,
            sha256: None,
            timings: Vec::new(),
            checkpoint: Checkpoint { recipe: Some(digest), ..Checkpoint::default() },
            operations: Vec::new(),
            cleanup: Vec::new(),
            features: Vec::new(),
            capabilities: Vec::new(),
            resumed_from: None,
            omitted_setup_bytes: 0,
            discarded: false,
        };
        Self::with(dir, job, lock, sink)
    }

    /// Continues a stopped job; `output` gives it a new ISO name when the saved one exists by now.
    pub fn resume(dir: &Path, output: Option<PathBuf>, sink: &'a mut dyn FnMut(&str)) -> Result<Self> {
        if !dir.join("job.json").is_file() {
            bail!("{} is not a lean11 job folder (no job.json)", dir.display());
        }
        // lock first, then read the saved state
        let lock = lock_dir(dir).ok_or_else(|| anyhow!("This job is already running in another process."))?;
        let mut job: Job = serde_json::from_slice(&fs::read(dir.join("job.json")).context("no job.json in that directory")?)?;
        if job.stage == Stage::Done {
            bail!("this job already finished");
        }
        if job.discarded {
            bail!("This job's working copy was discarded; start a new build.");
        }
        job.recipe.validate()?;
        if let Some(want) = &job.checkpoint.recipe
            && *want != recipe_digest(&job.recipe)?
        {
            bail!("The saved removal choices of this job changed after it was saved; start a new build.");
        }
        if let Some(o) = output {
            job.recipe.output = o;
        }
        if job.recipe.output.exists() {
            bail!("{} already exists; resume with --out <new name>", job.recipe.output.display());
        }
        // the ISO stage finished but its output is not there (new name or removed): write it again
        if job.stage == Stage::Iso {
            job.stage = Stage::BootImage;
        }
        check_host(dir, &job.recipe.output, 0)?;
        let mut b = Self::with(dir.to_path_buf(), job, lock, sink)?;
        b.verify_checkpoint()?;
        b.job.resumed_from = Some(format!("{:?}", b.job.stage));
        Ok(b)
    }

    /// Resume checks: the saved working image and the staged media must be exactly what was recorded.
    fn verify_checkpoint(&mut self) -> Result<()> {
        // a mount or wimlib staging data left by the interrupted run is discarded first
        for (wim, dir) in [(self.working_wim(), self.dir.join("mount")), (self.dir.join("setup/boot.wim"), self.dir.join("mount-boot"))] {
            lean11_wim::release_stale(&wim, &dir, &mut |l| self.log(l))?;
        }
        if self.job.stage >= Stage::Exported && self.job.stage < Stage::Compressed {
            let (len, sha) = self.job.checkpoint.working.clone().ok_or_else(|| anyhow!("this job has no saved working image record; start a new build"))?;
            self.log("Verifying the saved Windows image…");
            if file_digest(&self.working_wim())? != (len, sha) {
                bail!("The saved working image changed after it was saved (its SHA-256 differs), so it cannot be trusted. Start a new build.");
            }
        }
        if self.job.stage >= Stage::Media && self.job.stage < Stage::Iso {
            self.log("Verifying the staged media…");
            let media = self.media();
            let present = list_files(&media)?;
            let expected: Vec<String> = self.job.checkpoint.media.keys().cloned().collect();
            if present != expected {
                bail!("The staged media differs from the saved progress (files added or missing). Start a new build.");
            }
            for (rel, want) in self.job.checkpoint.media.clone() {
                if file_digest(&media.join(&rel))? != want {
                    bail!("The staged file {rel} changed after it was saved, so the job cannot be resumed. Start a new build.");
                }
            }
        }
        self.log("Saved progress verified.");
        Ok(())
    }

    fn record_media(&mut self, rel: &str) -> Result<()> {
        let d = file_digest(&self.media().join(rel))?;
        self.job.checkpoint.media.insert(rel.to_string(), d);
        Ok(())
    }

    fn with(dir: PathBuf, job: Job, lock: fs::File, sink: &'a mut dyn FnMut(&str)) -> Result<Self> {
        let log_file = fs::OpenOptions::new().create(true).append(true).open(dir.join("build.log"))?;
        let b = Builder { dir, job, _lock: lock, cancel: None, current_stage: "Prepare".into(), log_file: log_file.into(), sink: std::cell::RefCell::new(sink) };
        b.save()?;
        Ok(b)
    }

    pub fn log(&self, msg: &str) {
        let _ = writeln!(self.log_file.borrow_mut(), "{msg}");
        (self.sink.borrow_mut())(msg);
    }

    /// Records an operation outcome.
    fn op(&mut self, id: String, title: String, state: &str, detail: Option<String>, ms: Option<f64>) {
        let stage = self.current_stage.clone();
        self.job.operations.retain(|o| o.id != id);
        self.job.operations.push(Operation { id, stage, title, state: state.into(), detail, duration_milliseconds: ms });
    }

    fn warn(&mut self, msg: String) {
        self.log(&format!("WARNING: {msg}"));
        self.job.warnings.push(msg);
    }

    fn save(&self) -> Result<()> {
        let tmp = self.dir.join("job.json.new");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.job)?)?;
        fs::rename(tmp, self.dir.join("job.json"))?;
        Ok(())
    }

    fn media(&self) -> PathBuf {
        self.dir.join("media")
    }
    fn working_wim(&self) -> PathBuf {
        self.dir.join("install-work.wim")
    }
    fn source_install(&self) -> Result<PathBuf> {
        for name in ["source-install.wim", "source-install.esd"] {
            let p = self.dir.join(name);
            if p.exists() {
                return Ok(p);
            }
        }
        let src = &self.job.recipe.source;
        if src.is_dir() {
            for name in ["sources/install.wim", "sources/install.esd"] {
                if let Some(p) = lean11_wim::resolve_ci(src, name).filter(|p| p.is_file()) {
                    return Ok(p);
                }
            }
        }
        bail!("source has no sources/install.wim or install.esd")
    }

    fn stage<F: FnOnce(&mut Self) -> Result<()>>(&mut self, stage: Stage, title: &str, f: F) -> Result<()> {
        if self.job.stage >= stage {
            self.log(&format!("== {title}: already done"));
            return Ok(());
        }
        if self.cancel.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
            self.log(&format!("Stopped before \"{title}\"."));
            bail!("Stopped at a safe boundary before \"{title}\". Resume with: lean11 build --resume {}", self.dir.display());
        }
        self.log(&format!("== {title}"));
        self.current_stage = title.to_string();
        let id = format!("stage:{stage:?}");
        let t = Instant::now();
        if let Err(e) = f(self) {
            self.op(id, title.to_string(), "Failed", Some(format!("{e:#}")), Some(t.elapsed().as_secs_f64() * 1000.0));
            let _ = self.save();
            return Err(e);
        }
        let secs = t.elapsed().as_secs_f64();
        self.log(&format!("   {title} done in {secs:.0} s"));
        self.job.timings.push((title.to_string(), secs));
        self.op(id, title.to_string(), "Completed", None, Some(secs * 1000.0));
        self.job.stage = stage;
        self.save()
    }

    pub fn run(&mut self) -> Result<PathBuf> {
        if lacks_privileges() {
            bail!("building with LEAN11_WIMLIB=1 needs root (WIM images are mounted read-write through FUSE)");
        }
        self.log(&format!("job directory: {}", self.dir.display()));
        if let Err(e) = self.run_stages() {
            // failure path: keep the operation history and timings, point at resume
            let cancelled = self.cancel.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst));
            let _ = self.save();
            let _ = self.write_history();
            let kind = if cancelled { "cancelled" } else { "failed" };
            let resumable = self.job.stage > Stage::Start;
            self.log(&format!("Build {kind}: {e:#}"));
            return Err(e.context(format!(
                "Build {kind}. The source was not changed. Working files and logs are retained at {}.{}",
                self.dir.display(),
                if resumable { " Verified saved progress exists; resume with lean11 build --resume <dir> to continue without repeating the finished work." } else { "" }
            )));
        }
        let out = self.job.recipe.output.clone();
        // a report problem never turns a published ISO into a failure
        if let Err(e) = self.write_reports() {
            self.warn(format!("The build report could not be written: {e:#}"));
        }
        self.job.stage = Stage::Done;
        self.save()?;
        self.cleanup_work();
        Ok(out)
    }

    fn run_stages(&mut self) -> Result<()> {
        self.stage(Stage::Media, "Prepare media", |b| {
            b.prepare_media()?;
            for rel in list_files(&b.media())? {
                b.record_media(&rel)?;
            }
            Ok(())
        })?;
        self.stage(Stage::Exported, "Export edition", |b| {
            b.export_edition()?;
            b.job.checkpoint.working = Some(file_digest(&b.working_wim())?);
            Ok(())
        })?;
        self.stage(Stage::Serviced, "Remove components and apply settings", |b| {
            b.service()?;
            b.log("Hashing the committed image…");
            b.job.checkpoint.working = Some(file_digest(&b.working_wim())?);
            Ok(())
        })?;
        self.stage(Stage::Compressed, "Compress image", Self::compress)?;
        self.stage(Stage::BootImage, "Setup image", Self::boot_image)?;
        self.stage(Stage::Iso, "Create ISO", Self::make_iso)
    }

    fn cleanup_work(&mut self) {
        if !self.job.recipe.keep_work {
            // media, mount, scratch, setup and compress go, plus the working image
            for p in [
                self.media(),
                self.working_wim(),
                self.dir.join("source-install.wim"),
                self.dir.join("source-install.esd"),
                self.dir.join("setup"),
                self.dir.join("compress"),
            ] {
                if p.is_dir() {
                    let _ = fs::remove_dir_all(&p);
                } else {
                    let _ = fs::remove_file(&p);
                }
            }
            // mount points only when empty: never recurse into something still mounted
            for d in ["mount", "mount-boot"] {
                let _ = fs::remove_dir(self.dir.join(d));
            }
        }
    }

    /// report.json, operations.json and timings.json in the job directory.
    fn write_reports(&mut self) -> Result<()> {
        let r = &self.job.recipe;
        let legacy = r.trims_winsxs()
            || r.actions.iter().any(|a| a.kind == inventory::Kind::ComponentPayload && a.mode == inventory::Mode::Remove);
        let removed_bytes: u64 = self.job.cleanup.iter().map(|c| c.logical_bytes).sum();
        let output_bytes = fs::metadata(&r.output).map(|m| m.len()).ok();
        let report = serde_json::json!({
            "SchemaVersion": 1,
            "CompletedUtc": chrono_now(),
            "Image": self.job.image,
            "Flavor": if r.is_core() { "Core" } else { "Regular" },
            "Mode": r.mode,
            "LegacyInstallerEnabled": legacy,
            "SelectedOptions": r.options,
            "ExpertActions": r.actions,
            "Compression": r.compression,
            "TurboMode": r.turbo,
            "RemoveRedundantData": r.remove_redundant_data,
            "OmitNetFx3SetupPayload": r.omit_sxs,
            "SetupMedia": { "OmittedBytes": self.job.omitted_setup_bytes },
            "RedundantData": self.job.cleanup,
            "RemovedLogicalBytes": removed_bytes,
            "OptionalFeatures": self.job.features,
            "Capabilities": self.job.capabilities,
            "Resumed": self.job.resumed_from.is_some(),
            "ResumedFrom": self.job.resumed_from,
            "Output": r.output,
            "Sha256": self.job.sha256,
            "BootValidated": false,
            "OperationLog": "operations.json",
            "TimingLog": "timings.json",
            "OutputBytes": output_bytes,
            "Warnings": self.job.warnings,
            "Notes": [
                "Consult build.log for every applied, missing or failed operation.",
                "Offline registry writes do not prove policy enforcement by this Windows build/edition.",
                "Core/expert and unsupported-hardware images require isolated VM boot testing."
            ],
        });
        fs::write(self.dir.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
        self.write_history()
    }

    /// operations.json and timings.json (also written when a build fails or is stopped).
    fn write_history(&self) -> Result<()> {
        let r = &self.job.recipe;
        let total_ms: f64 = self.job.timings.iter().map(|(_, s)| s * 1000.0).sum();
        fs::write(self.dir.join("operations.json"), serde_json::to_vec_pretty(&self.job.operations)?)?;
        let stages: Vec<serde_json::Value> = self
            .job
            .operations
            .iter()
            .filter(|o| o.id.starts_with("stage:"))
            .map(|o| serde_json::json!({ "Stage": o.stage, "State": o.state, "Milliseconds": o.duration_milliseconds }))
            .collect();
        let timings = serde_json::json!({
            "TurboMode": r.turbo,
            "TotalMilliseconds": total_ms,
            "Resumed": self.job.resumed_from.is_some(),
            "ResumedFrom": self.job.resumed_from,
            "Stages": stages,
        });
        fs::write(self.dir.join("timings.json"), serde_json::to_vec_pretty(&timings)?)?;
        Ok(())
    }

    // ---------------------------------------------------------------- media

    fn prepare_media(&mut self) -> Result<()> {
        let media = self.media();
        if media.exists() {
            fs::remove_dir_all(&media)?;
        }
        let src = self.job.recipe.source.clone();
        let omit_sxs = self.job.recipe.omit_sxs;
        let is_install = |p: &str| {
            let l = p.to_ascii_lowercase();
            l == "sources/install.wim" || l == "sources/install.esd" || l == "sources/install.swm"
        };
        let skip = |p: &str| is_install(p) || (omit_sxs && p.to_ascii_lowercase().starts_with("sources/sxs/"));
        if src.is_file() {
            let r = lean11_iso::UdfReader::open(&src)?;
            self.job.label = r.label().unwrap_or_default();
            let entries = r.walk()?;
            if entries.iter().any(|e| e.path.eq_ignore_ascii_case("sources/install.swm")) {
                bail!("split install.swm media is not supported");
            }
            let total: u64 = entries.iter().filter(|e| !skip(&e.path)).map(|e| e.size).sum();
            if omit_sxs {
                self.job.omitted_setup_bytes =
                    entries.iter().filter(|e| e.path.to_ascii_lowercase().starts_with("sources/sxs/")).map(|e| e.size).sum();
            }
            self.log(&format!("extracting {:.1} GiB of setup files", total as f64 / 1073741824.0));
            r.extract(&media, &skip, &mut |_, _| {})?;
            let inst = entries
                .iter()
                .find(|e| is_install(&e.path) && !e.is_dir)
                .ok_or_else(|| anyhow!("the ISO has no sources/install.wim or install.esd"))?;
            let ext = if inst.path.to_ascii_lowercase().ends_with(".esd") { "esd" } else { "wim" };
            let dest = self.dir.join(format!("source-install.{ext}"));
            self.log(&format!("extracting {} ({:.1} GiB)", inst.path, inst.size as f64 / 1073741824.0));
            let mut f = std::io::BufWriter::with_capacity(8 << 20, fs::File::create(&dest)?);
            r.copy_file(inst, &mut f)?;
            f.flush()?;
        } else if src.is_dir() {
            self.job.label = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if omit_sxs && let Some(sxs) = lean11_wim::resolve_ci(&src, "sources/sxs") {
                self.job.omitted_setup_bytes = dir_size(&sxs);
            }
            copy_tree(&src, &media, "", &skip)?;
        } else {
            bail!("source {} not found", src.display());
        }
        for need in ["sources/boot.wim", "efi/microsoft/boot/efisys.bin"] {
            if lean11_wim::resolve_ci(&media, need).is_none() {
                bail!("installation media is incomplete: {need} missing");
            }
        }
        if let Some(l) = self.job.recipe.label.clone() {
            self.job.label = l;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- export

    fn export_edition(&mut self) -> Result<()> {
        let src = self.source_install()?;
        let images = lean11_wim::info(&src)?;
        for i in &images {
            self.log(&format!("  [{}] {} ({}, {}, {})", i.index, i.name, i.edition_id, i.arch(), i.version()));
        }
        let img = lean11_wim::select(&images, self.job.recipe.edition.as_deref())?.clone();
        validate_image(&img)?;
        self.log(&format!("selected [{}] {} {} {}", img.index, img.name, img.arch(), img.version()));
        let work = self.working_wim();
        let _ = fs::remove_file(&work);
        // fast-compressed working image
        let r = &self.job.recipe;
        let fast_working = r.turbo
            && (r.trims_winsxs()
                || r.compression == Compression::Fast
                || r.actions.iter().any(|a| a.kind == inventory::Kind::ComponentPayload));
        let working = if fast_working { Compression::Fast } else { Compression::Lzx };
        if fast_working {
            self.log("Turbo: using fast intermediate compression to accelerate commit. Final compression remains as selected.");
        }
        lean11_wim::export(&src, img.index, &work, working, &mut |l| self.log(l))?;
        self.job.image = Some(img);
        Ok(())
    }

    // ---------------------------------------------------------------- service

    fn service(&mut self) -> Result<()> {
        // a retried stage starts from the exported image again: forget the outcomes of the failed attempt
        let title = self.current_stage.clone();
        self.job.operations.retain(|o| o.stage != title || o.id.starts_with("stage:"));
        self.job.features.clear();
        self.job.capabilities.clear();
        self.job.cleanup.clear();
        self.job.removed.clear();
        let mount_dir = self.dir.join("mount");
        let mount = Mount::rw(&self.working_wim(), 1, &mount_dir, &mut |l| self.log(l))?;
        let result = self.service_mounted(&mount);
        let r = match result {
            Ok(()) => mount.commit(&mut |l| self.log(l)),
            Err(e) => {
                let _ = mount.discard(&mut |_| {});
                Err(e)
            }
        };
        // wimlib can leave its staging directory (~140 MB) next to the WIM after unmounting
        if r.is_ok() && !lean11_wim::is_mountpoint(&mount_dir) {
            let _ = lean11_wim::release_stale(&self.working_wim(), &mount_dir, &mut |_| {});
        }
        r
    }

    /// Removes optional features (with payload) and capabilities like DISM; see cbs.rs.
    fn remove_components(&mut self, root: &Path, targets: &[cbs::Target]) -> Result<usize> {
        let store = cbs::Store::open(root)?;
        let plan = store.plan(targets)?;
        for m in &plan.missing {
            self.log(&format!("   not in this image: {m}"));
        }
        if plan.packages.is_empty() && plan.pairs.is_empty() {
            return Ok(0);
        }
        self.log(&format!("   removing {} packages ({} features, {} capabilities)", plan.packages.len(), plan.features.len(), plan.capabilities.len()));
        let report = cbs::remove(&store, &plan, &mut |s| self.log(&format!("   {s}")))?;
        let (features, capabilities) = cbs::verify(root, &plan)?;
        for f in &features {
            self.log(&format!("Feature removal outcome: {} => {}.", f.name, f.describe()));
            self.op(format!("feature:{}", f.name), format!("Remove optional feature: {}", f.name), "Completed", Some(format!("Verified {}.", f.describe())), None);
        }
        for c in &capabilities {
            self.log(&format!("Capability removal outcome: {} => {}.", c.name, c.describe()));
            self.op(format!("capability:{}", c.name), format!("Request capability removal: {}", c.name), "Completed", Some(format!("Verified {}.", c.describe())), None);
        }
        self.job.features.extend(features);
        self.job.capabilities.extend(capabilities);
        Ok(report.packages)
    }

    fn selected(&self, id: &str) -> bool {
        self.job.recipe.options.iter().any(|o| o == id)
    }

    fn service_mounted(&mut self, m: &Mount) -> Result<()> {
        let root = m.dir.clone();
        let arch = self.job.image.as_ref().map(|i| i.arch().to_string()).unwrap_or_default();

        // custom servicing: expert actions, validated against this image's inventory first
        let mut actions = self.job.recipe.actions.clone();
        if !actions.is_empty() {
            self.log("Revalidating expert actions against the actual mounted image.");
            let items = inventory::read(&root)?;
            if self.job.recipe.adapt_actions {
                // template actions: matched by name, the result is what this job (and a resume) uses
                let (adapted, notes) = inventory::adapt(&actions, &items);
                for n in &notes {
                    self.log(&format!("template action: {n}"));
                }
                actions = adapted;
                self.job.recipe.actions = actions.clone();
                self.job.recipe.adapt_actions = false;
                // the adapted actions are this job's choice now, also for a resume's integrity check
                self.job.checkpoint.recipe = Some(recipe_digest(&self.job.recipe)?);
                self.save()?;
            }
            inventory::validate(&actions, &items)?;
            // with the real inventory the readable names are known too
            let breaking = crate::knowledge::breaking_choices(&self.job.recipe, Some(&items));
            if !breaking.is_empty() && !self.job.recipe.breaking_acknowledged {
                bail!("These custom actions break setup or Windows (red): {}. Accept with --accept-breaking.", breaking.join(", "));
            }
            let res = inventory::apply_servicing(&root, &actions, &mut |s| self.log(&format!("   {s}")))?;
            self.job.removed.push(format!("{} expert servicing actions", res.done));
            for a in actions.iter().filter(|a| matches!(a.kind, inventory::Kind::ProvisionedApp | inventory::Kind::Package | inventory::Kind::Capability | inventory::Kind::Feature)) {
                self.op(format!("expert:{:?}:{}", a.kind, a.identity), format!("Expert {:?}: {:?} {}", a.mode, a.kind, a.identity), "Completed", None, None);
            }
            self.job.features.extend(res.features);
            self.job.capabilities.extend(res.capabilities);
        }

        // provisioned apps
        let app_targets: Vec<&'static catalog::CleanupOption> = self
            .job
            .recipe
            .options
            .iter()
            .filter_map(|id| catalog::option(id))
            .filter(|o| o.kind == Kind::App)
            .collect();
        if !app_targets.is_empty() {
            let removed = appx::remove_provisioned(&root, &app_targets, &mut |s| self.log(s));
            match removed {
                Ok(list) => {
                    for p in &list {
                        self.op(format!("app:{p}"), format!("Remove provisioned app: {p}"), "Completed", None, None);
                    }
                    self.job.removed.extend(list.into_iter().map(|p| format!("app {p}")));
                }
                Err(e) => self.warn(format!("provisioned apps were not removed: {e:#}")),
            }
        }

        // features, capabilities, packages
        let cbs_targets: Vec<cbs::Target> = self
            .job
            .recipe
            .options
            .iter()
            .filter_map(|id| catalog::option(id))
            .flat_map(|o| {
                o.targets.iter().filter_map(move |t| match o.kind {
                    Kind::Feature => Some(cbs::Target::Feature(t.to_string())),
                    Kind::Capability => Some(cbs::Target::Capability(t.to_string())),
                    _ => None,
                })
            })
            .collect();
        // WebView2 is the hidden FOD capability Edge.Webview2.Platform: removing it through the store
        // keeps the component store healthy (deleting its files makes ScanHealth report 426 corrupt files)
        let mut cbs_targets = cbs_targets;
        if self.selected("edge-files") {
            cbs_targets.push(cbs::Target::Capability("Edge.Webview2.Platform".into()));
        }
        if !cbs_targets.is_empty() {
            // a failure may leave the servicing store half edited: fail the stage so the mount is discarded
            let n = self.remove_components(&root, &cbs_targets).context("removing features and capabilities")?;
            self.job.removed.push(format!("{n} servicing packages"));
        }

        // files
        let mut targets: Vec<String> = Vec::new();
        for id in self.job.recipe.options.clone() {
            targets.extend(catalog::file_targets(&id).into_iter().map(str::to_string));
        }
        for t in targets {
            match lean11_wim::resolve_ci(&root, &t) {
                Some(p) => {
                    remove_path(&p).with_context(|| format!("cannot remove {t}"))?;
                    self.log(&format!("removed {t}"));
                    self.op(format!("file:{t}"), format!("Remove {t}"), "Completed", None, None);
                    self.job.removed.push(t);
                }
                None => {
                    self.log(&format!("not present: {t}"));
                    self.op(format!("file:{t}"), format!("Remove {t}"), "Skipped", Some("Not present.".into()), None);
                }
            }
        }
        let removes_payload = self.job.recipe.trims_winsxs()
            || actions.iter().any(|a| a.kind == inventory::Kind::ComponentPayload && a.mode == inventory::Mode::Remove);
        if removes_payload {
            // no pending operations allowed: Core would delete the files pending operations need
            let pending = offline::pending_operations(&root)?;
            if !pending.is_empty() {
                for p in &pending {
                    self.log(&format!("Pending operation: {p}"));
                }
                bail!(
                    "Core stopped before trimming any component: the image has pending operations, and Core would delete the files \
                     needed to finish them at first boot. Build a serviceable Lean11, which keeps those files."
                );
            }
            self.log("No pending operations found.");
        }
        if self.job.recipe.trims_winsxs() {
            self.trim_winsxs(&root, &arch)?;
        }
        if self.job.recipe.removes_winre() {
            self.remove_winre(&root)?;
        }
        if !actions.is_empty() {
            let n = inventory::apply_native(&root, &actions, &mut |s| self.log(&format!("   {s}")))?;
            if n > 0 {
                self.job.removed.push(format!("{n} expert native actions"));
            }
        }
        if self.job.recipe.remove_redundant_data {
            let results = offline::clean_redundant_data(&root, &mut |s| self.log(s))?;
            let (files, bytes) = results.iter().fold((0, 0), |(f, b), r| (f + r.files, b + r.logical_bytes));
            self.job.removed.push(format!("redundant data: {files} files, {bytes} bytes"));
            for r in &results {
                self.op(format!("cleanup:{}", r.path), format!("Clean {}", r.path), &r.state.clone(), Some(r.detail.clone()), None);
            }
            self.job.cleanup = results;
        }

        // registry
        self.apply_registry(&root)?;

        // optional remote access
        self.inject_ssh(&root, &arch)?;
        // additional software
        self.inject_software(&root, &arch)?;
        Ok(())
    }

    /// Resolves, downloads and stages the selected programs; SetupComplete.cmd installs them as SYSTEM.
    fn inject_software(&mut self, root: &Path, arch: &str) -> Result<()> {
        if self.job.recipe.software.is_empty() {
            return Ok(());
        }
        let lang = self.job.image.as_ref().map(|i| i.default_language.clone()).filter(|l| !l.is_empty()).unwrap_or_else(|| "en-US".into());
        self.log(&format!("Adding software ({}), language {lang}", self.job.recipe.software.join(", ")));
        let win = lean11_wim::resolve_ci(root, "Windows").ok_or_else(|| anyhow!("image has no Windows directory"))?;
        let setup = lean11_wim::resolve_ci(root, "Windows/Setup").unwrap_or_else(|| win.join("Setup"));
        let files = lean11_wim::resolve_ci(&setup, "Files").unwrap_or_else(|| setup.join("Files"));
        let dir = lean11_wim::resolve_ci(&files, "Software").unwrap_or_else(|| files.join("Software"));
        let ids = self.job.recipe.software.clone();
        let staged = crate::software::stage(&ids, arch, &lang, &dir, &mut |m| self.log(&format!("   {m}")))?;
        add_setupcomplete(root, crate::software::SETUPCOMPLETE_LINE)?;
        for st in &staged {
            self.op(
                format!("software:{}", st.id),
                format!("Add {} {}", st.name, st.version),
                "Completed",
                Some(format!("{} {} sha256 {}", st.kind, st.url, st.sha256)),
                None,
            );
        }
        self.job.removed.push(format!("added software: {}", staged.iter().map(|s| format!("{} {}", s.name, s.version)).collect::<Vec<_>>().join(", ")));
        Ok(())
    }

    /// Adds an OpenSSH server and the authorized key so the installed Windows is reachable over SSH
    /// right after setup (built-in Administrator, elevated). Offline via SetupComplete.cmd (runs as SYSTEM).
    fn inject_ssh(&mut self, root: &Path, arch: &str) -> Result<()> {
        let Some(key) = self.job.recipe.ssh_authorized_key.clone() else { return Ok(()) };
        self.log("Adding the OpenSSH server and the authorized key (built-in Administrator).");
        let msi = lean11_msdl::openssh::msi(arch, &mut |m| self.log(m))?;
        let win = lean11_wim::resolve_ci(root, "Windows").ok_or_else(|| anyhow!("image has no Windows directory"))?;
        let setup = lean11_wim::resolve_ci(root, "Windows/Setup").unwrap_or_else(|| win.join("Setup"));
        // existing directories in any letter case are reused (the image is case-insensitive)
        let files = lean11_wim::resolve_ci(&setup, "Files").unwrap_or_else(|| setup.join("Files"));
        fs::create_dir_all(&files)?;
        fs::copy(&msi, files.join("OpenSSH.msi")).with_context(|| "cannot stage OpenSSH.msi")?;
        fs::write(files.join("lean11_authorized_key.pub"), format!("{}\r\n", key.trim()))?;
        fs::write(files.join("lean11-ssh-setup.ps1"), ssh::setup_script())?;
        fs::write(files.join("lean11.psm1"), ssh::MODULE_PSM1)?;
        add_setupcomplete(root, ssh::SETUPCOMPLETE_LINE)?;
        self.op("ssh".into(), "Add OpenSSH server and authorized key (Administrator)".into(), "Completed", None, None);
        self.job.removed.push("added OpenSSH server + authorized key (Administrator)".into());
        Ok(())
    }

    fn trim_winsxs(&mut self, root: &Path, arch: &str) -> Result<()> {
        let sxs = lean11_wim::resolve_ci(root, "Windows/WinSxS").ok_or_else(|| anyhow!("image has no WinSxS"))?;
        let keep = regex::Regex::new(catalog::CORE_KEEP_PATTERN).unwrap();
        let native = if arch == "arm64" { "arm64_" } else { "amd64_" };
        let names: Vec<String> = fs::read_dir(&sxs)?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        for family in ["common-controls", "gdiplus", "servicing"] {
            if !names.iter().any(|n| n.to_ascii_lowercase().starts_with(native) && n.to_ascii_lowercase().contains(family)) {
                bail!("Core cannot identify the {arch} {family} runtime in this build; nothing was pruned");
            }
        }
        let mut count = 0usize;
        for n in &names {
            let path = sxs.join(n);
            if !path.is_dir() || catalog::CORE_KEEP_DIRS.iter().any(|k| k.eq_ignore_ascii_case(n)) || keep.is_match(n) {
                continue;
            }
            remove_path(&path)?;
            count += 1;
        }
        self.log(&format!("removed {count} WinSxS component directories (component store trimmed)"));
        self.job.removed.push(format!("{count} WinSxS component directories"));
        Ok(())
    }

    fn remove_winre(&mut self, root: &Path) -> Result<()> {
        if let Some(p) = lean11_wim::resolve_ci(root, "Windows/System32/Recovery/winre.wim") {
            remove_path(&p)?;
            self.log("removed Windows/System32/Recovery/winre.wim (no recovery environment)");
            self.job.removed.push("Windows/System32/Recovery/winre.wim".into());
        }
        Ok(())
    }

    fn apply_registry(&mut self, root: &Path) -> Result<()> {
        let path = |rel: &str| lean11_wim::resolve_ci(root, rel).ok_or_else(|| anyhow!("image has no {rel}"));
        let mut software = Hive::open(&path("Windows/System32/config/SOFTWARE")?, true)?;
        let mut system = Hive::open(&path("Windows/System32/config/SYSTEM")?, true)?;
        let mut user = Hive::open(&path("Users/Default/NTUSER.DAT")?, true)?;
        let mut dot_default = Hive::open(&path("Windows/System32/config/DEFAULT")?, true)?;
        let current = system.get("Select", "Current")?.and_then(|d| d.as_dword()).filter(|c| (1..1000).contains(c)).unwrap_or(1);
        let control_set = format!("ControlSet{current:03}");

        let mut ops: Vec<RegOp> = Vec::new();
        for id in self.job.recipe.options.clone() {
            ops.extend(catalog::registry_ops(&id));
        }
        if self.job.recipe.local_account {
            ops.extend(catalog::local_account_ops());
        }
        if self.job.recipe.is_core() {
            ops.extend(catalog::core_policy_ops());
        }
        let mut count = 0;
        for op in ops {
            match op {
                RegOp::Set(v) => {
                    let key = v.key.replace("{ControlSet}", &control_set);
                    let hive = match v.hive {
                        H::Software => &mut software,
                        H::System => &mut system,
                        H::DefaultUser => &mut user,
                        H::DotDefault => &mut dot_default,
                    };
                    // never create service registrations that do not exist
                    if v.hive == H::System && key.contains("\\Services\\") && hive.key(&key)?.is_none() {
                        self.log(&format!("not present: SYSTEM\\{key}"));
                        continue;
                    }
                    let data = match v.value {
                        Value::Dword(d) => RegData::dword(d),
                        Value::Sz(s) => RegData::sz(s),
                    };
                    hive.set(&key, v.name, &data)?;
                    count += 1;
                }
                RegOp::DeleteKey { hive, key } => {
                    let h = match hive {
                        H::Software => &mut software,
                        H::System => &mut system,
                        H::DefaultUser => &mut user,
                        H::DotDefault => &mut dot_default,
                    };
                    if h.delete_key(key)? {
                        self.log(&format!("deleted key {key}"));
                    }
                }
            }
        }
        // Edge's installed-program entry goes after its files:
        // only "Microsoft Edge" with the expected identity; Edge Update and WebView2 entries stay.
        if self.selected("edge-files") {
            for pf in ["Program Files", "Program Files (x86)"] {
                if lean11_wim::resolve_ci(root, &format!("{pf}/Microsoft/Edge")).is_some() {
                    bail!("Edge files remain in the offline image. Its installed-program entry was not removed.");
                }
            }
            for path in [r"Microsoft\Windows\CurrentVersion\Uninstall", r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"] {
                let key = format!(r"{path}\Microsoft Edge");
                let Some(node) = software.key(&key)? else { continue };
                let s = |n: &str| software.value(node, n).ok().flatten().and_then(|d| d.as_string()).unwrap_or_default();
                if !s("DisplayName").eq_ignore_ascii_case("Microsoft Edge") || !s("Publisher").eq_ignore_ascii_case("Microsoft Corporation") {
                    self.log(&format!("Retained offline uninstall entry with an unexpected identity: {key}"));
                    continue;
                }
                software.delete_key(&key)?;
                if software.key(&key)?.is_some() {
                    bail!("The offline Edge installed-program entry could not be removed.");
                }
                self.log(&format!("Removed offline Edge uninstall entry: {key}"));
            }
        }
        let mut off: Vec<&str> = Vec::new();
        if self.job.recipe.disables_updates() {
            off.extend(catalog::UPDATE_SERVICES);
        }
        if self.job.recipe.disables_defender() {
            off.extend(catalog::DEFENDER_SERVICES);
        }
        if !off.is_empty() {
            let sets: Vec<String> = system.children(system.root()).into_iter().map(|(n, _)| n).filter(|n| is_control_set(n)).collect();
            for cs in sets {
                for svc in &off {
                    let key = format!(r"{cs}\Services\{svc}");
                    if system.key(&key)?.is_some() {
                        system.set(&key, "Start", &RegData::dword(4))?;
                        count += 1;
                        self.log(&format!("disabled service {key}"));
                    }
                }
            }
        }
        // privacy settings
        let privacy = crate::privacy::resolve(&self.job.recipe, &mut |m| self.log(m))?;
        let mut privacy_hosts = std::collections::BTreeSet::new();
        if !privacy.is_empty() {
            let sets: Vec<String> = system.children(system.root()).into_iter().map(|(n, _)| n).filter(|n| is_control_set(n)).collect();
            let mut hv = crate::privacy::Hives { software: &mut software, system: &mut system, user: &mut user, dot_default: &mut dot_default };
            let a = crate::privacy::apply_registry(root, &privacy, &mut hv, &sets, &control_set)?;
            for sk in &a.skipped {
                self.log(&format!("privacy: {sk}"));
            }
            let mut tasks = 0;
            for t in &a.tasks {
                if crate::privacy::disable_task(root, &mut software, t)? {
                    tasks += 1;
                } else {
                    self.log(&format!("privacy: task {t} not in the image"));
                }
            }
            if tasks > 0 {
                self.log(&format!("privacy: {tasks} scheduled tasks disabled"));
            }
            self.log(&format!("privacy: {} settings, {} registry values, {} services, {} hosts entries", privacy.len(), a.registry, a.services, a.hosts.len()));
            count += a.registry + a.services;
            privacy_hosts = a.hosts;
        }
        if crate::privacy::after_setup_user_script(&privacy).is_some() {
            let k = format!(r"Microsoft\Active Setup\Installed Components\{}", crate::privacy::ACTIVE_SETUP_ID);
            software.set(&k, "", &RegData::sz("lean11 privacy settings"))?;
            software.set(
                &k,
                "StubPath",
                &RegData {
                    kind: lean11_hive::REG_EXPAND_SZ,
                    data: RegData::sz(&format!(r"%SystemRoot%\System32\cmd.exe /c call %SystemRoot%\Setup\Scripts\{}", crate::privacy::AFTER_SETUP_USER_SCRIPT)).data,
                },
            )?;
            software.set(&k, "Version", &RegData::sz("1,0"))?;
            software.set(&k, "IsInstalled", &RegData::dword(1))?;
        }
        for h in [&mut software, &mut system, &mut user, &mut dot_default] {
            h.commit()?;
        }
        if !privacy_hosts.is_empty() {
            let hosts = lean11_wim::resolve_ci(root, "Windows/System32/drivers/etc/hosts").ok_or_else(|| anyhow!("image has no hosts file"))?;
            let old = fs::read(&hosts)?;
            let text = String::from_utf8(old).map_err(|_| anyhow!("the image's hosts file is not UTF-8"))?;
            fs::write(&hosts, crate::privacy::hosts_file(&text, &privacy_hosts))?;
            self.log(&format!("privacy: {} host names blocked in the hosts file", privacy_hosts.len()));
        }
        // values that setup itself resets (security template, language setup) are written again after
        // it: once at the first sign-in (answer file FirstLogonCommands), per account by Active Setup,
        // and HKLM ones on every start by the local Group Policy (Registry.pol)
        if crate::privacy::needs_after_setup(&privacy) {
            let scripts = setup_scripts_dir(root)?;
            let put = |name: &str, text: Option<String>| -> Result<()> {
                if let Some(t) = text {
                    let path = lean11_wim::resolve_ci(&scripts, name).unwrap_or_else(|| scripts.join(name));
                    fs::write(path, t)?;
                }
                Ok(())
            };
            put(crate::privacy::AFTER_SETUP_SCRIPT, crate::privacy::after_setup_script(&privacy))?;
            put(crate::privacy::AFTER_SETUP_USER_SCRIPT, crate::privacy::after_setup_user_script(&privacy))?;
            if let Some(entries) = crate::privacy::registry_pol_entries(&privacy) {
                let sys32 = lean11_wim::resolve_ci(root, "Windows/System32").ok_or_else(|| anyhow!("image has no System32"))?;
                let gp = lean11_wim::resolve_ci(&sys32, "GroupPolicy").unwrap_or_else(|| sys32.join("GroupPolicy"));
                let machine = lean11_wim::resolve_ci(&gp, "Machine").unwrap_or_else(|| gp.join("Machine"));
                fs::create_dir_all(&machine)?;
                let pol = lean11_wim::resolve_ci(&machine, "Registry.pol").unwrap_or_else(|| machine.join("Registry.pol"));
                let old = if pol.is_file() { Some(fs::read(&pol)?) } else { None };
                let new = crate::privacy::registry_pol(old.as_deref(), &entries)?;
                let changed = old.as_deref() != Some(new.as_slice());
                if changed {
                    fs::write(&pol, new)?;
                }
                // gpt.ini must name the registry extension; the version only rises when the policy changed
                let ini = lean11_wim::resolve_ci(&gp, "gpt.ini").unwrap_or_else(|| gp.join("gpt.ini"));
                let (old_ini, utf16) = if ini.is_file() {
                    let b = fs::read(&ini)?;
                    match b.strip_prefix(&[0xff, 0xfe]) {
                        Some(body) if body.len() % 2 == 0 => {
                            let u: Vec<u16> = body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                            (Some(String::from_utf16(&u).map_err(|_| anyhow!("the image's gpt.ini is not valid UTF-16"))?), true)
                        }
                        _ => (Some(String::from_utf8(b).map_err(|_| anyhow!("the image's gpt.ini is neither UTF-8 nor UTF-16"))?), false),
                    }
                } else {
                    (None, false)
                };
                let has_ext = old_ini.as_deref().is_some_and(|t| t.to_ascii_uppercase().contains("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}"));
                if changed || !has_ext {
                    let text = crate::privacy::gpt_ini(old_ini.as_deref());
                    let bytes = if utf16 {
                        [0xff, 0xfe].into_iter().chain(text.encode_utf16().flat_map(|c| c.to_le_bytes())).collect()
                    } else {
                        text.into_bytes()
                    };
                    fs::write(&ini, bytes)?;
                }
            }
            if self.job.recipe.ssh_authorized_key.is_some() {
                add_setupcomplete(root, crate::privacy::SETUPCOMPLETE_COMMAND)?;
            }
            self.log("privacy: values reset by setup are written again at the first sign-in, per account (Active Setup) and by the local Group Policy");
        }
        self.log(&format!("registry: {count} values written and verified"));
        self.job.registry_values = count;
        self.op("registry".into(), "Apply registry settings".into(), "Completed", Some(format!("{count} values written.")), None);
        Ok(())
    }

    // ---------------------------------------------------------------- compress

    fn compress(&mut self) -> Result<()> {
        let comp = self.job.recipe.compression;
        let sources = self.media().join("sources");
        for old in ["install.wim", "install.esd"] {
            let _ = fs::remove_file(sources.join(old));
        }
        // export into a fresh private folder, check it, then place it
        let partial_dir = self.dir.join("compress");
        let _ = fs::remove_dir_all(&partial_dir);
        fs::create_dir_all(&partial_dir)?;
        let partial = partial_dir.join(comp.file_name());
        lean11_wim::export(&self.working_wim(), 1, &partial, comp, &mut |l| self.log(l))?;
        let images = lean11_wim::info(&partial)?;
        let want = self.job.image.clone().ok_or_else(|| anyhow!("the job has no image record"))?;
        if images.len() != 1 || images[0].build != want.build || images[0].arch() != want.arch() {
            bail!("The final installation image failed its edition/build/architecture check.");
        }
        let dest = sources.join(comp.file_name());
        fs::rename(&partial, &dest)?;
        let _ = fs::remove_dir_all(&partial_dir);
        self.log(&format!("{}: {:.2} GiB", comp.file_name(), fs::metadata(&dest)?.len() as f64 / 1073741824.0));
        self.log("Hashing the compressed image…");
        for old in ["sources/install.wim", "sources/install.esd"] {
            self.job.checkpoint.media.remove(old);
        }
        self.record_media(&format!("sources/{}", comp.file_name()))?;
        // the working image is only needed until a verified compressed checkpoint exists
        if !self.job.recipe.keep_work {
            let _ = fs::remove_file(self.working_wim());
        }
        Ok(())
    }

    // ---------------------------------------------------------------- boot.wim

    fn boot_image(&mut self) -> Result<()> {
        let bypass = self.selected("hardware-bypass");
        // legacy installer: Core, an explicit WinSxS payload removal, or no WinRE (the current setup extracts
        // Windows\System32\Recovery\winre.wim from install.wim as its SafeOS and fails with 0x80070003 without it)
        let legacy = self.job.recipe.trims_winsxs()
            || self.job.recipe.removes_winre()
            || self.job.recipe.actions.iter().any(|a| a.kind == inventory::Kind::ComponentPayload && a.mode == inventory::Mode::Remove);
        if !bypass && !legacy {
            self.log("setup image unchanged");
            return Ok(());
        }
        // edit a private copy; the staged boot.wim is replaced only after the copy committed and validated
        let staged = lean11_wim::resolve_ci(&self.media(), "sources/boot.wim").ok_or_else(|| anyhow!("the media has no sources/boot.wim"))?;
        let private_dir = self.dir.join("setup");
        let _ = fs::remove_dir_all(&private_dir);
        fs::create_dir_all(&private_dir)?;
        let boot = private_dir.join("boot.wim");
        fs::copy(&staged, &boot)?;
        let images = lean11_wim::info(&boot)?;
        let setup = images
            .iter()
            .find(|i| i.name.to_ascii_lowercase().contains("setup"))
            .or_else(|| images.iter().find(|i| i.index == 2))
            .ok_or_else(|| anyhow!("Cannot identify Windows Setup in boot.wim."))?
            .index;
        let mount_dir = self.dir.join("mount-boot");
        let m = Mount::rw(&boot, setup, &mount_dir, &mut |l| self.log(l))?;
        let r = (|| -> Result<()> {
            if bypass {
                let p = lean11_wim::resolve_ci(&m.dir, "Windows/System32/config/SYSTEM").ok_or_else(|| anyhow!("setup image has no SYSTEM hive"))?;
                let mut system = Hive::open(&p, true)?;
                for op in catalog::setup_bypass_ops() {
                    if let RegOp::Set(v) = op {
                        let Value::Dword(d) = v.value else { continue };
                        system.set(v.key, v.name, &RegData::dword(d))?;
                    }
                }
                system.commit()?;
                self.log("setup image: hardware checks bypassed");
            }
            if legacy {
                let exe = ["sources/setup_old.exe", "sources/setup.exe"]
                    .into_iter()
                    .find(|p| lean11_wim::resolve_ci(&m.dir, p).is_some())
                    .ok_or_else(|| anyhow!("This Windows Setup image has no legacy installer. Core/component-store removals require media containing sources\\setup.exe."))?;
                if lean11_wim::resolve_ci(&m.dir, exe).and_then(|f| f.metadata().ok()).is_none_or(|x| x.len() == 0) {
                    bail!("The legacy installer in the Windows Setup image is empty.");
                }
                let sys32 = lean11_wim::resolve_ci(&m.dir, "Windows/System32").unwrap();
                let content = format!("[LaunchApps]\r\n%SYSTEMROOT%\\System32\\wpeinit.exe\r\n%SYSTEMDRIVE%\\{}\r\n", exe.replace('/', "\\"));
                let ini = lean11_wim::resolve_ci(&m.dir, "Windows/System32/winpeshl.ini").unwrap_or(sys32.join("winpeshl.ini"));
                fs::write(&ini, &content)?;
                self.log(&format!("setup image: legacy installer {exe}"));
            }
            Ok(())
        })();
        match r {
            Ok(()) => m.commit(&mut |l| self.log(l))?,
            Err(e) => {
                let _ = m.discard(&mut |_| {});
                return Err(e);
            }
        }
        let edited = lean11_wim::info(&boot)?;
        let idx = |v: &[ImageInfo]| v.iter().map(|i| i.index).collect::<Vec<_>>();
        if idx(&edited) != idx(&images) {
            bail!("The edited Windows Setup image no longer lists its original indexes. The staged boot.wim was left unchanged.");
        }
        fs::rename(&boot, &staged)?;
        // media paths are recorded with '/' on every platform (list_files, the ISO writer)
        let rel = staged.strip_prefix(self.media())?.to_string_lossy().replace('\\', "/");
        self.record_media(&rel)?;
        let _ = fs::remove_dir_all(&private_dir);
        Ok(())
    }

    // ---------------------------------------------------------------- iso

    fn make_iso(&mut self) -> Result<()> {
        let media = self.media();
        let arch = self.job.image.as_ref().map(|i| i.arch().to_string()).unwrap_or_else(|| "x64".into());
        let xml = unattend::build(&unattend::UnattendOptions {
            arch: if arch == "arm64" { "arm64" } else { "amd64" },
            compact: self.job.recipe.compact,
            local_account: self.job.recipe.local_account,
            first_logon: crate::privacy::resolve(&self.job.recipe, &mut |_| {})?
                .iter()
                .any(|s| s.ops.iter().any(|o| o.after_setup))
                .then_some((crate::privacy::FIRST_LOGON_COMMAND, "lean11 privacy settings"))
                .into_iter()
                // SetupComplete.cmd is skipped when setup uses an OEM product key: the first sign-in installs then
                .chain((!self.job.recipe.software.is_empty()).then_some((crate::software::FIRST_LOGON_COMMAND, "lean11 software")))
                .collect(),
        });
        fs::write(media.join("autounattend.xml"), xml)?;
        self.record_media("autounattend.xml")?;
        self.save()?;
        let has = |p: &str| lean11_wim::resolve_ci(&media, p).is_some_and(|f| f.is_file());
        let uefi = if self.job.recipe.no_prompt && has(lean11_iso::UEFI_BOOT_NOPROMPT) { lean11_iso::UEFI_BOOT_NOPROMPT } else { lean11_iso::UEFI_BOOT };
        let rel = |p: &str| -> Option<String> {
            let real = lean11_wim::resolve_ci(&media, p)?;
            Some(real.strip_prefix(&media).ok()?.to_string_lossy().replace('\\', "/"))
        };
        let opts = lean11_iso::WriteOptions {
            label: if self.job.label.is_empty() { "LEAN11".into() } else { self.job.label.clone() },
            // BIOS boot entry on x64 when the source has it
            bios_image: if arch == "x64" && has(lean11_iso::BIOS_BOOT) { rel(lean11_iso::BIOS_BOOT) } else { None },
            uefi_image: rel(uefi),
        };
        let out = self.job.recipe.output.clone();
        let tmp = out.with_extension("iso.part");
        let mut last = Instant::now();
        lean11_iso::write_iso(&media, &tmp, &opts, &mut |d, t| {
            if last.elapsed().as_secs() >= 10 {
                last = Instant::now();
                self.log(&format!("   ISO {:.1} / {:.1} GiB", d as f64 / 1073741824.0, t as f64 / 1073741824.0));
            }
        })?;
        validate_iso(&tmp)?;
        let hash = sha256(&tmp)?;
        if out.exists() {
            bail!("{} appeared during the build; the finished ISO is kept at {}", out.display(), tmp.display());
        }
        // publish without overwriting a file that appeared meanwhile (hard link fails if `out` exists)
        match fs::hard_link(&tmp, &out) {
            Ok(()) => {
                let _ = fs::remove_file(&tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                bail!("{} appeared during the build; the finished ISO is kept at {}", out.display(), tmp.display())
            }
            // file systems without hard links (exFAT, some network shares): plain rename
            Err(_) => fs::rename(&tmp, &out)?,
        }
        self.log(&format!("ISO: {} ({:.2} GiB)\nSHA-256: {hash}", out.display(), fs::metadata(&out)?.len() as f64 / 1073741824.0));
        self.job.sha256 = Some(hash);
        Ok(())
    }
}


/// `Windows/Setup/Scripts` of the image (existing directories in any letter case are reused).
fn setup_scripts_dir(root: &Path) -> Result<PathBuf> {
    let win = lean11_wim::resolve_ci(root, "Windows").ok_or_else(|| anyhow!("image has no Windows directory"))?;
    let setup = lean11_wim::resolve_ci(root, "Windows/Setup").unwrap_or_else(|| win.join("Setup"));
    let scripts = lean11_wim::resolve_ci(&setup, "Scripts").unwrap_or_else(|| setup.join("Scripts"));
    fs::create_dir_all(&scripts)?;
    Ok(scripts)
}

/// Adds a line to the image's SetupComplete.cmd: ours go first (an existing script may end with `exit`);
/// its own commands are kept, an unreadable one stops the build instead of being replaced.
fn add_setupcomplete(root: &Path, line: &str) -> Result<()> {
    let scripts = setup_scripts_dir(root)?;
    let sc = lean11_wim::resolve_ci(&scripts, "SetupComplete.cmd").unwrap_or_else(|| scripts.join("SetupComplete.cmd"));
    let existing = if sc.is_file() {
        let bytes = fs::read(&sc).with_context(|| format!("cannot read {}", sc.display()))?;
        Some(String::from_utf8(bytes).map_err(|_| anyhow!("the image's SetupComplete.cmd is not ASCII/UTF-8; it was left unchanged"))?)
    } else {
        None
    };
    fs::write(&sc, ssh::setupcomplete_with(existing.as_deref(), line))?;
    Ok(())
}

fn is_control_set(n: &str) -> bool {
    let b = n.as_bytes();
    b.len() == 13 && b[..10].eq_ignore_ascii_case(b"ControlSet") && b[10..].iter().all(|c| c.is_ascii_digit())
}

fn dir_size(p: &Path) -> u64 {
    let Ok(m) = p.symlink_metadata() else { return 0 };
    if !m.is_dir() {
        return m.len();
    }
    fs::read_dir(p).map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum()).unwrap_or(0)
}

fn remove_path(p: &Path) -> Result<()> {
    let meta = p.symlink_metadata()?;
    if meta.is_dir() { fs::remove_dir_all(p)? } else { fs::remove_file(p)? }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path, rel: &str, skip: &dyn Fn(&str) -> bool) -> Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let r = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let ft = e.file_type()?;
        if ft.is_dir() {
            copy_tree(&e.path(), &dst.join(&name), &r, skip)?;
        } else if ft.is_file() && !skip(&r) {
            fs::copy(e.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

/// ISO structure check: ISO-sized and a CD001/BEA01/NSR02/NSR03 descriptor from sector 16.
fn validate_iso(p: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let len = fs::metadata(p)?.len();
    if len < 34816 || len % 2048 != 0 {
        bail!("The file is not a valid ISO-sized image.");
    }
    let mut f = fs::File::open(p)?;
    f.seek(SeekFrom::Start(2048 * 16))?;
    let mut buf = vec![0u8; 2048 * 16];
    let n = f.read(&mut buf)?;
    let ok = (0..n / 2048).any(|i| matches!(&buf[i * 2048 + 1..i * 2048 + 6], b"CD001" | b"BEA01" | b"NSR02" | b"NSR03"));
    if !ok {
        bail!("The file has no recognized ISO/UDF volume descriptor.");
    }
    Ok(())
}

/// Current UTC time as RFC 3339 (`2026-10-23T19:50:57Z`).
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn sha256(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// Default recipe for a mode.
pub fn recipe_for(mode: Mode, source: PathBuf, output: PathBuf) -> Recipe {
    Recipe {
        source,
        edition: None,
        mode,
        core: mode == Mode::Core,
        options: catalog::for_mode(mode).into_iter().map(str::to_string).collect(),
        compression: Compression::Recovery,
        local_account: true,
        compact: true,
        ssh_authorized_key: None,
        output,
        label: None,
        no_prompt: false,
        keep_work: false,
        omit_sxs: false,
        remove_redundant_data: false,
        actions: Vec::new(),
        turbo: false,
        core_acknowledged: false,
        expert_acknowledged: false,
        privacy: Vec::new(),
        adapt_actions: false,
        software: Vec::new(),
        breaking_acknowledged: false,
    }
}
