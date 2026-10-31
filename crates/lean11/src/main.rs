use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lean11_core::catalog::{self, Mode};
use lean11_msdl::{Arch, Catalog};

mod picker;
mod tui;

#[derive(Parser)]
#[command(name = "lean11", version, about = "Build trimmed, private Windows 11 ISOs")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Download the latest Windows 11 ISO from Microsoft
    Download {
        /// Language name ("German") or locale ("de-DE"); default: $LANG
        #[arg(long)]
        lang: Option<String>,
        /// x64 or arm64; default: host architecture
        #[arg(long)]
        arch: Option<String>,
        /// Target directory
        #[arg(long, short, default_value = ".")]
        out: PathBuf,
        /// Only list the available languages
        #[arg(long)]
        list_languages: bool,
        /// Only print the resolved link as JSON, do not download
        #[arg(long)]
        resolve_only: bool,
        /// Manual official link (other languages, Insider media); only Microsoft hosts are accepted
        #[arg(long, conflicts_with = "list_languages")]
        url: Option<String>,
        /// Published SHA-256 to verify a manual link against
        #[arg(long, requires = "url")]
        sha256: Option<String>,
    },
    /// Interactive wizard in the terminal
    Tui {
        /// Preselected ISO or media directory
        source: Option<PathBuf>,
    },
    /// Build a trimmed ISO
    Build(BuildArgs),
    /// List provisioned apps of a mounted image directory or an offline SOFTWARE hive
    Apps {
        path: PathBuf,
        /// Remove the apps of these catalog options (mounted image directory only)
        #[arg(long, value_delimiter = ',')]
        remove: Vec<String>,
    },
    /// Show the editions of an ISO, media directory or WIM
    Info { source: PathBuf },
    /// Developer tool: extract one WIM image into a directory with the native WIM code
    #[command(hide = true)]
    WimExtract { wim: PathBuf, index: u32, dir: PathBuf },
    /// Developer tool: export one WIM image with the native writer (fast, lzx, maximum, recovery)
    #[command(hide = true)]
    WimExport { src: PathBuf, index: u32, dest: PathBuf, compression: String },
    /// Developer tool: extract an image, run a shell command on it ($WS = directory), commit it back
    #[command(hide = true)]
    WimEdit { wim: PathBuf, index: u32, dir: PathBuf, command: String },
    /// Inspect, extract or create installation ISOs
    Iso {
        #[command(subcommand)]
        cmd: IsoCmd,
    },
    /// Servicing store of a mounted image directory: list or remove features, capabilities, packages
    Cbs {
        path: PathBuf,
        /// What to list: features, capabilities or packages
        #[arg(long, default_value = "features")]
        list: String,
        /// Remove these optional features (Disable-Feature /Remove)
        #[arg(long, value_delimiter = ',')]
        remove_feature: Vec<String>,
        /// Disable these optional features and keep their payload (Disable-Feature)
        #[arg(long, value_delimiter = ',')]
        disable_feature: Vec<String>,
        /// Remove these capabilities (name or prefix, e.g. App.StepsRecorder)
        #[arg(long, value_delimiter = ',')]
        remove_capability: Vec<String>,
        /// Remove these packages (name or full identity)
        #[arg(long, value_delimiter = ',')]
        remove_package: Vec<String>,
        /// Only show what would be removed
        #[arg(long)]
        dry_run: bool,
        /// Print the decoded manifest of a WinSxS component (name or unique prefix)
        #[arg(long)]
        show_manifest: Option<String>,
    },
    /// Inventory of an edition (apps, features, capabilities, packages, services, system apps, WinSxS
    /// payloads) for Custom-mode expert actions; source: ISO, media directory, WIM/ESD or mounted image
    Inventory {
        source: PathBuf,
        /// Image index, name or edition id (default Professional)
        #[arg(long)]
        edition: Option<String>,
        /// Only this kind (app, system-app, feature, capability, package, service, payload)
        #[arg(long)]
        kind: Option<String>,
        /// Output JSON
        #[arg(long)]
        json: bool,
        /// Working directory for the extracted install image (default: next to the source)
        #[arg(long)]
        work: Option<PathBuf>,
    },
    /// List unfinished jobs (a working directory or one job folder) and release their leftover mounts;
    /// --discard removes their working copies (logs, recipe and reports stay)
    Recover {
        work: PathBuf,
        #[arg(long)]
        discard: bool,
    },
    /// Privacy settings catalog: list, verify against an image, VM check script
    Privacy {
        #[command(subcommand)]
        cmd: PrivacyCmd,
    },
    /// Additional software: list the catalog, resolve the current versions in the winget catalog
    Software {
        #[command(subcommand)]
        cmd: SoftwareCmd,
    },
    /// List the removal and settings catalog
    Catalog {
        /// Show which options a mode selects
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
    },
}

#[derive(Subcommand)]
enum SoftwareCmd {
    /// List the programs that can be added (id, category, name)
    List {
        #[arg(long)]
        json: bool,
    },
    /// Resolve programs in the winget catalog: version, installer, URL and SHA-256 (no download)
    Resolve {
        /// Comma separated ids (default: all)
        ids: Option<String>,
        #[arg(long, default_value = "x64")]
        arch: String,
        #[arg(long, default_value = "en-US")]
        lang: String,
    },
}

#[derive(Subcommand)]
enum PrivacyCmd {
    /// List the settings (category, level, id, title)
    List {
        /// Only settings of this preset (recommended, strict)
        #[arg(long)]
        preset: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Developer tool: check every setting against an extracted image (ADMX policies, hives, services, tasks)
    Verify {
        /// Extracted install image (e.g. from `lean11 wim-extract`)
        image: PathBuf,
        /// Show all findings, not only problems
        #[arg(long)]
        all: bool,
        /// Check this catalog file instead of the built-in one (curation drafts)
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// Additional ADMX folders (Edge, Chrome, Firefox templates), repeatable
        #[arg(long = "admx-dir")]
        admx_dirs: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Developer tool: search the image's ADMX policies (key, value name, policy or display name)
    Admx {
        image: PathBuf,
        /// Case-insensitive substring
        pattern: String,
        /// Additional ADMX folders, repeatable
        #[arg(long = "admx-dir")]
        admx_dirs: Vec<PathBuf>,
    },
    /// Developer tool: PowerShell that reads the settings back on an installed system
    CheckScript {
        /// Preset (recommended, strict) or comma separated ids
        #[arg(default_value = "strict")]
        which: String,
    },
    /// Batch script that SetupComplete.cmd runs for the values Windows setup resets (empty when none)
    AfterSetupScript {
        /// Preset (recommended, strict) or comma separated ids
        #[arg(default_value = "strict")]
        which: String,
    },
}

#[derive(clap::Args)]
struct BuildArgs {
    /// Windows 11 ISO or extracted media directory
    source: Option<PathBuf>,
    /// Output ISO
    #[arg(long, short)]
    out: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "lean")]
    mode: ModeArg,
    /// Image index, name or edition id (default: Professional)
    #[arg(long)]
    edition: Option<String>,
    /// Working directory (needs ~40 GiB; default: next to the output)
    #[arg(long)]
    work: Option<PathBuf>,
    /// Final compression (default recovery)
    #[arg(long, value_enum)]
    compression: Option<CompArg>,
    /// Add catalog options (comma separated ids, see `lean11 catalog`)
    #[arg(long, value_delimiter = ',')]
    enable: Vec<String>,
    /// Remove catalog options from the mode's selection
    #[arg(long, value_delimiter = ',')]
    disable: Vec<String>,
    /// Do not prefer a local account during setup
    #[arg(long)]
    no_local_account: bool,
    /// Do not use compact installation
    #[arg(long)]
    no_compact: bool,
    /// UEFI boot without "press any key"
    #[arg(long)]
    no_prompt: bool,
    #[arg(long)]
    keep_work: bool,
    /// Leave sources\sxs (.NET 3.5 payload) out of the ISO
    #[arg(long)]
    omit_sxs: bool,
    /// Remove offline caches, archived logs and crash reports from the image
    #[arg(long)]
    remove_redundant_data: bool,
    /// Install an OpenSSH server and authorize this public key file for the built-in Administrator
    /// (elevated SSH access right after setup; downloads the OpenSSH installer)
    #[arg(long, value_name = "PUBKEY")]
    ssh_key: Option<PathBuf>,
    /// Custom expert action on an inventory item: kind:identity[:disable|remove] (repeatable),
    /// kinds: app, system-app, feature, capability, package, service, payload (see `lean11 inventory`)
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Turbo mode: fast intermediate image for Core, fast output or WinSxS actions (final compression unchanged)
    #[arg(long)]
    turbo: bool,
    /// Add Core's irreversible removals to a Custom build (needs --accept-core)
    #[arg(long)]
    core: bool,
    /// Accept that Core loses updates, recovery and antivirus protection (required for --mode core, --core
    /// and the irreversible options remove-winre and trim-winsxs)
    #[arg(long)]
    accept_core: bool,
    /// Privacy settings preset: recommended, strict or none (see `lean11 privacy list`)
    #[arg(long, value_name = "PRESET")]
    privacy: Option<String>,
    /// Add privacy settings (comma separated ids)
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    privacy_enable: Vec<String>,
    /// Remove privacy settings from the preset
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    privacy_disable: Vec<String>,
    /// Accept that expert actions can make the image unbootable (required with --action)
    #[arg(long)]
    accept_expert: bool,
    /// Accept choices rated red (they break setup or Windows; see the ratings in `lean11 catalog` and the TUI)
    #[arg(long)]
    accept_breaking: bool,
    /// Add programs, installed at the end of setup (comma separated ids, see `lean11 software list`)
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    software: Vec<String>,
    /// Volume label (default: the source's)
    #[arg(long)]
    label: Option<String>,
    /// Load the recipe from a JSON file (other options are ignored)
    #[arg(long)]
    recipe: Option<PathBuf>,
    /// Start from a template (the choice saved with --save-template or in the TUI, also a recipe file);
    /// its mode replaces --mode, the other options add to or change it. Custom actions are matched to
    /// this image by name.
    #[arg(long, value_name = "FILE")]
    template: Option<PathBuf>,
    /// Only save the resulting choice as a template (no source needed) and exit
    #[arg(long, value_name = "FILE", conflicts_with = "resume")]
    save_template: Option<PathBuf>,
    /// Only write the recipe as JSON to stdout
    #[arg(long)]
    print_recipe: bool,
    /// Resume an interrupted job (its directory)
    #[arg(long)]
    resume: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CompArg {
    Recovery,
    Maximum,
    Fast,
}

#[derive(Subcommand)]
enum IsoCmd {
    /// List files of a UDF ISO
    Ls { iso: PathBuf },
    /// Extract a UDF ISO into a directory
    Extract { iso: PathBuf, dest: PathBuf },
    /// Create a bootable ISO from a media directory (like oscdimg -u2 -udfver102)
    Make {
        dir: PathBuf,
        out: PathBuf,
        #[arg(long, default_value = "LEAN11")]
        label: String,
        /// Use efisys_noprompt.bin (no "press any key" on UEFI boot)
        #[arg(long)]
        no_prompt: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    Lean,
    Core,
    Custom,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    // listing commands end quietly when their reader goes away (`lean11 catalog | head`); builds,
    // downloads and the TUI keep Rust's default so a closed pipe never kills a mounted image operation
    // (no SIGPIPE on Windows: a closed pipe is a write error there)
    #[cfg(unix)]
    if !matches!(cli.cmd, Cmd::Build(_) | Cmd::Tui { .. } | Cmd::Download { .. } | Cmd::Cbs { .. } | Cmd::Apps { .. } | Cmd::Recover { .. } | Cmd::WimExport { .. } | Cmd::WimEdit { .. } | Cmd::WimExtract { .. }) {
        unsafe {
            signal(13, 0);
        }
    }
    match cli.cmd {
        Cmd::WimExport { src, index, dest, compression } => {
            let t = std::time::Instant::now();
            let c = match compression.as_str() {
                "fast" => lean11_wim::Compression::Fast,
                "lzx" => lean11_wim::Compression::Lzx,
                "maximum" => lean11_wim::Compression::Maximum,
                "recovery" => lean11_wim::Compression::Recovery,
                o => anyhow::bail!("unknown compression {o}"),
            };
            lean11_wim::write::export(&src, index, &dest, c, &mut |l| eprintln!("{l}"))?;
            eprintln!("{:.1} s, {} bytes", t.elapsed().as_secs_f64(), std::fs::metadata(&dest)?.len());
            Ok(())
        }
        Cmd::WimEdit { wim, index, dir, command } => {
            let t = std::time::Instant::now();
            let ws = lean11_wim::workspace::Workspace::rw(&wim, index, &dir, &mut |l| eprintln!("{l}"))?;
            eprintln!("extracted in {:.1} s", t.elapsed().as_secs_f64());
            let st = std::process::Command::new("bash").arg("-c").arg(&command).env("WS", &ws.dir).status()?;
            if !st.success() {
                ws.discard(&mut |l| eprintln!("{l}"))?;
                anyhow::bail!("edit command failed: {st}");
            }
            let t = std::time::Instant::now();
            ws.commit(&mut |l| eprintln!("{l}"))?;
            eprintln!("committed in {:.1} s", t.elapsed().as_secs_f64());
            Ok(())
        }
        Cmd::WimExtract { wim, index, dir } => {
            let t = std::time::Instant::now();
            let w = lean11_wim::native::Wim::open(&wim)?;
            let x = lean11_wim::native::extract(&w, index, &dir, &mut |l| eprintln!("{l}"))?;
            eprintln!("{} nodes, {:.1} s", x.nodes.len(), t.elapsed().as_secs_f64());
            Ok(())
        }
        Cmd::Download { lang, arch, out, list_languages, resolve_only, url, sha256 } => match url {
            Some(u) => {
                let media = lean11_msdl::manual(&u, sha256.as_deref())?;
                if resolve_only {
                    println!("{}", serde_json::to_string_pretty(&media)?);
                    Ok(())
                } else {
                    fetch(media, out)
                }
            }
            None => download(lang, arch, out, list_languages, resolve_only),
        },
        Cmd::Iso { cmd } => iso(cmd),
        Cmd::Build(a) => build(a),
        Cmd::Tui { source } => tui::run(source),
        Cmd::Info { source } => info(source),
        Cmd::Recover { work, discard } => {
            let jobs = lean11_core::build::recover(&work, discard, &mut |l| eprintln!("{l}"))?;
            for (dir, stage) in &jobs {
                println!("{stage:<14} {}", dir.display());
            }
            if jobs.is_empty() {
                println!("no unfinished jobs in {}", work.display());
            } else if !discard {
                println!("resume with: lean11 build --resume <dir>   or discard the working copy with: lean11 recover <dir> --discard");
            }
            Ok(())
        }
        Cmd::Inventory { source, edition, kind, json, work } => inventory_cmd(source, edition, kind, json, work),
        Cmd::Apps { path, remove } if !remove.is_empty() => {
            // option ids, or pkg:<DisplayName> for a single package (testing)
            let opts: Vec<&'static catalog::CleanupOption> = remove
                .iter()
                .map(|id| match id.strip_prefix("pkg:") {
                    Some(name) => {
                        let targets: &'static [&'static str] = Box::leak(vec![&*Box::leak(name.to_string().into_boxed_str())].into_boxed_slice());
                        Ok(&*Box::leak(Box::new(catalog::CleanupOption {
                            id: "custom", title: "custom", description: "", kind: catalog::Kind::App, balanced: false, minimal: false, targets,
                        })))
                    }
                    None => catalog::option(id).ok_or_else(|| anyhow::anyhow!("unknown option {id}")),
                })
                .collect::<Result<_>>()?;
            let removed = lean11_core::appx::remove_provisioned(&path, &opts, &mut |m| eprintln!("{m}"))?;
            println!("{} packages removed", removed.len());
            Ok(())
        }
        Cmd::Apps { path, .. } => {
            let apps = if path.is_dir() { lean11_core::appx::list(&path)? } else { lean11_core::appx::list_from_hive(&lean11_hive::Hive::open(&path, false)?)? };
            let opts: Vec<_> = catalog::OPTIONS.iter().filter(|o| o.kind == catalog::Kind::App).collect();
            for a in &apps {
                let by = opts.iter().find(|o| catalog::matches_app(o, &a.display_name, &a.package_name)).map(|o| o.id).unwrap_or("-");
                println!("{:<16} {}  (+{} deps)", by, a.package_name, a.dependencies.len());
            }
            Ok(())
        }
        Cmd::Cbs { path, list, remove_feature, disable_feature, remove_capability, remove_package, dry_run, show_manifest } => {
            use lean11_core::cbs::{self, Target};
            if let Some(c) = show_manifest {
                print!("{}", cbs::manifest_text(&path, &c)?);
                return Ok(());
            }
            let store = cbs::Store::open(&path)?;
            let targets: Vec<Target> = remove_feature
                .into_iter()
                .map(Target::Feature)
                .chain(disable_feature.into_iter().map(Target::DisableFeature))
                .chain(remove_capability.into_iter().map(Target::Capability))
                .chain(remove_package.into_iter().map(Target::Package))
                .collect();
            if !targets.is_empty() {
                let plan = store.plan(&targets)?;
                for m in &plan.missing {
                    eprintln!("not present: {m}");
                }
                for p in &plan.packages {
                    println!("remove {p}");
                }
                for p in &plan.pairs {
                    println!("remove content {p}");
                }
                for p in &plan.stage {
                    println!("stage {p}");
                }
                if !dry_run {
                    let r = cbs::remove(&store, &plan, &mut |m| eprintln!("{m}"))?;
                    println!("{r:?}");
                    let (f, c) = cbs::verify(&path, &plan)?;
                    for x in &f {
                        println!("verified feature {} => {}", x.name, x.describe());
                    }
                    for x in &c {
                        println!("verified capability {} => {}", x.name, x.describe());
                    }
                }
                return Ok(());
            }
            match list.as_str() {
                "features" => {
                    for f in store.features() {
                        println!("{:<60} {}", f.name, f.state);
                    }
                }
                "capabilities" => {
                    for c in store.capabilities() {
                        println!("{:<70} {}", c.name, if c.installed { "Installed" } else { "Not Present" });
                    }
                }
                "packages" => {
                    for p in store.packages.values() {
                        println!("{:<110} 0x{:02x}", p.identity, p.state);
                    }
                }
                other => anyhow::bail!("unknown list {other} (features, capabilities, packages)"),
            }
            Ok(())
        }
        Cmd::Privacy { cmd } => privacy_cmd(cmd),
        Cmd::Software { cmd } => software_cmd(cmd),
        Cmd::Catalog { mode } => {
            let selected = mode.map(|m| {
                catalog::for_mode(match m {
                    ModeArg::Lean => Mode::Lean,
                    ModeArg::Core => Mode::Core,
                    ModeArg::Custom => Mode::Custom,
                })
            });
            for o in catalog::OPTIONS {
                let mark = match &selected {
                    Some(s) if s.contains(&o.id) => "[x] ",
                    Some(_) => "[ ] ",
                    None => "",
                };
                let r = lean11_core::knowledge::option_rating(o.id).map(|r| r.label()).unwrap_or("-");
                println!("{mark}{:<22} {:<11} {:<8} {}", o.id, format!("{:?}", o.kind).to_lowercase(), r, o.title);
            }
            Ok(())
        }
    }
}

fn download(lang: Option<String>, arch: Option<String>, out: PathBuf, list: bool, resolve_only: bool) -> Result<()> {
    let arch = match arch {
        Some(a) => Arch::parse(&a)?,
        None => Arch::host(),
    };
    let catalog = Catalog::open(arch)?;
    if list {
        for sku in catalog.languages()? {
            println!("{}", sku.language);
        }
        return Ok(());
    }
    let lang = lang
        .or_else(|| std::env::var("LANG").ok().map(|l| l.split('.').next().unwrap_or("en_US").to_string()))
        .unwrap_or_else(|| "en-US".into());
    // like the TUI: a language without an ISO falls back to English
    let media = catalog.resolve(&lang, true)?;
    if resolve_only {
        println!("{}", serde_json::to_string_pretty(&media)?);
        return Ok(());
    }
    eprintln!("{} ({}, {:?})", media.description, media.language, media.arch);
    fetch(media, out)
}

fn fetch(media: lean11_msdl::OfficialMedia, out: PathBuf) -> Result<()> {
    let dest = out.join(&media.file_name);
    let mut last = std::time::Instant::now();
    let (path, hash) = lean11_msdl::download(&media, &dest, &mut |done, total| {
        if last.elapsed().as_millis() >= 1000 {
            last = std::time::Instant::now();
            match total {
                Some(t) => eprint!("\r{:>7.1} / {:.1} MiB ({:.0} %)   ", done as f64 / 1048576.0, t as f64 / 1048576.0, done as f64 * 100.0 / t as f64),
                None => eprint!("\r{:>7.1} MiB   ", done as f64 / 1048576.0),
            }
            let _ = std::io::stderr().flush();
        }
    })?;
    eprintln!();
    println!("{}  {}", hash, path.display());
    Ok(())
}

fn bar(label: &str, done: u64, total: u64, last: &mut std::time::Instant) {
    if last.elapsed().as_millis() >= 1000 || done == total {
        *last = std::time::Instant::now();
        eprint!("\r{label}: {:.1} / {:.1} GiB ({:.0} %)   ", done as f64 / 1073741824.0, total as f64 / 1073741824.0,
            if total == 0 { 100.0 } else { done as f64 * 100.0 / total as f64 });
        let _ = std::io::stderr().flush();
    }
}

fn iso(cmd: IsoCmd) -> Result<()> {
    match cmd {
        IsoCmd::Ls { iso } => {
            let r = lean11_iso::UdfReader::open(&iso)?;
            for e in r.walk()? {
                if e.is_dir { println!("{:>14}  {}/", "", e.path) } else { println!("{:>14}  {}", e.size, e.path) }
            }
        }
        IsoCmd::Extract { iso, dest } => {
            let r = lean11_iso::UdfReader::open(&iso)?;
            let total: u64 = r.walk()?.iter().map(|e| e.size).sum();
            let mut done = 0;
            let mut last = std::time::Instant::now();
            r.extract(&dest, &|_| false, &mut |_, n| { done += n; bar("extract", done, total, &mut last) })?;
            eprintln!();
        }
        IsoCmd::Make { dir, out, label, no_prompt } => {
            if out.exists() { anyhow::bail!("{} exists", out.display()); }
            let has = |p: &str| dir.join(p).is_file();
            let uefi = if no_prompt && has(lean11_iso::UEFI_BOOT_NOPROMPT) { lean11_iso::UEFI_BOOT_NOPROMPT } else { lean11_iso::UEFI_BOOT };
            let opts = lean11_iso::WriteOptions {
                label,
                bios_image: has(lean11_iso::BIOS_BOOT).then(|| lean11_iso::BIOS_BOOT.to_string()),
                uefi_image: has(uefi).then(|| uefi.to_string()),
            };
            let mut last = std::time::Instant::now();
            lean11_iso::write_iso(&dir, &out, &opts, &mut |d, t| bar("write", d, t, &mut last))?;
            eprintln!();
        }
    }
    Ok(())
}

fn mode_of(m: ModeArg) -> Mode {
    match m {
        ModeArg::Lean => Mode::Lean,
        ModeArg::Core => Mode::Core,
        ModeArg::Custom => Mode::Custom,
    }
}

static STOP: std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicBool>> = std::sync::OnceLock::new();

const STOP_MSG: &[u8] = b"\nStopping after the current stage; the job stays resumable.\n";

#[cfg(unix)]
unsafe extern "C" {
    /// `sighandler_t signal(int, sighandler_t)`; the handler as an address so SIG_DFL (0) fits.
    fn signal(sig: i32, handler: usize) -> usize;
    fn write(fd: i32, buf: *const std::ffi::c_void, n: usize) -> isize;
}

/// Ctrl+C: stop at the next stage boundary (job stays resumable). A running image
/// operation is never killed, so later presses only repeat the notice (async-signal-safe `write`).
#[cfg(unix)]
extern "C" fn on_sigint(_: i32) {
    if let Some(f) = STOP.get() {
        f.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    unsafe {
        write(2, STOP_MSG.as_ptr().cast(), STOP_MSG.len());
    }
}

/// Windows console Ctrl+C / Ctrl+Break: the same, handled on the console's own thread.
#[cfg(windows)]
unsafe extern "system" fn on_ctrl(kind: u32) -> windows_sys::core::BOOL {
    // CTRL_C_EVENT 0, CTRL_BREAK_EVENT 1; closing the window is not intercepted
    if kind > 1 {
        return 0;
    }
    if let Some(f) = STOP.get() {
        f.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    let _ = std::io::Write::write_all(&mut std::io::stderr(), STOP_MSG);
    1
}

fn stop_flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let f = STOP.get_or_init(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))).clone();
    #[cfg(unix)]
    unsafe {
        signal(2, on_sigint as extern "C" fn(i32) as usize);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
    f
}

fn build(a: BuildArgs) -> Result<()> {
    use lean11_core::build::{Builder, Recipe, recipe_for};
    // a closed stderr must not panic a running build: write errors are ignored
    let mut sink = |m: &str| {
        let _ = writeln!(std::io::stderr(), "{m}");
    };
    if let Some(dir) = &a.resume {
        let mut b = Builder::resume(dir, a.out.clone(), &mut sink)?;
        b.cancel = Some(stop_flag());
        let out = b.run()?;
        println!("{}", out.display());
        return Ok(());
    }
    let recipe: Recipe = if let Some(r) = &a.recipe {
        // modified preset recipes load as Custom (Core's removals kept)
        let mut r: Recipe = serde_json::from_slice(&std::fs::read(r)?)?;
        r.normalize_mode();
        r
    } else {
        // a template needs no source when it is only saved
        let source = match (&a.source, &a.save_template) {
            (Some(s), _) => s.clone(),
            (None, Some(_)) => PathBuf::new(),
            (None, None) => anyhow::bail!("source ISO or directory missing"),
        };
        let mut r = recipe_for(mode_of(a.mode), source, PathBuf::new());
        if let Some(t) = &a.template {
            for n in lean11_core::template::Template::load(t)?.apply(&mut r) {
                eprintln!("template: {n}");
            }
        }
        // the default name follows the mode that applies (a template's mode replaces --mode)
        r.output = a.out.clone().unwrap_or_else(|| PathBuf::from(if r.is_core() { "lean11-core.iso" } else { "lean11.iso" }));
        for id in &a.enable {
            if catalog::option(id).is_none() { anyhow::bail!("unknown option {id} (see `lean11 catalog`)"); }
            if !r.options.contains(id) { r.options.push(id.clone()); }
        }
        for id in &a.disable {
            if catalog::option(id).is_none() { anyhow::bail!("unknown option {id} (see `lean11 catalog`)"); }
            r.options.retain(|o| o != id);
        }
        r.edition = a.edition.clone();
        // flags change a template's settings only where they are given
        if let Some(c) = a.compression {
            r.compression = match c {
                CompArg::Recovery => lean11_wim::Compression::Recovery,
                CompArg::Maximum => lean11_wim::Compression::Maximum,
                CompArg::Fast => lean11_wim::Compression::Fast,
            };
        }
        r.local_account &= !a.no_local_account;
        r.compact &= !a.no_compact;
        r.no_prompt |= a.no_prompt;
        r.keep_work = a.keep_work;
        r.omit_sxs |= a.omit_sxs;
        r.remove_redundant_data |= a.remove_redundant_data;
        if let Some(k) = &a.ssh_key {
            let text = std::fs::read_to_string(k).with_context(|| format!("cannot read the SSH key {}", k.display()))?;
            if !lean11_core::ssh::valid_authorized_key(&text) {
                anyhow::bail!("{} is not a valid OpenSSH public key", k.display());
            }
            r.ssh_authorized_key = Some(text.trim().to_string());
        }
        let cli_actions: Vec<lean11_core::inventory::Action> = a.actions.iter().map(|x| x.parse()).collect::<Result<_>>()?;
        r.actions.extend(cli_actions);
        r.core_acknowledged |= a.accept_core;
        r.turbo |= a.turbo;
        r.expert_acknowledged |= a.accept_expert;
        r.breaking_acknowledged |= a.accept_breaking;
        if a.label.is_some() {
            r.label = a.label.clone();
        }
        r.core |= a.core;
        for id in &a.software {
            if lean11_core::software::program(id).is_none() { anyhow::bail!("unknown software {id} (see `lean11 software list`)"); }
            if !r.software.contains(id) { r.software.push(id.clone()); }
        }
        // --privacy replaces the template's selection, --privacy-enable/-disable change it
        let mut privacy = match &a.privacy {
            Some(p) => lean11_core::privacy::preset(p)?,
            None => std::mem::take(&mut r.privacy),
        };
        for id in &a.privacy_enable {
            if lean11_core::privacy::setting(id).is_none() { anyhow::bail!("unknown privacy setting {id} (see `lean11 privacy list`)"); }
            if !privacy.contains(id) { privacy.push(id.clone()); }
        }
        for id in &a.privacy_disable {
            if lean11_core::privacy::setting(id).is_none() { anyhow::bail!("unknown privacy setting {id} (see `lean11 privacy list`)"); }
            privacy.retain(|x| x != id);
        }
        // hidden settings (component removed or already set) are dropped with a note; a saved template
        // keeps the whole choice (the build skips what does not apply)
        r.privacy = privacy;
        let mut kept = Vec::new();
        if a.save_template.is_some() {
            kept = std::mem::take(&mut r.privacy);
        }
        for id in std::mem::take(&mut r.privacy) {
            match lean11_core::privacy::setting(&id).map(|s| lean11_core::privacy::status(s, &r)) {
                Some(lean11_core::privacy::Status::Hidden(why)) => eprintln!("privacy: {id} skipped ({why})"),
                _ => kept.push(id),
            }
        }
        r.privacy = kept;
        let preset = r.mode;
        r.normalize_mode();
        if r.mode != preset {
            eprintln!("The {preset:?} removal set was changed: building as Custom{}.", if r.core { " with Core's removals" } else { "" });
        }
        if a.core && r.mode != lean11_core::catalog::Mode::Custom && preset != lean11_core::catalog::Mode::Core {
            r.mode = lean11_core::catalog::Mode::Custom;
        }
        r
    };
    if let Some(path) = &a.save_template {
        lean11_core::template::Template::from_recipe(&recipe).save(path)?;
        println!("{}", path.display());
        return Ok(());
    }
    if a.print_recipe {
        println!("{}", serde_json::to_string_pretty(&recipe)?);
        return Ok(());
    }
    let out_abs = std::path::absolute(&recipe.output)?;
    let work = match &a.work {
        Some(w) => w.clone(),
        None => out_abs.parent().unwrap_or(std::path::Path::new(".")).join("lean11-work"),
    };
    let mut b = Builder::new(&work, recipe, &mut sink)?;
    b.cancel = Some(stop_flag());
    eprintln!("Ctrl+C stops after the current stage; the job stays resumable.");
    let out = b.run()?;
    println!("{}", out.display());
    Ok(())
}

fn software_cmd(cmd: SoftwareCmd) -> Result<()> {
    use lean11_core::software;
    match cmd {
        SoftwareCmd::List { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(software::catalog())?);
            } else {
                for p in software::catalog() {
                    println!("{:<12} {:<20} {}", p.id, p.category, p.name);
                }
            }
        }
        SoftwareCmd::Resolve { ids, arch, lang } => {
            let list: Vec<&software::Program> = match ids {
                Some(s) => s.split(',').map(|id| software::program(id.trim()).ok_or_else(|| anyhow::anyhow!("unknown software {id}"))).collect::<Result<_>>()?,
                None => software::catalog().iter().collect(),
            };
            let index = lean11_msdl::winget::Index::load(&mut |m| eprintln!("{m}"))?;
            let mut failed = 0;
            for p in list {
                if p.kind == software::ProgramKind::Scoop {
                    println!("{:<12} script  {}", p.id, software::SCOOP_INSTALLER_URL);
                    continue;
                }
                let ids: Vec<&str> = p.winget.iter().map(String::as_str).collect();
                match lean11_msdl::winget::resolve(&index, &ids, &arch, &lang) {
                    Ok(i) => println!("{:<12} {} {} [{} {}] {}\n             args: {}  sha256 {}", p.id, i.id, i.version, i.kind, i.architecture, i.url, i.args, i.sha256),
                    Err(e) => {
                        failed += 1;
                        println!("{:<12} ERROR {e:#}", p.id)
                    }
                }
            }
            if failed > 0 {
                anyhow::bail!("{failed} programs could not be resolved");
            }
        }
    }
    Ok(())
}

fn privacy_cmd(cmd: PrivacyCmd) -> Result<()> {
    use lean11_core::privacy;
    let pick = |which: &str| -> Result<Vec<&'static privacy::Setting>> {
        let ids = if matches!(which, "recommended" | "strict") {
            privacy::preset(which)?
        } else if which == "all" {
            privacy::catalog().setting.iter().map(|s| s.id.clone()).collect()
        } else {
            which.split(',').map(str::to_string).collect()
        };
        ids.iter().map(|id| privacy::setting(id).ok_or_else(|| anyhow::anyhow!("unknown privacy setting {id}"))).collect()
    };
    match cmd {
        PrivacyCmd::List { preset, json } => {
            let list = pick(preset.as_deref().unwrap_or("all"))?;
            if json {
                let v: Vec<_> = list
                    .iter()
                    .map(|s| serde_json::json!({"id": s.id, "category": privacy::category_path(&s.category), "level": s.level, "title": s.title,
                        "description": s.description, "sources": s.sources, "verified": s.verified, "hidden_if": s.hidden_if, "conflicts": s.conflicts,
                        "rating": lean11_core::knowledge::privacy_rating(s)}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                let mut last = String::new();
                for s in &list {
                    let cat = privacy::category_path(&s.category);
                    if cat != last {
                        println!("\n{cat}");
                        last = cat;
                    }
                    let lvl = format!("{:?}", s.level).to_lowercase();
                    println!("  {:<12} {:<44} {}", lvl, s.id, s.title);
                }
                eprintln!("\n{} settings", list.len());
            }
        }
        PrivacyCmd::Verify { image, all, json, catalog, admx_dirs } => {
            let draft = catalog.map(|p| std::fs::read_to_string(&p).map_err(anyhow::Error::from).and_then(|t| privacy::parse_catalog(&t))).transpose()?;
            let list: Vec<&privacy::Setting> = match &draft {
                Some(c) => c.setting.iter().collect(),
                None => pick("all")?,
            };
            let found = privacy::verify(&image, &list, &admx_dirs)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&found)?);
            } else {
                for f in found.iter().filter(|f| all || !matches!(f.status, "ok" | "info")) {
                    println!("{:<13} {:<40} {}\n              {}", f.status, f.setting, f.op, f.detail);
                }
            }
            let mut counts = std::collections::BTreeMap::new();
            for f in &found {
                *counts.entry(f.status).or_insert(0) += 1;
            }
            eprintln!("{} ops: {counts:?}", found.len());
        }
        PrivacyCmd::Admx { image, pattern, admx_dirs } => {
            let mut pol = lean11_core::admx::Policies::load(&image)?;
            for d in &admx_dirs {
                pol.add_dir(d)?;
            }
            let pat = pattern.to_lowercase();
            let mut rows: Vec<String> = Vec::new();
            for ((key, name), vals) in &pol.values {
                for v in vals {
                    let line = format!("{key}!{name}  [{}] {} \"{}\" {:?}", v.class, v.policy, v.display, v.allowed);
                    if line.to_lowercase().contains(&pat) {
                        rows.push(line);
                    }
                }
            }
            rows.sort();
            for r in &rows {
                println!("{r}");
            }
            eprintln!("{} matches in {} ADMX files", rows.len(), pol.files);
        }
        PrivacyCmd::CheckScript { which } => print!("{}", privacy::check_script(&pick(&which)?)),
        PrivacyCmd::AfterSetupScript { which } => print!("{}", privacy::after_setup_script(&pick(&which)?).unwrap_or_default()),
    }
    Ok(())
}

fn inventory_cmd(source: PathBuf, edition: Option<String>, kind: Option<String>, json: bool, work: Option<PathBuf>) -> Result<()> {
    use lean11_core::inventory;
    let filter: Option<inventory::Kind> = kind.map(|k| k.parse()).transpose()?;
    let work = work.unwrap_or_else(|| source.parent().unwrap_or(std::path::Path::new(".")).to_path_buf());
    let items = inventory::read_source(&source, edition.as_deref(), &work, &mut |l| eprintln!("{l}"))?;
    let items: Vec<_> = items.into_iter().filter(|i| filter.is_none_or(|k| i.kind == k)).collect();
    if json {
        // each item with its knowledge entry (rating, what, effect, verified), if there is one
        let v: Vec<serde_json::Value> = items
            .iter()
            .map(|i| {
                let mut o = serde_json::to_value(i).unwrap_or_default();
                if let (Some(e), Some(m)) = (lean11_core::knowledge::item(i), o.as_object_mut()) {
                    m.insert("rating".into(), serde_json::json!(e.rating));
                    m.insert("what".into(), serde_json::json!(e.what));
                    m.insert("effect".into(), serde_json::json!(e.effect));
                    m.insert("verified_rating".into(), serde_json::json!(e.verified));
                }
                o
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        for i in &items {
            let r = lean11_core::knowledge::item(i).map(|e| e.rating.label()).unwrap_or("-");
            println!("{:<17} {} {:<8} {:<60} {}  [{}]", format!("{:?}", i.kind), if i.protected { "P" } else { " " }, r, i.label(), i.identity, i.detail);
        }
        eprintln!("{} items (P = protected; rating safe/limited/breaks, - = not rated)", items.len());
    }
    Ok(())
}

fn info(source: PathBuf) -> Result<()> {
    let images = if source.is_dir() {
        let wim = lean11_wim::resolve_ci(&source, "sources/install.wim").or_else(|| lean11_wim::resolve_ci(&source, "sources/install.esd"))
            .ok_or_else(|| anyhow::anyhow!("no sources/install.wim|esd"))?;
        lean11_wim::info(&wim)?
    } else if source.extension().is_some_and(|e| e.eq_ignore_ascii_case("iso")) {
        let r = lean11_iso::UdfReader::open(&source)?;
        let e = r.find("sources/install.wim")?.or(r.find("sources/install.esd")?).ok_or_else(|| anyhow::anyhow!("no install image in ISO"))?;
        lean11_wim::info_from_header(&mut |o, l| r.read_range(&e, o, l))?
    } else {
        lean11_wim::info(&source)?
    };
    for i in images {
        println!("[{}] {}  ({}, {}, {}, {:.1} GiB)", i.index, i.name, i.edition_id, i.arch(), i.version(), i.total_bytes as f64 / 1073741824.0);
    }
    Ok(())
}
