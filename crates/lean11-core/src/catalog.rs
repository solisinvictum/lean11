//! Removal and settings catalog: apps, files, capabilities, features and the registry settings of the
//! Components step, including scheduled tasks, start pins and the Outlook/DevHome update orchestrator.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// The default preset.
    Lean,
    Core,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Provisioned Appx packages, matched by display name.
    App,
    /// Plain file/directory removal inside the image.
    File,
    /// CBS capability (Remove-Capability), matched by name prefix.
    Capability,
    /// Optional feature (Disable-Feature /Remove).
    Feature,
    /// Registry values only.
    Policy,
    /// Irreversible system removal (WinRE, WinSxS pruning); parts of Core, offered singly in Custom.
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    /// Windows\System32\config\SOFTWARE, keys relative to HKLM\SOFTWARE.
    Software,
    /// Windows\System32\config\SYSTEM; `{ControlSet}` is replaced by the current control set.
    System,
    /// Users\Default\NTUSER.DAT (default user profile).
    DefaultUser,
    /// Windows\System32\config\DEFAULT (.DEFAULT user, used by the original script for the hardware cache).
    DotDefault,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Dword(u32),
    Sz(&'static str),
}

#[derive(Debug, Clone)]
pub struct RegValue {
    pub hive: Hive,
    pub key: &'static str,
    pub name: &'static str,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub enum RegOp {
    Set(RegValue),
    /// Delete a key with all subkeys.
    DeleteKey { hive: Hive, key: &'static str },
}

#[derive(Debug, Clone)]
pub struct CleanupOption {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub kind: Kind,
    /// Default in the "balanced" selection.
    pub balanced: bool,
    /// Part of the "minimal" selection (Core base).
    pub minimal: bool,
    pub targets: &'static [&'static str],
}

const fn app(id: &'static str, title: &'static str, description: &'static str, balanced: bool, minimal: bool, targets: &'static [&'static str]) -> CleanupOption {
    CleanupOption { id, title, description, kind: Kind::App, balanced, minimal, targets }
}
const fn feature(id: &'static str, title: &'static str, description: &'static str, balanced: bool, minimal: bool, targets: &'static [&'static str]) -> CleanupOption {
    CleanupOption { id, title, description, kind: Kind::Feature, balanced, minimal, targets }
}
const fn policy(id: &'static str, title: &'static str, description: &'static str, balanced: bool, minimal: bool) -> CleanupOption {
    CleanupOption { id, title, description, kind: Kind::Policy, balanced, minimal, targets: &[] }
}

pub static OPTIONS: &[CleanupOption] = &[
    app("copilot-app", "Copilot apps", "Remove preinstalled Copilot apps. Keep shared runtimes and shell components.", true, true,
        &["Microsoft.Copilot", "Microsoft.Windows.Copilot", "Microsoft.549981C3F5F10"]),
    app("outlook", "New Outlook and Mail", "Remove Outlook and the retired Mail / Calendar apps.", true, true,
        &["Microsoft.OutlookForWindows", "microsoft.windowscommunicationsapps"]),
    app("teams", "Teams", "Remove personal Teams clients.", true, true, &["MSTeams", "MicrosoftTeams", "Microsoft.Windows.Teams"]),
    app("xbox", "Xbox and gaming overlays", "Remove Xbox apps and Game Bar. Gaming sign-in and recording may be unavailable.", true, true,
        &["Microsoft.GamingApp", "Microsoft.XboxApp", "Microsoft.Xbox.TCUI", "Microsoft.XboxGameOverlay",
          "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay"]),
    app("news-weather", "News, weather and Bing apps", "Remove packaged feed apps; local Windows Search is preserved.", true, true,
        &["Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingSearch"]),
    app("office-promos", "Microsoft 365 promotions", "Remove Office Hub and Office push-notification promotional apps.", true, true,
        &["Microsoft.MicrosoftOfficeHub", "Microsoft.OfficePushNotificationUtility"]),
    app("clipchamp", "Clipchamp", "Remove the bundled video editor.", true, true, &["Clipchamp.Clipchamp"]),
    app("solitaire", "Solitaire", "Remove bundled games.", true, true, &["Microsoft.MicrosoftSolitaireCollection"]),
    app("phone", "Phone Link and cross-device apps", "Remove phone integration apps. Cross-device features may stop working.", true, true,
        &["Microsoft.YourPhone", "Microsoft.Windows.CrossDevice"]),
    app("feedback", "Feedback, tips and help", "Remove Feedback Hub, Get Help, and introductory apps.", true, true,
        &["Microsoft.WindowsFeedbackHub", "Microsoft.GetHelp", "Microsoft.Getstarted"]),
    app("devhome", "Dev Home and Power Automate", "Remove Dev Home and Power Automate Desktop.", true, true,
        &["Microsoft.Windows.DevHome", "Microsoft.PowerAutomateDesktop"]),
    app("social", "People, To Do, Family and Skype", "Remove optional organizer and communication apps.", true, true,
        &["Microsoft.People", "Microsoft.Todos", "Microsoft.SkypeApp", "MicrosoftCorporationII.MicrosoftFamily"]),
    app("maps", "Maps and Mixed Reality", "Remove retired Maps and Mixed Reality clients.", true, true,
        &["Microsoft.WindowsMaps", "Microsoft.MixedReality.Portal"]),
    app("media", "Media Player and Movies", "Remove bundled media playback apps; codecs and shared frameworks remain.", false, true,
        &["Microsoft.ZuneMusic", "Microsoft.ZuneVideo"]),
    app("utilities", "Clock, Recorder and Sticky Notes", "Remove optional personal utilities.", false, true,
        &["Microsoft.WindowsAlarms", "Microsoft.WindowsSoundRecorder", "Microsoft.MicrosoftStickyNotes"]),
    app("quickassist", "Quick Assist", "Remove Microsoft's remote-assistance client.", false, true, &["MicrosoftCorporationII.QuickAssist"]),
    app("paint", "Paint, 3D Viewer and OneNote", "Remove Paint, 3D Viewer and OneNote. Leave unchecked to keep them.", false, false,
        &["Microsoft.Paint", "Microsoft.MSPaint", "Microsoft.Microsoft3DViewer", "Microsoft.Office.OneNote"]),
    app("camera", "Camera", "Remove the Camera app, not camera drivers.", false, false, &["Microsoft.WindowsCamera"]),
    app("terminal", "Windows Terminal", "Remove Terminal. PowerShell and Command Prompt remain.", false, false, &["Microsoft.WindowsTerminal"]),
    app("oem", "OEM promotional apps", "Remove Intel management status and Dolby promotional applications, not drivers.", false, false,
        &["AppUp.IntelManagementandSecurityStatus", "DolbyLaboratories.DolbyAccess", "DolbyLaboratories.DolbyDigitalPlusDecoderOEM"]),
    CleanupOption { id: "edge-files", title: "Remove Edge and WebView2",
        description: "Delete Edge and WebView2 files. Apps that require WebView2 may stop working. Updates may reinstall Edge.",
        kind: Kind::File, balanced: false, minimal: false, targets: &[] },
    CleanupOption { id: "onedrive-files", title: "Remove OneDrive setup binaries",
        description: "Remove both architecture-specific OneDrive installers from the offline image.",
        kind: Kind::File, balanced: false, minimal: false, targets: &[] },
    CleanupOption { id: "language-extras", title: "Speech, OCR and handwriting payloads",
        description: "Remove optional language capabilities in every image language; retain basic language support.",
        kind: Kind::Capability, balanced: false, minimal: false,
        targets: &["Language.Handwriting", "Language.OCR", "Language.Speech", "Language.TextToSpeech"] },
    CleanupOption { id: "legacy-capabilities", title: "Retired accessories and wallpaper payloads",
        description: "Remove WordPad, Steps Recorder, Math Recognizer, legacy Media Player and extended wallpapers where installed.",
        kind: Kind::Capability, balanced: false, minimal: true,
        targets: &["Microsoft.Windows.WordPad", "App.StepsRecorder", "MathRecognizer", "Media.WindowsMediaPlayer", "Microsoft.Windows.Wallpaper.Extended"] },
    feature("xps", "XPS printing", "Disable optional XPS printing and remove its payload.", false, true, &["Printing-XPSServices-Features"]),
    feature("workfolders", "Work Folders", "Disable enterprise Work Folders sync and remove its payload.", false, true, &["WorkFolders-Client"]),
    feature("legacy", "Legacy Internet Explorer", "Disable the retired Internet Explorer optional feature where present.", true, true,
        &["Internet-Explorer-Optional-amd64", "Internet-Explorer-Optional-arm64"]),
    feature("recall-feature", "Recall optional feature", "Disable and remove Recall's payload only if this image exposes it to DISM.", true, true, &["Recall"]),
    policy("ads", "Ads, recommendations and sponsored apps", "Suppress consumer content, Settings suggestions, Explorer promotions and welcome tips.", true, true),
    policy("privacy", "Optional diagnostics and personalization", "Keep required diagnostic data. Disable advertising ID, personalized suggestions and input collection.", true, true),
    policy("copilot", "Disable Copilot and Recall", "Apply policies to disable Copilot and Recall. Support varies by build and edition.", true, true),
    policy("widgets", "Widgets and taskbar feeds", "Disable Widgets by policy and hide its taskbar entry.", true, true),
    policy("search", "Web search and search highlights", "Turn off web suggestions, cloud search and dynamic search highlights; keep local search.", true, true),
    policy("onedrive", "OneDrive sync and backup prompts", "Disable OneDrive sync by policy. OneDrive binaries are retained; use this only if you do not need sync.", true, true),
    policy("edge", "Edge first-run and promotional UI", "Suppress first-run, sidebar and recommendations. Preserve Edge and WebView2 for app compatibility.", true, true),
    policy("oobe", "Setup privacy and finish-setting-up nags", "Suppress privacy setup and post-sign-in setup suggestions without creating accounts or accepting the EULA.", true, true),
    policy("hardware-bypass", "Bypass setup hardware requirements", "Set CPU, RAM, TPM, storage and Secure Boot bypass values in setup and Windows.", false, false),
    policy("reserved-storage", "Disable reserved storage", "Stop reserving disk space for updates. This can leave less space available during servicing.", false, false),
    policy("device-encryption", "Disable automatic device encryption", "Prevent automatic BitLocker device encryption; do not use if you require encryption by default.", false, false),
    // Core's four parts, offered singly in Custom
    policy("disable-defender", "Disable Microsoft Defender",
        "Turn off Defender antivirus and real-time protection (services WinDefend, WdNisSvc, WdNisDrv, WdFilter, Sense and policies). \
         The component stays installed, updates keep working; reversible by re-enabling the services.", false, false),
    policy("disable-windows-update", "Disable Windows Update",
        "Stop Windows Update, the update orchestrator and its repair service and block update access by policy. \
         No security updates while it is off; reversible.", false, false),
    CleanupOption { id: "remove-winre", title: "Remove the recovery environment (WinRE)",
        description: "Delete winre.wim: no Startup Repair, Reset this PC or recovery boot; setup switches to the legacy installer. Irreversible for the installed system.",
        kind: Kind::System, balanced: false, minimal: false, targets: &[] },
    CleanupOption { id: "trim-winsxs", title: "Trim the component store (WinSxS)",
        description: "Delete WinSxS component folders except common controls, GDI+, CRT and servicing. The image can no longer be \
         updated, repaired or get features added; setup switches to the legacy installer. Irreversible.",
        kind: Kind::System, balanced: false, minimal: false, targets: &[] },
];

/// Parts of Core that are irreversible and need the same acknowledgement as Core.
pub const IRREVERSIBLE: &[&str] = &["remove-winre", "trim-winsxs"];

pub fn option(id: &str) -> Option<&'static CleanupOption> {
    OPTIONS.iter().find(|o| o.id == id)
}

/// Option ids selected by a mode. Lean = all apps and all non-capability options, Core = the minimal
/// selection plus Core's extras.
pub fn for_mode(mode: Mode) -> Vec<&'static str> {
    match mode {
        Mode::Lean => OPTIONS
            .iter()
            .filter(|o| {
                o.kind == Kind::App
                    || !matches!(o.id, "language-extras" | "legacy-capabilities" | "disable-defender" | "disable-windows-update" | "remove-winre" | "trim-winsxs")
            })
            .map(|o| o.id)
            .collect(),
        Mode::Core => OPTIONS
            .iter()
            .filter(|o| {
                o.minimal
                    || matches!(o.id, "language-extras" | "edge-files" | "onedrive-files" | "hardware-bypass" | "reserved-storage" | "device-encryption")
            })
            .map(|o| o.id)
            .collect(),
        Mode::Custom => Vec::new(),
    }
}

/// True if a provisioned package belongs to an app option: display name equals a target and
/// the full package name starts with `target_` (case-insensitive).
pub fn matches_app(opt: &CleanupOption, display_name: &str, package_name: &str) -> bool {
    opt.kind == Kind::App
        && opt.targets.iter().any(|t| {
            display_name.eq_ignore_ascii_case(t)
                && package_name.len() > t.len()
                && package_name[..t.len()].eq_ignore_ascii_case(t)
                && package_name.as_bytes()[t.len()] == b'_'
        })
}

macro_rules! reg {
    ($v:ident, $hive:ident, $key:expr, $name:expr, dword $val:expr) => {
        $v.push(RegOp::Set(RegValue { hive: Hive::$hive, key: $key, name: $name, value: Value::Dword($val) }))
    };
    ($v:ident, $hive:ident, $key:expr, $name:expr, sz $val:expr) => {
        $v.push(RegOp::Set(RegValue { hive: Hive::$hive, key: $key, name: $name, value: Value::Sz($val) }))
    };
}

/// Registry operations of a policy option (install image).
pub fn registry_ops(id: &str) -> Vec<RegOp> {
    const CLOUD: &str = r"Policies\Microsoft\Windows\CloudContent";
    const USER_CLOUD: &str = r"Software\Policies\Microsoft\Windows\CloudContent";
    const CDM: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    const ADV: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    let mut v = Vec::new();
    match id {
        "ads" => {
            for n in ["DisableWindowsConsumerFeatures", "DisableConsumerAccountStateContent", "DisableCloudOptimizedContent"] {
                reg!(v, Software, CLOUD, n, dword 1);
            }
            for n in ["DisableWindowsSpotlightFeatures", "DisableThirdPartySuggestions", "DisableTailoredExperiencesWithDiagnosticData"] {
                reg!(v, DefaultUser, USER_CLOUD, n, dword 1);
            }
            for n in [
                "ContentDeliveryAllowed", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled",
                "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SubscribedContentEnabled",
                "SystemPaneSuggestionsEnabled", "SubscribedContent-310093Enabled", "SubscribedContent-338388Enabled",
                "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled",
            ] {
                reg!(v, DefaultUser, CDM, n, dword 0);
            }
            reg!(v, DefaultUser, ADV, "ShowSyncProviderNotifications", dword 0);
            reg!(v, Software, r"Policies\Microsoft\PushToInstall", "DisablePushToInstall", dword 1);
            reg!(v, Software, r"Policies\Microsoft\Teams", "DisableInstallation", dword 1);
            reg!(v, Software, r"Policies\Microsoft\Windows\Windows Mail", "PreventRun", dword 1);
        }
        "privacy" => {
            reg!(v, Software, r"Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", dword 1);
            reg!(v, Software, r"Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", dword 1);
            reg!(v, DefaultUser, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", dword 0);
            reg!(v, DefaultUser, r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", dword 0);
            reg!(v, DefaultUser, r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", dword 0);
            reg!(v, DefaultUser, r"Software\Microsoft\Input\TIPC", "Enabled", dword 0);
            reg!(v, DefaultUser, r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", dword 1);
            reg!(v, DefaultUser, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", dword 1);
            reg!(v, DefaultUser, r"Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", dword 0);
        }
        "copilot" => {
            reg!(v, Software, r"Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", dword 1);
            reg!(v, DefaultUser, r"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", dword 1);
            reg!(v, Software, r"Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", dword 1);
            reg!(v, DefaultUser, r"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", dword 1);
            reg!(v, DefaultUser, ADV, "ShowCopilotButton", dword 0);
        }
        "widgets" => reg!(v, Software, r"Policies\Microsoft\Dsh", "AllowNewsAndInterests", dword 0),
        "search" => {
            reg!(v, DefaultUser, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", dword 1);
            reg!(v, Software, r"Policies\Microsoft\Windows\Windows Search", "AllowCloudSearch", dword 0);
            reg!(v, Software, r"Policies\Microsoft\Windows\Windows Search", "EnableDynamicContentInWSB", dword 0);
        }
        "onedrive" => reg!(v, Software, r"Policies\Microsoft\Windows\OneDrive", "DisableFileSyncNGSC", dword 1),
        "edge" => {
            reg!(v, Software, r"Policies\Microsoft\Edge", "HideFirstRunExperience", dword 1);
            for n in ["HubsSidebarEnabled", "ShowRecommendationsEnabled", "UserFeedbackAllowed", "SpotlightExperiencesAndRecommendationsEnabled"] {
                reg!(v, Software, r"Policies\Microsoft\Edge", n, dword 0);
            }
        }
        "oobe" => {
            reg!(v, Software, r"Policies\Microsoft\Windows\OOBE", "DisablePrivacyExperience", dword 1);
            reg!(v, DefaultUser, r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement", "ScoobeSystemSettingEnabled", dword 0);
            reg!(v, DefaultUser, CDM, "SubscribedContent-310093Enabled", dword 0);
            reg!(v, DefaultUser, ADV, "TaskbarMn", dword 0);
            reg!(v, Software, r"Policies\Microsoft\Windows\Windows Chat", "ChatIcon", dword 3);
        }
        "hardware-bypass" => {
            v.extend(setup_bypass_ops());
            for n in ["SV1", "SV2"] {
                reg!(v, DefaultUser, r"Control Panel\UnsupportedHardwareNotificationCache", n, dword 0);
            }
        }
        "reserved-storage" => reg!(v, Software, r"Microsoft\Windows\CurrentVersion\ReserveManager", "ShippedWithReserves", dword 0),
        "device-encryption" => reg!(v, System, r"{ControlSet}\Control\BitLocker", "PreventDeviceEncryption", dword 1),
        // the services of these two are switched off in build.rs (every control set)
        "disable-defender" => v.extend(defender_policy_ops()),
        "disable-windows-update" => v.extend(update_policy_ops()),
        _ => {}
    }
    v
}

/// Hardware-check bypass for both the installed system and the setup image (boot.wim index 2).
pub fn setup_bypass_ops() -> Vec<RegOp> {
    let mut v = Vec::new();
    for n in ["BypassCPUCheck", "BypassRAMCheck", "BypassSecureBootCheck", "BypassStorageCheck", "BypassTPMCheck"] {
        reg!(v, System, r"Setup\LabConfig", n, dword 1);
    }
    reg!(v, System, r"Setup\MoSetup", "AllowUpgradesWithUnsupportedTPMOrCPU", dword 1);
    v
}

/// Local-account OOBE.
pub fn local_account_ops() -> Vec<RegOp> {
    let mut v = Vec::new();
    reg!(v, Software, r"Microsoft\Windows\CurrentVersion\OOBE", "BypassNRO", dword 1);
    v
}

/// Services disabled in every control set by `disable-windows-update` / `disable-defender` (and Core).
pub const UPDATE_SERVICES: &[&str] = &["wuauserv", "UsoSvc", "WaaSMedicSvc"];
pub const DEFENDER_SERVICES: &[&str] = &["WinDefend", "WdNisSvc", "WdNisDrv", "WdFilter", "Sense"];

fn update_policy_ops() -> Vec<RegOp> {
    let mut v = Vec::new();
    reg!(v, Software, r"Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", dword 1);
    reg!(v, Software, r"Policies\Microsoft\Windows\WindowsUpdate", "DisableWindowsUpdateAccess", dword 1);
    v
}

fn defender_policy_ops() -> Vec<RegOp> {
    let mut v = Vec::new();
    reg!(v, Software, r"Policies\Microsoft\Windows Defender", "DisableAntiSpyware", dword 1);
    reg!(v, Software, r"Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", dword 1);
    v
}

/// Core's update and Defender policies.
pub fn core_policy_ops() -> Vec<RegOp> {
    let mut v = update_policy_ops();
    v.extend(defender_policy_ops());
    v
}

/// Files and directories (relative to the image root, `/` separated) for file options.
pub fn file_targets(id: &str) -> Vec<&'static str> {
    match id {
        "onedrive-files" => vec!["Windows/System32/OneDriveSetup.exe", "Windows/SysWOW64/OneDriveSetup.exe"],
        "edge-files" => vec![
            "Program Files/Microsoft/Edge", "Program Files/Microsoft/EdgeCore", "Program Files/Microsoft/EdgeUpdate",
            "Program Files/Microsoft/EdgeWebView", "Program Files (x86)/Microsoft/Edge", "Program Files (x86)/Microsoft/EdgeCore",
            "Program Files (x86)/Microsoft/EdgeUpdate", "Program Files (x86)/Microsoft/EdgeWebView",
            // System32\Microsoft-Edge-Webview and its WinSxS payload go with the Edge.Webview2.Platform
            // capability (build.rs); deleted here only if the image has no such capability
            "Windows/System32/Microsoft-Edge-Webview",
        ],
        _ => Vec::new(),
    }
}

/// Core keeps these WinSxS entries (metadata folders and runtime families), everything else is pruned.
pub const CORE_KEEP_DIRS: &[&str] = &["Catalogs", "FileMaps", "Fusion", "InstallTemp", "Manifests", "SettingsManifests", "Temp"];
pub const CORE_KEEP_PATTERN: &str =
    r"(?i)(?:common-controls|c\.\.-controls|gdiplus|isolationautomation|utomation\.proxystub|microsoft\.vc\d+\.crt|servicing|s\.\.(?:ngstack|stack))";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unique_and_resolvable() {
        let mut ids: Vec<_> = OPTIONS.iter().map(|o| o.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), OPTIONS.len());
        for mode in [Mode::Lean, Mode::Core] {
            for id in for_mode(mode) {
                assert!(option(id).is_some());
            }
        }
    }

    #[test]
    fn lean11_has_no_capabilities_core_has_features() {
        let t = for_mode(Mode::Lean);
        assert!(!t.contains(&"language-extras") && t.contains(&"edge-files") && t.contains(&"hardware-bypass"));
        let c = for_mode(Mode::Core);
        assert!(c.contains(&"language-extras") && c.contains(&"xps") && !c.contains(&"paint"));
    }

    #[test]
    fn app_matching_needs_exact_prefix() {
        let opt = option("xbox").unwrap();
        assert!(matches_app(opt, "Microsoft.XboxApp", "Microsoft.XboxApp_48.104.4001.0_x64__8wekyb3d8bbwe"));
        assert!(!matches_app(opt, "Microsoft.XboxApp", "Microsoft.XboxAppX_1_x64__8wekyb3d8bbwe"));
        assert!(!matches_app(opt, "Microsoft.Xbox", "Microsoft.Xbox_1_x64__8wekyb3d8bbwe"));
    }

    #[test]
    fn every_policy_has_registry_ops() {
        for o in OPTIONS.iter().filter(|o| o.kind == Kind::Policy && o.id != "cleanup") {
            assert!(!registry_ops(o.id).is_empty(), "{}", o.id);
        }
    }
}
