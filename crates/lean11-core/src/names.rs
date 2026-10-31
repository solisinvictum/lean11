//! Human-readable names for inventory items. Features, capabilities, packages and services carry their
//! names in the image (manifests, registry); provisioned and system apps get the names Windows shows
//! in Start and Settings from the tables below; everything else falls back to a cleaned-up identity.

/// Provisioned Appx packages by package family name prefix (`Microsoft.BingNews`).
const APPS: &[(&str, &str)] = &[
    ("Clipchamp.Clipchamp", "Clipchamp video editor"),
    ("Microsoft.549981C3F5F10", "Cortana"),
    ("Microsoft.ApplicationCompatibilityEnhancements", "Application Compatibility Enhancements"),
    ("Microsoft.AV1VideoExtension", "AV1 Video Extension (codec)"),
    ("Microsoft.AVCEncoderVideoExtension", "AVC Encoder Video Extension (codec)"),
    ("Microsoft.BingNews", "Microsoft News (Bing News)"),
    ("Microsoft.BingSearch", "Bing Search"),
    ("Microsoft.BingWeather", "Weather (Bing Weather)"),
    ("Microsoft.Copilot", "Copilot"),
    ("Microsoft.DesktopAppInstaller", "App Installer (winget)"),
    ("Microsoft.Edge.GameAssist", "Edge Game Assist"),
    ("Microsoft.GamingApp", "Xbox app"),
    ("Microsoft.GetHelp", "Get Help"),
    ("Microsoft.Getstarted", "Tips"),
    ("Microsoft.HEIFImageExtension", "HEIF Image Extension (codec)"),
    ("Microsoft.HEVCVideoExtension", "HEVC Video Extension (codec)"),
    ("Microsoft.Microsoft3DViewer", "3D Viewer"),
    ("Microsoft.MicrosoftEdge.Stable", "Microsoft Edge"),
    ("Microsoft.MicrosoftJournal", "Journal"),
    ("Microsoft.MicrosoftOfficeHub", "Microsoft 365 Copilot (Office hub)"),
    ("Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection"),
    ("Microsoft.MicrosoftStickyNotes", "Sticky Notes"),
    ("Microsoft.MixedReality.Portal", "Mixed Reality Portal"),
    ("Microsoft.MPEG2VideoExtension", "MPEG-2 Video Extension (codec)"),
    ("Microsoft.MSPaint", "Paint 3D"),
    ("Microsoft.Office.OneNote", "OneNote"),
    ("Microsoft.OneDriveSync", "OneDrive"),
    ("Microsoft.OutlookForWindows", "Outlook (new)"),
    ("Microsoft.Paint", "Paint"),
    ("Microsoft.People", "People"),
    ("Microsoft.PowerAutomateDesktop", "Power Automate"),
    ("Microsoft.RawImageExtension", "Raw Image Extension (codec)"),
    ("Microsoft.ScreenSketch", "Snipping Tool"),
    ("Microsoft.SecHealthUI", "Windows Security app"),
    ("Microsoft.SkypeApp", "Skype"),
    ("Microsoft.StartExperiencesApp", "Start experiences (Start menu web content)"),
    ("Microsoft.StorePurchaseApp", "Store purchase app"),
    ("Microsoft.Todos", "Microsoft To Do"),
    ("Microsoft.VP9VideoExtensions", "VP9 Video Extensions (codec)"),
    ("Microsoft.Wallet", "Wallet"),
    ("Microsoft.WebMediaExtensions", "Web Media Extensions (Ogg, Vorbis, Theora codecs)"),
    ("Microsoft.WebpImageExtension", "WebP Image Extension (codec)"),
    ("Microsoft.Whiteboard", "Whiteboard"),
    ("Microsoft.WidgetsPlatformRuntime", "Widgets platform runtime"),
    ("Microsoft.Windows.Ai.Copilot.Provider", "Copilot provider"),
    ("Microsoft.Windows.DevHome", "Dev Home"),
    ("Microsoft.Windows.Photos", "Photos"),
    ("Microsoft.WindowsAlarms", "Clock (Alarms & Clock)"),
    ("Microsoft.WindowsCalculator", "Calculator"),
    ("Microsoft.WindowsCamera", "Camera"),
    ("microsoft.windowscommunicationsapps", "Mail and Calendar"),
    ("Microsoft.WindowsFeedbackHub", "Feedback Hub"),
    ("Microsoft.WindowsMaps", "Maps"),
    ("Microsoft.WindowsNotepad", "Notepad"),
    ("Microsoft.WindowsSoundRecorder", "Sound Recorder"),
    ("Microsoft.WindowsStore", "Microsoft Store"),
    ("Microsoft.WindowsTerminal", "Windows Terminal"),
    ("Microsoft.Xbox.TCUI", "Xbox Live in-game overlay"),
    ("Microsoft.XboxApp", "Xbox Console Companion"),
    ("Microsoft.XboxGameOverlay", "Xbox Game Bar plugin"),
    ("Microsoft.XboxGamingOverlay", "Xbox Game Bar"),
    ("Microsoft.XboxIdentityProvider", "Xbox Identity Provider (sign-in)"),
    ("Microsoft.XboxSpeechToTextOverlay", "Xbox game chat speech-to-text"),
    ("Microsoft.YourPhone", "Phone Link"),
    ("Microsoft.ZuneMusic", "Media Player"),
    ("Microsoft.ZuneVideo", "Movies & TV"),
    ("MicrosoftCorporationII.MicrosoftFamily", "Family Safety"),
    ("MicrosoftCorporationII.QuickAssist", "Quick Assist"),
    ("MicrosoftWindows.Client.WebExperience", "Widgets (Windows Web Experience Pack)"),
    ("MicrosoftWindows.CrossDevice", "Cross Device Experience Host (phone integration)"),
    ("MicrosoftTeams", "Microsoft Teams (classic)"),
    ("MSTeams", "Microsoft Teams"),
    ("AppUp.IntelManagementandSecurityStatus", "Intel Management and Security Status"),
    ("DolbyLaboratories.DolbyAccess", "Dolby Access"),
    ("DolbyLaboratories.DolbyDigitalPlusDecoderOEM", "Dolby Digital Plus decoder"),
];

/// Built-in apps under Windows\SystemApps by folder name prefix (without the publisher id).
const SYSTEM_APPS: &[(&str, &str)] = &[
    ("Microsoft.AAD.BrokerPlugin", "Work or school account sign-in (Entra ID broker)"),
    ("Microsoft.AccountsControl", "Account sign-in dialogs"),
    ("Microsoft.AIFabric.CBS", "AI Fabric (on-device AI runtime)"),
    ("Microsoft.AsyncTextService", "Messaging text service"),
    ("Microsoft.BioEnrollment", "Windows Hello enrollment"),
    ("microsoft.creddialoghost", "Credential dialog"),
    ("Microsoft.ECApp", "Eye Control"),
    ("Microsoft.LockApp", "Lock screen"),
    ("Microsoft.MicrosoftEdgeDevToolsClient", "Edge DevTools client"),
    ("Microsoft.UI.Xaml.CBS", "WinUI/XAML framework"),
    ("Microsoft.Win32WebViewHost", "Web view host for desktop apps"),
    ("Microsoft.Windows.AddSuggestedFoldersToLibraryDialog", "Add suggested folders to library dialog"),
    ("Microsoft.Windows.AppRep.ChxApp", "SmartScreen (app reputation)"),
    ("Microsoft.Windows.AppResolverUX", "\"Open with\" app picker"),
    ("Microsoft.Windows.AssignedAccessLockApp", "Kiosk mode lock screen"),
    ("Microsoft.Windows.AugLoop.CBS", "Augmentation Loop (Office AI services)"),
    ("Microsoft.Windows.CapturePicker", "Screen capture picker"),
    ("Microsoft.Windows.CloudExperienceHost", "Setup and sign-in screens (OOBE, Microsoft account)"),
    ("Microsoft.Windows.ContentDeliveryManager", "Content delivery (Spotlight, suggestions, ads)"),
    ("Microsoft.Windows.FileExplorer", "File Explorer (modern parts)"),
    ("Microsoft.Windows.FilePicker", "File picker"),
    ("microsoft.windows.narratorquickstart", "Narrator quick start"),
    ("Microsoft.Windows.OOBENetworkCaptivePortal", "Setup: network captive portal"),
    ("Microsoft.Windows.OOBENetworkConnectionFlow", "Setup: network connection"),
    ("Microsoft.Windows.ParentalControls", "Parental controls"),
    ("Microsoft.Windows.PeopleExperienceHost", "People bar"),
    ("Microsoft.Windows.PinningConfirmationDialog", "Pin to taskbar confirmation"),
    ("Microsoft.Windows.PrintQueueActionCenter", "Print queue"),
    ("Microsoft.Windows.SecureAssessmentBrowser", "Take a Test (secure assessment browser)"),
    ("Microsoft.Windows.SecHealthUI", "Windows Security"),
    ("Microsoft.Windows.StartMenuExperienceHost", "Start menu"),
    ("Microsoft.Windows.XGpuEjectDialog", "External GPU eject dialog"),
    ("Microsoft.WindowsAppRuntime.CBS", "Windows App SDK runtime"),
    ("Microsoft.XboxGameCallableUI", "Xbox in-game UI"),
    ("MicrosoftWindows.Client.AIX", "AI experiences (Click to Do and others)"),
    ("MicrosoftWindows.Client.CBS", "Windows shell components (taskbar, search, Start)"),
    ("MicrosoftWindows.Client.CoreAI", "Windows AI core"),
    ("MicrosoftWindows.Client.Core", "Windows shell core"),
    ("MicrosoftWindows.Client.FileExp", "File Explorer extensions"),
    ("MicrosoftWindows.Client.OOBE", "Setup (OOBE) screens"),
    ("MicrosoftWindows.Client.Photon", "Shell components (Photon)"),
    ("MicrosoftWindows.UndockedDevKit", "Shell components (undocked dev kit)"),
    ("ParentalControls", "Parental controls"),
    ("Shared", "Shared files of the system apps"),
    ("ShellExperienceHost", "Shell experience host (notifications, quick settings, calendar flyout)"),
    ("SxS", "Side-by-side files of the system apps"),
    ("Windows.CBSPreview", "Barcode scanner camera preview"),
    ("Windows.PrintDialog", "Print dialog"),
];

fn lookup(table: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    // longest matching prefix, so Client.Core does not catch Client.CoreAI
    table
        .iter()
        .filter(|(k, _)| {
            key.get(..k.len()).is_some_and(|p| p.eq_ignore_ascii_case(k))
                && key.get(k.len()..).is_some_and(|rest| rest.chars().next().is_none_or(|c| !c.is_ascii_alphanumeric()))
        })
        .max_by_key(|(k, _)| k.len())
        .map(|(_, v)| *v)
}

/// "Microsoft.WindowsCalculator" → "Windows Calculator": vendor prefixes off, CamelCase and dots split.
pub fn humanize(id: &str) -> String {
    let mut s = id;
    for pre in ["MicrosoftCorporationII.", "MicrosoftWindows.", "Microsoft.Windows.", "Microsoft.", "microsoft.windows.", "microsoft."] {
        if let Some(r) = s.strip_prefix(pre) {
            s = r;
            break;
        }
    }
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if matches!(c, '.' | '-' | '_') {
            if !out.ends_with(' ') {
                out.push(' ');
            }
            continue;
        }
        if i > 0 && c.is_uppercase() {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev.is_lowercase() || (prev.is_uppercase() && next_lower) || prev.is_ascii_digit() {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// Microsoft's pseudo-localization ("VβŞÇЃĪΡŦ", "Ŋóτēрằď (šýŝτèм)") left in some manifests: most
/// letters outside ASCII although the text is meant to be English.
pub fn looks_pseudo(s: &str) -> bool {
    let letters: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    let foreign = letters.iter().filter(|c| !c.is_ascii()).count();
    !letters.is_empty() && foreign * 3 >= letters.len()
}

/// Provisioned app by its family name (`Microsoft.BingNews`).
pub fn app(family: &str) -> String {
    lookup(APPS, family).map(str::to_string).unwrap_or_else(|| humanize(family))
}

/// System app by folder name (`Microsoft.LockApp_cw5n1h2txyewy`).
pub fn system_app(folder: &str) -> String {
    let base = folder.rsplit_once('_').map(|(b, _)| b).unwrap_or(folder);
    lookup(SYSTEM_APPS, base).map(str::to_string).unwrap_or_else(|| humanize(base))
}

/// Parts of a WinSxS folder name `arch_name_token_version_lang_hash`.
pub struct Payload<'a> {
    pub arch: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub lang: &'a str,
}

pub fn split_payload(folder: &str) -> Option<Payload<'_>> {
    let parts: Vec<&str> = folder.rsplitn(5, '_').collect();
    // rsplitn: [hash, lang, version, token, arch_name]
    if parts.len() != 5 || parts[3].len() != 16 {
        return None;
    }
    let (arch, name) = parts[4].split_once('_')?;
    Some(Payload { arch, name, version: parts[2], lang: parts[1] })
}

/// Readable WinSxS component: full component name (from the manifest when the folder name is
/// shortened with ".."), "Microsoft-Windows-" off, 32-bit and language marked.
pub fn payload(folder: &str, full: Option<(&str, &str)>) -> String {
    let Some(p) = split_payload(folder) else { return folder.to_string() };
    let mut name = full.map(|f| f.0).unwrap_or(p.name).to_string();
    // the folder's language is shortened too ("qps..ocm"); the full culture comes with the name
    let lang = match full {
        Some((_, c)) if p.lang.contains("..") && !c.is_empty() => c,
        _ => p.lang,
    };
    for pre in ["microsoft-windows-", "Microsoft-Windows-"] {
        if name.len() > pre.len() && name.get(..pre.len()).is_some_and(|p| p.eq_ignore_ascii_case(pre)) {
            name = name[pre.len()..].to_string();
        }
    }
    let mut extra = Vec::new();
    match p.arch {
        "wow64" | "x86" => extra.push("32-bit".to_string()),
        "msil" => extra.push(".NET".to_string()),
        _ => {}
    }
    if lang != "none" {
        extra.push(lang.to_string());
    }
    if extra.is_empty() { name } else { format!("{name} ({})", extra.join(", ")) }
}

/// Short technical id for the second column: version, publisher hash and empty fields dropped.
pub fn short_id(kind: crate::inventory::Kind, identity: &str) -> String {
    use crate::inventory::Kind;
    match kind {
        // Name_Version_Arch_ResourceId_PublisherId → Name
        Kind::ProvisionedApp => identity.split('_').next().unwrap_or(identity).to_string(),
        Kind::SystemApp => identity.rsplit_once('_').map(|(b, _)| b).unwrap_or(identity).to_string(),
        // Name~Token~Arch~Lang~Version → Name (lang) version
        Kind::Package => {
            let f: Vec<&str> = identity.split('~').collect();
            match f.as_slice() {
                [name, _, _, lang, ver] => {
                    if lang.is_empty() { format!("{name} {ver}") } else { format!("{name} {lang} {ver}") }
                }
                _ => identity.to_string(),
            }
        }
        // Name~~~Lang~Version → Name (lang)
        Kind::Capability => {
            let f: Vec<&str> = identity.split('~').collect();
            match f.as_slice() {
                [name, _, _, lang, _] if !lang.is_empty() => format!("{name} {lang}"),
                [name, ..] => name.to_string(),
                _ => identity.to_string(),
            }
        }
        Kind::ComponentPayload => match split_payload(identity) {
            Some(p) => format!("{}_{} {}", p.arch, p.name, p.version),
            None => identity.to_string(),
        },
        Kind::Feature | Kind::Service => identity.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_and_system_apps() {
        assert_eq!(app("Microsoft.BingWeather"), "Weather (Bing Weather)");
        assert_eq!(app("Microsoft.HEVCVideoExtension"), "HEVC Video Extension (codec)");
        assert_eq!(app("Contoso.SomeNewApp"), "Contoso Some New App");
        assert_eq!(system_app("MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy"), "Windows AI core");
        assert_eq!(system_app("MicrosoftWindows.Client.Core_cw5n1h2txyewy"), "Windows shell core");
        assert_eq!(system_app("Microsoft.WindowsAppRuntime.CBS.2_8wekyb3d8bbwe"), "Windows App SDK runtime");
        assert_eq!(system_app("Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy"), "Start menu");
    }

    #[test]
    fn non_ascii_names_do_not_panic() {
        let _ = app(&"é".repeat(20));
        let _ = system_app(&format!("{}_x", "ü".repeat(30)));
        let _ = payload("amd64_x_31bf3856ad364e35_1.0_none_0123456789abcdef", Some((&format!("x{}", "é".repeat(10)), "")));
    }

    #[test]
    fn pseudo_localization() {
        for p in ["VβŞÇЃĪΡŦ", "Ŋóτēрằď (šýŝτèм)", "Ŝτëφş Ŗéçøŕďэŕ", "ШМĮ€", "Ẅïńďôŵŝ ΡöŵèŗŜĥéļļ ĮŞĚ"] {
            assert!(looks_pseudo(p), "{p}");
        }
        for n in ["VBSCRIPT", "Windows PowerShell ISE", "Notepad (system)", "Über die Datenträgerverwaltung", "WMIC"] {
            assert!(!looks_pseudo(n), "{n}");
        }
    }

    #[test]
    fn humanize_ids() {
        assert_eq!(humanize("Microsoft.WindowsCalculator"), "Windows Calculator");
        assert_eq!(humanize("Microsoft.AV1VideoExtension"), "AV1 Video Extension");
        assert_eq!(humanize("Microsoft.HEVCVideoExtension"), "HEVC Video Extension");
    }

    #[test]
    fn payloads() {
        let f = "amd64_hyperv-compute-cont..ce-shared.resources_31bf3856ad364e35_10.0.26100.1_de-de_bf6359c60ccb4ef1";
        assert_eq!(payload(f, Some(("hyperv-compute-container-service-shared.resources", "de-DE"))), "hyperv-compute-container-service-shared.resources (de-de)");
        let q = "amd64_microsoft-windows-cdosys.resources_31bf3856ad364e35_10.0.26100.1_qps..ocm_b63798b2d3a608d1";
        assert_eq!(payload(q, Some(("Microsoft-Windows-cdosys.resources", "qps-plocm"))), "cdosys.resources (qps-plocm)");
        assert_eq!(payload("wow64_microsoft-windows-audio_31bf3856ad364e35_10.0.26100.1_none_0123456789abcdef", None), "audio (32-bit)");
        assert_eq!(short_id(crate::inventory::Kind::ComponentPayload, f), "amd64_hyperv-compute-cont..ce-shared.resources 10.0.26100.1");
        assert_eq!(
            short_id(crate::inventory::Kind::Package, "Microsoft-Windows-Client-LanguagePack-Package~31bf3856ad364e35~amd64~de-DE~10.0.26100.9457"),
            "Microsoft-Windows-Client-LanguagePack-Package de-DE 10.0.26100.9457"
        );
        assert_eq!(short_id(crate::inventory::Kind::Capability, "Language.OCR~~~de-DE~0.0.1.0"), "Language.OCR de-DE");
        assert_eq!(short_id(crate::inventory::Kind::ProvisionedApp, "Microsoft.BingNews_4.11.6001.0_neutral_~_8wekyb3d8bbwe"), "Microsoft.BingNews");
    }
}
