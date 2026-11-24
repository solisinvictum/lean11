//! autounattend.xml for the output ISO or USB stick.
//! No product key, automatic logon or EULA acceptance is injected. The windowsPE pass carries an empty
//! `<ProductKey><Key/>` like tiny11builder's answer file: with `InstallFrom` and no `UserData/ProductKey`
//! at all, Setup stops with "cannot read the <ProductKey> setting from the unattend answer file"; the empty
//! key skips the key page without supplying one.
//! With the setup answers (on by default) the oobeSystem pass also answers the region, keyboard, network
//! and privacy pages, and creates a local account when one is named (only then is a password written).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Answers to the questions Windows setup asks after the first reboot (OOBE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupAnswers {
    /// Answer the region, keyboard, network and privacy pages (default on).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Region and formats, e.g. `de-DE`; default: the language of the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Keyboard: a language tag (`de-CH`) or `0407:00000407`, several separated by `;`; default: the locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard: Option<String>,
    /// Local administrator account created by setup; without it setup asks for the account as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Password of that account (readable in the answer file); none or empty: no password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

fn yes() -> bool {
    true
}

impl Default for SetupAnswers {
    fn default() -> Self {
        SetupAnswers { enabled: true, locale: None, keyboard: None, account: None, password: None }
    }
}

/// Names Windows keeps for itself (English and the common localized ones).
const RESERVED_ACCOUNTS: &[&str] = &[
    "administrator", "administrador", "administrateur", "amministratore", "guest", "gast", "invité", "invitado", "invitato",
    "defaultaccount", "wdagutilityaccount", "defaultuser0", "system", "none", "everyone", "users", "administrators",
];

/// A language tag like `de-DE`, `en-GB` or `sr-Latn-RS`.
pub fn valid_locale(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    let alpha = |x: &str, n: std::ops::RangeInclusive<usize>| n.contains(&x.len()) && x.chars().all(|c| c.is_ascii_alphabetic());
    match p.as_slice() {
        [l, r] => alpha(l, 2..=3) && (alpha(r, 2..=2) || (r.len() == 3 && r.chars().all(|c| c.is_ascii_digit()))),
        [l, s, r] => alpha(l, 2..=3) && alpha(s, 4..=4) && alpha(r, 2..=2),
        _ => false,
    }
}

/// One or more keyboards: language tags or `LLLL:KKKKKKKK` (hex), separated by `;`.
pub fn valid_keyboard(s: &str) -> bool {
    let hex = |x: &str, n: usize| x.len() == n && x.chars().all(|c| c.is_ascii_hexdigit());
    !s.trim().is_empty()
        && s.split(';').map(str::trim).all(|k| valid_locale(k) || k.split_once(':').is_some_and(|(a, b)| hex(a, 4) && hex(b, 8)))
}

/// Characters XML 1.0 allows (others cannot be escaped).
fn xml_char(c: char) -> bool {
    matches!(c as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

/// Checks a password for the answer file: at most 127 UTF-16 units (Windows' limit), no control characters
/// and nothing XML cannot carry.
pub fn check_password(p: &str) -> Result<()> {
    if p.encode_utf16().count() > 127 || p.chars().any(|c| c.is_control() || !xml_char(c)) {
        bail!("The password must have at most 127 characters and no control characters.");
    }
    Ok(())
}

/// A local account name Windows accepts: 1 to 20 characters, none of `"/\[]:;|=,+*?<>@`, not only dots and
/// spaces, not a name Windows keeps for itself.
pub fn check_account(name: &str) -> Result<()> {
    // Windows counts UTF-16 units
    let n = name.encode_utf16().count();
    if n == 0 || n > 20 {
        bail!("The account name must have 1 to 20 characters.");
    }
    if let Some(c) = name.chars().find(|c| "\"/\\[]:;|=,+*?<>@".contains(*c) || c.is_control() || !xml_char(*c)) {
        bail!("The account name must not contain {c:?}.");
    }
    if name.chars().all(|c| c == '.' || c == ' ') || name.ends_with('.') {
        bail!("The account name must not end with a dot or consist of dots and spaces only.");
    }
    if RESERVED_ACCOUNTS.contains(&name.to_lowercase().as_str()) {
        bail!("{name} is a name Windows uses itself; choose another account name.");
    }
    Ok(())
}

impl SetupAnswers {
    /// Checks the given values (also when the answers are off, so a saved recipe stays valid).
    pub fn validate(&self) -> Result<()> {
        if let Some(l) = &self.locale {
            if !valid_locale(l) {
                bail!("{l} is not a language tag like de-DE or en-GB.");
            }
        }
        if let Some(k) = &self.keyboard {
            if !valid_keyboard(k) {
                bail!("{k} is not a keyboard like de-DE, de-CH or 0407:00000407 (several separated by ;).");
            }
        }
        if let Some(a) = &self.account {
            check_account(a)?;
        }
        if self.password.as_deref().is_some_and(|p| !p.is_empty()) && self.account.is_none() {
            bail!("A password needs an account name.");
        }
        if let Some(p) = &self.password {
            check_password(p)?;
        }
        Ok(())
    }

    /// The account has a password that ends up readable in the answer file.
    pub fn has_password(&self) -> bool {
        self.enabled && self.account.is_some() && self.password.as_deref().is_some_and(|p| !p.is_empty())
    }
}

/// The setup answers with the image's language filled in.
pub struct Answers {
    /// Display language: always the image's (Windows has no other one).
    pub ui_language: String,
    pub locale: String,
    pub keyboard: String,
    pub account: Option<String>,
    pub password: Option<String>,
}

impl Answers {
    /// `None` when the answers are off.
    pub fn resolve(a: &SetupAnswers, image_language: &str) -> Option<Self> {
        if !a.enabled {
            return None;
        }
        let ui = if image_language.is_empty() { "en-US" } else { image_language }.to_string();
        let locale = a.locale.clone().unwrap_or_else(|| ui.clone());
        let keyboard = a.keyboard.clone().unwrap_or_else(|| locale.clone());
        Some(Answers { ui_language: ui, locale, keyboard, account: a.account.clone(), password: a.password.clone().filter(|p| !p.is_empty()) })
    }
}

pub struct UnattendOptions {
    /// "amd64" or "arm64".
    pub arch: &'static str,
    pub compact: bool,
    pub local_account: bool,
    /// Commands run once at the first sign-in (FirstLogonCommands) with a description, e.g. the privacy
    /// settings that Windows setup resets or the software installation when SetupComplete did not run.
    pub first_logon: Vec<(&'static str, &'static str)>,
    /// Answers for the setup pages; `None` leaves them to the user.
    pub answers: Option<Answers>,
}

fn component(arch: &str, name: &str, body: &str) -> String {
    format!(
        "    <component name=\"{name}\" processorArchitecture=\"{arch}\" publicKeyToken=\"31bf3856ad364e35\" \
         language=\"neutral\" versionScope=\"nonSxS\">\n{body}    </component>\n"
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

pub fn build(o: &UnattendOptions) -> String {
    let setup = format!(
        "      <ImageInstall>\n        <OSImage>\n          <Compact>{}</Compact>\n          <WillShowUI>OnError</WillShowUI>\n\
         \x20         <InstallFrom>\n            <MetaData wcm:action=\"add\">\n              <Key>/IMAGE/INDEX</Key>\n\
         \x20             <Value>1</Value>\n            </MetaData>\n          </InstallFrom>\n        </OSImage>\n      </ImageInstall>\n\
         \x20     <UserData>\n        <ProductKey>\n          <Key/>\n        </ProductKey>\n      </UserData>\n\
         \x20     <DynamicUpdate>\n        <Enable>false</Enable>\n      </DynamicUpdate>\n",
        o.compact
    );
    let a = o.answers.as_ref();
    let account = a.and_then(|a| a.account.as_deref());
    let mut oobe = String::from("      <OOBE>\n        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>\n");
    if o.local_account || account.is_some() {
        oobe.push_str("        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n");
    }
    if a.is_some() {
        // network page, then the privacy pages (location, find my device, diagnostics, inking, offers): all off
        oobe.push_str("        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n        <ProtectYourPC>3</ProtectYourPC>\n");
    }
    if account.is_some() {
        oobe.push_str("        <HideLocalAccountScreen>true</HideLocalAccountScreen>\n");
    }
    oobe.push_str("      </OOBE>\n");
    if let (Some(name), Some(a)) = (account, a) {
        let pw = a.password.as_deref().unwrap_or("");
        oobe.push_str(&format!(
            "      <UserAccounts>\n        <LocalAccounts>\n          <LocalAccount wcm:action=\"add\">\n\
             \x20           <Name>{n}</Name>\n            <DisplayName>{n}</DisplayName>\n            <Group>Administrators</Group>\n\
             \x20           <Password>\n              <Value>{}</Value>\n              <PlainText>true</PlainText>\n            </Password>\n\
             \x20         </LocalAccount>\n        </LocalAccounts>\n      </UserAccounts>\n",
            esc(pw),
            n = esc(name)
        ));
    }
    if !o.first_logon.is_empty() {
        oobe.push_str("      <FirstLogonCommands>\n");
        for (n, (cmd, desc)) in o.first_logon.iter().enumerate() {
            oobe.push_str(&format!(
                "        <SynchronousCommand wcm:action=\"add\">\n          <Order>{}</Order>\n\
                 \x20         <CommandLine>{}</CommandLine>\n          <Description>{}</Description>\n\
                 \x20       </SynchronousCommand>\n",
                n + 1,
                esc(cmd),
                esc(desc)
            ));
        }
        oobe.push_str("      </FirstLogonCommands>\n");
    }
    let intl = a
        .map(|a| {
            component(
                o.arch,
                "Microsoft-Windows-International-Core",
                &format!(
                    "      <InputLocale>{}</InputLocale>\n      <SystemLocale>{}</SystemLocale>\n      <UILanguage>{}</UILanguage>\n      <UserLocale>{}</UserLocale>\n",
                    esc(&a.keyboard),
                    esc(&a.locale),
                    esc(&a.ui_language),
                    esc(&a.locale)
                ),
            )
        })
        .unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<unattend xmlns=\"urn:schemas-microsoft-com:unattend\" \
         xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">\n  <settings pass=\"windowsPE\">\n{}  </settings>\n\
         \x20 <settings pass=\"oobeSystem\">\n{}{}  </settings>\n</unattend>\n",
        component(o.arch, "Microsoft-Windows-Setup", &setup),
        intl,
        component(o.arch, "Microsoft-Windows-Shell-Setup", &oobe)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(answers: Option<Answers>) -> UnattendOptions {
        UnattendOptions { arch: "amd64", compact: true, local_account: true, first_logon: Vec::new(), answers }
    }

    #[test]
    fn contains_expected_parts() {
        let x = build(&opts(None));
        assert!(!x.contains("FirstLogonCommands"));
        let f = build(&UnattendOptions { first_logon: vec![("cmd /c a >b 2>&1", "lean11 privacy settings"), ("x", "lean11 software")], ..opts(None) });
        assert!(f.contains("<CommandLine>cmd /c a &gt;b 2&gt;&amp;1</CommandLine>"), "{f}");
        assert!(x.contains("<Compact>true</Compact>"));
        assert!(x.contains("HideOnlineAccountScreens"));
        assert!(x.contains("processorArchitecture=\"amd64\""));
        assert!(x.contains("<Key>/IMAGE/INDEX</Key>"));
        // Setup refuses an answer file with InstallFrom but without UserData/ProductKey
        assert!(x.contains("<UserData>\n        <ProductKey>\n          <Key/>\n        </ProductKey>\n      </UserData>"), "{x}");
        // without answers nothing of them
        assert!(!x.contains("International-Core") && !x.contains("ProtectYourPC") && !x.contains("UserAccounts"));
        let y = build(&UnattendOptions { arch: "arm64", compact: false, local_account: false, first_logon: Vec::new(), answers: None });
        assert!(!y.contains("HideOnlineAccountScreens") && y.contains("arm64"));
        assert!(roxmltree::Document::parse(&x).is_ok() && roxmltree::Document::parse(&f).is_ok());
    }

    #[test]
    fn setup_answers() {
        let mut s = SetupAnswers::default();
        let a = Answers::resolve(&s, "de-DE").unwrap();
        assert_eq!((a.locale.as_str(), a.keyboard.as_str(), a.ui_language.as_str()), ("de-DE", "de-DE", "de-DE"));
        let x = build(&opts(Some(a)));
        for want in [
            "name=\"Microsoft-Windows-International-Core\"",
            "<InputLocale>de-DE</InputLocale>",
            "<UserLocale>de-DE</UserLocale>",
            "<HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>",
            "<ProtectYourPC>3</ProtectYourPC>",
        ] {
            assert!(x.contains(want), "{want}\n{x}");
        }
        assert!(!x.contains("UserAccounts") && !x.contains("HideLocalAccountScreen"), "no account without a name");
        // locale, keyboard, account with a password that needs escaping
        s.locale = Some("en-GB".into());
        s.keyboard = Some("de-CH; 0407:00000407".into());
        s.account = Some("Tho&mas".into());
        s.password = Some("p<w>\"'&".into());
        s.validate().unwrap();
        assert!(s.has_password());
        let x = build(&opts(Answers::resolve(&s, "de-DE")));
        let doc = roxmltree::Document::parse(&x).unwrap();
        let text = |tag: &str| doc.descendants().find(|n| n.has_tag_name(tag)).and_then(|n| n.text()).map(str::to_string);
        assert_eq!(text("Name").as_deref(), Some("Tho&mas"));
        let pw = doc.descendants().find(|n| n.has_tag_name("Password")).and_then(|p| p.children().find(|c| c.has_tag_name("Value")));
        assert_eq!(pw.and_then(|v| v.text()), Some("p<w>\"'&"));
        assert_eq!(text("UILanguage").as_deref(), Some("de-DE"));
        assert_eq!(text("UserLocale").as_deref(), Some("en-GB"));
        assert_eq!(text("InputLocale").as_deref(), Some("de-CH; 0407:00000407"));
        assert!(x.contains("<HideLocalAccountScreen>true</HideLocalAccountScreen>"));
        // off: as before
        s.enabled = false;
        assert!(Answers::resolve(&s, "de-DE").is_none());
        assert!(!s.has_password());
        // old recipes without the field get the default (on)
        let d: SetupAnswers = serde_json::from_str("{}").unwrap();
        assert_eq!(d, SetupAnswers::default());
    }

    #[test]
    fn checks() {
        assert!(valid_locale("de-DE") && valid_locale("sr-Latn-RS") && valid_locale("es-419"));
        assert!(!valid_locale("de") && !valid_locale("de_DE") && !valid_locale("<x>-DE"));
        assert!(valid_keyboard("0407:00000407") && valid_keyboard("de-DE;en-US") && !valid_keyboard("0407") && !valid_keyboard(""));
        assert!(check_account("thomas").is_ok() && check_account("Thomas Ciesla").is_ok());
        assert!(check_password("ok pässwört").is_ok() && check_password("a\u{FFFE}").is_err() && check_password(&"😀".repeat(64)).is_err());
        for bad in ["", "Administrator", "gast", "a/b", "x@y", "abcdefghijklmnopqrstu", "...", "name.", "a\u{FFFF}", &"😀".repeat(11)] {
            assert!(check_account(bad).is_err(), "{bad}");
        }
        let pw_only = SetupAnswers { password: Some("x".into()), ..Default::default() };
        assert!(pw_only.validate().is_err());
        let empty_pw = SetupAnswers { account: Some("thomas".into()), password: Some(String::new()), ..Default::default() };
        assert!(empty_pw.validate().is_ok() && !empty_pw.has_password());
    }
}
