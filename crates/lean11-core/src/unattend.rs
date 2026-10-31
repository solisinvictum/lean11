//! autounattend.xml for the output ISO.
//! No account, password, product key, automatic logon or EULA acceptance is injected.

pub struct UnattendOptions {
    /// "amd64" or "arm64".
    pub arch: &'static str,
    pub compact: bool,
    pub local_account: bool,
    /// Commands run once at the first sign-in (FirstLogonCommands) with a description, e.g. the privacy
    /// settings that Windows setup resets or the software installation when SetupComplete did not run.
    pub first_logon: Vec<(&'static str, &'static str)>,
}

fn component(arch: &str, name: &str, body: &str) -> String {
    format!(
        "    <component name=\"{name}\" processorArchitecture=\"{arch}\" publicKeyToken=\"31bf3856ad364e35\" \
         language=\"neutral\" versionScope=\"nonSxS\">\n{body}    </component>\n"
    )
}

pub fn build(o: &UnattendOptions) -> String {
    let setup = format!(
        "      <ImageInstall>\n        <OSImage>\n          <Compact>{}</Compact>\n          <WillShowUI>OnError</WillShowUI>\n\
         \x20         <InstallFrom>\n            <MetaData wcm:action=\"add\">\n              <Key>/IMAGE/INDEX</Key>\n\
         \x20             <Value>1</Value>\n            </MetaData>\n          </InstallFrom>\n        </OSImage>\n      </ImageInstall>\n\
         \x20     <DynamicUpdate>\n        <Enable>false</Enable>\n      </DynamicUpdate>\n",
        o.compact
    );
    let mut oobe = String::from("      <OOBE>\n        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>\n");
    if o.local_account {
        oobe.push_str("        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n");
    }
    oobe.push_str("      </OOBE>\n");
    if !o.first_logon.is_empty() {
        let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
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
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<unattend xmlns=\"urn:schemas-microsoft-com:unattend\" \
         xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">\n  <settings pass=\"windowsPE\">\n{}  </settings>\n\
         \x20 <settings pass=\"oobeSystem\">\n{}  </settings>\n</unattend>\n",
        component(o.arch, "Microsoft-Windows-Setup", &setup).replace("\n    ", "\n    "),
        component(o.arch, "Microsoft-Windows-Shell-Setup", &oobe)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_expected_parts() {
        let x = build(&UnattendOptions { arch: "amd64", compact: true, local_account: true, first_logon: Vec::new() });
        assert!(!x.contains("FirstLogonCommands"));
        let f = build(&UnattendOptions { arch: "amd64", compact: true, local_account: true, first_logon: vec![("cmd /c a >b 2>&1", "lean11 privacy settings"), ("x", "lean11 software")] });
        assert!(f.contains("<CommandLine>cmd /c a &gt;b 2&gt;&amp;1</CommandLine>"), "{f}");
        assert!(x.contains("<Compact>true</Compact>"));
        assert!(x.contains("HideOnlineAccountScreens"));
        assert!(x.contains("processorArchitecture=\"amd64\""));
        assert!(x.contains("<Key>/IMAGE/INDEX</Key>"));
        let y = build(&UnattendOptions { arch: "arm64", compact: false, local_account: false, first_logon: Vec::new() });
        assert!(!y.contains("HideOnlineAccountScreens") && y.contains("arm64"));
    }
}
