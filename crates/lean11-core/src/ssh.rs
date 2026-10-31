//! Optional remote access: an OpenSSH server and an authorized key injected into the image, so the
//! installed Windows is reachable over SSH right after setup.
//!
//! The key is placed for the built-in Administrator
//! (`administrators_authorized_keys`), which gives a fully elevated admin session over SSH; a helper
//! (`Invoke-AsSystem`) runs commands as SYSTEM for anything an administrator alone cannot touch.
//! The Administrator gets a random password that is discarded: only the key can log in.
//!
//! The work runs offline from `C:\Windows\Setup\Scripts\SetupComplete.cmd`, which Windows executes as
//! SYSTEM at the end of setup.

const KEY_TYPES: [&str; 8] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 != 0 {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 || b[..b.len() - pad].contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let mut n = 0u32;
        let mut k = 0;
        for &c in q {
            if c == b'=' {
                if !last {
                    return None;
                }
                n <<= 6;
            } else {
                n = (n << 6) | val(c)?;
                k += 1;
            }
        }
        // k data characters carry k - 1 bytes (4 -> 3, 3 -> 2, 2 -> 1)
        if k < 2 {
            return None;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..k - 1]);
    }
    Some(out)
}

/// Accepts one OpenSSH public key line (`.pub` format: type, base64 blob, optional comment) whose
/// blob is valid base64 and starts with the same algorithm name.
pub fn valid_authorized_key(key: &str) -> bool {
    let line = key.trim();
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return false;
    }
    let mut parts = line.split_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else { return false };
    if !KEY_TYPES.contains(&kind) {
        return false;
    }
    let Some(raw) = base64_decode(blob) else { return false };
    if raw.len() < 4 + kind.len() + 16 {
        return false;
    }
    let n = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    n == kind.len() && &raw[4..4 + n] == kind.as_bytes()
}

/// `SetupComplete.cmd` line; it is put before an existing script's commands (which may `exit`).
pub const SETUPCOMPLETE_LINE: &str = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SystemRoot%\\Setup\\Files\\lean11-ssh-setup.ps1\" >\"%SystemRoot%\\Temp\\lean11-ssh-setup.log\" 2>&1\r\n";

/// Combines our line with an existing `SetupComplete.cmd` (ours first; idempotent).
pub fn setupcomplete(existing: Option<&str>) -> String {
    setupcomplete_with(existing, SETUPCOMPLETE_LINE)
}

/// Puts `line` (CRLF-terminated) before the commands of an existing `SetupComplete.cmd`, which may end
/// with `exit`; a script that already has the line is returned unchanged.
pub fn setupcomplete_with(existing: Option<&str>, line: &str) -> String {
    match existing {
        // only an exact command line counts (a comment or a longer line containing it does not)
        Some(old) if old.lines().any(|l| l.trim().eq_ignore_ascii_case(line.trim())) => old.to_string(),
        Some(old) if !old.trim().is_empty() => format!("@echo off\r\n{line}{old}"),
        _ => format!("@echo off\r\n{line}"),
    }
}

/// PowerShell module installed machine-wide (so `Invoke-AsSystem` is available in each SSH session).
pub const MODULE_PSM1: &str = r#"# lean11 remote-access helpers (installed by the --ssh-key build option).
function Invoke-AsSystem {
    <#
      .SYNOPSIS
      Runs a command as NT AUTHORITY\SYSTEM and returns its output.
      SYSTEM can take ownership of anything, so this reaches TrustedInstaller-owned files and keys too.
      .EXAMPLE
      Invoke-AsSystem 'whoami /priv'
      .EXAMPLE
      Invoke-AsSystem -TimeoutSeconds 3600 'dism /online /cleanup-image /restorehealth'
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)] [string[]] $Command,
        [int] $TimeoutSeconds = 600
    )
    $cmd = $Command -join ' '
    $out = Join-Path $env:SystemRoot ("Temp\t11sys-{0}.log" -f [guid]::NewGuid())
    $wrapped = "try { $cmd *> `"$out`" } catch { `$_ | Out-File `"$out`" -Append }"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapped))
    $tn = "lean11-system-" + [guid]::NewGuid()
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -EncodedCommand $b64"
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $tn -Action $a -Principal $p -Force | Out-Null
    $done = $false
    try {
        Start-ScheduledTask -TaskName $tn
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        Start-Sleep -Milliseconds 300
        while ((Get-Date) -lt $deadline) {
            if ((Get-ScheduledTask -TaskName $tn).State -ne 'Running') { $done = $true; break }
            Start-Sleep -Milliseconds 200
        }
        if (-not $done) { Stop-ScheduledTask -TaskName $tn }
    } finally {
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false
    }
    if (Test-Path $out) { Get-Content $out; Remove-Item $out -Force }
    if (-not $done) { throw "Invoke-AsSystem: timed out after $TimeoutSeconds s, the command was stopped" }
}
Export-ModuleMember -Function Invoke-AsSystem
"#;

/// The offline setup script run by `SetupComplete.cmd` as SYSTEM.
pub fn setup_script() -> String {
    r#"$ErrorActionPreference = 'Stop'
Write-Output "lean11 SSH setup $(Get-Date -Format o)"
$files = "$env:SystemRoot\Setup\Files"
try {
    # 1. Install the OpenSSH server (and client) offline.
    $log = "$env:SystemRoot\Temp\lean11-openssh-msi.log"
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "`"$files\OpenSSH.msi`"", 'ADDLOCAL=ALL', '/qn', '/norestart', '/l*v', "`"$log`""
    if ($p.ExitCode -notin 0, 3010) { throw "OpenSSH installer failed with exit code $($p.ExitCode) (log: $log)" }
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { throw "the sshd service is missing after the installation" }

    # 2. sshd writes its default configuration on the first start; then enforce key-only login.
    $sshData = "$env:ProgramData\ssh"
    Start-Service sshd
    Stop-Service sshd
    $cfg = Join-Path $sshData 'sshd_config'
    if (-not (Test-Path $cfg)) {
        $def = "$env:ProgramFiles\OpenSSH\sshd_config_default"
        if (Test-Path $def) { Copy-Item $def $cfg } else { New-Item -ItemType File $cfg | Out-Null }
    }
    $t = Get-Content $cfg -Raw
    if ($null -eq $t) { $t = '' }
    foreach ($kv in @(@('PasswordAuthentication', 'no'), @('PubkeyAuthentication', 'yes'), @('KbdInteractiveAuthentication', 'no'))) {
        $re = '(?m)^#?\s*' + $kv[0] + '\b.*$'
        if ($t -match $re) { $t = $t -replace $re, ($kv[0] + ' ' + $kv[1]) }
        else { $t = ($kv[0] + ' ' + $kv[1] + "`r`n") + $t }
    }
    if ($t -notmatch '(?m)^\s*Match Group administrators') {
        $t += "`r`nMatch Group administrators`r`n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`r`n"
    }
    Set-Content $cfg $t -Encoding ascii

    # 3. The authorized key for administrators, readable only by Administrators and SYSTEM.
    $ak = Join-Path $sshData 'administrators_authorized_keys'
    Copy-Item "$files\lean11_authorized_key.pub" $ak -Force
    & icacls.exe $ak /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $ak ($LASTEXITCODE)" }

    # 4. Built-in Administrator (SID ...-500): enabled, random password nobody knows, so only the key logs in.
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' }
    if (-not $admin) { throw "built-in Administrator not found" }
    # Windows PowerShell 5.1 (.NET Framework): RNGCryptoServiceProvider, no RandomNumberGenerator.GetInt32
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 64
    $rng.GetBytes($buf)
    $chars = [char[]](33..126)
    $pw = -join ($buf | ForEach-Object { $chars[$_ % $chars.Length] }) + 'aA1!'
    Set-LocalUser -Name $admin.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -PasswordNeverExpires $true
    Remove-Variable pw
    Enable-LocalUser -Name $admin.Name

    # 5. PowerShell as the SSH shell, scripts allowed (client Windows defaults to Restricted, which
    #    blocks .ps1 files and the profile); full admin token for remote administrator logons.
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
        -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null

    # 6. Port 22 open in every firewall profile.
    Get-NetFirewallRule -Name 'lean11-sshd' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name 'lean11-sshd' -DisplayName 'OpenSSH Server (lean11)' `
        -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null

    # 7. Invoke-AsSystem for every PowerShell session (appended to the machine-wide profile).
    $mod = "$env:ProgramData\lean11"
    New-Item -ItemType Directory -Force $mod | Out-Null
    Copy-Item "$files\lean11.psm1" "$mod\lean11.psm1" -Force
    $prof = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1"
    $line = "Import-Module '$mod\lean11.psm1' -ErrorAction SilentlyContinue"
    if (-not ((Test-Path $prof) -and (Select-String -Path $prof -SimpleMatch $line -Quiet))) {
        Add-Content -Path $prof -Value $line -Encoding ascii
    }

    Set-Service sshd -StartupType Automatic
    Set-Service ssh-agent -StartupType Automatic
    Start-Service sshd
    if ((Get-Service sshd).Status -ne 'Running') { throw "sshd did not start" }
    Write-Output "lean11 SSH setup done"
} catch {
    Write-Output "lean11 SSH setup FAILED: $_"
    exit 1
}
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";

    #[test]
    fn key_validation() {
        assert!(valid_authorized_key(ED));
        assert!(valid_authorized_key(&format!("{ED}\n")));
        assert!(!valid_authorized_key("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"));
        assert!(!valid_authorized_key("ssh-ed25519 ================================"));
        assert!(!valid_authorized_key("ssh-ed25519"));
        assert!(!valid_authorized_key("not a key"));
        assert!(!valid_authorized_key(&format!("{ED}\nssh-ed25519 AAAA")));
        assert!(!valid_authorized_key(""));
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert!(base64_decode("a=bc").is_none());
    }

    #[test]
    fn setupcomplete_order() {
        assert!(setupcomplete(None).starts_with("@echo off\r\npowershell.exe"));
        let merged = setupcomplete(Some("@echo off\r\nexit /b 0\r\n"));
        assert!(merged.find("lean11-ssh-setup.ps1").unwrap() < merged.find("exit /b").unwrap());
        assert_eq!(setupcomplete(Some(&merged)), merged);
        let commented = format!("rem {SETUPCOMPLETE_LINE}");
        assert!(setupcomplete(Some(&commented)).starts_with(&format!("@echo off\r\n{SETUPCOMPLETE_LINE}")));
    }

    #[test]
    fn script_mentions_key_steps() {
        let s = setup_script();
        assert!(s.contains("OpenSSH.msi") && s.contains("administrators_authorized_keys"));
        assert!(s.contains("LocalAccountTokenFilterPolicy") && s.contains("LocalPort 22"));
        assert!(!s.contains("LimitBlankPasswordUse"));
        assert!(s.contains("Set-ExecutionPolicy Bypass -Scope LocalMachine"));
        assert!(MODULE_PSM1.contains("PositionalBinding = $false"));
        assert!(MODULE_PSM1.contains("Invoke-AsSystem"));
    }
}
