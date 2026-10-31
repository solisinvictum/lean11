//! Additional software: programs from `data/software.toml` added to the image and installed silently at
//! the end of setup.
//!
//! At build time every selected program is resolved in the winget catalog (latest version, the vendor's
//! download URL, SHA-256, silent switches; see `lean11_msdl::winget`), downloaded and verified, then placed
//! in `Windows\Setup\Files\Software` with a list (`software.json`). `SetupComplete.cmd` runs the install
//! script as SYSTEM: each installer is checked against its SHA-256 again, run with a time limit, logged to
//! `C:\Windows\Logs\lean11-software.log` and deleted. Scoop is per user: a Run entry sets it up at each
//! account's sign-in until it succeeded (it needs internet).

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

const DATA: &str = include_str!("../data/software.toml");
/// Scoop's official installer script.
pub const SCOOP_INSTALLER_URL: &str = "https://raw.githubusercontent.com/ScoopInstaller/Install/master/install.ps1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgramKind {
    #[default]
    Winget,
    Scoop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub kind: ProgramKind,
    #[serde(default)]
    pub winget: Vec<String>,
    #[serde(default)]
    pub extra_args: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    program: Vec<Program>,
}

pub fn catalog() -> &'static [Program] {
    static C: OnceLock<Vec<Program>> = OnceLock::new();
    C.get_or_init(|| parse(DATA).expect("data/software.toml is invalid"))
}

fn parse(text: &str) -> Result<Vec<Program>> {
    let f: File = toml::from_str(text).context("software catalog")?;
    for p in &f.program {
        if p.kind == ProgramKind::Winget && p.winget.is_empty() {
            bail!("software {}: no winget id", p.id);
        }
    }
    Ok(f.program)
}

pub fn program(id: &str) -> Option<&'static Program> {
    catalog().iter().find(|p| p.id == id)
}

/// Checks a selection: known ids, no duplicates.
pub fn validate(ids: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if program(id).is_none() {
            bail!("unknown software {id:?}; see `lean11 software list`");
        }
        if !seen.insert(id) {
            bail!("software {id:?} is selected twice");
        }
    }
    Ok(())
}

/// One staged installer as recorded in `software.json` and the build report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Staged {
    pub id: String,
    pub name: String,
    pub version: String,
    pub winget_id: String,
    pub url: String,
    pub sha256: String,
    /// msi, nullsoft, inno, burn, exe or scoop.
    pub kind: String,
    pub args: String,
    pub file: String,
}

/// FirstLogonCommands fallback: installs at the first sign-in when SetupComplete.cmd did not run (Windows skips
/// it when setup uses an OEM product key), in a visible window with a progress bar; the script does nothing when
/// SetupComplete already ran it.
pub const FIRST_LOGON_COMMAND: &str =
    r#"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\Setup\Files\Software\lean11-software.ps1" -Visible"#;

/// `SetupComplete.cmd` line for the install script.
pub const SETUPCOMPLETE_LINE: &str = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SystemRoot%\\Setup\\Files\\Software\\lean11-software.ps1\" >\"%SystemRoot%\\Temp\\lean11-software.out\" 2>&1\r\n";

/// Resolves, downloads and stages the selection into the image's `Windows\Setup\Files\Software`
/// (`files`), writes the list and the scripts. Returns what was staged.
pub fn stage(ids: &[String], arch: &str, lang: &str, files: &Path, log: &mut dyn FnMut(&str)) -> Result<Vec<Staged>> {
    validate(ids)?;
    fs::create_dir_all(files)?;
    let mut staged = Vec::new();
    let needs_index = ids.iter().any(|id| program(id).is_some_and(|p| p.kind == ProgramKind::Winget));
    let index = if needs_index { Some(lean11_msdl::winget::Index::load(log)?) } else { None };
    for id in ids {
        let p = program(id).ok_or_else(|| anyhow!("unknown software {id}"))?;
        match p.kind {
            ProgramKind::Winget => {
                let ids: Vec<&str> = p.winget.iter().map(String::as_str).collect();
                let ins = lean11_msdl::winget::resolve(index.as_ref().unwrap(), &ids, arch, lang)
                    .with_context(|| format!("cannot resolve {}", p.name))?;
                let path = lean11_msdl::winget::download(&ins, log)?;
                fs::copy(&path, files.join(&ins.file_name)).with_context(|| format!("cannot stage {}", ins.file_name))?;
                let args = if p.extra_args.is_empty() { ins.args.clone() } else { format!("{} {}", ins.args, p.extra_args) };
                log(&format!("{} {} ({}, {} installer, {})", p.name, ins.version, ins.id, ins.kind, ins.architecture));
                staged.push(Staged {
                    id: p.id.clone(),
                    name: p.name.clone(),
                    version: ins.version,
                    winget_id: ins.id,
                    url: ins.url,
                    sha256: ins.sha256,
                    kind: ins.kind,
                    args,
                    file: ins.file_name,
                });
            }
            ProgramKind::Scoop => {
                let script = lean11_msdl::winget::fetch_text(SCOOP_INSTALLER_URL).context("cannot download Scoop's installer")?;
                if !script.contains("scoop") {
                    bail!("{SCOOP_INSTALLER_URL} does not look like Scoop's installer");
                }
                fs::write(files.join("scoop-install.ps1"), &script)?;
                fs::write(files.join("scoop-user.ps1"), SCOOP_USER_SCRIPT)?;
                let sha = lean11_msdl::winget::sha256_hex(script.as_bytes());
                log(&format!("{}: installer script {} (set up at sign-in)", p.name, &sha[..12]));
                staged.push(Staged {
                    id: p.id.clone(),
                    name: p.name.clone(),
                    version: "latest at sign-in".into(),
                    winget_id: String::new(),
                    url: SCOOP_INSTALLER_URL.into(),
                    sha256: sha,
                    kind: "scoop".into(),
                    args: String::new(),
                    file: "scoop-install.ps1".into(),
                });
            }
        }
    }
    fs::write(files.join("software.json"), serde_json::to_string_pretty(&staged)?)?;
    fs::write(files.join("lean11-software.ps1"), INSTALL_SCRIPT)?;
    Ok(staged)
}

/// Run as SYSTEM from SetupComplete.cmd: installs every staged program.
pub const INSTALL_SCRIPT: &str = r#"param([switch]$Visible)
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = "$env:SystemRoot\Logs\lean11-software.log"
function Log($m) {
    "$(Get-Date -Format s) $m" | Out-File $log -Append -Encoding utf8
    if ($Visible) { Write-Host $m }
}
# Descendants of a process (bootstrappers start the real installer and may exit first). Windows keeps the
# parent id of orphans, so the tree is found from the first pid even after it exited.
function Get-Tree([int]$root) {
    $all = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
    $ids = @($root); $found = @()
    while ($ids.Count -gt 0) {
        $kids = @($all | Where-Object { $ids -contains $_.ParentProcessId -and $found -notcontains $_.ProcessId } | ForEach-Object { $_.ProcessId })
        $found += $kids; $ids = $kids
    }
    $found
}
# Waits for the installer (stopping its whole tree after $seconds), then up to $grace seconds for the processes
# it started (bootstrappers hand over to the real installer); helpers that keep running (Firefox leaves one
# behind) are left alone after that.
# Returns 'done', 'timeout' or the names of the processes still running.
function Wait-Tree($p, [int]$seconds, [int]$grace) {
    $deadline = (Get-Date).AddSeconds($seconds)
    $known = @()
    while (-not $p.HasExited) {
        $known = @(@($known) + @(Get-Tree $p.Id) | Select-Object -Unique)
        if ((Get-Date) -gt $deadline) {
            foreach ($id in @($p.Id) + $known) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
            return 'timeout'
        }
        Start-Sleep -Seconds 2
    }
    $until = (Get-Date).AddSeconds($grace)
    while ((Get-Date) -lt $until) {
        $known = @(@($known) + @(Get-Tree $p.Id) | Select-Object -Unique)
        if (@($known | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }).Count -eq 0) { return 'done' }
        Start-Sleep -Seconds 2
    }
    return (@($known | ForEach-Object { (Get-Process -Id $_ -ErrorAction SilentlyContinue).ProcessName } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
}
$done = Join-Path $dir 'software.done'
if (Test-Path $done) { exit 0 }  # SetupComplete ran it already (this is the first sign-in's fallback call)
if ($Visible) {
    $Host.UI.RawUI.WindowTitle = 'lean11: installing additional software'
    Write-Host 'lean11 is installing the additional software chosen for this image.'
    Write-Host 'Please leave this window open; it closes by itself when everything is installed.'
    Write-Host ''
}
Log "lean11 software installation ($env:USERNAME)"
# PowerShell 5.1 passes a JSON array on as one object: enumerate it explicitly
$list = @((Get-Content (Join-Path $dir 'software.json') -Raw | ConvertFrom-Json) | ForEach-Object { $_ })
$i = 0
foreach ($s in $list) {
    $i++
    if ($Visible) {
        Write-Progress -Activity 'lean11: installing additional software' -Status "$i of $($list.Count): $($s.name)" -PercentComplete ([int](100 * ($i - 1) / $list.Count))
    }
    try {
        if ($s.kind -eq 'scoop') {
            $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $dir 'scoop-user.ps1') + '"'
            New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'lean11-scoop' -Value $cmd -PropertyType String -Force | Out-Null
            Log "$($s.name): set up at each account's sign-in"
            continue
        }
        $f = Join-Path $dir $s.file
        # an earlier, interrupted run handled it (installers are deleted after their run)
        if (-not (Test-Path $f)) { Log "$($s.name): handled by an earlier run"; continue }
        $h = (Get-FileHash $f -Algorithm SHA256).Hash
        if ($h -ne $s.sha256) { Log "$($s.name): SHA-256 $h does not match $($s.sha256), not installed"; continue }
        Log "$($s.name) $($s.version): installing ($($s.kind) $($s.args))"
        if ($s.kind -eq 'msi') {
            $p = Start-Process msiexec.exe -PassThru -ArgumentList ('/i "' + $f + '" ' + $s.args + ' /l*v "' + "$env:SystemRoot\Logs\lean11-$($s.id)-msi.log" + '"')
        } else {
            $p = Start-Process $f -PassThru -ArgumentList $s.args
        }
        $null = $p.Handle  # keeps the handle, so ExitCode is available after the exit
        $w = Wait-Tree $p 1800 120
        if ($w -eq 'timeout') { Log "$($s.name): timed out after 30 min, its processes were stopped"; continue }
        $p.WaitForExit()
        $note = if ($w -and $w -ne 'done') { ", still running: $w" } else { '' }
        if ($p.ExitCode -in 0, 1641, 3010) { Log "$($s.name): done (exit $($p.ExitCode)$note)" }
        else { Log "$($s.name): failed with exit code $($p.ExitCode)$note" }
    } catch {
        Log "$($s.name): $_"
    } finally {
        if ($s.kind -ne 'scoop') { Remove-Item (Join-Path $dir $s.file) -Force -ErrorAction SilentlyContinue }
    }
}
New-Item -ItemType File -Force $done | Out-Null
Log "finished"
if ($Visible) {
    Write-Progress -Activity 'lean11: installing additional software' -Completed
    Write-Host ''
    Write-Host "Done. Log: $log. This window closes in 15 seconds."
    Start-Sleep -Seconds 15
}
"#;

/// Run at each sign-in (HKLM Run, the user's own non-elevated session) until Scoop is set up.
pub const SCOOP_USER_SCRIPT: &str = r#"$state = Join-Path $env:LOCALAPPDATA 'lean11'
$marker = Join-Path $state 'scoop.done'
if (Test-Path $marker) { exit 0 }
New-Item -ItemType Directory -Force $state | Out-Null
$log = Join-Path $state 'scoop-install.log'
if (Test-Path (Join-Path $env:USERPROFILE 'scoop\shims\scoop.ps1')) { New-Item -ItemType File -Force $marker | Out-Null; exit 0 }
try {
    "$(Get-Date -Format s) installing Scoop" | Out-File $log -Append -Encoding utf8
    & (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'scoop-install.ps1') *>&1 | Out-File $log -Append -Encoding utf8
    if (Test-Path (Join-Path $env:USERPROFILE 'scoop\shims\scoop.ps1')) { New-Item -ItemType File -Force $marker | Out-Null }
} catch {
    "$(Get-Date -Format s) $_" | Out-File $log -Append -Encoding utf8
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_catalog_parses() {
        let c = catalog();
        assert!(c.len() >= 14);
        let mut ids: Vec<&str> = c.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), c.len(), "duplicate software ids");
    }

    #[test]
    fn validation() {
        assert!(validate(&["vlc".into(), "scoop".into()]).is_ok());
        assert!(validate(&["nope".into()]).is_err());
        assert!(validate(&["vlc".into(), "vlc".into()]).is_err());
    }
}
