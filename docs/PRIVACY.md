# Privacy settings

lean11 has its own catalog of privacy and telemetry settings (`crates/lean11-core/data/privacy.toml`, compiled
into the binary). The settings are applied offline to the image, so
the installed Windows starts with them. HKCU values go into the default profile, so they apply to every account
created on the installed system. Only the few values that Windows setup itself resets are written again after
setup (see below).

```
lean11 privacy list [--preset recommended|strict] [--json]
lean11 build Win11.iso --privacy recommended [--privacy-enable ID,...] [--privacy-disable ID,...]
```

In the TUI the settings are a step of their own after Components, grouped by category: Space toggles a
setting (on a category heading: its recommended and strict settings on, or all off), `r` / `s` / `n` select
the presets recommended, strict or none, `/` filters by title, id or category. Hidden settings are listed
grey with the reason. Selecting a setting that contradicts a chosen one turns the other off. Selecting
privacy settings builds as Custom (like `--ssh-key`), because the result differs from the presets.

## Levels

| Level | Meaning |
|---|---|
| recommended | No visible feature is lost. |
| strict | Costs a feature or convenience; the description names it. |
| optional | Special cases with side effects, never part of a preset. |

`--privacy recommended` selects all recommended settings, `--privacy strict` recommended and strict.

## Sources

Settings come from Microsoft's documentation and the ADMX templates of the image and of Edge, Chrome, Firefox and
Office. Candidates can be drafted with the developer tools in `scripts/privacy/` (`expand.py`, `draft.py`) and
checked against a real image with `lean11 privacy verify --catalog`; the shipped catalog is written by hand.

## Verification

Every setting has a `verified` field with the evidence for the current Windows 11 release:

- Registry values below a `Policies` key, and every other value that an ADMX policy defines, must match a
  policy in the image's own ADMX templates (`Windows/PolicyDefinitions`, plus the vendor templates of Edge,
  Chrome and Firefox with `--admx-dir`): key, value name, class (machine or user) and an allowed value. `lean11 privacy
  verify <extracted image>` checks this for the whole catalog.
- Services and scheduled tasks must exist in the image.
- Other registry values need a documented source or a test on an installed system, named in `evidence`:
  `doc` (Microsoft documents the value; the `verified` text names the article) and/or `vm` (read back after a
  fresh installation). `verify` reports them as `evidence` instead of `not-policy`.
- `lean11 privacy check-script` writes a PowerShell script that reads every value back on an installed
  system; the VM tests run it after setup.

Settings whose target no longer exists (services or tasks removed by Microsoft), policies written to the wrong
branch, or values outside the policy's range were dropped or corrected; the `note` field says so.

## Setup's privacy page

Windows setup asks for location, Find my device, diagnostic data, inking and typing, tailored experiences and
the advertising ID. With the Components option `oobe` (on in the Lean and Core presets) the policy
`DisablePrivacyExperience` skips that page. Where it is shown (Custom without `oobe`), the choices there do not
undo lean11's settings: each of the six has a policy in the catalog (`diagnostic-data-off`, `location-off` with
`app-access-location`, `find-my-device-off`, `inking-typing-personalization-off`, `tailored-experiences-off`,
`advertising-id-off`), and policies win over the switches. Verified in VM p8/p9 with every switch on.

## Logic

- `hidden_if` hides a setting when its component is gone or off: `defender-off`, `updates-off`,
  `edge-removed`, `onedrive-removed`, `option:<id>` (a Components option), `app-removed:<family>`.
- A setting whose registry writes are all done identically by the selected Components options is shown as
  covered and skipped.
- `conflicts` lists settings that contradict each other (mutual); a build with both is refused.
- Removing apps, capabilities and features is not part of this catalog: that is Components and Custom.
  Cleanup actions (history, caches) are left out as well, a fresh installation has nothing to clean.

## How changes are applied offline

| Operation | Offline change |
|---|---|
| `reg` under HKLM | SOFTWARE or SYSTEM hive (`CurrentControlSet` = the image's current control set) |
| `reg` under HKCU | default user profile (`Users/Default/NTUSER.DAT`): every account created later starts with it |
| `service` | `Start` in every control set; a service missing in the image is skipped, never created |
| `task` | Task Scheduler cache: the JobBucket's enabled flag in the `Triggers` value is cleared. Where the task XML exists (an already installed image) the XML gets `<Enabled>false</Enabled>`, and `Hash` (SHA-256 of the XML without BOM) and the JobBucket CRC-32 are updated the way `Disable-ScheduledTask` does. A fresh install image has no task XML files; setup writes them from the cache. |
| `hosts` | marked block in `Windows/System32/drivers/etc/hosts` |
| `after_setup = true` | written offline and again after setup, see below |
| `firewall_block` | outbound block rule for the program in the image's Windows Firewall rule store (`SharedAccess\Parameters\FirewallPolicy\FirewallRules`, every control set); rule id `lean11-<setting>-<path>`, switchable in Windows Defender Firewall |

Windows setup resets a few values after the image is applied: its security template (`Windows/INF/defltwk.inf`,
section Registry Values) sets `Lsa!RestrictAnonymous` and `ClearPageFileAtShutdown` to 0, and the language setup
recreates `HKCU\Control Panel\International\User Profile` in the default profile (VM p3, 25.10.2026). If the
privacy page of setup is answered with everything on (VM p8, 26.10.2026: `ProtectYourPC` 1), setup also sets the
location and presence device switches of the app permissions back to Allow; the AppPrivacy policies still deny
access, but the switches would show Allow. These five values carry `after_setup = true` and are written again by
three independent ways:

- `FirstLogonCommands` in lean11's `autounattend.xml` runs `Windows/Setup/Scripts/lean11-privacy.cmd` once at the
  first sign-in (elevated): HKLM values, HKCU values into the default profile and for the first account. Log:
  `Windows/Temp/lean11-privacy.log`.
- Active Setup (`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{6F1D5C2A-7B3E-4C11-9A1D-711CE0DE0011}`)
  runs `lean11-privacy-user.cmd` once for every account at its first sign-in (HKCU values).
- The local Group Policy (`Windows/System32/GroupPolicy/Machine/Registry.pol` and `gpt.ini`) writes the HKLM
  values on every start.

- With the SSH option (which runs from `SetupComplete.cmd` anyway) `SetupComplete.cmd` also runs
  `lean11-privacy.cmd setup` (HKLM and default profile), so accounts used over SSH before the first sign-in start
  with the repaired default profile. VM p5 showed the gap without it: the Administrator's profile, created by an
  SSH logon before the first sign-in, lacked the HKCU value (Active Setup only runs with Explorer).

Setup does not reset them again later (tested: the security policy refresh keeps a changed value). None of these
ways depends on `SetupComplete.cmd`, which Windows skips when setup uses an OEM product key.

The service profiles (`HKU\S-1-5-19`, `S-1-5-20`) do not exist in an install image; settings there use the
equivalent policy instead.

## Catalog format

```toml
[[category]]
id = "telemetry"
title = "Diagnostic data (telemetry)"
parent = "data-collection"

[[setting]]
id = "diagtrack-service-off"
category = "telemetry"
title = "Turn off the telemetry service (DiagTrack)"
description = "What it does, and what it costs for strict settings."
level = "recommended"            # recommended | strict | optional
hidden_if = ["defender-off"]     # optional
conflicts = ["other-id"]         # optional, mutual
sources = ["Microsoft Learn: <article>"]   # optional
verified = "evidence for 26H2"
evidence = ["doc", "vm"]           # optional, for values outside the ADMX templates
note = "what was dropped or corrected"   # optional
ops = [
  { reg = 'HKLM\SOFTWARE\Policies\...', name = "Value", dword = 0 },   # also qword, sz, expand_sz, multi_sz, binary
  { reg = 'HKCU\Software\...', name = "Value", delete = true },
  { reg = 'HKLM\SOFTWARE\...\Key', delete_key = true },
  { service = "DiagTrack", start = 4 },
  { task = '\Microsoft\Windows\...\Name' },
  { hosts = ["example.microsoft.com"] },
  { firewall_block = '%SystemRoot%\System32\Program.exe' },
  { reg = 'HKLM\SYSTEM\...', name = "Value", dword = 1, after_setup = true },   # setup resets it
]
```

The tests check ids, categories, conditions, mutual conflicts and every op.
