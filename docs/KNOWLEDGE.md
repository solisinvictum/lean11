# Knowledge base

`crates/lean11-core/data/knowledge.toml` (compiled into the binary) rates catalog options, privacy settings and
inventory items and says precisely what each one is and what removing or disabling it does. The TUI shows the
rating as a colored dot and the text in the description box; `lean11 inventory --json` and
`lean11 privacy list --json` can carry it too.

## Ratings

| Rating | Dot | Meaning |
|---|---|---|
| `safe` | green | Setup and Windows keep working; only the named item goes, nothing else depends on it. |
| `limited` | yellow | Setup and Windows keep working, but other functions or apps that build on it are impaired. |
| `breaks` | red | Setup or Windows itself fails, or the PC is unusable (no keyboard or mouse input). Only with proof: a test install, Microsoft's documentation, or lean11's servicing planning refusing the removal. |
| (no entry) | grey | Not rated yet. |

Privacy settings without an entry take their rating from their level: recommended is safe, strict and optional
are limited.

## Entry format

```toml
[[entry]]
kind = "service"                 # option | privacy | provisioned-app | system-app | feature | capability |
                                 # package | service | component-payload
match = ["DiagTrack"]            # case-insensitive, `*` = any text; against the identity or the readable name
rating = "safe"                  # safe | limited | breaks
what = "What the item is."
effect = "What removing or disabling it does, including what stops working."
verified = "Evidence: documentation, analysis of the image, test install (VM name)."
```

The most specific match wins: an exact pattern beats a glob, a longer literal beats a shorter one, so a general
rule (`*servicingstack*`) can be refined by single entries.

## How entries are made

1. Documentation first (Microsoft Learn, Microsoft support), then the image itself: what the package, feature or
   service contains and what depends on it (manifests, service dependencies, registrations).
2. Where that does not settle it: a test install. Items are removed in groups; when a group breaks setup or
   Windows, it is split until the cause is found. `breaks` is only set with such a proof.
3. `verified` names the evidence, so every rating can be checked again for a new Windows release.

## Test installs

Each test builds an image with the items to test, installs it unattended in a QEMU VM (q35, AHCI disk, e1000e
network, no USB) and runs a health check after the first sign-in. Its 14 checks: Explorer, Start menu host,
search host, Settings starts, Notepad, core services, automatic services running, network, AppX deployment, WMI,
scheduled tasks, component store, no crash dumps, no app crashes since boot. A test whose setup or first
sign-in never completes counts as broken.

Tests with several VMs at once can make setup's OOBE fail on its own (a script load timeout of
CloudExperienceHost). Every red result from such a run was therefore repeated with no other test VM running;
only results that hold up there are red (FileCrypt, for example, was not).

Red so far (26H2), each proven alone or by planning:

- System apps: CloudExperienceHost, Client.OOBE and the OOBE network apps (setup's OOBE does not start),
  StartMenuExperienceHost (no Start menu), UI.Xaml.CBS (grey desktop, shell crashes), Client.Core and
  UndockedDevKit (OOBE fails, no account is created).
- Services that setup needs: AppReadiness, SystemEventsBroker, Schedule, TimeBrokerSvc, RpcSs, DcomLaunch,
  RpcEptMapper, LSM, ProfSvc, UserManager, CoreMessagingRegistrar, StateRepository, BrokerInfrastructure and
  AppXSvc and EventLog (setup or the first sign-in hangs).
- Drivers without which Windows does not boot (bluescreen): ACPI, pci, disk, partmgr, mountmgr, volmgr, volume,
  Wdf01000, the disk and volume filters EhStorClass, fvevol, iorate, rdyboost and volsnap, CNG, KSecDD, Npfs,
  DXGKrnl, WindowsTrustedRT and Wof; the storage controller drivers (storahci, stornvme and 37 more), because
  the one the system disk uses is needed to boot and an image does not know its target hardware.
- Drivers without which setup's OOBE or the first sign-in fails: ahcache, KSecPkg, pdc, and srv2 or srvnet
  on their own (the whole SMB group, server and client drivers together, works).
- Drivers without which the PC cannot be used (decision of 30.10.2026): kbdclass, mouclass, i8042prt, the USB
  host stack (USBXHCI, USBHUB3, usbhub, Ucx01000), the HID class drivers, BasicDisplay and BasicRender, and the
  Device Install service (DeviceInstall, decision of 31.10.2026: devices such as the network adapter and possibly
  USB keyboards and mice stay without a driver).
- Capabilities and packages the planning refuses: WOW64, the display language and its language pack, the base
  packages, the cumulative update, the servicing stack, the edition, its licenses and the enablement package.
