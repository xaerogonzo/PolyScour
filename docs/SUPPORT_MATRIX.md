# Windows support matrix

Stated from day one so that "unavailable on this build" can be a clear message
rather than an obscure error. The capability layer (`polybedrock.capabilities`)
answers these at runtime; probes are observational and never change anything.

## Supported

| Version | Status |
|---|---|
| Windows 11 (all builds) | Supported — the development target |
| Windows 10 21H2+ (build 19044+) | Supported |
| Windows 10 below 21H2 | Untested. Nothing in 0.1 is known to require anything newer. |
| Windows Server | Untested, unsupported |
| ARM64 | Untested, and now explicitly **not** built for: `installer/polyscour.iss` sets `ArchitecturesAllowed=x64compatible`. Nothing in the source is architecture-specific, so this is a packaging decision rather than a limitation — but refusing to install is more honest than installing and failing later. |

Non-Windows is not a target. Tests that touch Windows behaviour skip on other
platforms rather than pretending to pass.

## Per-feature availability

| Feature | Requires | Without it |
|---|---|---|
| Scanning, cleaning, vault, undo, history | Nothing beyond Python 3.11 | — |
| Reparse-point inspection | `st_file_attributes` (Windows) | Falls back to `S_ISLNK`, for test rigs only |
| Browser-open detection | `psutil` | The rule **skips** rather than guessing — an unknown answer behaves like the dangerous one |
| System health tile | `powershell.exe` on PATH | Tile reports unavailable, with the reason |
| Windows temp cleaning | Administrator | Files are skipped and reported, never silently omitted |
| PolyShield tile | PolyShield installed and running | The tile does not render at all |
| Storage analyser | `psutil` for volume enumeration | No volumes are listed, and the screen says so rather than showing an empty tree |
| Storage: on-disk sizes | `kernel32.GetCompressedFileSizeW` | Falls back to logical size, labelled as which — a worse answer, not a wrong one |
| Storage: comparing scans over time | `kernel32.GetVolumeNameForVolumeMountPointW`, for a volume identity that survives a drive-letter change | The volume has no identity: its scans are **not saved** and never compared, and the screen says why. Falling back to the drive letter would compare a swapped disk against the old one (adr/0008) |
| Startup: view-only list of tasks | `%SystemRoot%\System32\schtasks.exe` | The section says the tasks **could not be read** — not "none found". `System32\Tasks` and the registry `TaskCache` are administrator-only, so `schtasks` is the only unelevated source (adr/0011) |
| Startup: view-only list of services, folders, `RunOnce` | Nothing beyond the registry and the filesystem | Each source reports its own failure in its own section |
| Storage: complete totals | Administrator | **Not offered.** Unreadable directories are counted and named; the residual grows and says why. Elevation is not requested to shrink a number |
| Recycle Bin | `shell32.SHQueryRecycleBinW` / `SHEmptyRecycleBinW` | Not offered on the Clean screen. Never emulated by deleting inside `$Recycle.Bin` (adr/0012) |
| Uninstall: list | Nothing beyond the registry (`...\Uninstall\*` under HKLM, HKLM WOW6432Node, HKCU) | A hive that cannot be read says so; it is not shown as "nothing installed" |
| Uninstall: launch | `shell32.CommandLineToArgvW`, to split `UninstallString` | The row's button is **disabled with the reason**. Never launched through a shell instead (adr/0013) |
| Scheduled cleaning: create / remove | `%SystemRoot%\System32\schtasks.exe` | The schedule is not created, and Settings says why |
| Scheduled cleaning: run | `powershell.exe`, for `Get-ScheduledTask` — `schtasks /query /xml` corrupts long values | The run is **refused**: a task that cannot be verified is treated as untrusted, not assumed unchanged (adr/0014) |
| PolyShield path awareness | PolyShield running and answering `PATH_STATUS` | Exactly as if PolyShield were absent: nothing is refused *because* it is missing, and nothing is cleared by its silence (adr/0015) |

## Capabilities declared today

`polybedrock.capabilities` is deliberately populated only with what something
actually consumes. A registry of eight serving three call sites is the
over-engineering this project is avoiding.

- `POWERSHELL` — answered by looking for the executable, never by running it
- `SYSTEM_SECURITY` — available-but-partial without elevation, which the state
  distinguishes from unavailable

The enum grows when a feature arrives, not in anticipation of one.
