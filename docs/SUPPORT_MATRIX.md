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
| ARM64 | Untested. Nothing in 0.1 is architecture-specific; packaging is the open question. |

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

## Capabilities declared today

`polybedrock.capabilities` is deliberately populated only with what something
actually consumes. A registry of eight serving three call sites is the
over-engineering this project is avoiding.

- `POWERSHELL` — answered by looking for the executable, never by running it
- `SYSTEM_SECURITY` — available-but-partial without elevation, which the state
  distinguishes from unavailable

The enum grows when a feature arrives, not in anticipation of one.
