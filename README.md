# PolyScour

> A transparent, evidence-based Windows maintenance suite. Free, local, and
> willing to tell you what it does not know.

![Status](https://img.shields.io/badge/status-0.1%20development-orange)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey)
![Python](https://img.shields.io/badge/python-3.11%2B-green)
![Licence](https://img.shields.io/badge/licence-MIT-blue)

PolyScour scans first, explains what it found, shows exactly what will change,
and lets you decide. Risky operations are reversible where that is honestly
possible — and labelled **"Not reversible"** where it is not.

## What it refuses to do

This list is part of the product, not a disclaimer.

- **No invented numbers.** No "PC health score", no "2,347 problems found". The
  dashboard once headlined *"63 devices not reporting OK"* — the raw output of
  `Get-PnpDevice | Where Status -ne 'OK'`, which counts every USB device you have
  ever plugged in. That was removed as a headline, because it was exactly the
  kind of alarming-but-meaningless figure this project exists to replace.
- **No forcing.** No closing other applications' file handles, no clearing
  read-only bits. A locked file is skipped, reported, and left alone.
- **No silent registry edits.** Registry cleaning is not in 0.1 at all.
- **No telemetry.** Not opt-in, not anonymous, not "just crash reports". None.
- **No account, no cloud, no ads, no bundled software.**
- **No claiming an undo that does not exist.** A regenerable cache is deleted
  and labelled permanent, because moving it would not free any space and
  pretending otherwise would be a lie.

## What 0.1 does

A single vertical slice, end to end and heavily tested:

```
Launch → scan → findings → plan → confirm → clean → verify → record → undo
```

Eight cleaning rules, grouped so you decide by category rather than by file:

| Rule | Risk | Reversible |
|---|---|---|
| User temporary files | Low | No — permanent |
| Windows temporary files | Low | No — needs admin, skipped and reported |
| Explorer thumbnail cache | Safe | No — Windows rebuilds it |
| DirectX shader cache | Safe | No — regenerated on demand |
| Chrome / Edge / Firefox cache | Safe | No — rebuilt as you browse |
| Application crash dumps | Moderate | **Yes** — moved to the vault |

Browser rules refuse to run while that browser is open, because clearing a cache
out from under a live profile can corrupt it. If process enumeration fails, the
rule skips rather than guessing.

Runs **entirely unelevated**. Anything needing administrator rights is skipped
and said so plainly.

## What it deliberately does not do yet

Driver management, registry cleaning, secure wipe, duplicate finder, storage
analyser, uninstaller, WinGet updater, browser extension manager, cloud-drive
cleaner, process explorer, service manager, scheduled cleaning, Game Mode, CLI,
portable mode, Recycle Bin.

The strongest part of this project is what it refuses to build. The shared
substrate and one trustworthy cleaner come first.

## Running it

```powershell
python -m venv venv
.\venv\Scripts\pip install -e "..\PolyBedrock\core" -e "..\PolyBedrock\ui" -e .
.\venv\Scripts\python -m polyscour.app
```

```powershell
.\venv\Scripts\python -m pytest
```

### Looking at the UI without running it

```powershell
.\venv\Scripts\python tools\uishot\__main__.py --check
```

Captures every screen to `artifacts/ui/` and diffs it against the recorded look
in `tests/golden/ui/`. Nothing appears on screen, nothing takes focus, and the
mouse is never touched — the window is rendered on a hidden Windows desktop.

## Optional: PolyShield

If [PolyShield](https://github.com/xaerogonzo/Polyshield-Antivirus) is installed
and running, the dashboard gains one tile showing real security posture and
threat-intelligence freshness.

If it is not, the tile simply does not appear. No greyed-out teaser, no
advertisement. PolyScour is a complete application on its own, and an
integration test asserts it behaves identically whether PolyShield is absent,
present, or installed-but-crashed.

The integration asks exactly three questions — `PING`, `STATUS`,
`GET_INTEL_STATUS` — over an authenticated local socket, and **fails closed**.
There is no code path from PolyScour that asks PolyShield to *do* anything.

## Architecture

PolyScour and PolyShield share [PolyBedrock](../PolyBedrock), a Windows substrate
neither of them owns:

```
                    PolyBedrock
              ┌─────────────────┐
       polybedrock-core       polybedrock-ui
       Windows substrate   shared UI
              └────────┬────────┘
              ┌────────┴────────┐
         PolyShield         PolyScour
         security           maintenance
              └───────┬─────────┘
                 tiny optional
                  IPC seam
```

## Documentation

| Document | Covers |
|---|---|
| [docs/SAFETY.md](docs/SAFETY.md) | The guard chain, in detail |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Accidental safety vs adversarial local security |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, data flow, threading |
| [docs/CLEANING_RULES.md](docs/CLEANING_RULES.md) | The rule format, and how to add one |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What is read, stored, and never sent |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | Windows versions and feature availability |
| [docs/adr/](docs/adr/) | Decisions, with their reasoning |

## Licence

MIT.
