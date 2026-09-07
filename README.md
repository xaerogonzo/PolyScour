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
- **No silent registry edits.** PolyScour writes to the registry in exactly
  one place — the Startup Manager's approval byte, the same switch Task
  Manager uses — and only when you flip it. Every such change names the key
  and value, is recorded in History, and is undoable. Registry *cleaning* —
  deleting keys because they look unused — is not in 0.1 and is not planned.
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
cleaner, process explorer, service manager, scheduled cleaning, CLI,
portable mode, Recycle Bin.

The strongest part of this project is what it refuses to build. The shared
substrate and one trustworthy cleaner come first.

## Administrator rights

Some work needs them: clearing `C:\Windows\Temp`, and machine-wide startup
entries. PolyScour 0.1 skipped both and said so. It can now ask.

**It asks per operation, and never on its own.** There is no service, nothing
stays elevated, and no screen requests rights "in advance" — you see a prompt
when you have asked for something that needs one.

The elevated part is deliberately small: a closed list of named operations, no
"run this command" of any kind, and it re-checks every path against the same
safety rules the main application uses rather than trusting what it was handed.
It assumes the program that asked it might be wrong. `docs/THREAT_MODEL.md`
sets out what that does and does not protect you from — including the two cases
it cannot.

## Startup

What Windows starts for you, and a switch for each one.

Turning an entry off writes the same approval byte Task Manager writes, in
`HKCU\...\Explorer\StartupApproved\Run`. **The `Run` value itself is never
touched**, so nothing is deleted, Task Manager shows the same state, and you can
turn it back on from either place. Machine-wide (`HKLM`) entries are listed but
their switch is refused with the reason, because changing them needs
administrator rights that 0.1 does not use.

PolyScour does not suggest what to turn off, and there is no "recommended" set.
Startup impact is usually small, and an entry you rarely use is not evidence
that disabling it helps. An entry whose file is missing is described as exactly
that, not as safe to remove — a missing target is very often an installer that
will put the file back.

Undo checks before it acts: if the entry now launches something different from
what it launched when PolyScour changed it, the undo is refused and says so,
rather than restoring a decision you never made.

## Game Mode

Suspend background programs while you play, and resume them afterwards. A
suspended program is frozen, not closed: it keeps its memory and carries on
where it left off.

PolyScour does not choose for you. The list is sorted by memory use because
that is a fact worth showing — but nothing arrives ticked, and there is no
"recommended" set. Processes it refuses to touch are shown greyed **with the
reason**, rather than quietly missing from the list.

It will not suspend kernel processes, the Windows shell, the audio service,
service hosts, security software, itself, or anything not running as you — and
that last rule is what covers the processes nobody thought to name.

If PolyScour is closed without resuming them, the next launch resumes them and
says so. If it is hard killed and never launched again, they stay frozen until
you reboot; that gap is real and is why a supervising process is on the list for
0.2 rather than improvised here.

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

**This comparison is a local gate, not a CI gate.** The golden PNGs encode one
machine's font rasterisation and DPI, so a GitHub runner differs from them for
reasons that say nothing about the code — and its image is rebuilt roughly
monthly. CI therefore skips that one comparison and says so, while still
proving the mechanism works there: it records a golden, compares against it,
and confirms that a deliberately corrupted golden is actually *caught*. Run
`--check` yourself before committing a UI change; that is where it means
something.

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
