# PolyScour

> A transparent, evidence-based Windows maintenance suite. Free, local, and
> willing to tell you what it does not know.

![Status](https://img.shields.io/badge/status-0.2%20development-orange)
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
| Windows temporary files | Low | No — needs admin, offered as a retry |
| Explorer thumbnail cache | Safe | No — Windows rebuilds it |
| DirectX shader cache | Safe | No — regenerated on demand |
| Chrome / Edge / Firefox cache | Safe | No — rebuilt as you browse |
| Application crash dumps | Moderate | **Yes** — moved to the vault |

Browser rules refuse to run while that browser is open, because clearing a cache
out from under a live profile can corrupt it. If process enumeration fails, the
rule skips rather than guessing.

The ordinary run is **entirely unelevated**. Anything needing administrator
rights is skipped and said so plainly — and then offered as a retry you can
decline, with the count and the rule named before the prompt appears.

## Storage

Where the disk actually went — and, with equal prominence, where PolyScour
could not look.

A cleaner's honest figure is small. Clearing every cache on a full 500 GB drive
frees a few hundred megabytes, and "we freed 900 MB" tells you nothing about the
other 499 GB. This screen is what makes the real answer sayable: your disk is
full of things a cleaner must never touch.

**It changes nothing, and there is nothing on it to click that would.** No
Delete, no Clean, no "optimise". Folders are sorted by size because size is a
fact; a button beside that fact would turn it into a recommendation, and this
program does not make those.

The number it is most careful about is the one it *cannot* account for. A walk
never adds up to what Windows reports as used — the page file, the file table,
restore points, the component store, and every folder an ordinary program is not
allowed to open. So the unaccounted figure is shown next to the total rather
than quietly absorbed into it, broken down by reason where that is knowable and
labelled plainly where it is not:

- Directories it could not open are counted, **never estimated**. It could not
  read them, so their size is exactly what it does not know, and inventing a
  number there would defeat the purpose of the panel.
- Junctions are not followed and their contents are *not* reported as missing —
  they are counted where the files really live.
- Files sharing storage under two names are counted once. On this machine 86.7%
  of the files in `C:\Windows\System32` are shared that way; counting each name
  separately would roughly double the reported size of Windows.
- Compressed and sparse files report what they take on disk, not what they
  claim, because the question is where the space went.

It never asks for administrator rights to make the number look better. An
unreadable folder stays unreadable and stays counted.

## What it deliberately does not do yet

Driver management, registry cleaning, secure wipe, duplicate finder,
uninstaller, WinGet updater, browser extension manager, cloud-drive cleaner,
process explorer, service manager, scheduled cleaning, CLI, portable mode,
Recycle Bin.

A duplicate finder is the nearest of these and is still declined: it needs you
to hand it a folder to search, and every path PolyScour accepts today can only
ever *narrow* what it may touch. It also has to decide which copy is the real
one, which is a recommendation it cannot honestly make. `docs/adr/0007` records
that rather than leaving it as an omission.

The strongest part of this project is what it refuses to build. The shared
substrate and one trustworthy cleaner come first.

## Administrator rights

Some work needs them: clearing `C:\Windows\Temp`, and machine-wide startup
entries. PolyScour 0.1 skipped both and said so. It can now ask.

**It asks per operation, and never on its own.** There is no service, nothing
stays elevated, and no screen requests rights "in advance" — you see a prompt
when you have asked for something that needs one. There is no setting that
turns this on permanently, and there will not be one.

Clearing `C:\Windows\Temp` is **one prompt, not one per file**. It earns that
by asking for less, not more: the request names the cleaning rule and cannot
name a file at all, so the elevated part works out for itself what that rule is
allowed to delete. A retry tells you how many items it covers and how many it
will *not* — files in use are not something administrator rights fix, and they
are counted separately rather than folded into one number.

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
turn it back on from either place. Machine-wide (`HKLM`) entries have a working
switch and a stated cost: changing one affects every account, so it asks for
administrator rights. The row says so before you touch it, rather than
explaining afterwards.

This is a real trade. Machine-wide autoruns being refused outright was a
limit on the damage this screen could do — most security software registers
there — and that limit is gone. What is left is that nothing is pre-selected,
nothing is recommended, and Windows asks you to confirm. `docs/THREAT_MODEL.md`
T14 records the judgement rather than presenting it as a free improvement.

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
says so.

A recovery supervisor — an ordinary, unprivileged helper that lives only as long
as a session — shortens the window in which a hard termination can leave
programs suspended. **It is not a guarantee.** If something takes PolyScour and
the supervisor together, the programs stay frozen until PolyScour runs again, or
until you reboot. Resume-at-next-launch remains the fallback, and that gap is
described in `docs/THREAT_MODEL.md` T20 rather than papered over here.

## Installing it

> **No release is published yet**, but it has now been installed and measured.
> `C:\Program Files\PolyScour` came out administrator-only — checked as an
> ordinary user, by permissions *and* by trying to write into it, across all
> 981 installed files rather than only the one with PolyScour's name on it. The
> installer added no data directory, no autorun, no service and no scheduled
> task, and the installed version matches the source. `docs/adr/0006` records
> the numbers, and the two privilege problems the builds found on the way.

`PolyScour-Setup-<version>.exe` needs administrator rights, and asks for them
for exactly one reason: to make `C:\Program Files\PolyScour` a directory an
ordinary user cannot write.

That is not paperwork. `PolyScour.exe` is also the elevated helper, so every
rule inside it — the closed operation set, the safety checks re-run at
privilege — is worth exactly as much as the answer to *who can rewrite this
file?* Installing is what settles that; unzipping does not.

**And it is the whole directory that has to be protected, not one file.**
PolyScour ships as an executable plus the runtime it loads — around a thousand
files — because the alternative packs them into a single `.exe` that unpacks
itself into your temporary folder and runs from there. That folder is one you
can write, so it would have put the code running as administrator outside the
very boundary this installer exists to create. That was measured rather than
guessed, and `docs/THREAT_MODEL.md` T24 records it.

It installs the program and nothing else:

- **No data directory.** The vault, history and settings are created in
  `%LOCALAPPDATA%\PolyScour` by the application itself, the first time it runs.
- **No autorun.** PolyScour does not start with Windows. A maintenance tool
  that installs its own autorun while shipping a screen that declines to
  recommend disabling anyone else's would be saying two different things.
- **No service, no scheduled task, no browser extension, no bundled anything.**
- **Uninstalling leaves your vault alone**, because it may hold the only
  remaining copy of a file you deleted through PolyScour. Delete
  `%LOCALAPPDATA%\PolyScour` yourself if you want it gone.

You can check the permissions rather than take the claim on trust — **as an
ordinary user, not as an administrator**, since an administrator can write
anywhere and would see a boundary that is not there:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\PolyScour\set_program_acls.ps1" -Root "C:\Program Files\PolyScour" -Verify
```

It tries to write into the directory and expects to fail, tries to read the
executable and expects to succeed, and checks every shipped file rather than
only the one with PolyScour's name on it — any of them is loaded by the process
that runs as administrator.

From a source checkout there is a fuller version, which also checks that the
installer registered where it says it did, created no data directory, added no
autorun, and installed the version the source claims:

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_install.ps1 -Stage Installed
```

It refuses to run elevated rather than warning about it, because an
administrator can write anywhere and would get a pass that measured nothing.

## Running it from source

```powershell
python -m venv venv
.\venv\Scripts\pip install -e "..\PolyBedrock\core" -e "..\PolyBedrock\ui" -e .
.\venv\Scripts\python -m polyscour.entry
```

`polyscour.entry` is the entry point an installed build uses; `polyscour.app`
still runs the GUI directly if you prefer. The difference matters only for the
elevated helper, which is the *same* program under a different argument — see
[docs/adr/0006](docs/adr/0006-one-executable-two-programs.md).

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
