# 0006 — Packaging is 0.2, and one executable is two programs

**Status:** Accepted · **Date:** 2026-09-08

## Context

Two documents disagreed about when packaging happens.

`build.ps1`'s header said packaging "lands in 0.9". `docs/adr/0001` put the
installer in 0.2. That was harmless while nothing depended on it, and stopped
being harmless when the elevated helper shipped:

- **T15** requires the installed location be one only administrators can write.
  An attacker who can rewrite the helper has defeated every rule inside it, so
  every other guarantee in `THREAT_MODEL.md` rests on a directory that does not
  exist without an installer.
- `elevation/client._helper_command()` has a branch for frozen builds. Until
  there is a frozen build, that branch is unreachable, untested, and — as it
  turned out — wrong.

## Decision

**Packaging is 0.2.** `build.ps1`'s header is corrected rather than left as a
stale note.

**One executable, two programs, dispatched on one argument.**
`PolyScour.exe` with no arguments is the GUI. `PolyScour.exe
--elevated-helper <request>` is the helper. There is no `helper.exe`.

**`src/polyscour/entry.py` is the compiled entry point**, not `app.py`.

## Why one binary rather than two

The helper must be the *same* trusted binary, in the same
administrator-protected directory. A separate `helper.exe` would be a second
file to protect with ACLs and a second to verify, for no gain — and a build
that shipped one without the other would produce a helper the GUI could launch
but nobody had reviewed together with it.

The cost is that the dispatch has to be trustworthy, which is what the rest of
this decision is about.

## Why `entry.py` and not `app.py`

`app.py` imports CustomTkinter at module scope, and importing that imports Tk
and Tcl.

Entering through it would mean **a GUI toolkit loaded into an elevated
process**: tens of thousands of lines running as administrator in order to
delete one file, in a program whose threat model says the elevated part is
deliberately small. Not a vulnerability anyone can name today — an enormous
increase in what runs at privilege, for nothing.

`entry.py` imports neither branch at module scope. The helper branch returns
before any GUI import can happen, and `test_the_elevated_branch_never_imports_the_gui`
asserts that in a **subprocess** — checking `sys.modules` in-process would prove
nothing, because pytest has already imported CustomTkinter for the UI tests.

## Unknown arguments are refused

This is the command line of a program that runs as administrator. Ignoring an
argument it does not understand means proceeding on the overlap between what
the caller meant and what it understood, which is the mistake
`protocol.Request.from_json` already refuses to make about parameters.

`--elevated-helper` is an exact string comparison. `--elevated-helper-x`,
`-elevated-helper` and `--ELEVATED-HELPER` are unknown arguments, and there are
tests for each, because a prefix match or a case-insensitive one would accept
all three.

A bare launch — no arguments, which is what a shortcut and a double-click
produce — is the GUI. That is the only case decided implicitly.

## The bug this found

`_helper_command()` chose its branch with `getattr(sys, "frozen", False)`.

**Nuitka does not set `sys.frozen`.** That is PyInstaller's flag. Nuitka injects
`__compiled__` into every module, which is exactly what
`polybedrock.paths.is_frozen()` already checks, and has checked since it was
extracted.

So a compiled build would have taken the *source* branch and run
`PolyScour.exe -m polyscour.entry "<request>"` — an argument the executable
refuses, from an executable with no interpreter to run a module with. Every
development run would have passed. The first failure would have been a user
clicking *Retry as administrator* on an installed build.

The lesson recorded here is narrower than "test the frozen path": **"am I
frozen" is not a question worth answering twice.** One predicate, in the
substrate, already correct for both packagers.

## Cleaning rules ship inside the binary

*Added 2026-09-08, with the installer.* Same decision area: what the compiled
artifact contains.

`paths.rules_dir()` resolves from the module tree, so `--include-data-dir` puts
the rules in the payload and an installed machine has no rules folder at all.

The alternative — installing `rules/cleaners/` beside the executable — was
rejected because it offers the *appearance* of configurability with none of the
authority. Adding a rule already requires a reviewed `PolicyEntry` in
`safety/policy.py`; a rules directory an administrator could edit would invite
exactly the edit that cannot work, and would hand T1 an easier target for
nothing in return.

### And the third bug of the same family

`rules_dir()` resolved from `__file__` with a fixed `parents[2]`. A build has no
`src/` level, so that walks one directory too high and finds nothing — a Clean
screen with no rules on it, which reads as *a scan that found nothing* rather
than as a broken build.

`resource_root()` now makes the level explicit, and the reasoning is borrowed
rather than invented: PolyShield hit the same off-by-one and its `paths.py`
records both the fix and that **`sys.executable` is the wrong source** — in a
Nuitka standalone build it names a `python.exe` that does not exist, so a
version using it "works by luck while resting on a path to nothing".

**No unit test in this suite can check that.** The discrepancy lives in a
`__file__` layout that only exists inside a real build. `tools/build_probe.py`
is compiled with the same flags and run from the build, and `build.ps1` gates
on it — exactly how PolyShield found its own. What the suite *can* check is the
policy, and does: that the frozen root is one level below the checkout root,
that rules live under the resource root in both modes, and that the data root
never does.

## Consequences

- `--include-package=polybedrock` is required. It is installed editable from a
  sibling checkout, so Nuitka does not find it by tracing imports; without the
  flag the build succeeds and the executable dies on first import.
- `PIL` and `pystray` are dropped from the build. Nothing in PolyScour imports
  either — pillow arrives only through `polybedrock-ui`'s `uishot`, a
  development tool with no business in a shipped build.
- The installer's job is now small and unambiguous: `Administrators:F`,
  `Users:Read-and-Execute` on `C:\Program Files\PolyScour`. `docs/adr/0005`
  already removed the data-directory question by keeping the vault in
  `%LOCALAPPDATA%`.
- `tests/test_entry.py` asserts both modes and that they *disagree*. A
  predicate that always answered the same way would satisfy each mode's test
  separately, which is how this bug survived having a branch for it.

## What the first real build did

*Updated 2026-09-08. Nuitka 4.2.1, zig 0.16.0, Python 3.13, `--onefile`.*

It works, and it found something.

**Confirmed:**

| Claim | Result |
|---|---|
| `is_frozen()` returns True in a build | yes — the `__compiled__` check holds |
| `resource_root()`'s level adjustment | correct: rules resolve, all eight found |
| the data root stays in `%LOCALAPPDATA%` | yes, and not under the extraction dir |
| `--include-package=polybedrock` needed | yes; it is not traced without it |
| the GUI starts | yes — window titled PolyScour, ~72 MB working set |
| the helper answers | yes — refuses an unknown rule, writes its response, exits 1 |
| an unknown argument | exits 2 |
| payload | 58.9 MB uncompressed, 15.5 MB on disk |

**Found — see T23.** `sys.executable` under onefile is
`%TEMP%\onefile_<n>\python.exe`, not the installed binary, and that directory
is writable by the user. The frozen branch of `_helper_command()` was therefore
about to `ShellExecute("runas", ...)` a path an ordinary process could replace
first. Fixed with `paths.running_executable()`, plus a refusal in `_launch()`
and a gate in the probe.

Four bugs of this family have now been found and every one was invisible from
source. The probe exists so the next one is caught by a machine rather than by
a reader.

## A consequence worth knowing: the build has no console

`--windows-console-mode=disable` makes this a Windows-subsystem binary, so
`print(..., file=sys.stderr)` reaches nobody. The usage text in `entry.py` is
therefore invisible in a real build — someone who types a wrong argument gets
exit code 2 and silence.

That is acceptable rather than good: the command line is not a supported
interface, and the two flags on it are launched by PolyScour itself. It is
recorded here so nobody assumes the usage message is doing work it cannot do.
The elevated helper is unaffected — it answers in a *file*, precisely because
a process launched by `ShellExecute("runas")` has no inherited pipes.

## Still not done

The installer is not compiled: Inno Setup is not installed on this machine, and
`build.ps1` says so and continues rather than failing. `installer/polyscour.iss`
and the ACL script are reviewed and the verifier has been exercised against real
directories, but no `PolyScour-Setup-*.exe` exists yet.
