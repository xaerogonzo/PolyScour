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

## What is still unverified

No build has been run: Nuitka is not installed in `venv/`. Everything above is
argued from the source and tested at the seams — the argument dispatch, both
`_helper_command` branches, the import surface of the elevated process, and
that the data root does not move when frozen.

The remaining unknowns are Nuitka's, not this project's: whether `tk-inter`
plus `--include-package=polybedrock` produces a working GUI, and what the
onefile payload weighs. Those need a machine with Nuitka on it, and this file
should be updated with what the first real build actually did.
