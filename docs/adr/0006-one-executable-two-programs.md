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

`--windows-console-mode=disable` makes this a Windows-subsystem binary, so it
allocates no console of its own.

**Corrected 2026-09-08, by running the installed build.** This section
previously said the usage text was "invisible in a real build — someone who
types a wrong argument gets exit code 2 and silence". That is too strong, and
it was itself a claim about a packaged build that had never been tested against
one. Measured:

```
Start-Process "C:\Program Files\PolyScour\PolyScour.exe" `
    -ArgumentList "--not-a-real-flag" -Wait -PassThru -NoNewWindow
```

prints `unknown argument: '--not-a-real-flag'` and the full usage text, then
exits 2. A Windows-subsystem process does not *create* a console, but it
inherits the standard handles of one that launched it — so the message reaches
a terminal and is lost only on a double-click or a launch with no inherited
handles.

The conclusion is unchanged and the reasoning is now right: the command line is
not a supported interface, the flags on it are launched by PolyScour itself,
and nobody should assume the usage message is doing work it cannot do. The
elevated helper is unaffected either way — it answers in a *file*, precisely
because a process launched by `ShellExecute("runas")` has no inherited pipes.

That correction is the fifth of the family this file catalogues, and the
cheapest: nothing depended on it. It is recorded because the pattern is what
matters, not the blast radius.

## The installer compiles too

`PolyScour-Setup-0.2.0.exe`, 17.5 MB, from Inno Setup 6.7.3.

It took two fixes, and both are the same shape as everything else in this file
— an assumption that was never tested against the thing it described:

- **The ISCC search list assumed Program Files.** Inno Setup 6 offers a
  per-user install under `%LOCALAPPDATA%\Programs`, which is where this machine
  had it, so `build.ps1` reported "not found" on a machine that had it. Cheap,
  because the script warned and continued rather than acting on the wrong
  answer — the same mistake as `sys.executable`, without the blast radius.
- **There was no `LICENSE` file.** `README.md` said "MIT" and `pyproject.toml`
  declared `license = { text = "MIT" }`, and neither is a licence. Nothing in
  the test suite could notice, because nothing imports a licence. It took a
  build step that has to *open the file* to turn the claim into a check.

## The packaging changed again, and this time for a security reason

*Added 2026-09-08. `--onefile` is gone; the build is `--standalone`.*

Generalising T15 from "an attacker who can rewrite `PolyScour.exe`" to "an
attacker who can rewrite **anything the trusted process loads**" produced a
question this ADR had not asked, and `tools/build_probe.py` was extended to
answer it rather than reason about it.

Under `--onefile`, `PolyScour.exe` unpacked its Python runtime and every native
extension module into `%TEMP%\onefile_{PID}_{TIME_US}_{RANDOM}` and executed
from there. Measured:

```
extraction_dir             %LOCALAPPDATA%\Temp\onefile_7592_116693_qJKINLtzAbM
extraction_dir_writable    true
extraction_dir_dacl        NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                           BUILTIN\Administrators:(I)(OI)(CI)(F)
                           XAERO\pmpd:(I)(OI)(CI)(F)
```

Every ACE inherited, and the user holds Full Control. So the code executing as
administrator lived **outside** the directory T15's ACLs protect — the same
shape as T23, one step further along the same path. `THREAT_MODEL.md` **T24**
records it in full, including that the obvious fix (a static
`--onefile-tempdir-spec`) makes it strictly worse by trading an unpredictable
per-run directory for a predictable, persistent one.

**`--standalone` is the fix**, and it is the only one that closes rather than
narrows: the DLLs ship beside the executable, so what runs at privilege is
inside the boundary the installer establishes.

**This ADR's decision is untouched.** "One executable, two programs" is about
`entry.py` dispatching on an argument before importing either branch. It was
never about onefile. There is still exactly one `PolyScour.exe`, it is still
both programs, and `--standalone` changes only what sits next to it.

### What the standalone build measured

| Claim | Result |
|---|---|
| the runtime no longer resolves into `%TEMP%` | `runtime_dir_in_temp: false` |
| `sys.executable` | `<install>\python.exe`, inside the program directory |
| `resource_root()` under a directory build | correct — all eight rules resolve |
| the data root stays in `%LOCALAPPDATA%` | yes, and not under the program directory |
| the GUI payload | 56.6 MB across **978 files** |
| the installer still compiles | yes — `PolyScour-Setup-0.2.0.exe`, 15.9 MB |
| the probe gate can still fail | yes — exit 1, confirmed by running it against the wrong expectation |

### Three things it broke, all in `build.ps1`

Worth listing because each was silent in a different way:

- **`Clear-NuitkaOrphans` deleted `*.dist`.** Under onefile that was scratch;
  under `--standalone` it is the *product*. Left alone, the build would have
  reported success and shipped nothing.
- **The payload sanity check parsed `"Onefile payload compression ratio"`**, a
  line `--standalone` never prints. It would not have errored — it would have
  quietly stopped checking anything while still printing reassuringly. It now
  measures the output directory. A check that silently matches nothing is worse
  than no check, because it still reports.
- **`build_probe.py`'s T23 gate asked the wrong question.** It failed a build
  whose launcher was inside `resource_root()`, which under onefile meant "inside
  the extraction directory" and was right by accident. Under `--standalone` the
  resource root *is* the program directory, so that gate would have failed every
  build. It now enforces the invariant that survives both packagings: **nothing
  frozen may run out of a temporary directory.**

### And a consequence for verification

The installed payload is 978 files, not one. "Check the ACLs on `PolyScour.exe`"
was never the right claim, and is now visibly not: `tools/verify_install.ps1`
checks every file in the program directory, because any one of them is loaded
by the process that runs as the elevated helper.

## What supports T15 now

*This section used to be titled "What remains unverified" and began "Nobody has
installed it." Both were true when written and neither is now. It is rewritten
rather than annotated, because a stale claim left in place is the thing this ADR
is otherwise a catalogue of.*

T15 — the installed program directory is one an ordinary user cannot write — is
supported by three things, in ascending order of what they prove:

1. **An argument.** The installer applies `Administrators:F` /
   `Users:Read-and-Execute` and then re-runs the script with `-Verify`.
2. **Tests.** `tests/test_program_acls.py` exercises the verifier unelevated
   against a directory where Users hold `FILE_DELETE_CHILD` (must fail) and
   against `C:\Program Files\Windows Defender` (must pass). Both controls, and
   the negative one has been watched failing.
3. **A measurement.** `tools/verify_install.ps1 -Stage Installed`, run as an
   ordinary user against the real installation, walking every one of its 981
   files. See the section above.

Only the third proves rather than describes, and it is the one that did not
exist when this ADR was first written.

### A gap the tests found in the verifier itself

Writing `tests/test_program_acls.py` turned up a hole in `set_program_acls.ps1`:
`$WRITE_MASK` omitted `DeleteSubdirectoriesAndFiles` (`FILE_DELETE_CHILD`).

Measured, because the two are easy to assume related and are not:

```
Delete                        = 65536   (0x10000)  a right on the FILE
DeleteSubdirectoriesAndFiles  = 64      (0x40)     a right on the DIRECTORY
Delete implies FILE_DELETE_CHILD?  False
```

`FILE_DELETE_CHILD` on a directory permits removing a child **without** holding
`Delete` on that child. So an ACE granting Users only that bit satisfied every
check the script made, while leaving an ordinary user able to remove
`PolyScour.exe` and put their own there — T15, reached through the one door the
mask did not cover.

The negative control was then itself checked by removing the flag again and
re-running: the test failed, and it failed on the DACL assertion rather than on
the exit code, which matters. The fixture's own directory is owned by the test
user, so the write probe fires there whatever the mask says — an exit-code check
alone would have passed a regressed mask for an unrelated reason. That is
recorded in the test, because a control nobody has watched fail is not yet a
control.

## What the first real installation measured

*2026-09-08, unelevated, `tools/verify_install.ps1`, against
`C:\Program Files\PolyScour`.*

**T15 is measured rather than argued.** That sentence is the point of this
section, and of the tool that produced it.

### The run that found the stale installation

The first run was against an installation this ADR did not know existed. Its
own text said "nobody has installed it" — written, true when written, and
nothing ever opened the registry to notice it had stopped being true. The
uninstall key was there the whole time.

That installation was the **onefile** build: 4 files, 19.9 MB. The payload check
flagged it as a live T24 installation, which is the new gate earning its place
on a real machine rather than a fixture. T15 passed on it too — the ACLs were
right; it was the *packaging inside them* that was wrong.

### The measurement that counts

Uninstalled, re-snapshotted clean, and reinstalled from the `--standalone`
build:

| Claim | Result |
|---|---|
| the program directory is administrator-only | **yes** — `acl_verify_exit: 0`, DACL *and* write probe, unelevated, across **every one of 981 files** |
| the payload is a directory build | yes — 981 files, 63,906,155 bytes |
| the installer registered where it installed | yes — resolved from `InstallLocation`, not assumed from `%ProgramFiles%` |
| `DisplayVersion` matches `pyproject.toml` | yes — `0.2.0` at both ends, closing the version chain |
| the installer creates no data directory | **yes, as a delta** — `%LOCALAPPDATA%\PolyScour` absent before *and* after |
| no autorun, no service, no scheduled task | none |
| the payload actually loads | yes — both branches run from the installed location: an unknown argument exits **2** with usage, and the helper exits **1** having written `<request>.response` with `refused_by: protocol` |

The last row matters more for a directory build than it did for onefile. 981
files is 981 chances for one to be missing from the installer's `[Files]`
section, and the failure mode is an application that installs cleanly and dies
on launch. Neither the build probe nor the ACL check would notice; only running
it does.

**981 = 978 + 3.** The build produces 978 files; the installer adds
`set_program_acls.ps1`, `unins000.exe` and `unins000.dat`. Every file inside the
trusted boundary is accounted for — nothing arrived that the build did not
produce or the installer did not declare.

### Why the PreInstall stage exists, demonstrated

"The installer creates no data directory" is a **delta**, and the first attempt
at this check was an absolute: *`%LOCALAPPDATA%\PolyScour` must be absent*. That
is false on any machine PolyScour has ever been *run* from, and it was false on
this one — the first snapshot recorded two files already there, which would have
made an absolute check report a failure that meant nothing.

Taken against a genuinely clean machine the delta is `exists: false` before and
`exists: false` after, and now says something. A check that cannot fail for the
right reason is not made better by also being able to fail for the wrong one.

### Still outstanding

`%LOCALAPPDATA%\PolyScour` had not been created at the time of the measurement,
because the application had not been launched. Re-running `-Stage Installed`
after one launch covers the remaining half — that the data root is writable and
is not under the program directory. `-Stage Uninstalled` has not been run.

## The manual half

Three things `tools/verify_install.ps1` cannot reach, because each needs a real
UAC prompt and `tests/conftest.py` exists to make a prompt raised from an
automated context fail loudly. That guard is not going to acquire an exception;
these are run by hand, once per release.

- [ ] **The elevated Clean retry.** Clean → a rule covering `C:\Windows\Temp` →
      *Retry as administrator*. Check that the consent dialog names PolyScour
      **from the install root**, and that the item count appears *before* the
      prompt rather than after (T18). Then check History records an
      `ElevationRecord` matching what actually happened.
- [ ] **A machine-wide startup toggle.** Startup → flip an `HKLM` entry. One
      prompt, not one per operation; Task Manager agrees afterwards; the row
      said it would need administrator rights *before* it was touched (T14).
      Undo it and confirm the undo refuses if the target changed (T13).
- [ ] **Supervisor recovery.** Game Mode → suspend something → kill PolyScour
      from Task Manager → confirm the supervisor resumes it without PolyScour
      being restarted (T20), and that the ledger row is marked resumed.

An unticked box here is not a failing test. It is a statement that this release
has not been through the three things only a person at the machine can do.
