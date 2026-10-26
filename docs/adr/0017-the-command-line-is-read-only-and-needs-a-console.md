# ADR 0017 — The command line is read-only, and needs a console

**Status:** accepted

## Context

The README listed a CLI among the things PolyScour "deliberately does not do
yet". Two things already existed that a CLI could be built on: the Clean
screen's scan, and the ledger's history. Three things made it less obvious than
"expose them":

1. **What the scheduled runner checks is not what a typed command would need.**
   `scheduling/runner.py` can run a clean unattended because a person consented
   *once, at creation*, to an exact digest of the rules (adr/0014). A person
   typing `clean` has given no such consent, and the usual substitute — a
   `--yes` flag — is the thing that teaches people to stop reading
   confirmations.
2. **`Ledger.history()` is not a read.** Every `Ledger` method goes through
   `_conn()`, which creates the data directory and the database file, runs the
   schema script, and migrates old columns, then commits. A `history` command
   built on it would create a ledger on a machine that had none and alter an
   old one, while presenting itself as read-only. Found by reading `_conn()`
   before writing the command, and pinned by a test that shows the ordinary
   read *does* create the file.
3. **The installed program has no console.** `build.ps1` builds with
   `--windows-console-mode=disable`. A program with no console has no standard
   output to print to, and by Windows' documented behaviour `cmd.exe` and
   PowerShell do not wait for a GUI-subsystem program, so a script could not
   read its exit code either. *This is documented behaviour and was not
   measured on this machine; the code does not depend on the details, only on
   `sys.stdout` being `None`, which Nuitka's disabled-console mode produces.*

## Decision

1. **Two verbs, both read-only: `scan` and `history`.** Reached as
   `PolyScour.exe --cli <verb>`.
2. **No `plan` verb.** A plan is the executor's input. With no verb that
   executes, a printed plan is a recommendation with no decision behind it, and
   `scan` already prints what a plan would add — each finding's risk and
   whether it could be undone. "A finding is not a recommendation" is the
   reason, and the earlier sketch of this feature (scan, plan, history) was
   trimmed to match.
3. **No mutating verb, and none without a decision of its own.** A `clean`
   needs a consent model for a person at a keyboard that is not a flag, and the
   guard is called twice and the executor constructed with
   `allow_elevation` never true (`CLAUDE.md`). That is an ADR and a threat-model
   entry before code, not a follow-up to this one.
4. **`--cli` is a flag, not a bare verb.** `entry.py` dispatches on exact
   strings and refuses what it does not recognise; `PolyScour.exe scna` stays an
   unknown argument. Inside the branch `argparse` parses the rest with
   `allow_abbrev=False`, so `--js` is not `--json`.
5. **`scan` builds its own scanner; it does not build `Services`.** `app.py`
   imports CustomTkinter at module scope, and `Services` creates the vault,
   initialises the ledger and runs Game Mode recovery — all of which change the
   machine. The scan is the Clean screen's own construction (guard with the
   user's exclusions, the PolyShield advisor, `disabled_rules` honoured, the
   Recycle Bin appended) and nothing else. Naming a rule disabled in Settings
   is refused: the command line is not a way around a setting.
6. **`Ledger.history_readonly()`** opens the file with `mode=ro`, creates
   nothing, migrates nothing, and returns `None` when no ledger exists. "No
   ledger", "an empty ledger" and "a ledger that could not be read" are three
   different outputs; the last exits 3 and is never shown as empty.
7. **Unread is not empty, in the exit code too.** Exit 1 means part of it could
   not be read — a rule aborted, a rule file did not load, the scan was
   cancelled — and the output says which. Exit 0 means everything asked for was
   read. Exit 2 is usage, 3 is "could not run", 130 is an interrupt (nothing
   had been changed).
8. **No console, no output, exit 3.** The installed executable is not a
   supported place to run this. The command works from a source checkout and
   from a console-mode build, and says so in `--help` and the README.

## Alternatives rejected

- **`AttachConsole(ATTACH_PARENT_PROCESS)` in the windowed build.** It would
  make output appear in a terminal, but not make the shell wait, so exit codes
  and pipelines would still be wrong. A half-working CLI that looks working is
  worse than an unsupported one that says so.
- **A second, console-subsystem executable.** adr/0006 chose one executable
  because a second binary is a second thing to protect and verify (T15, T24).
- **Building the one executable with a console and hiding its window for the
  GUI.** Probably the right eventual answer, and a real trade (a console window
  can flash on every GUI launch). It changes how every user launches the
  program, so it needs a measurement on a real installed build first. Not done
  here.
- **A `--json` flag on `plan`.** See decision 2.

## Consequences

- Scripts can read what a scan would find and what PolyScour did, from a source
  checkout or a console build, with a versioned JSON schema (`schema: 1`; keys
  are added, never renamed without bumping it).
- `scan --json` prints the path of every finding, to whatever the caller
  redirected stdout to. That is the same disclosure the Clean screen makes to
  its viewer and nothing is stored or sent (docs/PRIVACY.md).
- The one-line text report groups by rule; `--list` prints every path. A scan
  of this author's temp folder is 37,682 items, which is why that is opt-in.
- A scan takes as long as the Clean screen's: 43 s on the development machine.
- Open question, deliberately left: how the *installed* program gets a console
  (see the third rejected alternative).

## Verified

- `scan` and `history` against an empty data directory (`POLYSCOUR_DATA_DIR`)
  leave it empty. The suite asserts this through the real entry point, and each
  of three deliberate breakages (a read through the mutating reader, a GUI
  import, a scan that initialises the ledger) was watched to turn tests red.
- A full `user-temp` scan was run by hand; the suite runs the Recycle Bin's real
  scan because the file-rule scan is too slow for every run.
- Not verified: behaviour in a built, installed executable.
