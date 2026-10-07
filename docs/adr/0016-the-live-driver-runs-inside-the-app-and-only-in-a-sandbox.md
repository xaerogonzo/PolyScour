# ADR 0016 — The live driver runs inside the app, and only in a sandbox

**Status:** accepted

## Context

`tools/uishot` photographs screens; it cannot press a button and watch what
happens next. Several behaviours only exist in a running window (a scan that
finishes, a setting that changes the next scan, a screen that fails to build).
Other projects of this author use a *live driver*: a script runs **inside** the
real application, on Tk's own timer, with no mouse or keyboard synthesis, and
leaves an evidence ledger. TokenSave Manager's `templates/drive/` is the pattern.

PolyScour deletes files. A scripting hook in such a program is itself a
hazard, so the driver needed more guard rails than the template has.

## Decision

1. **In-app, not an external harness.** `src/polyscour/drive/driver.py` is
   started by `app.py` only when `POLYSCOUR_DRIVE` is set. Widgets are driven
   through Tk (`invoke()`, `toggle()`), never by input events.
2. **The ledger is Manager's, unchanged.** `drive/ledger.py` is a byte copy,
   pinned by SHA-256 in `tests/test_drive.py` (and compared with Manager's copy
   when it is on the machine). Channels are added around it, never inside it.
3. **Sandbox or refusal.** The driver exits 2 unless `POLYSCOUR_DATA_DIR` is
   set, and always in a built program (`polybedrock.paths.is_frozen()`). The
   launcher (`tools/drive/__main__.py`) redirects data, TEMP, LOCALAPPDATA,
   APPDATA, USERPROFILE and PROGRAMDATA into one throwaway directory.
4. **An allowlist, not a denylist.** A script may click only whole-label matches
   of `scan`, `scan for things to clean`, `cancel`, `preview`, `open storage`,
   and toggle three named settings. Nothing that changes the machine is on it.
   v1 deliberately has **no step that performs a real clean**.
5. **A script it does not understand is refused before a window opens.**
   Unknown scenario keys, step names or step keys exit 2; a script must end
   with `quit`. Ignoring an argument means acting on the overlap between what
   the author meant and what the driver understood.
6. **The PolyShield port override is drive-only.** `POLYSCOUR_DRIVE_POLYSHIELD_PORT`
   is applied inside `driver.begin()` after the gates, so it cannot redirect
   the product's loopback traffic in normal use. The scripted PolyShield in the
   launcher is the single shared fake, `tests/_polyshield_fake.py`, which holds
   PolyShield's verbatim matching code and is compared with the real file by
   AST when that checkout is present.
7. **The verdict is the report's.** The launcher exits 0 passed / 1 failed /
   2 refused / 3 could not run, and flags a disagreement between the child's
   exit code and its report.

8. **The console is evidence too.** The pinned ledger hears warnings, ERROR
   records and uncaught exceptions, but not a `print`, a library writing to
   stderr, or an INFO record -- what `run.bat --console` shows. `driver.Console`
   (built around the ledger, never inside it) tees stdout/stderr and records
   every logging record. Scripts assert with `console_contains` /
   `no_console_text` (optional `stream`: stdout, stderr, log); the report gains a
   `console` section (tail plus a `dropped` count, because a bounded tail that
   hid its own start would let "no such text" pass on lines never seen). It never
   fails a run by itself -- a library may legitimately chatter -- and the
   driver's own narration bypasses it.

## Consequences

- Two lessons from building it: the template's `quit` raced a destroy plus a
  0.2 s timer and a *failed* run exited 0, so `quit` now exits immediately when
  a script is set; and `must_fail.json` is shipped because a check that cannot
  say no is not a check.
- The first real finding: Game Mode builds one row per running process and
  spends ~7,500 of Windows' 10,000 per-process USER objects on one machine, so
  later screens fail with `No more menus can be allocated`. `handle_budget.json`
  encodes it; its test is a strict xfail until the screen's cost is bounded.
- The whole-app walks take ~25 s and read this machine's real state, so they are
  local gates like the golden check (skipped when `CI` is set; force with
  `POLYSCOUR_DRIVE_FULL=1`).
- Not done on purpose: typed-confirmation dialogs and real cleans. Adding them
  would need their own threat entry first.
