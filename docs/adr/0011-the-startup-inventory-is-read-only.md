# 0011 — The Startup inventory lists more than the Run keys, and changes none of it

**Status:** Accepted · **Date:** 2026-09-23

## Context

The Startup Manager (`startup/manager.py`) reads the registry `Run` values and
can flip Task Manager's approval byte for them. On the machine this was
developed on, that is one of five places Windows starts things from:

| Mechanism | Found here |
|---|---|
| `Run` values (HKCU, HKLM, 32-bit view) | listed and switchable today |
| Startup folders | 1 |
| `RunOnce` keys | 0 |
| Scheduled tasks with a logon or boot trigger | 57 |
| Services set to start automatically | 105 (22 outside the Windows folder) |

A screen titled "Startup" that shows only the first row is an incomplete
account of what starts up, which is the "63 devices not reporting OK" failure in
the opposite direction: a reassuring short list that is short because of where
it looked.

Widening the *reading* and widening the *authority to change* are different
decisions, and the invariant that a finding is not a recommendation says to
keep them apart.

## Decision 1 — The new sources are read-only, with no switch

Scheduled tasks and services are listed with the exact mechanism that starts
them, what they launch, whether that target exists, who they run as, and their
enabled state. They have no toggle.

Disabling a task or a service is a different mechanism (Task Scheduler's
`Enabled` setting; the service's `Start` value or the Service Control Manager),
each with its own failure modes — a disabled service can break the thing that
depends on it, and nothing on this screen can see dependencies. That deserves
its own threat-model entry and helper operation *before* there is code, the same
order as the elevated helper (PR #6 before #7). This change adds **no** helper
operation, no `RootFamily`, no `PolicyEntry`, no ledger row and no vault use.
`inventory.py` contains no call that writes, and a test greps for the ones that
would (and is shown able to fail).

## Decision 2 — Tasks are read through `schtasks.exe`, not the filesystem

`%SystemRoot%\System32\Tasks` cannot be listed without administrator rights
(measured: `WinError 5`), and neither can the registry `TaskCache`. The
unelevated door is `schtasks.exe /query /xml ONE`, invoked by absolute path,
with `shell=False`, a fixed argument list containing no user input, no window,
and a 60 s timeout. A test asserts exactly that command line.

Two properties of its output were **measured, not assumed**, because the first
draft assumed both and was wrong:

- Piped, it is a single `<Tasks>` wrapper with `<!-- path -->` comments and **no
  `<?xml` header**. The first version looked for headers, found none, and
  reported "no scheduled tasks" — with no error — on a machine with 226. The
  reader now treats output it cannot use as *unread*, never as empty, and a test
  keeps that regression.
- It is written in the console's OEM code page. A character that does not
  survive decoding is left as U+FFFD and makes the target *unresolved*, never
  "not on disk": a path that might be wrong must not become a confident
  "missing".

## Decision 3 — One filter, by location, and it is counted

Hundreds of tasks and services are Windows' own and would bury the few that are
not. A task or service is **counted and not listed** only when *every* program
it runs is inside the Windows folder. This is a claim about a *location*, not
about trust, and the screen says how many were left out.

Rejected alternatives:

- **Filter by the task's name or path (`\Microsoft\Windows\…`).** Anyone can
  create a task there, so this hides exactly what an inspector wants to see.
- **Filter by publisher signature.** Needs Authenticode verification per file:
  a large new surface, and "signed" is still not "wanted".
- **Show all 400.** Accurate and unusable; it hides the answer in volume.

The filter is fail-open: an action it cannot read (empty command, an action type
with nothing to compare, a COM class with no registered server) keeps the row
listed. Services hosted by `svchost.exe` are judged by their `ServiceDll`,
because otherwise a third-party service hosted there would sit under
`C:\Windows\System32\svchost.exe` and be counted as Windows' own.

## Decision 4 — Loading is off the UI thread and each source fails alone

`read_inventory()` runs through `app.run_off_thread`; a screen that freezes
behind a subprocess is the wrong trade for a section that changes nothing. Each
source has its own status, so one failing marks only itself *unread* — shown in
its own section — and never blanks the others or reads as "none found". An
answer that arrives after the list was rebuilt is dropped.

## Consequences

- The Startup screen gains an "Also starts with Windows — view only" section.
- Nothing that runs elevated changes; the helper's operation set stays closed.
- `.lnk` targets in Startup folders are not resolved (that needs COM); a
  shortcut is listed as the file it is.
- Per-user COM class registrations are not consulted, so such a task stays
  listed with "no registered server found" rather than being hidden.
- **Found while doing this, and deliberately not fixed here:** Windows keeps the
  approval byte for `HKLM\...\WOW6432Node\...\Run` values under
  `StartupApproved\Run32`, while `startup/manager.py` reads (and would write)
  `StartupApproved\Run` for them. Observed on this machine: the one 32-bit
  entry has its record under `Run32`, so a 32-bit entry disabled in Task Manager
  would show as enabled here. That is a defect in the *writing* half of the
  Startup Manager, so it is a separate change with its own tests, not folded into
  a read-only one. The byte values seen in `Run` (`02`, `03`, `04`, `06`) also
  go beyond the two the reader distinguishes; what `04` and `06` mean has not
  been established here.
