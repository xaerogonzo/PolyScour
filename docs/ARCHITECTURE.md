# Architecture

## The pipeline

Every destructive subsystem follows the same shape, and the separation is the
point: no stage can do the next stage's job.

```
DISCOVER ─ ANALYZE ─ PRESENT ─ PLAN ─ CONFIRM ─ EXECUTE ─ VERIFY ─ LOG
   scanner.py          planner.py          executor.py       ledger.py
```

- **`scanner.py`** has *no destructive capability at all* — not a guarded one,
  none. It walks, measures and describes. That is why "scan" can be the default
  thing the product does, and why it needs no elevation.
- **`planner.py`** turns findings into recommendations. This is where *a finding
  is not a recommendation* lives: nothing above `SAFE` is pre-ticked.
- **`executor.py`** is the only code in PolyScour that removes anything.
- **`ledger.py`** records every operation, including dry runs, labelled as
  rehearsals.

## Layers

```
views/          CustomTkinter. No business logic. No safety decisions.
   │
app.py          Shell + Services (one Guard, Vault, Ledger, Scanner, Executor)
   │
cleaning/       scanner → planner → executor
   │
safety/         policy → guard → reparse.      THE AUTHORITY.
   │
polybedrock        paths, settings, ps_run, win_security, capabilities
```

Dependencies point downward only. A view that made a safety decision, or a
scanner that deleted something, would be an architectural failure rather than a
bug.

`Services` is constructed once in `app.py` and passed to every view. A view
building its own `Executor` could get a `Guard` with no exclusions, quietly
widening what the product may delete — so views never construct one, and a test
asserts they share.

## The safety layer

See [SAFETY.md](SAFETY.md) for the full chain. Structurally:

| Module | Responsibility |
|---|---|
| `safety/policy.py` | `RootFamily`, `Operation`, `Scope`, `PolicyEntry`, `POLICY`. **Code, not data.** Resolves symbolic families to concrete directories. |
| `safety/reparse.py` | Component-wise reparse inspection *before* canonicalisation; containment; volume check. |
| `safety/guard.py` | Runs the chain, applies the denylist and exclusions, returns a canonical path. |

Rules never name paths. `rules/cleaners/*.json` names a `RootFamily`; only
`policy.py` knows what one resolves to.

## Data flow

```
rules/cleaners/*.json
   │  rules.load_all()  — validated, reconciled against POLICY (narrow only)
   ▼
Rule[]  ──► Scanner.scan(cancel, on_progress)
                 │  per candidate: guard.authorize()
                 ▼
            ScanResult { RuleOutcome[] { Finding[] , aborted, reason } }
                 │  planner.recommend()
                 ▼
            Recommendation[]  ──► user ticks groups ──► planner.plan(dry_run)
                 ▼
            ActionPlan (frozen)  ──► Executor.execute()
                 │  per item: guard.authorize() AGAIN
                 │  VAULT ops: vault.store() → verify → remove
                 ▼
            ActionResult { outcome, skips, reversals }
                 ├──► vault.write_manifest()   once, at the end
                 └──► ledger.record()
```

`ActionPlan` is frozen and separate from `ScanResult` because the set the user
confirmed is not necessarily the set that was found — and that difference is
exactly what a confirmation step is for.

## Game Mode

A second feature with a second authority, and deliberately not part of the
cleaning pipeline above. It does not touch the filesystem, so it does not run
through the guard chain; it gets its own veto in `gamemode/policy.py`, built to
the same principle — the user's selection proposes, reviewed code disposes.

```
enumerate  ->  veto (list time)  ->  user selects  ->  veto AGAIN  ->
    record in ledger  ->  suspend
```

The second veto is not redundant. A PID can be recycled between building a list
and acting on it, which is the same race `authorize()` is called twice to lose.

### Ordering, and what it buys

`record_suspension` runs **before** `suspend_pid`, mirroring "vault object
before delete". Dying between the two costs one harmless resume at next launch;
the reverse order would leave a frozen process nothing knows how to release.
`Services.__init__` calls `gamemode.recover()` on every start, before any view
exists, and compares the recorded process creation time so a reused PID is
identified rather than resumed blindly.

### Threading and locking

A Game Mode session holds **no** lock for its duration. The mutation lock
serialises changes to the vault and ledger, and a session lasts as long as
someone is playing — holding it across that would block every other PolyScour
operation for hours. Each ledger write takes it briefly instead.

### The gap, and how far a supervisor closes it

Nothing resumes anything until PolyScour runs again. A hard kill with no
subsequent launch leaves processes frozen until reboot — `docs/THREAT_MODEL.md`
T12.

`gamemode/supervisor.py` narrows that and does not remove it.

```
  GUI  --(first successful suspension)--> supervisor (unelevated, detached)
                                              |
                                     OpenProcess(SYNCHRONIZE | ...)
                                     GetProcessTimes(handle) == expected?
                                              |  no --> exit, do nothing
                                              |  yes
                                     WaitForSingleObject(handle, INFINITE)
                                              |
                                     session.recover(ledger) --> exit
```

A **handle**, not a pid. A pid recycles; a handle names a process object, so
once opened it cannot be redirected. The creation time is read through
`GetProcessTimes` **on that handle** rather than looked up by pid again —
a second pid lookup would be answerable by whatever owns the number now, which
is the confusion the check exists to detect.

It calls `session.recover(ledger)`, not a copy. If the parent exited cleanly
there are no open rows and recovery does nothing, which is why one code path
serves both endings.

`ensure_running()` is idempotent and never raises: Game Mode can be entered and
left repeatedly in one run, and a supervisor is an improvement on the failure
path rather than a precondition. If it cannot start, recovery still happens at
the next launch — where it happened before this existed.

What it buys is a smaller window — "until PolyScour's process ends" rather than
"until the user next opens it, which may be never" — and T20 says plainly that
a kill taking both processes leaves the original gap untouched. The Game Mode
screen says so too, in one sentence, whenever anything is frozen.

## The Storage Analyser

The only subsystem with no executor, and the only one that calls no guard.

```
storage/volumes.py    which fixed volumes exist, and how full Windows says they are
storage/analyser.py   a budgeted, read-only, depth-first walk of exactly one of them
views/storage_view.py three sorted lists and a residual panel; zero action controls
```

`cleaning/` is DISCOVER -> ANALYZE -> PLAN -> EXECUTE. This stops after ANALYZE
and imports neither a planner nor an executor, which is why it lives outside
that package rather than inside it: a read-only walker filed next to the only
module that deletes things is a walker somebody eventually wires to it.

### Why the guard is not in this chain

`safety/guard.py` authorises an *operation against a path*. There is no
operation here, and `Guard.authorize()` takes one. Calling it anyway would not
be harmless belt-and-braces — the guard refuses everything outside the eight
root families, and everything outside those families is what this subsystem
exists to describe. `docs/adr/0007` records the decision so a reviewer does not
read the absence as an oversight.

`safety/reparse.is_reparse_point()` *is* reused, as a measurement rather than a
safety check: a junction is skipped because descending it double-counts and can
loop, not because it is dangerous.

### The residual, and what may not go into it

The walk's total never equals used space. That gap is reported with the same
prominence as the total, because an unexplained 120 GB is the
"63 devices not reporting OK" failure in a new costume.

Three categories, and keeping them apart is the whole design:

| | Carries | Why |
|---|---|---|
| `ResidualReason.*` | **bytes** | Space we could not see *and can quantify* — the size and time budgets, system-managed regions |
| `permission_denied_directories` | **a count** | We could not open it, so its size is precisely what we do not know. A byte figure would be invented |
| `reparse_points_skipped`, `hardlinks_deduplicated` | **counts** | Those bytes are counted elsewhere in the tree. Putting them in the residual would invent missing space out of correct deduplication |

`residual_breakdown()` derives its unexplained remainder rather than
accumulating one, so the parts cannot disagree with the whole.

### Sizes, and one measurement that overturned the design

`st_size` is logical. `scandir` supplies `st_file_attributes` free, and
`FILE_ATTRIBUTE_COMPRESSED` / `FILE_ATTRIBUTE_SPARSE_FILE` mark exactly the
files whose on-disk size differs — so `GetCompressedFileSizeW` is called only
for those. Both sizes are carried on every node.

Hardlinks cost more. `scandir` reports `st_ino = 0` and `st_nlink = 0` on
Windows — the attributes exist and the values are zero, because directory
enumeration does not carry them — so deduplication needs a full `os.stat()`.

A shortcut was tried and abandoned, and the reason is recorded in the source
because reasoning would not have reached it. "Stat under `%SystemRoot%` only"
was supported by measurement (86.7% of `System32` files hardlinked, 0% across
120,000 files of user data) and failed twice: an audit that stat'd one skipped
file in 500 anyway found **27% violations** on a full C: walk, and timing showed
the shortcut was *slower than not having it* — `Path.is_relative_to()` per file
costs more than the `os.stat()` it avoided.

```
no stat at all           16,819 entries/s   double-counts
stat everything          13,514 entries/s   correct
stat under %SystemRoot%  12,193 entries/s   wrong AND slowest
```

Correctness costs 1.24x. CLAUDE.md's rule — performance work needs a
measurement, not a guess — held in both directions here.

### Budgets, and stopping honestly

`cleaning/scanner.py` aborts a rule that exceeds its ceiling, because a partial
cache figure presented as complete is a lie. The analyser cannot do that:
exceeding the budget on a large disk is the *normal* case. So it takes a
wall-clock and an entry budget, and reports `StopReason` — `COMPLETED`,
`BUDGET_EXHAUSTED`, `TIME_EXHAUSTED`, `CANCELLED`, `ERROR` — rather than a
`complete: bool`. A scan that ran out of time says something about the disk; one
the user cancelled says nothing at all.

Volume usage is snapshotted at **both ends**, so a machine that wrote 1.8 GB
during the walk reads as a machine doing its job rather than an analyser that
cannot add up.

One volume per call. A single sweep over every disk gives worse progress, worse
cancellation, and a residual that means nothing because it mixes several
volumes' unreadable directories together.

## The Startup Manager

The second feature outside the cleaning pipeline, and the first that writes to
the registry.

```
polybedrock.startup.iter_run_entries()   read: hive, key, value name
        |
   startup/manager.py     read the approval byte; classify the target
        |
   startup/policy.py      may this be changed?
        |
   startup/service.py     veto -> ledger record -> registry write
```

`policy` imports `manager` (for the record type), so the orchestration cannot
live in either without making the pair circular — hence `service`.

### Identity

An entry is named by `hive \ key path \ value name`, never by position.
Enumeration order is not guaranteed, so a stored index would point at a
different entry after any change to the key. The identity is a readable string
rather than a hash, so a ledger row remains legible a year later.

### State

`enabled` and `target` are separate facts, not one status. An entry can be
disabled *and* have a missing file, and collapsing them would force a choice
about which to show. `TargetState.UNRESOLVED` exists because a `Run` value whose
command line cannot be parsed is common, and forcing it into present/missing
would be inventing a fact.

Absence of an approval record means **enabled** — that is Windows' default, and
most entries never get a record. Orphan records (an approval naming a `Run`
value that no longer exists) are excluded: they are not startup items, and
listing them would offer a switch that governs nothing.
## Two lifetimes: resource and data

    RESOURCE   ships with the build, read-only, may sit in a temporary
               extraction directory that is DELETED when the process exits
    DATA       written by the user or the application, must survive a restart

`polybedrock.paths` opens with that distinction; `paths.resource_root()` is
PolyScour's half of it. Conflating them is how a onefile build loses a vault:
resolve durable state under the extraction directory and every file a user
believed was recoverable disappears when they close the program.

`resource_root()` derives from `__file__`, and the level differs because a
build has no `src/` level:

    checkout    src/polyscour/paths.py   ->  parents[2] is the repo root
    build       polyscour/paths.py       ->  parents[1] is the bundle root

Not from `sys.executable`, which looks obvious and is wrong: in a Nuitka
standalone build it names a `python.exe` that does not exist. Its parent
happens to be right, so that version works by luck on a path to nothing.

Cleaning rules are a resource, so a packaged build carries them inside itself
and an installed machine has no rules folder to edit.

**Only a real build can check the level.** The suite drives frozen behaviour
by overriding a flag, which covers the policy and not the detection.
`tools/build_probe.py` is compiled with the same flags, run from the build, and
`build.ps1` fails if it reports anything durable resolving under the extraction
directory.

## The installer, and what it is for

One thing: **who may write the program directory.**

`PolyScour.exe` is also the elevated helper, so every rule inside it is worth
exactly as much as the answer to that question — T15. `set_program_acls.ps1`
sets `Administrators:F`, `SYSTEM:F`, `Users:ReadAndExecute`, disables
inheritance, and sets the owner to Administrators, because an owner can rewrite
a DACL whatever it says.

It installs no data root. PolyScour has no privileged writer, so the vault,
ledger and settings stay in `%LOCALAPPDATA%` and the application creates them
itself — `docs/adr/0005`.

`-Verify` runs twice: once from the installer, and once by hand as an ordinary
user. Only the second proves anything. An administrator can write anywhere, so
an elevated check describes the boundary rather than crossing it; the script
says so and skips the write probe rather than reporting a pass it did not earn.

## The entry point: one executable, two programs

`PolyScour.exe` with no arguments is the GUI. `PolyScour.exe
--elevated-helper <request>` is the helper. There is no `helper.exe` — the
helper has to be the same trusted binary in the same administrator-protected
directory, or it is a second thing to protect and a second thing to verify.

`entry.py` is the compiled entry point, **not** `app.py`, and imports neither
branch at module scope:

```
argv --> entry.main()
           |
           +-- "--elevated-helper" --> import helper, run it, exit
           |                           (no GUI import happens on this path)
           +-- nothing              --> import app, mainloop()
           +-- anything else        --> refuse, exit 2
```

`app.py` imports CustomTkinter at module scope, so entering through it would
load Tk and Tcl into an elevated process — an enormous increase in what runs at
privilege, for nothing. A subprocess test asserts `customtkinter` is absent
from `sys.modules` after a real elevated run; asserting it in-process would
prove nothing, because pytest has already imported it for the UI tests.

Unknown arguments are refused rather than ignored, and `--elevated-helper` is
an exact string: `--elevated-helper-x` and `--ELEVATED-HELPER` are unknown
arguments, with a test each. See `docs/adr/0006`.

### Frozen and source differ, and the difference is asked once

`elevation/client._helper_command()` chose its branch with `sys.frozen` — which
is **PyInstaller's** flag. Nuitka, which builds this project, injects
`__compiled__`. A compiled build would have taken the source branch and asked
the executable to run a module, and only an installed build would ever have
shown it.

`polybedrock.paths.is_frozen()` already answers correctly for both packagers
and is overridable for tests. There is now one predicate, and
`test_the_two_modes_disagree` catches a future one that always answers the same
way.

## The elevated helper

Specified in `docs/THREAT_MODEL.md` before it was written. The shape:

```
  PolyScour GUI (unelevated)
        |  writes one request file, ShellExecute("runas")
        v
  helper.py (elevated)  --> re-runs the SAME guard chain --> acts --> exits
        |  writes <request>.response beside it
        v
  GUI reads the result
```

### Why the GUI launches it rather than connecting to it

There is no port and no pipe waiting to be claimed, so there is nothing for
another process to impersonate. The response is advisory: a lying one can
produce a wrong History entry, never a wrong privileged action.

The request file is writable by the unelevated user, which makes it
attacker-controlled input by construction. That is fine, and it is the reason
the helper re-authorises everything rather than trusting what it reads.

### Validation happens at privilege, not before it

`helper.handle` runs `polyscour.safety.Guard.authorize` in its own process
against the path as it exists at that moment. This is the same reasoning that
already makes `authorize()` run twice inside the unelevated app, taken one step
further: different time, different process, **different privilege level**, and
only the last one is the security boundary. The GUI's check keeps bad requests
off the wire; it proves nothing.

The helper also refuses directories outright. A recursive delete at
administrator privilege driven by a caller-supplied path is the most dangerous
thing it could offer, and nothing needs it.

### The batched operation, and why it is the narrow one

`DELETE_APPROVED_PATHS_FOR_RULE` takes a rule id and the user's exclusions. It
takes **no path**: the helper resolves the rule's permitted roots from its own
`safety/policy.py` and walks them itself. So the operation covering hundreds of
files is narrower than the one covering a single file — the caller loses the
ability to name a target at all.

It exists because per-file elevation is one UAC prompt per file, and
`windows-temp` is several hundred files. See T19 and `docs/adr/0004`.

Three things follow from the helper doing its own enumeration:

- **The age floor moves into `PolicyEntry`.** The helper must not read
  `rules/cleaners/*.json` to decide how much to delete: that is data the caller
  could have rewritten. `min_age_days` is now a floor in reviewed code, which a
  rule may raise and never lower — the mirror of how the ceilings already work.
- **`authorize()` runs per item**, immediately before that item's `unlink()`.
  Never once for the batch; hoisting it would collapse the TOCTOU protection
  into one check with a long window behind it.
- **The client's timeout becomes a *silence* timeout.** A batch can outlast any
  fixed limit, and treating that as a dead helper is the dangerous failure: the
  GUI reporting failure and re-scanning while an elevated process is still
  deleting. The helper heartbeats; the clock resets on it. A cancel sentinel
  file goes the other way.

### Nothing asks for elevation on its own

`Executor(allow_elevation=False)` is the default and has no path to the helper.
The flag is **run-scoped**: `clean_view` builds a fresh `Executor` for an
administrator retry rather than setting it on the shared one, so consent cannot
outlive the click that gave it. There is no settings key, and there must never
be one — a persisted "always elevate" is the retained elevation the threat
model refuses.

Only `SkipReason.PERMISSION` is retried. A locked file is in use, and
administrator rights do not open it; offering to elevate for one would spend a
prompt to achieve nothing.

The offer appears **after** a run, never before, and names both what it will
retry and what it will not — 412 needing administrator rights next to 23 in use
must not read as 435 about to be handled.

### The four elevation facts

`ElevationRecord` carries requested / granted / attempted / succeeded rather
than a boolean, because "elevated: yes" is untrue in both common failure paths:
a declined prompt was requested and not granted, and a partial run was granted
and did not finish. The ledger has a column for each, added to `operations` by
an additive migration — `CREATE TABLE IF NOT EXISTS` does nothing to a database
that already exists, and a history file must survive an upgrade intact.

### What the helper does *not* unblock

`docs/adr/0001` deferred moving the vault to `%ProgramData%\PolyScour` "in 0.2,
alongside the installer and the elevated helper". The helper arrived, and
re-examining the deferral is what showed the premise was wrong —
`docs/adr/0005` supersedes it.

`%ProgramData%` makes PolyShield's data a boundary because a LocalSystem
*service* owns the protected subtrees and the GUI only reads them. PolyScour's
vault is written by the unelevated GUI on every clean, so the writer and the
would-be attacker are the same principal: an ACL that lets PolyScour write its
own history lets anything running as the user write it too.

The helper is not that owner and is deliberately the wrong shape to become one.
It is launched per operation and exits; making it the vault's writer would mean
a UAC prompt per clean, which is retained elevation with extra steps.

**The vault stays in `%LOCALAPPDATA%`, and T5 stands as written** — a
convenience, not a security boundary. The installer is unblocked and smaller for
it: what it must protect is the *program directory*, because an attacker who can
rewrite the helper has defeated every rule inside it (T15).

## The Startup Manager and privilege

`startup/policy.py` answers two questions that used to be one string:

```
veto(item)                may this change at all?     absolute, any privilege
requires_elevation(item)  what would it cost?         a prompt, not a refusal
```

A cost is something a user can choose to pay. Machine-wide entries are no
longer refused; they route through `SET_MACHINE_STARTUP_APPROVAL`, which
re-applies the absolute vetoes at privilege, compares `expected_raw_value`
against what the entry launches now, writes, and **reads back** — because
`SetValueEx` returning without error is not evidence the value is what was
asked for.

`startup_view` runs an elevated toggle through `run_off_thread`. The UAC prompt
is modal to the desktop rather than to us, so doing it inline freezes the window
behind the dialog and Windows paints it as "not responding".
## Threading

Tk is not thread-safe. One rule covers it:

> Work happens on a worker thread; **widgets are touched only on the UI thread**,
> via `App.run_off_thread(work, done)` or `self.app.after(0, ...)`.

A full scan of a real machine takes ~39 seconds. Inline, that would freeze the
window and make **Cancel** unclickable, defeating the point of cancellation.

- `Scanner.scan(cancel, on_progress)` — `on_progress` fires on the worker
  thread every 2,000 files; the view marshals it with `after(0, ...)`.
- Cancellation is a `threading.Event`, checked **between** items — never inside
  one. A cancelled run leaves completed items completed and writes exactly one
  manifest describing them.

## Concurrency across processes

The GUI, a future scheduled task, a future CLI and a future elevated helper can
all want to act at once.

> Only one mutating PolyScour operation may hold the ledger/vault mutation lock
> at a time. Scanning may run concurrently; mutation serialises.

One lock covers **both** the ledger and the vault, because a vault write and its
ledger row are a single logical change and a lock per store would let a second
process interleave between them. It is a cross-process `msvcrt` file lock, not a
`threading.Lock` — the processes above are genuinely separate.

PolyShield learned what an in-process lock buys you here (nothing) the expensive
way: two components that resolved the lock file to *different paths* were both
handed the lock, silently, over a SQLite write. Hence one path, derived once,
from `polyscour.paths`.

## Storage

```
%LOCALAPPDATA%\PolyScour\
├── config\settings.json      atomic write + cross-process lock (polybedrock)
├── history.sqlite            operations, reversals, skips
├── history.lock              the mutation lock
└── vault\
    ├── VERSION
    ├── objects\aa\bb\<sha256>    content-addressed payload, sharded
    └── manifests\<operation>.json
```

`%LOCALAPPDATA%`, not `%ProgramData%` — see
[adr/0001-vault-location.md](adr/0001-vault-location.md) and
[adr/0005-the-vault-stays-user-scoped.md](adr/0005-the-vault-stays-user-scoped.md).
PolyScour has no privileged writer: everything that touches the vault runs as
the logged-in user, so per-user storage is correct and gets sound ACLs for free,
and a machine-wide tree could not wall the vault off from the only process that
writes it. This is settled rather than pending.

**Vault collection rule:** an object may only be collected when no retained
manifest references it. Refcounted by scanning manifests rather than by keeping
a count, because a stored count can drift out of agreement with reality and a
derived one cannot.

## Performance

The first live scan took over 90 seconds and did not finish. Measurement, not
inspection, found why:

| Cause | Cost | Fix |
|---|---|---|
| `permitted_roots()` globbed the Chrome profile tree **once per candidate file** | 7.2 ms × ~36,000 | Per-operation root cache (`Guard.begin()`) |
| `root.resolve()` recomputed per file on an already-canonical path | ~19 s total | `assert_within(root_is_canonical=True)` |

Result: **>90 s → 39 s** for 36,194 findings across 8 rules.

Neither fix weakens the guard. What protects an individual path — the per-file
reparse walk, containment, the denylist, exclusions — still runs on every single
file, every time. Only the *root set* is cached, and only for one operation.

## The PolyBedrock substrate

`polybedrock-core` and `polybedrock-ui` are shared with PolyShield and owned by
neither. See [../PolyBedrock/docs/adr/](../../PolyBedrock/docs/adr/) for what was
extracted and, more importantly, what was not.

PolyScour consumes `polybedrock.paths`, `polybedrock.settings`,
`polybedrock.win_security`, `polybedrock.capabilities` and `polybedrock.ui.theme`.

## Testing the GUI

`tools/uishot/` photographs every screen with **no visible window, no focus
stealing and no mouse control**, then diffs the result against recorded goldens.
The machinery is shared with PolyShield via `polybedrock.ui.uishot`; what lives
here is PolyScour's scene list and its entry-point wiring.

Two things make it trustworthy rather than merely convenient:

- **A hidden Win32 desktop, not off-screen coordinates.** Tk will not paint a
  window positioned outside the virtual screen — a window parked at
  (-3200, -3200) captures its text but none of its backgrounds. Measured on
  PolyShield: 95.58% of pixels wrong off-screen, 0 of 912,000 wrong through a
  hidden desktop.
- **The real entry point is imported.** `app.py` sets the CustomTkinter
  appearance mode at module level; a harness that skipped that would render
  every unstyled label against the wrong defaults and hand back a screenshot
  that looks fine and is wrong.

Scenes construct their state directly — a real scan takes ~39 s and never
returns the same numbers twice. `POLYSCOUR_DATA_DIR` is redirected to a temp
directory before import, so photographing the UI cannot touch the real vault.

`test_uishot.py` runs the CLI through a **subprocess**: `SetThreadDesktop` fails
once the calling thread owns a window, and `test_ui_smoke.py` holds a Tk root.
