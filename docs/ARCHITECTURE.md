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

### The gap that is not closed

Nothing resumes anything until PolyScour runs again. A hard kill with no
subsequent launch leaves processes frozen until reboot. A supervising process
would fix it and is deferred to 0.2's elevated helper, where a second process
gets a threat model written before its code — see `docs/THREAT_MODEL.md` T12.

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

### Still deferred

`docs/adr/0001-vault-location.md` moves the vault to `%ProgramData%\PolyScour`
"in 0.2, alongside the installer and the elevated helper". The helper now
exists; the installer does not, and moving the vault to a machine-wide location
without one would leave it somewhere an unelevated PolyScour cannot write. It
stays where it is until the installer lands — and when that lands, the ADR's
premise needs re-deriving rather than assuming: the helper is per-operation and
does not persist, so it is not the privileged *owner* the ADR was waiting for.

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
[adr/0001-vault-location.md](adr/0001-vault-location.md). 0.1 has no service and
no elevated component, so per-user storage is correct and gets sound ACLs for
free; creating a ProgramData tree from an unelevated first run would inherit
permissive defaults.

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
