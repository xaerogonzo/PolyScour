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
