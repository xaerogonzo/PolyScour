# 0007 — The Storage Analyser changes nothing, and says what it could not see

**Status:** Accepted · **Date:** 2026-09-08

## Context

Every figure PolyScour produces today is a cleaning figure. A scan finds a few
hundred megabytes of cache, and the honest summary is *"we freed 900 MB"*.

What that number cannot say is **why it is small**. A user with a full 500 GB
drive reads "900 MB reclaimed" and concludes the tool is weak, when the correct
conclusion is that their disk is full of things a cleaner must never touch. The
product has no way to say that, and saying it is squarely within what this
product is for.

An analyser is also the cheapest possible next feature in the one currency this
codebase actually spends: **authority**. It needs no `RootFamily`, no
`PolicyEntry`, no fourth helper operation, no ledger row and no vault. Both
authority modules — `safety/policy.py` for paths, `gamemode/policy.py` for
processes — are untouched, and the elevated operation set stays closed at three.

Three decisions follow, and each has a plausible wrong answer that a later
reader would otherwise arrive at.

## Decision 1 — It does not call the guard, and that is not a hole

`safety/guard.py` is called twice by the cleaner, and `CLAUDE.md` says so
prominently. A reviewer finding a new filesystem walker that never calls it will
reasonably assume a mistake.

**The guard constrains what may be *changed*.** The analyser changes nothing —
it has no `DELETE`, no `VAULT`, no executor, no plan. There is no operation to
authorise, and `Guard.authorize()` takes an operation.

Calling it anyway would not be harmlessly redundant. It would break the feature
outright: the guard refuses everything outside the eight root families, and
everything outside those families is precisely what the analyser exists to
describe. A "safety check" that must be bypassed to do the job is not a safety
check; it is a habit.

The analyser does reuse `safety/reparse.is_reparse_point()`, but as a
**measurement** tool rather than a safety one. A junction is skipped because
descending it double-counts bytes and can loop —
`C:\Users\All Users` → `C:\ProgramData` is the standard example, and
`C:\Documents and Settings` → `C:\Users` is the other — not because it is
dangerous.

### What replaces the guard, since something must

Nothing in this module can delete, so the property to preserve is a weaker one:
it must not *become* able to. The structural answer is that the package has no
executor and imports none, and `storage/` sits outside `cleaning/` precisely so
that a read-only walker is not filed next to the only module that removes
things.

## Decision 2 — The residual is a first-class number, and a narrow one

A walk's total will not equal used space, and the gap is large: `$MFT`, `System
Volume Information`, `hiberfil.sys`, `pagefile.sys`, the `WinSxS` hardlink farm,
restore points, and every directory an unelevated process cannot read.

A screen that says *"your 500 GB drive holds 380 GB of files"* and leaves 120 GB
unexplained is **the same failure as "63 devices not reporting OK"** — a
confident number that means nothing, which is the thing this product exists to
replace. So the unaccounted-for figure is displayed, named, and given the same
prominence as the total.

**But it must not be inflated either**, and this is the part that is easy to get
backwards. Bytes behind a **skipped reparse point are usually not unaccounted
for** — they are counted elsewhere in the tree, which is the entire reason the
junction was skipped. Adding them to the residual would invent missing space out
of correct deduplication, and the resulting number would be wrong in the
alarming direction.

So the model separates two things that both look like "we didn't walk that":

| Goes into the residual (bytes) | A diagnostic counter only (count) |
|---|---|
| `permission_denied` | `reparse_points_skipped` |
| `budget_exhausted` | `hardlinks_deduplicated` |
| `time_exhausted` | |
| `system_managed` — named files, where readable | |
| `other_unaccounted` | |

The categories exist in the model from the start so the product can become more
informative without a rewrite. The *display* may lead with a single total and
decompose underneath; that is a UI decision, not a data one.

### Explorer is a cross-check, not ground truth

The acceptance criterion is deliberately not "walked + residual equals used
space". Filesystem metadata, reserved space, quotas, compression and cluster
slack all mean the two do not reconcile exactly, and requiring exact equality
would make the analyser assert a precision it cannot have — in the one feature
whose purpose is making uncertainty visible.

`volume_used` is therefore snapshotted at the **start and end** of every scan.
When it moves materially the report says so, because a machine that wrote 1.8 GB
during the scan is a machine doing its job, not an analyser that is broken.

## Decision 3 — Both sizes are modelled, and the expensive one is nearly free

`st_size` is the **logical** size. For sparse and NTFS-compressed files that is
not what the disk gave up, and this feature's entire pitch is *where the disk
actually went*. Reporting logical bytes for a compressed tree overstates
consumption, confidently.

The obvious fix is `GetCompressedFileSizeW`, and the obvious objection is that
it is one extra Win32 call per file across a walk of a million of them.

**Both are avoidable, and no profiling is needed to decide.** `os.stat()`
already returns `st_file_attributes` at no additional cost — it is the same
field `safety/reparse.py:36` reads — and two bits in it identify *exactly* the
files where the two sizes can diverge:

```
FILE_ATTRIBUTE_COMPRESSED   0x800
FILE_ATTRIBUTE_SPARSE_FILE  0x200
```

So the model carries **both** `logical_size` and `allocated_size`, the UI leads
with allocated where it is available and labels which it is showing, and the
Win32 call is made only for the small fraction of files that need it.

This is the same shape as the `st_nlink > 1` rule below, and as the
`permitted_roots()` lesson `CLAUDE.md` records: stop doing per-file work that
only a few files need. The difference is that here it was cheap enough to see in
advance, because the discriminating information was already being fetched.

### Hardlinks are deduplicated, and the assumption is tested rather than made

`WinSxS` is the worst case and exactly where a naive analyser invents tens of
gigabytes. Files are deduplicated on `(st_dev, st_ino)`, and **only when
`st_nlink > 1`**, so the set stays small.

Python populates `st_ino` and `st_nlink` on Windows, but these are not Unix
inodes and the presence of an attribute is not a guarantee about its semantics.
`tests/test_storage.py` therefore **creates real hard links on NTFS** and
asserts that two directory entries produce one counted allocation. If that turns
out not to hold on a supported runtime, the design needs a documented fallback
rather than silently wrong totals.

## Consequences

- A new package `src/polyscour/storage/`, not under `cleaning/`. `cleaning/` is
  DISCOVER → ANALYZE → PLAN → EXECUTE; the analyser stops after ANALYZE and has
  no planner or executor at all.
- Its own dataclasses rather than `Finding`/`ScanResult`. A `Finding` carries
  `reversible` and `requires_elevation`, which are properties of *something you
  might do to it*. Reusing the type would imply an action path that does not
  exist.
- `stop_reason` is an enum — `COMPLETED`, `BUDGET_EXHAUSTED`, `TIME_EXHAUSTED`,
  `CANCELLED`, `ERROR` — rather than a `complete: bool`. Those are four
  different things and the UI should be able to say which.
- Volumes are scanned **one at a time**. Clearer progress, clearer cancellation,
  and a residual that means something per volume.
- **No action controls anywhere on the screen.** No Delete, Clean, Remove or
  Optimise. Sorting by size is a fact worth showing; a button beside it is the
  recommendation the top invariant forbids.
- `docs/SAFETY.md`, `docs/THREAT_MODEL.md` and `docs/CLEANING_RULES.md` are
  **not** updated, and that is the finding rather than an omission: the analyser
  adds no authority, so it adds nothing to the guard chain, nothing to the
  threat model, and no rule format. Recording that here is worth more than three
  sections that say "nothing to add".

## The alternative that was rejected

A duplicate finder was the other candidate for this slot and is more useful to
users. It was declined for now because it inverts the rule that makes the guard
tractable: **a request may narrow, never widen.** Today the only user-supplied
paths are exclusions, permitted precisely because they can only ever cause a
refusal. A duplicate finder needs a user-supplied *scan root*, which widens —
and then a decision about which copy to keep, which is a recommendation the
program cannot honestly make.

That is not an argument that it can never be built. It is an argument that it
needs its own threat-model section first, in the order this project already
uses.
