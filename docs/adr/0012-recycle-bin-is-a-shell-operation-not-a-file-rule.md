# 0012 — The Recycle Bin is a Shell operation, not a file-glob cleaning rule

**Status:** Accepted · **Date:** 2026-09-27

## Context

Every cleaning rule PolyScour has shipped so far names a symbolic `RootFamily`
in `safety/policy.py`, is walked by `cleaning/scanner.py`'s glob-based
DISCOVER step, and is deleted file by file in `cleaning/executor.py`. Emptying
the Recycle Bin was the next candidate, and the obvious implementation is to
treat `$Recycle.Bin\<SID>` as one more `RootFamily` and let the existing
machinery walk and unlink it like any cache.

That is the wrong implementation, for two independent reasons.

## Decision 1 — The Shell API is the authority, not the filesystem layout

`$Recycle.Bin\<SID>` is Windows' own bookkeeping for an index the Shell
maintains, not a directory a rule chooses to point at. Deleting its contents
directly — rather than through `SHEmptyRecycleBinW` — risks corrupting that
index, particularly if a run is interrupted partway by a locked item, which is
an ordinary condition PolyScour's own "never force" rule guarantees it will
hit sooner or later on a live machine.

PolyScour therefore asks the Shell, not the filesystem:

- **`SHQueryRecycleBinW`** for DISCOVER — item count and total bytes, without
  enumerating a single file.
- **`SHEmptyRecycleBinW`** for EXECUTE, with its own confirmation, progress
  dialog and sound suppressed (`SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI |
  SHERB_NOSOUND`) — PolyScour's own confirmation is the single consent
  surface for this operation, and a second, Windows-drawn confirmation on top
  of it would be noise, not an extra safeguard.

No `RootFamily`, no `PolicyEntry`, and no JSON rule file were added for this.
There is no glob-scanned path here for `safety/policy.py` to grant a rule
against, and inventing one that resolves to `$Recycle.Bin\<SID>` would
misrepresent a Shell operation as an ordinary directory rule. The guard chain
is not involved at all: the Shell API only ever operates on the current
user's own Recycle Bin, which is authorization enough on its own, in the same
sense that a user emptying it from Explorer needs no additional permission
check.

This is implemented in `cleaning/recyclebin.py`, called from
`cleaning/executor.py`'s `_rehearse`/`_perform` via a `finding.rule_id ==
recyclebin.RULE_ID` branch that runs *before* the generic per-finding path —
`recyclebin.RULE_ID` ("recycle-bin") is not registered in
`safety.policy.POLICY`, so reaching the generic path with it would raise
`PolicyViolation`, which is deliberate: it is the same failure a genuine
attempt to smuggle an unauthorised rule id through would hit.

## Decision 2 — Risk is `moderate` and the operation is explicitly irreversible

The obvious classification is `safe`: the user already decided to delete
these files once. That reasoning is wrong. **The Recycle Bin provides
recovery *before* this operation; emptying it permanently removes that
recovery path.** It is not a second, PolyScour-controlled undo layer — once
`SHEmptyRecycleBinW` succeeds, there is nothing left for PolyScour's own vault
or ledger to restore. Consenting to delete a file into the Recycle Bin is not
the same consent as consenting to its permanent destruction.

The rule's `RiskLevel` is therefore `MODERATE`, `reversible=False`, and its
`Evidence.rationale` states the recovery-path framing directly rather than
leaving it implied. `cleaning/planner.recommend()` already refuses to
pre-tick anything above `SAFE`, so this finding arrives unticked with "Not
regenerable... review before selecting" or "Permanent. Review before
selecting", exactly as any other moderate/irreversible finding would.

## Decision 3 — The operation is per-volume, and verified after the fact

A Recycle Bin's natural unit is one figure per volume (`Recycle Bin on C: —
3.8 GB, 1,842 items`), not one `Finding` per contained file — `SHQueryRecycleBinW`
does not enumerate files at all, and manufacturing thousands of synthetic
`Finding` objects to fit the per-file shape would misrepresent what is
actually being planned. `cleaning/recyclebin.scan()` therefore produces one
`Finding` per fixed volume with a non-empty bin, `path` set to the volume
root (`"C:\\"`) rather than a deletable file.

The executor re-queries `SHQueryRecycleBinW` immediately after
`SHEmptyRecycleBinW` succeeds and compares the before/after item count and
byte total. If the bin is not actually empty afterward — most likely because
an item was locked by another process — the run is `bytes_freed`-honest
(reporting only what the before/after difference actually shows) and the
overall `ActionResult.outcome` becomes `SUCCESS_WITH_UNEXPECTED_REMAINDER`
rather than a silent `SUCCESS`. This is a new `OperationOutcome` member,
distinct from `SUCCESS_WITH_SKIPS`, because there is no single failed
`Finding` to attach a `Skip` to that explains it — only the bin's own
before/after figures do.

## Consequences

- `cleaning/rules.py` and `rules/cleaners/*.json` are untouched; this feature
  does not go through the JSON-rule pipeline at all, and `docs/CLEANING_RULES.md`
  says so.
- `Executor` gained one more thing it must recognise before treating a
  `Finding` generically (`finding.rule_id == recyclebin.RULE_ID`). If a second
  non-file-glob operation is ever added, this special-casing is worth
  replacing with a real `operation_type` distinction on `Finding`/`Rule`
  (`FILE_DELETE` / `VAULT` / `SHELL_OPERATION`) rather than accumulating a
  third `if rule_id ==` branch — not done now, because one special case does
  not yet justify the abstraction.
- The Recycle Bin cannot be selectively cleaned by age, size, or file type
  from this screen; that would require enumerating its contents, which is
  exactly the filesystem-level access this decision avoids.
