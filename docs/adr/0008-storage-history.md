# 0008 — Storage history: what changed since the last scan, and what it cannot say

**Status:** Accepted · **Date:** 2026-09-21

## Context

The Storage Analyser (adr/0007) answers *where is the disk now*. The question a
person actually has is usually *where did it go* — the drive was fine last month
and is nearly full today. A single scan cannot say. Two scans can, and the
honest way to say it is the difference between them.

That is also where the easy mistakes are. Subtracting one scan's total from
another's produces a confident number, and there are at least four ways for it to
be wrong: the scans covered different territory, the volume is a different disk
that inherited a drive letter, a folder "appeared" only because a size cutoff
hid it last time, and the unaccounted-for part of the disk moved while the
accounted-for part did not.

This feature adds no authority. It reads what the analyser already produced and
writes one file of its own measurements.

## Decision 1 — Windows' own number leads, and the scan's attribution follows it

A comparison reports three figures, in this order:

1. **Volume used, then vs now** — Windows' figure, the one Explorer shows. It
   needs no scan to be complete, so it is reported even when nothing else can be.
2. **What the scan accounts for**, and where.
3. **The residual's own movement** — what the scan cannot see, moving separately.

They are not required to add up, and the model never claims they do. Residual is
clamped at zero (adr/0007), and compression and deduplication mean the tree can
measure less than the difference implies. A screen that made them reconcile would
be asserting precision it does not have, in the feature whose purpose is showing
uncertainty.

## Decision 2 — Retention is a first-class unknown, expressed as a ceiling

A snapshot cannot keep two million nodes. It keeps the largest directories, up to
a count, above a size floor, at any depth, and it **records how big an unlisted
directory could still be**: `directory_ceiling_bytes`.

That number is what makes a comparison honest. A directory in the new snapshot
and not the old one was, last time, at most the old ceiling. So its growth is
*at least* `new − old_ceiling` — a lower bound — and if that is not positive there
is no evidence it changed at all, and it is **not listed**. Listing it as "new"
would report growth manufactured entirely by the retention cutoff.

Both directions are handled the same way. A directory that left the list shrank
by at least `old − new_ceiling`. One-sided figures carry `exact=False` and the UI
must say "at least".

The ceiling is the size of the largest excluded directory when the count cap bit,
and the size floor when it did not. Files work the same way, with the analyser's
own retained-list length (100) as the cap.

**Alternative rejected:** a depth limit ("keep the first four levels"). It is
simpler to explain and wrong in the common case: the folder that grew is often
deep (`…\AppData\Local\…\Cache`), and a depth cut would report its ancestors
instead. Size-based retention keeps the thing that grew.

## Decision 3 — Comparing needs the same volume, not the same letter

`Volume` had no identity beyond `root` (`C:\`). A history keyed on that compares
a reformatted or swapped disk against the old one and reports a huge, confident
delta that is really "different disk".

`Volume` gains `volume_id`: the Windows volume GUID path
(`\\?\Volume{…}\`, from `GetVolumeNameForVolumeMountPointW`), or `None` when it
cannot be read. It follows the volume across drive-letter changes, which the
label does not, and it is available without elevation.

**Alternative rejected:** the volume serial number. It is easier to read but is
chosen at format time and copied by disk cloning, so it can say two different
disks are one. The GUID belongs to the volume object.

`None` means *unknown*, not *the same as another unknown*. Two snapshots with no
identity are never compared, and a snapshot with none is not saved — the screen
says why, rather than quietly keeping no history.

## Decision 4 — Only completed scans are history

A scan that stopped at a budget or was cancelled covered different territory, so
a delta against it is not a delta. Such scans are not saved. If the *new* scan is
incomplete the volume figure still appears and the attribution is refused with
the reason.

The store returns a closed `SaveOutcome`, not `None` or an exception: `SAVED`,
`NOT_COMPLETE`, `VOLUME_UNIDENTIFIED`. A caller has to handle each, and none of
them can be mistaken for success.

## Decision 5 — Its own file, not the ledger

Snapshots live in `storage_history.sqlite`, not `history.sqlite`. The ledger
means *what PolyScour did to this machine*. A scan did nothing, and a measurement
that appeared in History beside an operation would blur the one distinction the
ledger exists to keep. It also keeps snapshots out of the cross-process mutation
lock, which guards changes to Windows state, and makes *clear history* the
deletion of a file this feature owns.

The store is bounded: the newest 20 completed scans per volume are kept.

## Decision 6 — The screen's promise is narrowed to what was meant

adr/0007 and the Storage screen say it "cannot change anything". That was
shorthand for the real rule — **no action on findings**: no Delete or Clean beside
a list sorted by size, because that would be a recommendation. It is not a rule
against saving a report, and it becomes literally false the moment this feature
writes a history file.

The wording becomes: *this screen measures; it never deletes, moves or modifies
anything on your disk or in Windows; it keeps a local history of its own scans;
Export writes one file, only where you choose.* Export (clipboard and a saved
file) ships with the screen, not with this decision. Recording the narrowing here
means the change of wording is a decision that can be found, not a quiet edit.

## Consequences

- New modules under `src/polyscour/storage/`: `snapshots.py` (the model, its
  JSON, and building one from a report), `comparison.py` (a pure function of two
  snapshots), `history.py` (the store). None imports an executor or the guard;
  the package still has no way to change the machine.
- `docs/PRIVACY.md` is wrong about Storage today, independent of this feature: it
  says listings are read "under a rule's permitted roots" and the analyser walks
  whole volumes. This feature also stores **paths and sizes of the largest
  folders and files**, which is a new category. Both are fixed with the screen.
- `docs/SAFETY.md`, `docs/THREAT_MODEL.md` and `docs/CLEANING_RULES.md` are not
  updated, for adr/0007's reason: nothing here can authorise, so nothing here
  belongs in the guard chain or the threat model. A tampered history file can
  make the screen *say* something false about the past; it cannot make anything
  happen.
- Callers must treat a store failure (`sqlite3.Error`) as "no history", never as
  "no change".
