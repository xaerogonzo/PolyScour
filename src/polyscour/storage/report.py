r"""What the Storage screen says, as data -- so the screen and its export agree.

The screen and the text export both render from here. Wording lives in one place
because the sentences that matter most are the careful ones -- "at least",
"these need not add up", "not kept" -- and a careful sentence worded twice is
worded differently within a release.

Changes nothing and calls no guard. Recommends nothing: a row says how much a
folder moved, and there is no verb beside it. ``docs/adr/0008``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from polyscour.formatting import human, signed
from polyscour.storage import snapshots
from polyscour.storage.analyser import LARGEST_FILES_KEPT, StopReason, VolumeReport
from polyscour.storage.comparison import Attribution, Comparison, Refusal
from polyscour.storage.history import SaveOutcome
from polyscour.storage.review import Review

#: How many rows each list shows. The screen's existing lists show 12; the
#: change lists are shorter because each row means more.
LIST_ROWS = 12
FOLDER_CHANGE_ROWS = 10
FILE_CHANGE_ROWS = 5
EXTENSION_CHANGE_ROWS = 5

#: A volume that moved more than this while being scanned gets a note.
DRIFT_NOTE_BYTES = 64 * 1024 * 1024

STOP_LABEL = {
    StopReason.COMPLETED: "Complete",
    StopReason.BUDGET_EXHAUSTED: "Stopped at the size budget",
    StopReason.TIME_EXHAUSTED: "Stopped at the time budget",
    StopReason.CANCELLED: "Cancelled",
    StopReason.ERROR: "Stopped by an error",
}


# ── the scan itself ──────────────────────────────────────────────────────────

def scan_notes(report: VolumeReport) -> list[str]:
    """Why the residual is what it is, in plain sentences."""
    notes = []
    if report.permission_denied_directories:
        notes.append(f"{report.permission_denied_directories:,} directories "
                     f"could not be opened, so their size is unknown rather "
                     f"than zero")
    if report.reparse_points_skipped:
        notes.append(f"{report.reparse_points_skipped:,} junctions were not "
                     f"followed — their contents are counted where they "
                     f"really live, not missing")
    if report.hardlinks_deduplicated:
        notes.append(f"{report.hardlinks_deduplicated:,} files share storage "
                     f"with another name and were counted once "
                     f"({human(report.hardlink_bytes_saved)} not "
                     f"double-counted)")
    if abs(report.volume_drift_bytes) > DRIFT_NOTE_BYTES:
        notes.append(f"the volume's usage moved by "
                     f"{human(abs(report.volume_drift_bytes))} while this "
                     f"ran, so the two figures will not reconcile exactly")
    notes.append("This is a limit of the scan, not a fault on the machine. "
                 "Windows manages some of a disk in ways no ordinary "
                 "program can see.")
    return notes


# ── the change since the last scan ───────────────────────────────────────────

@dataclass(frozen=True)
class ChangeRow:
    """One line of movement. No action attaches to it, by design."""
    label: str
    delta: int
    #: False means ``delta`` is a lower bound and the text must say "at least".
    exact: bool

    @property
    def size_text(self) -> str:
        return signed(self.delta) if self.exact else f"at least {signed(self.delta)}"


@dataclass(frozen=True)
class HistorySummary:
    title: str
    headline: str | None
    detail: str | None
    #: Where the change happened -- or why that cannot be said.
    attribution: str | None
    folders: tuple[ChangeRow, ...]
    files: tuple[ChangeRow, ...]
    extensions: tuple[ChangeRow, ...]
    notes: tuple[str, ...]


def summarise(review: Review) -> HistorySummary:
    """Everything the screen says about history, including that there is none."""
    notes = _store_notes(review)
    comparison = review.comparison

    if isinstance(comparison, Comparison):
        return _from_comparison(comparison, notes)

    if isinstance(comparison, Refusal):
        return HistorySummary("Since the last scan", None, comparison.detail,
                              None, (), (), (), tuple(notes))

    # No baseline. Say so plainly -- "no earlier scan" is not "no change".
    first = (review.error is None and review.unreadable == 0
             and review.saved is SaveOutcome.SAVED)
    detail = (f"This is the first completed scan of {review.snapshot.volume_label} "
              f"that PolyScour has kept. Scan again later to see what changed."
              if first else None)
    return HistorySummary("Since the last scan", None, detail, None,
                          (), (), (), tuple(notes))


def _from_comparison(c: Comparison, notes: list[str]) -> HistorySummary:
    label = c.newer.volume_label
    if c.used_delta == 0:
        headline = f"Used space on {label} is unchanged"
    else:
        headline = f"{signed(c.used_delta)} used on {label}"
    detail = (f"Windows reports {human(c.newer.used_at_end)} used, against "
              f"{human(c.older.used_at_end)} {_gap(c.days)} earlier.")

    a = c.attribution
    if a is None:
        # The volume figure needs no complete scan; where it moved does.
        where = (f"{c.attribution_refusal.detail} The figure above is still "
                 f"Windows' own count.")
        return HistorySummary(f"Since the scan of {_date(c.older.taken_at)}",
                              headline, detail, where, (), (), (), tuple(notes))

    # Not "of that": the two figures cover different ground, so one can exceed
    # the headline (here +20 against +12) without either being wrong.
    where = (f"In what the scans could read, space moved by "
             f"{signed(a.measured_delta)}; in what they cannot see, by "
             f"{signed(a.residual_delta)}. These two do not have to add up to "
             f"the change above.")
    return HistorySummary(
        f"Since the scan of {_date(c.older.taken_at)}", headline, detail, where,
        folders=tuple(ChangeRow(d.path, d.delta, d.exact)
                      for d in a.directories[:FOLDER_CHANGE_ROWS]),
        files=tuple(ChangeRow(f.path, f.delta, f.exact)
                    for f in a.files[:FILE_CHANGE_ROWS]),
        extensions=tuple(ChangeRow(e.extension or "(no extension)", e.delta, True)
                         for e in a.extensions[:EXTENSION_CHANGE_ROWS]),
        notes=tuple(_attribution_notes(c, a) + notes))


def _attribution_notes(c: Comparison, a: Attribution) -> list[str]:
    notes = []
    if any(not d.exact for d in a.directories) or any(not f.exact for f in a.files):
        notes.append("“At least” marks something that was not on the earlier "
                     "scan's list, so it may have been just below it. Only the "
                     "part above that is counted; it may have moved more.")
    if a.unreadable_directories_delta:
        n = abs(a.unreadable_directories_delta)
        notes.append(f"{n:,} {'more' if a.unreadable_directories_delta > 0 else 'fewer'} "
                     f"directories could not be opened than last time, so the "
                     f"two scans did not cover exactly the same ground.")
    if c.total_delta:
        notes.append(f"The volume's size changed by {signed(c.total_delta)}.")
    notes.append(f"Each scan keeps only its {snapshots.RETENTION_MAX_DIRS} largest "
                 f"folders ({human(snapshots.RETENTION_MIN_BYTES)} and up) and its "
                 f"{LARGEST_FILES_KEPT} largest files. A change outside those "
                 f"lists is not shown.")
    return notes


def _store_notes(review: Review) -> list[str]:
    notes = []
    if review.unreadable:
        n = review.unreadable
        notes.append(f"{n:,} earlier scan{'s' if n != 1 else ''} could not be "
                     f"read and {'were' if n != 1 else 'was'} skipped"
                     + ("." if review.baseline is not None
                        else ", so there is nothing to compare with."))
    if review.error is not None:
        tail = " This scan was not kept." if review.saved is None else ""
        notes.append(f"Saved history could not be used ({review.error}).{tail}")
    elif review.saved is SaveOutcome.NOT_COMPLETE:
        notes.append("This scan stopped early, so it was not kept as history "
                     "and cannot be a baseline later.")
    elif review.saved is SaveOutcome.VOLUME_UNIDENTIFIED:
        notes.append("Windows gave this volume no identity that survives a "
                     "drive-letter change, so this scan was not kept and cannot "
                     "be compared later.")
    return notes


def _date(when: datetime) -> str:
    return when.astimezone().strftime("%d %b %Y")


def _gap(days: float) -> str:
    if days < 1:
        hours = max(1, round(days * 24))
        return f"{hours} hour{'s' if hours != 1 else ''}"
    whole = round(days)
    return f"{whole} day{'s' if whole != 1 else ''}"


# ── the export ───────────────────────────────────────────────────────────────

def render_text(report: VolumeReport, review: Review | None) -> str:
    """A plain-text report of what the screen shows.

    It contains folder and file **names from this computer**, which is why the
    first thing it says is so. Nothing sends it anywhere; it goes to the
    clipboard or to a file the person chose.
    """
    when = report.finished_at or report.started_at
    out = [
        "PolyScour storage report",
        f"{report.volume.label} — scanned {when.astimezone():%d %b %Y %H:%M}",
        "This report contains file and folder names from this computer.",
        "",
        f"{report.volume.label} — {human(report.volume.used_bytes)} used of "
        f"{human(report.volume.total_bytes)}",
        f"{human(report.measured_bytes)} accounted for, "
        f"{human(report.residual_bytes)} not",
        f"{STOP_LABEL[report.stop_reason]} — {report.entries_examined:,} items "
        f"in {report.elapsed_seconds:.0f}s",
        "",
        "What this scan could not account for",
    ]
    breakdown = report.residual_breakdown()
    out += [f"  {human(b):>10}  {r.label}" for r, b in breakdown] or ["  nothing named"]
    out += [f"  · {n}" for n in scan_notes(report)]

    out += ["", "Largest folders"]
    out += [f"  {human(c.allocated_bytes):>10}  {c.path}"
            for c in report.root.largest_children(LIST_ROWS)]
    out += ["", "Largest files"]
    out += [f"  {human(f.allocated_bytes):>10}  {f.path}"
            for f in report.largest_files[:LIST_ROWS]]
    by_ext = sorted(report.by_extension.items(), key=lambda kv: kv[1],
                    reverse=True)[:LIST_ROWS]
    if by_ext:
        out += ["", "By file type"]
        out += [f"  {human(size):>10}  {ext}" for ext, size in by_ext]

    if review is not None:
        out += ["", *_history_lines(summarise(review))]
    return "\n".join(out) + "\n"


def _history_lines(s: HistorySummary) -> list[str]:
    out = [s.title]
    for text in (s.headline, s.detail, s.attribution):
        if text:
            out.append(f"  {text}")
    for heading, rows in (("Folders", s.folders), ("Files", s.files),
                          ("File types", s.extensions)):
        if rows:
            out.append(f"  {heading}")
            out += [f"    {r.size_text:>22}  {r.label}" for r in rows]
    out += [f"  · {n}" for n in s.notes]
    return out
