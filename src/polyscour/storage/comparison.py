r"""Two snapshots of one volume, and what can honestly be said about the gap.

A pure function of its arguments: no disk, no store, no clock. Changes nothing
and recommends nothing -- growth is a fact, and a Delete beside it would be the
recommendation the top invariant forbids. See ``docs/adr/0008``.

**Three figures, in this order, and they are not required to add up:**

1. ``used_delta`` -- how the volume's used space moved, by Windows' own count.
   Needs no scan to have been complete, so it survives when nothing else does.
2. ``attribution.measured_delta`` -- what the scans account for.
3. ``attribution.residual_delta`` -- what the scans could not see, moving on its
   own. Residual is clamped at zero, and compression and deduplication mean a
   tree can measure less than a difference implies, so the model never claims
   ``measured + residual == used``.

**A one-sided directory is a bound, not a measurement.** A directory in the newer
snapshot and not the older one was, last time, at most the older snapshot's
ceiling -- so it grew by *at least* ``new - ceiling``. When that is not positive
there is no evidence it changed, and it is left out entirely. Listing it as
"new" would report growth that exists only because of where a retention cutoff
fell. That is the failure this module exists to not commit.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from polyscour.storage.snapshots import Snapshot


class RefusalReason(enum.Enum):
    VOLUME_UNIDENTIFIED = "volume_unidentified"
    DIFFERENT_VOLUME = "different_volume"
    NOT_NEWER = "not_newer"
    OLDER_INCOMPLETE = "older_incomplete"
    NEWER_INCOMPLETE = "newer_incomplete"


@dataclass(frozen=True)
class Refusal:
    """Why no comparison -- or no attribution -- was produced.

    A value, not an exception and not ``None``: the caller has to decide what to
    show, and "there was nothing to compare" cannot pass for "nothing changed".
    """
    reason: RefusalReason
    detail: str


@dataclass(frozen=True)
class DirChange:
    """One directory's movement.

    ``exact`` is True when it was retained in both snapshots. Otherwise
    ``delta`` is a **lower bound on the size of the change** -- positive when the
    directory entered the newer list, negative when it left -- and the caller must
    say "at least".
    """
    path: str
    old_bytes: int | None
    new_bytes: int | None
    delta: int
    exact: bool


@dataclass(frozen=True)
class FileChange:
    """As :class:`DirChange`, for one of the largest files."""
    path: str
    old_bytes: int | None
    new_bytes: int | None
    delta: int
    exact: bool


@dataclass(frozen=True)
class ExtensionChange:
    """Exact: every extension is kept, so a missing one really was zero."""
    extension: str
    old_bytes: int
    new_bytes: int

    @property
    def delta(self) -> int:
        return self.new_bytes - self.old_bytes


@dataclass(frozen=True)
class Attribution:
    """Where the scans say the change happened."""
    measured_delta: int
    residual_delta: int
    #: How the count of unopenable directories moved. When it is not zero, the
    #: two scans measured different territory, and the caller should say so.
    unreadable_directories_delta: int
    directories: tuple[DirChange, ...]
    files: tuple[FileChange, ...]
    extensions: tuple[ExtensionChange, ...]


@dataclass(frozen=True)
class Comparison:
    older: Snapshot
    newer: Snapshot
    days: float
    #: Windows' figure for the volume, then vs now.
    used_delta: int
    #: The volume's capacity moved -- resized, or the same volume grown.
    total_delta: int
    attribution: Attribution | None
    attribution_refusal: Refusal | None

    def __post_init__(self) -> None:
        # Exactly one. A comparison that has neither is a silent gap, and one
        # that has both is contradicting itself.
        if (self.attribution is None) == (self.attribution_refusal is None):
            raise ValueError("a Comparison has an attribution or a refusal, "
                             "never both and never neither")


def compare(older: Snapshot, newer: Snapshot) -> Comparison | Refusal:
    """What changed between two scans of the same volume, or why not."""
    if older.volume_id is None or newer.volume_id is None:
        return Refusal(RefusalReason.VOLUME_UNIDENTIFIED,
                       "Windows did not give one of these scans a volume "
                       "identity, so they cannot be shown to be the same disk.")
    if older.volume_id != newer.volume_id:
        return Refusal(RefusalReason.DIFFERENT_VOLUME,
                       f"{older.volume_label} and {newer.volume_label} are "
                       f"different volumes -- one may have replaced the other "
                       f"under the same drive letter.")
    if newer.taken_at <= older.taken_at:
        return Refusal(RefusalReason.NOT_NEWER,
                       "The second scan is not later than the first.")

    attribution: Attribution | None = None
    refusal = _attribution_refusal(older, newer)
    if refusal is None:
        attribution = _attribute(older, newer)

    return Comparison(
        older=older,
        newer=newer,
        days=(newer.taken_at - older.taken_at).total_seconds() / 86400.0,
        used_delta=newer.used_at_end - older.used_at_end,
        total_delta=newer.volume_total_bytes - older.volume_total_bytes,
        attribution=attribution,
        attribution_refusal=refusal,
    )


def _attribution_refusal(older: Snapshot, newer: Snapshot) -> Refusal | None:
    """A scan that stopped early covered different territory, so a delta against
    it is not a delta. The volume figure is still reported; only *where* is not."""
    if not older.is_complete:
        return Refusal(RefusalReason.OLDER_INCOMPLETE,
                       f"The earlier scan did not finish "
                       f"({older.stop_reason.value.replace('_', ' ')}), so it "
                       f"cannot say where space moved.")
    if not newer.is_complete:
        return Refusal(RefusalReason.NEWER_INCOMPLETE,
                       f"This scan did not finish "
                       f"({newer.stop_reason.value.replace('_', ' ')}), so it "
                       f"cannot say where space moved.")
    return None


def _attribute(older: Snapshot, newer: Snapshot) -> Attribution:
    return Attribution(
        measured_delta=newer.measured_bytes - older.measured_bytes,
        residual_delta=newer.residual_bytes - older.residual_bytes,
        unreadable_directories_delta=(newer.permission_denied_directories
                                      - older.permission_denied_directories),
        directories=_directory_changes(older, newer),
        files=_file_changes(older, newer),
        extensions=_extension_changes(older, newer),
    )


def _key(path: str) -> str:
    """Windows paths compare case-insensitively."""
    return path.casefold()


def _order(change) -> tuple[int, str]:
    return (-abs(change.delta), change.path)


def _directory_changes(older: Snapshot, newer: Snapshot) -> tuple[DirChange, ...]:
    old = {_key(d.path): d for d in older.directories}
    new = {_key(d.path): d for d in newer.directories}
    out: list[DirChange] = []

    for key, d in new.items():
        before = old.get(key)
        if before is not None:
            if d.allocated_bytes != before.allocated_bytes:
                out.append(DirChange(d.path, before.allocated_bytes,
                                     d.allocated_bytes,
                                     d.allocated_bytes - before.allocated_bytes,
                                     exact=True))
        else:
            # Not in the older list, so at most the older ceiling last time.
            at_least = d.allocated_bytes - older.directory_ceiling_bytes
            if at_least > 0:
                out.append(DirChange(d.path, None, d.allocated_bytes,
                                     at_least, exact=False))

    for key, d in old.items():
        if key not in new:
            # Not in the newer list, so at most the newer ceiling now.
            at_least = d.allocated_bytes - newer.directory_ceiling_bytes
            if at_least > 0:
                out.append(DirChange(d.path, d.allocated_bytes, None,
                                     -at_least, exact=False))

    return tuple(sorted(out, key=_order))


def _file_changes(older: Snapshot, newer: Snapshot) -> tuple[FileChange, ...]:
    old = {_key(f.path): f for f in older.files}
    new = {_key(f.path): f for f in newer.files}
    out: list[FileChange] = []

    for key, f in new.items():
        before = old.get(key)
        if before is not None:
            if f.allocated_bytes != before.allocated_bytes:
                out.append(FileChange(f.path, before.allocated_bytes,
                                      f.allocated_bytes,
                                      f.allocated_bytes - before.allocated_bytes,
                                      exact=True))
        else:
            # A ceiling of zero means the older list dropped nothing, so the
            # file genuinely was not there and the figure is exact.
            at_least = f.allocated_bytes - older.file_ceiling_bytes
            if at_least > 0:
                out.append(FileChange(f.path, None, f.allocated_bytes,
                                      at_least,
                                      exact=older.file_ceiling_bytes == 0))

    for key, f in old.items():
        if key not in new:
            at_least = f.allocated_bytes - newer.file_ceiling_bytes
            if at_least > 0:
                out.append(FileChange(f.path, f.allocated_bytes, None,
                                      -at_least,
                                      exact=newer.file_ceiling_bytes == 0))

    return tuple(sorted(out, key=_order))


def _extension_changes(older: Snapshot, newer: Snapshot) -> tuple[ExtensionChange, ...]:
    out = [ExtensionChange(ext, older.by_extension.get(ext, 0),
                           newer.by_extension.get(ext, 0))
           for ext in older.by_extension.keys() | newer.by_extension.keys()]
    return tuple(sorted((c for c in out if c.delta),
                        key=lambda c: (-abs(c.delta), c.extension)))
