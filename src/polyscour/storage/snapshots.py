r"""One scan, reduced to what can be compared later -- and what was dropped.

Reads what the analyser produced and changes nothing. Calls no guard; see
``docs/adr/0007`` for why that is a decision, and ``docs/adr/0008`` for this
module's own.

A snapshot cannot keep the whole tree: a volume scan reaches two million nodes.
So it keeps the **largest directories at any depth**, above a size floor and up
to a count, and it records the one number that makes that safe to compare
against later: ``directory_ceiling_bytes``, *how big a directory that is not in
the list could still be*.

Without that number a comparison invents growth. A folder present now and absent
last time is only "new" if last time it could not have been hiding just under the
cutoff -- and whether it could is exactly what the ceiling says. The same holds
for files, bounded by the analyser's own retained-list length.

Nothing here is estimated. A figure is either kept exactly, or bounded, or absent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from polyscour.storage.analyser import (LARGEST_FILES_KEPT, DirectoryNode,
                                        ResidualReason, StopReason,
                                        VolumeReport)

#: Bumped when the stored shape changes. A row from another version is reported
#: as unreadable rather than half-understood -- see ``SnapshotCorrupt``.
SCHEMA_VERSION = 1

#: A directory smaller than this is never kept. 64 MiB: below it a directory is
#: not what a person means by "where did the space go", and the list would
#: otherwise be dominated by thousands of small ones.
RETENTION_MIN_BYTES = 64 * 1024 * 1024

#: At most this many directories are kept, largest first. The ceiling rises to
#: match whenever the cap is what excluded something.
RETENTION_MAX_DIRS = 500


class SnapshotCorrupt(ValueError):
    """Stored bytes that are not a snapshot this version can trust.

    Raised rather than returning a partial object: a snapshot with a missing
    field would compare as if that field were zero, which is a measurement
    nobody made.
    """


@dataclass(frozen=True)
class RetainedDir:
    path: str
    allocated_bytes: int
    file_count: int


@dataclass(frozen=True)
class RetainedFile:
    path: str
    allocated_bytes: int


@dataclass(frozen=True)
class Snapshot:
    """A completed scan of one volume, at one moment."""
    volume_id: str | None
    volume_label: str
    fstype: str
    volume_total_bytes: int
    taken_at: datetime
    stop_reason: StopReason
    used_at_start: int
    used_at_end: int
    measured_bytes: int
    #: Named reasons only, ``ResidualReason.value`` -> bytes. The unexplained
    #: remainder is derived, never stored -- adr/0007.
    residual: dict[str, int]
    permission_denied_directories: int
    entries_examined: int
    directories: tuple[RetainedDir, ...]
    #: The largest a directory NOT in ``directories`` could be.
    directory_ceiling_bytes: int
    files: tuple[RetainedFile, ...]
    #: The largest a file NOT in ``files`` could be. Zero means nothing was
    #: dropped, which is a different claim from "unknown".
    file_ceiling_bytes: int
    by_extension: dict[str, int]

    @property
    def is_complete(self) -> bool:
        return self.stop_reason.is_complete

    @property
    def residual_bytes(self) -> int:
        """What the scan could not see. Never negative -- adr/0007."""
        return max(0, self.used_at_end - self.measured_bytes)

    # ── building one ─────────────────────────────────────────────────────────

    @classmethod
    def from_report(cls, report: VolumeReport) -> "Snapshot":
        directories, dir_ceiling = _retain_directories(report.root)
        files, file_ceiling = _retain_files(report)
        taken = report.finished_at or report.started_at
        if taken.tzinfo is None:
            taken = taken.replace(tzinfo=timezone.utc)
        return cls(
            volume_id=report.volume.volume_id,
            volume_label=report.volume.label,
            fstype=report.volume.fstype,
            volume_total_bytes=report.volume.total_bytes,
            taken_at=taken,
            stop_reason=report.stop_reason,
            used_at_start=report.used_at_start,
            used_at_end=report.used_at_end,
            measured_bytes=report.measured_bytes,
            residual={r.value: b for r, b in report.residual.items() if b > 0},
            permission_denied_directories=report.permission_denied_directories,
            entries_examined=report.entries_examined,
            directories=directories,
            directory_ceiling_bytes=dir_ceiling,
            files=files,
            file_ceiling_bytes=file_ceiling,
            by_extension=dict(report.by_extension),
        )

    # ── the stored form ──────────────────────────────────────────────────────

    def to_json(self) -> str:
        return json.dumps({
            "schema": SCHEMA_VERSION,
            "volume_id": self.volume_id,
            "volume_label": self.volume_label,
            "fstype": self.fstype,
            "volume_total_bytes": self.volume_total_bytes,
            "taken_at": self.taken_at.isoformat(),
            "stop_reason": self.stop_reason.value,
            "used_at_start": self.used_at_start,
            "used_at_end": self.used_at_end,
            "measured_bytes": self.measured_bytes,
            "residual": self.residual,
            "permission_denied_directories": self.permission_denied_directories,
            "entries_examined": self.entries_examined,
            "directories": [[d.path, d.allocated_bytes, d.file_count]
                            for d in self.directories],
            "directory_ceiling_bytes": self.directory_ceiling_bytes,
            "files": [[f.path, f.allocated_bytes] for f in self.files],
            "file_ceiling_bytes": self.file_ceiling_bytes,
            "by_extension": self.by_extension,
        }, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "Snapshot":
        """Parse, or raise :class:`SnapshotCorrupt`. Never a partial object."""
        try:
            raw = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise SnapshotCorrupt(f"not JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise SnapshotCorrupt("not an object")
        if raw.get("schema") != SCHEMA_VERSION:
            raise SnapshotCorrupt(f"schema {raw.get('schema')!r}, this version "
                                  f"reads {SCHEMA_VERSION}")
        try:
            return cls._from_dict(raw)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, SnapshotCorrupt):
                raise
            raise SnapshotCorrupt(f"malformed: {exc!r}") from exc

    @classmethod
    def _from_dict(cls, raw: dict) -> "Snapshot":
        volume_id = raw["volume_id"]
        if volume_id is not None and not isinstance(volume_id, str):
            raise SnapshotCorrupt("volume_id is neither text nor null")

        taken = datetime.fromisoformat(_text(raw, "taken_at"))
        if taken.tzinfo is None:
            raise SnapshotCorrupt("taken_at has no time zone")

        return cls(
            volume_id=volume_id,
            volume_label=_text(raw, "volume_label"),
            fstype=_text(raw, "fstype"),
            volume_total_bytes=_count(raw, "volume_total_bytes"),
            taken_at=taken,
            stop_reason=StopReason(_text(raw, "stop_reason")),
            used_at_start=_count(raw, "used_at_start"),
            used_at_end=_count(raw, "used_at_end"),
            measured_bytes=_count(raw, "measured_bytes"),
            residual=_sizes(raw, "residual", allowed=_RESIDUAL_KEYS),
            permission_denied_directories=_count(
                raw, "permission_denied_directories"),
            entries_examined=_count(raw, "entries_examined"),
            directories=tuple(
                RetainedDir(_row_text(r, 0), _row_count(r, 1), _row_count(r, 2))
                for r in _rows(raw, "directories", 3)),
            directory_ceiling_bytes=_count(raw, "directory_ceiling_bytes"),
            files=tuple(RetainedFile(_row_text(r, 0), _row_count(r, 1))
                        for r in _rows(raw, "files", 2)),
            file_ceiling_bytes=_count(raw, "file_ceiling_bytes"),
            by_extension=_sizes(raw, "by_extension"),
        )


# ── retention ────────────────────────────────────────────────────────────────

def _size(node: DirectoryNode) -> int:
    """Same rule as ``VolumeReport.measured_bytes`` and ``largest_children``."""
    return node.allocated_bytes or node.logical_bytes


def _retain_directories(root: DirectoryNode) -> tuple[tuple[RetainedDir, ...], int]:
    """The largest directories, and the largest one that was left out.

    Every node is visited; a subtree is *not* skipped because its parent is
    small. That would be safe only if a parent's size always covers its
    children's, and the ceiling below is a claim about what was left out -- it
    should not rest on an invariant nothing here checks.

    Iterative, because a directory tree can be deeper than Python's recursion
    limit and a snapshot that fails on a deep tree fails exactly where the disk
    is most interesting.
    """
    candidates: list[RetainedDir] = []
    stack = list(root.children)
    while stack:
        node = stack.pop()
        size = _size(node)
        if size >= RETENTION_MIN_BYTES:
            candidates.append(RetainedDir(str(node.path), size, node.file_count))
        stack.extend(node.children)

    candidates.sort(key=lambda d: (-d.allocated_bytes, d.path))
    if len(candidates) > RETENTION_MAX_DIRS:
        # The cap is what excluded something, so the largest excluded directory
        # is the largest one that could be missing.
        return (tuple(candidates[:RETENTION_MAX_DIRS]),
                candidates[RETENTION_MAX_DIRS].allocated_bytes)
    # Nothing was dropped for count; anything absent was under the floor.
    return tuple(candidates), RETENTION_MIN_BYTES


def _retain_files(report: VolumeReport) -> tuple[tuple[RetainedFile, ...], int]:
    ordered = sorted(report.largest_files,
                     key=lambda f: (-f.allocated_bytes, str(f.path)))
    kept = ordered[:LARGEST_FILES_KEPT]
    files = tuple(RetainedFile(str(f.path), f.allocated_bytes) for f in kept)
    if len(ordered) >= LARGEST_FILES_KEPT:
        # The analyser's list was full, so a file it dropped is no larger than
        # the smallest it kept.
        return files, files[-1].allocated_bytes
    return files, 0


# ── validation helpers ───────────────────────────────────────────────────────

_RESIDUAL_KEYS = frozenset(r.value for r in ResidualReason)


def _is_count(value) -> bool:
    # bool is an int in Python; "true" is not a byte count.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _text(raw: dict, key: str) -> str:
    value = raw[key]
    if not isinstance(value, str):
        raise SnapshotCorrupt(f"{key!r} is not text")
    return value


def _count(raw: dict, key: str) -> int:
    value = raw[key]
    if not _is_count(value):
        raise SnapshotCorrupt(f"{key!r} is not a non-negative integer")
    return value


def _sizes(raw: dict, key: str, allowed: frozenset[str] | None = None) -> dict[str, int]:
    value = raw[key]
    if not isinstance(value, dict):
        raise SnapshotCorrupt(f"{key!r} is not an object")
    for k, v in value.items():
        if not _is_count(v) or (allowed is not None and k not in allowed):
            raise SnapshotCorrupt(f"{key!r} has a bad entry {k!r}")
    return dict(value)


def _rows(raw: dict, key: str, width: int) -> list[list]:
    value = raw[key]
    if not isinstance(value, list) or any(
            not isinstance(r, list) or len(r) != width for r in value):
        raise SnapshotCorrupt(f"{key!r} rows are not {width} long")
    return value


def _row_text(row: list, index: int) -> str:
    if not isinstance(row[index], str):
        raise SnapshotCorrupt("a row's path is not text")
    return row[index]


def _row_count(row: list, index: int) -> int:
    if not _is_count(row[index]):
        raise SnapshotCorrupt("a row's size is not a non-negative integer")
    return row[index]
