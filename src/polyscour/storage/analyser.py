r"""The budgeted walk, the tree it builds, and the bytes it could not account for.

Deletes nothing. Authorises nothing. Calls no guard — `docs/adr/0007` explains
why that is a decision rather than an omission.

Three things make this harder than "sum the file sizes", and each is a place
where a plausible implementation produces a confidently wrong number:

**The residual.** A walk's total never equals used space -- `$MFT`, `System
Volume Information`, `hiberfil.sys`, `pagefile.sys`, restore points, and every
directory an unelevated process cannot read. Leaving that gap unexplained is
the "63 devices not reporting OK" failure, so it is reported with the same
prominence as the total. But it must not be *inflated* either: bytes behind a
skipped junction are counted elsewhere in the tree, which is exactly why the
junction was skipped, so they are a diagnostic count and not residual bytes.

**Two sizes.** `st_size` is logical. For sparse and compressed files that is not
what the disk gave up, and this module exists to say what the disk gave up.
Both are carried; `st_file_attributes` arrives free from `scandir` and says
which files can differ, so the expensive query is made only for those.

**Hardlinks.** One file, several directory entries. Counting each entry invents
space -- worst in `C:\Windows`, which is where it matters most. Deduplicating
needs `st_nlink`, which needs a full `os.stat()` per file -- see the note
above `_walk` for the shortcut that was tried, and why it failed twice.
"""
from __future__ import annotations

import enum
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from polyscour.safety.reparse import is_reparse_point
from polyscour.storage.volumes import Volume, usage_now

#: Free from ``scandir`` on Windows, and the only cheap signal for which files
#: have an on-disk size different from their logical one.
_COMPRESSED = getattr(stat, "FILE_ATTRIBUTE_COMPRESSED", 0x800)
_SPARSE = getattr(stat, "FILE_ATTRIBUTE_SPARSE_FILE", 0x200)


class StopReason(enum.Enum):
    """Why a scan ended. An enum rather than ``complete: bool``.

    Four different things, and a user reading "partial results" deserves to
    know which: a scan that ran out of time says something about the disk, one
    the user cancelled says nothing at all, and an error says something about
    PolyScour.
    """
    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIME_EXHAUSTED = "time_exhausted"
    CANCELLED = "cancelled"
    ERROR = "error"

    @property
    def is_complete(self) -> bool:
        return self is StopReason.COMPLETED


class ResidualReason(enum.Enum):
    """Why some of the volume is not in the tree.

    Every member here is **bytes we could not see, and can put a number on**.

    Two kinds of thing are deliberately absent. Bytes we did not walk because
    they are counted elsewhere -- junctions, deduplicated hardlinks -- are
    counters on ``VolumeReport``: putting them here would inflate the residual
    out of correct deduplication. And unreadable directories are a counter too,
    for the opposite reason: we could not open them, so their size is precisely
    what we do not know, and a byte figure would be invented.
    """
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIME_EXHAUSTED = "time_exhausted"
    SYSTEM_MANAGED = "system_managed"
    OTHER = "other"

    @property
    def label(self) -> str:
        return {
            ResidualReason.BUDGET_EXHAUSTED: "Beyond the scan's size budget",
            ResidualReason.TIME_EXHAUSTED: "Beyond the scan's time budget",
            ResidualReason.SYSTEM_MANAGED: "Managed by Windows",
            ResidualReason.OTHER: "Not accounted for",
        }[self]


@dataclass(frozen=True)
class StorageScanRequest:
    """What to walk, and how much of it.

    A dataclass rather than module constants so a caller states its limits
    explicitly and a test can set them small. Deliberately **not** built as a
    shared scan framework for a duplicate finder or a cloud analyser -- both
    were considered and declined in adr/0007, and a registry serving features
    that do not exist is the over-engineering `docs/SUPPORT_MATRIX.md` names.
    """
    volume: Volume
    max_seconds: float = 120.0
    max_entries: int = 2_000_000
    #: Whether to pay for hardlink deduplication: 1.24x, measured. Off makes
    #: the totals wrong in C:\Windows, so it exists for tests, not for users.
    deduplicate_hardlinks: bool = True


@dataclass
class DirectoryNode:
    """One directory, and everything measured beneath it."""
    path: Path
    logical_bytes: int = 0
    allocated_bytes: int = 0
    file_count: int = 0
    children: list["DirectoryNode"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.path.name or str(self.path)

    def largest_children(self, limit: int = 20) -> list["DirectoryNode"]:
        """Sorted by size. A fact, and never accompanied by an action button."""
        return sorted(self.children,
                      key=lambda c: c.allocated_bytes or c.logical_bytes,
                      reverse=True)[:limit]


@dataclass
class FileEntry:
    """One file, kept only when large enough to appear in a 'largest' list."""
    path: Path
    logical_bytes: int
    allocated_bytes: int


@dataclass
class VolumeReport:
    """Everything one scan of one volume established, including its limits."""
    volume: Volume
    root: DirectoryNode
    stop_reason: StopReason = StopReason.COMPLETED

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    elapsed_seconds: float = 0.0

    entries_examined: int = 0
    directories_examined: int = 0
    max_entries: int = 0
    max_seconds: float = 0.0

    #: Usage at both ends. The machine keeps writing during a walk, and a
    #: comparison against a single snapshot makes ordinary background activity
    #: look like an analyser fault. adr/0007.
    used_at_start: int = 0
    used_at_end: int = 0

    residual: dict[ResidualReason, int] = field(default_factory=dict)

    #: NOT residual. Bytes behind these are counted elsewhere in the tree; the
    #: counts are diagnostics, so a user can see the walk was doing something
    #: sensible rather than silently skipping their files.
    reparse_points_skipped: int = 0
    hardlinks_deduplicated: int = 0
    hardlink_bytes_saved: int = 0

    #: Directories that could not be opened. A COUNT, never bytes: we could not
    #: read them, so their size is exactly what we do not know. It explains the
    #: residual without claiming to quantify it.
    permission_denied_directories: int = 0

    largest_files: list[FileEntry] = field(default_factory=list)
    by_extension: dict[str, int] = field(default_factory=dict)

    @property
    def measured_bytes(self) -> int:
        return self.root.allocated_bytes or self.root.logical_bytes

    @property
    def residual_bytes(self) -> int:
        """What the walk could not see. Never negative.

        Clamped at zero because the alternative is a screen reporting negative
        unaccounted space, which is not a number anyone can act on. It goes
        negative legitimately: deduplication and compression both mean the tree
        can measure less than the difference implies, and the volume may have
        shrunk during the walk.
        """
        return max(0, self.used_at_end - self.measured_bytes)

    @property
    def volume_drift_bytes(self) -> int:
        """How much the volume's usage moved while we were walking it."""
        return self.used_at_end - self.used_at_start

    def residual_breakdown(self) -> list[tuple[ResidualReason, int]]:
        """Named reasons first, with the unexplained remainder last.

        The remainder is computed rather than accumulated: it is whatever the
        named reasons do not cover, which is the only honest way to derive it.
        """
        named = [(r, b) for r, b in self.residual.items() if b > 0]
        accounted = sum(b for _, b in named)
        remainder = self.residual_bytes - accounted
        if remainder > 0:
            named.append((ResidualReason.OTHER, remainder))
        return sorted(named, key=lambda pair: pair[1], reverse=True)


def _allocated_size(path: Path, logical: int, attrs: int) -> int:
    """On-disk size, but only asked for when it can differ from the logical one.

    ``GetCompressedFileSizeW`` is one Win32 call per file, and a walk makes a
    million of them. It is affordable here only because ``st_file_attributes``
    arrives free from ``scandir`` and identifies exactly the files where the
    answer differs -- a small fraction of any normal volume.

    The same shape as the ``st_nlink > 1`` rule, and as the
    ``permitted_roots()`` lesson in CLAUDE.md: stop doing per-file work that
    only a few files need.
    """
    if not attrs & (_COMPRESSED | _SPARSE):
        return logical

    try:
        import ctypes
        from ctypes import wintypes

        high = wintypes.DWORD(0)
        fn = ctypes.windll.kernel32.GetCompressedFileSizeW
        fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        fn.restype = wintypes.DWORD
        low = fn(str(path), ctypes.byref(high))
        if low == 0xFFFFFFFF:      # INVALID_FILE_SIZE; check the real error
            if ctypes.GetLastError() != 0:
                return logical
        return (high.value << 32) | low
    except (OSError, AttributeError, ValueError):
        # No kernel32, or a path it will not accept. The logical size is a
        # worse answer, not a wrong one, and it is labelled as which.
        return logical


# There is deliberately NO "only stat the files that might be hardlinked"
# shortcut here, and the reason is worth keeping because both halves of it were
# wrong in ways reasoning did not reach.
#
# `scandir` gives st_size and st_file_attributes free but reports st_ino = 0
# and st_nlink = 0 -- present, and zero, because Windows' directory enumeration
# does not carry them. Detecting a hardlink needs st_nlink, which needs an open
# handle, which is os.stat(). So a shortcut looked worth having.
#
# The proposed one was "stat under %SystemRoot%, skip elsewhere", on the
# strength of this:
#
#     C:\Windows\System32          86.7% of files hardlinked, 51.4% of bytes
#     C:\Windows\WinSxS            57.2% of files hardlinked, 47.1% of bytes
#     %LOCALAPPDATA%   (60k files)  0.0%
#     D:\Random Projects (60k)      0.0%
#
# It was wrong twice.
#
# **Wrong on correctness.** An audit that stat'd one skipped file in 500 anyway
# found 150 violations in 562 samples -- 27%. The two zero-percent trees were
# not representative of C:, which also holds Program Files, WindowsApps and
# ProgramData, where MSIX packaging and the component store hardlink heavily.
#
# **Wrong on performance**, which is the part no amount of thinking would have
# produced. Measured over C: with a warm cache:
#
#     no stat at all           16,819 entries/s   (double-counts)
#     stat everything          13,514 entries/s   (correct)
#     stat under %SystemRoot%  12,193 entries/s   (wrong AND slowest)
#
# `Path.is_relative_to()` per file costs more than the os.stat() it avoids. The
# optimisation was slower than not optimising.
#
# So: stat every file. Correctness costs 1.24x, and the earlier 3.2x figure
# came from os.walk + a separate os.stat re-resolving each path rather than
# scandir. CLAUDE.md's rule -- performance work needs a measurement, not a
# guess -- applies in both directions: this one would have made the scan slower
# and the totals wrong, for a saving that was never there.


def _walk(node: DirectoryNode, request: StorageScanRequest, report: VolumeReport,
          cancel: threading.Event, deadline: float,
          seen_links: set[tuple[int, int]]) -> StopReason:
    """One directory, depth-first. Returns why it stopped."""
    try:
        entries = list(os.scandir(node.path))
    except PermissionError:
        # Counted as a DIRECTORY, never as bytes.
        #
        # We could not open it, so we do not know how large it is -- that is
        # the whole content of the failure. Attributing a byte figure here
        # would mean inventing one, and an invented number in the panel whose
        # job is to say what we could not see would be self-defeating.
        #
        # The count still explains the residual: "412 directories were not
        # readable" tells a user why the totals do not add up, without
        # pretending to know by how much.
        report.permission_denied_directories += 1
        return StopReason.COMPLETED
    except OSError:
        return StopReason.COMPLETED

    report.directories_examined += 1

    for entry in entries:
        if cancel.is_set():
            return StopReason.CANCELLED
        if report.entries_examined >= request.max_entries:
            return StopReason.BUDGET_EXHAUSTED
        if time.monotonic() >= deadline:
            return StopReason.TIME_EXHAUSTED

        report.entries_examined += 1
        path = Path(entry.path)

        # Reparse points are not descended, and their bytes are NOT residual:
        # a junction's target is counted where it really lives. Counting it
        # here as "unaccounted" would invent missing space out of correct
        # deduplication. adr/0007.
        if is_reparse_point(path):
            report.reparse_points_skipped += 1
            continue

        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue

        if is_dir:
            child = DirectoryNode(path=path)
            reason = _walk(child, request, report, cancel, deadline, seen_links)
            node.children.append(child)
            node.logical_bytes += child.logical_bytes
            node.allocated_bytes += child.allocated_bytes
            node.file_count += child.file_count
            if reason is not StopReason.COMPLETED:
                return reason
            continue

        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue

        logical = st.st_size
        attrs = getattr(st, "st_file_attributes", 0)

        if request.deduplicate_hardlinks:
            # Every file, because there is no cheaper discriminator that is
            # also correct -- see the note above _walk.
            try:
                full = os.stat(path)
            except OSError:
                full = None
            if full is not None and getattr(full, "st_nlink", 0) > 1:
                key = (full.st_dev, full.st_ino)
                if key in seen_links:
                    report.hardlinks_deduplicated += 1
                    report.hardlink_bytes_saved += logical
                    continue
                seen_links.add(key)

        allocated = _allocated_size(path, logical, attrs)

        node.logical_bytes += logical
        node.allocated_bytes += allocated
        node.file_count += 1

        suffix = path.suffix.lower() or "(no extension)"
        report.by_extension[suffix] = report.by_extension.get(suffix, 0) + allocated

        report.largest_files.append(FileEntry(path, logical, allocated))
        if len(report.largest_files) > 4000:
            report.largest_files.sort(key=lambda f: f.allocated_bytes, reverse=True)
            del report.largest_files[500:]

    return StopReason.COMPLETED


def analyse(request: StorageScanRequest,
            cancel: threading.Event | None = None) -> VolumeReport:
    """Walk one volume and describe it. Changes nothing.

    One volume per call, deliberately. A single sweep over every fixed disk
    gives worse progress, worse cancellation, and a residual that means nothing
    because it mixes several volumes' unreadable directories together.
    """
    cancel = cancel or threading.Event()
    root_path = request.volume.root

    report = VolumeReport(
        volume=request.volume,
        root=DirectoryNode(path=root_path),
        max_entries=request.max_entries,
        max_seconds=request.max_seconds,
        used_at_start=request.volume.used_bytes,
    )

    started = time.monotonic()
    deadline = started + request.max_seconds

    try:
        report.stop_reason = _walk(report.root, request, report, cancel,
                                   deadline, set())
    except Exception:
        report.stop_reason = StopReason.ERROR

    report.elapsed_seconds = time.monotonic() - started
    report.finished_at = datetime.now(timezone.utc)

    # Read usage again rather than reusing the figure from before the walk.
    measured = usage_now(root_path)
    report.used_at_end = measured[1] if measured else request.volume.used_bytes

    # A budget that stopped the walk is bytes we could not see, and belongs in
    # the residual under its own name rather than folded into "other".
    if report.stop_reason is StopReason.BUDGET_EXHAUSTED:
        report.residual[ResidualReason.BUDGET_EXHAUSTED] = report.residual_bytes
    elif report.stop_reason is StopReason.TIME_EXHAUSTED:
        report.residual[ResidualReason.TIME_EXHAUSTED] = report.residual_bytes

    report.largest_files.sort(key=lambda f: f.allocated_bytes, reverse=True)
    del report.largest_files[100:]

    return report
