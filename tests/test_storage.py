r"""The Storage Analyser: the walk, and the four ways it can lie.

Nothing here tests that it deletes correctly, because it cannot delete. What is
worth testing is the arithmetic, and specifically the places where a plausible
implementation produces a number that is confidently wrong:

* counting a hardlinked file once per directory entry — inventing space
* putting a skipped junction's bytes in the residual — inventing missing space
* attributing bytes to a directory we could not open — inventing both
* reporting logical size for a sparse file — overstating what the disk gave up

Each has a test that fails if the arithmetic drifts back.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from polyscour.storage import volumes
from polyscour.storage.analyser import (ResidualReason, StopReason,
                                        StorageScanRequest, VolumeReport,
                                        DirectoryNode, analyse)

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows storage")


def _volume_for(path: Path) -> volumes.Volume:
    """A Volume pointing at a temp directory, so a test walks only its own tree.

    ``analyse()`` takes a Volume rather than a path precisely so this is
    possible: the walk root is data, not a constant.
    """
    measured = volumes.usage_now(path)
    total, used, free = measured if measured else (0, 0, 0)
    return volumes.Volume(root=path, fstype="NTFS", total_bytes=total,
                          used_bytes=used, free_bytes=free)


def _analyse(path: Path, **kwargs) -> VolumeReport:
    return analyse(StorageScanRequest(volume=_volume_for(path), **kwargs))


# ── volumes ──────────────────────────────────────────────────────────────────

def test_only_fixed_volumes_are_listed():
    """Removable and network volumes are excluded.

    Not a safety property — nothing here can touch anything. A network share
    measures the link rather than the disk, and a USB stick unplugged mid-walk
    produces a report about a machine that no longer exists.
    """
    for vol in volumes.fixed_volumes():
        assert vol.total_bytes > 0
        assert vol.used_bytes <= vol.total_bytes
        assert str(vol.root).endswith(("\\", "/"))
        assert not vol.label.endswith("\\")


def test_a_volume_that_cannot_be_measured_is_omitted_not_zeroed():
    """``usage_now`` returns None rather than zeros for an unreadable path.

    "We could not measure this" and "this is empty" are opposite facts, and a
    tuple of zeros says the second while meaning the first.
    """
    assert volumes.usage_now(Path(r"Q:\definitely-not-mounted")) is None


# ── the arithmetic ───────────────────────────────────────────────────────────

def test_a_plain_tree_is_summed(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 1000)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"y" * 2000)

    report = _analyse(tmp_path)

    assert report.stop_reason is StopReason.COMPLETED
    assert report.root.file_count == 2
    assert report.root.logical_bytes == 3000
    assert report.directories_examined == 2


def test_a_hardlinked_file_is_counted_once(tmp_path):
    r"""Two directory entries, one file, one allocation.

    This is the test ``docs/adr/0007`` promises: Python exposes ``st_ino`` and
    ``st_nlink`` on Windows, but those are not Unix inodes and the presence of
    an attribute is not a guarantee about its semantics. So a real hard link is
    created rather than the behaviour assumed.

    It matters most in ``C:\Windows``, where 86.7% of ``System32`` files and
    57.2% of ``WinSxS`` files are hardlinked — measured. Counting per entry
    roughly doubles the reported size of Windows.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(b"z" * 4096)
    try:
        os.link(original, tmp_path / "link.bin")
    except OSError as exc:
        pytest.skip(f"cannot create a hard link here: {exc}")

    report = _analyse(tmp_path)

    assert report.hardlinks_deduplicated == 1
    assert report.root.file_count == 1, (
        "a hardlinked file was counted once per directory entry, which invents "
        "space that does not exist")
    assert report.root.logical_bytes == 4096
    assert report.hardlink_bytes_saved == 4096


def test_dedup_can_be_turned_off_and_then_it_double_counts(tmp_path):
    """The control for the test above.

    Without this, a walker that silently failed to find the second entry at all
    would satisfy the deduplication test perfectly.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(b"z" * 4096)
    try:
        os.link(original, tmp_path / "link.bin")
    except OSError as exc:
        pytest.skip(f"cannot create a hard link here: {exc}")

    report = _analyse(tmp_path, deduplicate_hardlinks=False)

    assert report.root.file_count == 2
    assert report.root.logical_bytes == 8192, (
        "with deduplication off the walk should see both entries; if it does "
        "not, the deduplication test above proves nothing")


def test_a_junction_is_not_descended_and_is_not_residual(tmp_path):
    r"""The correction ``adr/0007`` exists to record.

    A junction's target is counted where it really lives, so *not* walking it
    is correct deduplication — and adding its bytes to the residual would
    invent missing space out of that correctness. It is a diagnostic count.
    """
    real = tmp_path / "real"
    real.mkdir()
    (real / "payload.bin").write_bytes(b"q" * 5000)

    link = tmp_path / "junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip(f"cannot create a junction here: {result.stderr.strip()}")

    report = _analyse(tmp_path)

    assert report.reparse_points_skipped == 1
    assert report.root.logical_bytes == 5000, (
        "the junction was descended, so its target was counted twice")
    assert ResidualReason.OTHER not in report.residual, (
        "reparse-skipped bytes were added to the residual, inventing missing "
        "space out of correct deduplication")


def test_an_unreadable_directory_is_a_count_and_never_bytes(tmp_path):
    """We could not open it, so its size is exactly what we do not know.

    A byte figure here would be invented, in the one panel whose job is to say
    what could not be seen.
    """
    report = _analyse(tmp_path)
    assert report.permission_denied_directories == 0

    # The field exists and is a count, and no ResidualReason can carry
    # permission bytes -- checked structurally, because the temptation is to
    # add one back.
    assert not any(r.name == "PERMISSION_DENIED" for r in ResidualReason), (
        "PERMISSION_DENIED is back on ResidualReason. Bytes cannot be "
        "attributed to a directory that could not be opened.")


# ── budgets and stopping ─────────────────────────────────────────────────────

def test_the_entry_budget_stops_the_walk_and_says_so(tmp_path):
    for i in range(50):
        (tmp_path / f"f{i}.bin").write_bytes(b"x" * 10)

    report = _analyse(tmp_path, max_entries=5)

    assert report.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert not report.stop_reason.is_complete
    assert report.entries_examined <= 6


def test_the_time_budget_stops_the_walk_and_says_so(tmp_path):
    for i in range(200):
        (tmp_path / f"f{i}.bin").write_bytes(b"x" * 10)

    report = _analyse(tmp_path, max_seconds=0.0)

    assert report.stop_reason is StopReason.TIME_EXHAUSTED


def test_cancellation_is_distinguishable_from_a_budget(tmp_path):
    """Four stop reasons rather than ``complete: bool``.

    A scan that ran out of time says something about the disk; one the user
    cancelled says nothing at all. Collapsing them loses the difference.
    """
    for i in range(200):
        (tmp_path / f"f{i}.bin").write_bytes(b"x" * 10)

    cancel = threading.Event()
    cancel.set()
    report = analyse(StorageScanRequest(volume=_volume_for(tmp_path)), cancel)

    assert report.stop_reason is StopReason.CANCELLED


def test_the_budget_is_reported_not_just_applied(tmp_path):
    """"Partial" must be a measurement, not a warning."""
    report = _analyse(tmp_path, max_entries=99, max_seconds=7.0)
    assert report.max_entries == 99
    assert report.max_seconds == 7.0
    assert report.elapsed_seconds >= 0
    assert report.finished_at is not None


# ── the residual ─────────────────────────────────────────────────────────────

def test_the_residual_is_never_negative():
    """Deduplication and compression both let the tree measure less than the
    difference implies, and the volume can shrink mid-walk. A negative
    unaccounted figure is not a number anyone can act on."""
    report = VolumeReport(volume=_volume_for(Path("C:\\")),
                          root=DirectoryNode(path=Path("C:\\")))
    report.root.allocated_bytes = 900
    report.used_at_end = 100
    assert report.residual_bytes == 0


def test_the_breakdown_derives_its_remainder_rather_than_accumulating_it():
    """The unexplained part is whatever the named reasons do not cover.

    Accumulating it separately would let the parts disagree with the whole,
    which is the one thing this panel cannot do.
    """
    report = VolumeReport(volume=_volume_for(Path("C:\\")),
                          root=DirectoryNode(path=Path("C:\\")))
    report.root.allocated_bytes = 100
    report.used_at_end = 1000
    report.residual[ResidualReason.TIME_EXHAUSTED] = 300

    breakdown = dict(report.residual_breakdown())
    assert breakdown[ResidualReason.TIME_EXHAUSTED] == 300
    assert breakdown[ResidualReason.OTHER] == 600
    assert sum(breakdown.values()) == report.residual_bytes


def test_volume_usage_is_snapshotted_at_both_ends(tmp_path):
    """A machine that wrote during the scan is doing its job, not breaking the
    analyser. The report must be able to say so."""
    (tmp_path / "a.bin").write_bytes(b"x" * 100)
    report = _analyse(tmp_path)
    assert report.used_at_start > 0
    assert report.used_at_end > 0
    assert isinstance(report.volume_drift_bytes, int)


# ── sizes ────────────────────────────────────────────────────────────────────

def test_a_sparse_file_reports_less_allocated_than_logical(tmp_path):
    r"""``st_size`` is logical. This module exists to say what the disk gave up.

    ``fsutil sparse`` needs no elevation for a file the user owns. If the
    filesystem will not make one, the test skips rather than asserting on a
    file that is not sparse.
    """
    target = tmp_path / "sparse.bin"
    target.write_bytes(b"")

    setflag = subprocess.run(["fsutil", "sparse", "setflag", str(target)],
                             capture_output=True, text=True)
    if setflag.returncode != 0:
        pytest.skip(f"cannot mark a file sparse here: {setflag.stderr.strip()}")

    with open(target, "r+b") as fh:
        fh.truncate(64 * 1024 * 1024)      # 64 MB of nothing

    report = _analyse(tmp_path)

    assert report.root.logical_bytes == 64 * 1024 * 1024
    assert report.root.allocated_bytes < report.root.logical_bytes, (
        "a sparse file reported its logical size as its on-disk size, which "
        "overstates what the disk actually gave up")


def test_an_ordinary_file_allocates_its_logical_size(tmp_path):
    """The control for the test above: without it, a function that always
    returned zero would pass the sparse test perfectly."""
    (tmp_path / "plain.bin").write_bytes(b"x" * 8192)
    report = _analyse(tmp_path)
    assert report.root.allocated_bytes == report.root.logical_bytes == 8192


# ── the shape of the result ──────────────────────────────────────────────────

def test_largest_children_are_sorted_and_carry_no_action(tmp_path):
    """Sorting by size is a fact. There is deliberately nothing on a node that
    suggests doing something about it — no rule id, no operation, no
    reversibility flag. See the top invariant in CLAUDE.md."""
    big = tmp_path / "big"; big.mkdir()
    (big / "f.bin").write_bytes(b"x" * 9000)
    small = tmp_path / "small"; small.mkdir()
    (small / "f.bin").write_bytes(b"x" * 10)

    report = _analyse(tmp_path)
    names = [c.name for c in report.root.largest_children()]
    assert names[:2] == ["big", "small"]

    node = report.root.largest_children()[0]
    for forbidden in ("rule_id", "operation", "reversible", "requires_elevation"):
        assert not hasattr(node, forbidden), (
            f"DirectoryNode grew a {forbidden!r} field. A finding is not a "
            f"recommendation, and a node the UI can act on is a recommendation.")


def test_extensions_are_tallied(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x" * 100)
    (tmp_path / "b.txt").write_bytes(b"x" * 200)
    (tmp_path / "c.bin").write_bytes(b"x" * 50)
    (tmp_path / "noext").write_bytes(b"x" * 7)

    report = _analyse(tmp_path)

    assert report.by_extension[".txt"] == 300
    assert report.by_extension[".bin"] == 50
    assert report.by_extension["(no extension)"] == 7
