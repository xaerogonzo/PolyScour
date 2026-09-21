r"""Storage history: comparing two scans without inventing a number.

Subtraction is easy and the plausible implementation is wrong in four places,
each of which has a test here that fails if it drifts back:

* a folder "appears" only because a retention cutoff hid it last time
* a swapped disk under the same drive letter is compared as if it were the same
* a scan that stopped early is treated as a baseline
* the three figures are forced to add up, asserting a precision nothing has

The checks that guard against these are each shown to be *capable of failing*:
the cutoff test asserts the same data both ways -- once where the ceiling hides
the folder, once where it does not -- so a comparison that ignored the ceiling
could not pass it.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from _storage_fixtures import (GiB, MiB, T0, T1, VOL_A, VOL_B, snap,
                               node as _node, report as _report)
from polyscour.storage import comparison, snapshots, volumes
from polyscour.storage.analyser import (DirectoryNode, FileEntry, ResidualReason,
                                        StopReason, StorageScanRequest,
                                        VolumeReport, analyse)
from polyscour.storage.comparison import (Comparison, Refusal, RefusalReason,
                                          compare)
from polyscour.storage.history import SaveOutcome, SnapshotStore
from polyscour.storage.snapshots import (RetainedDir, RetainedFile, Snapshot,
                                         SnapshotCorrupt)

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows storage")

def ok(older: Snapshot, newer: Snapshot) -> Comparison:
    result = compare(older, newer)
    assert isinstance(result, Comparison), result
    return result


# ── the retention cutoff must not manufacture growth ─────────────────────────

def test_a_directory_hidden_under_the_cutoff_is_not_reported_as_growth():
    """The failure this whole design exists to avoid, asserted both ways.

    ``X`` is 1.5 GiB now and absent from the older list. Whether that is growth
    depends entirely on how big something not in that list could have been.
    """
    x = RetainedDir(r"C:\Users\me\AppData\X", int(1.5 * GiB), 10)

    # The older scan could have been hiding anything up to 2 GiB. X may not have
    # changed at all, so there is no evidence, and it must not be listed.
    hidden = ok(snap(taken_at=T0, directory_ceiling_bytes=2 * GiB),
                snap(taken_at=T1, directories=(x,),
                     directory_ceiling_bytes=2 * GiB))
    assert hidden.attribution is not None
    assert hidden.attribution.directories == ()

    # The control: the identical data, but an older list that claims nothing over
    # 64 MiB was hidden. Now X provably grew, and a comparison that ignored the
    # ceiling could not have told these two cases apart.
    visible = ok(snap(taken_at=T0),
                 snap(taken_at=T1, directories=(x,),
                      directory_ceiling_bytes=2 * GiB))
    (change,) = visible.attribution.directories
    assert change.exact is False
    assert change.delta == x.allocated_bytes - snapshots.RETENTION_MIN_BYTES


def test_growth_beyond_the_ceiling_is_a_lower_bound_not_a_measurement():
    x = RetainedDir(r"C:\big", 5 * GiB, 10)
    result = ok(snap(taken_at=T0, directory_ceiling_bytes=2 * GiB),
                snap(taken_at=T1, directories=(x,)))
    (change,) = result.attribution.directories
    assert change.old_bytes is None and change.new_bytes == 5 * GiB
    assert change.delta == 3 * GiB          # at least, not exactly
    assert change.exact is False


def test_a_directory_that_left_the_list_is_bounded_the_same_way():
    gone = RetainedDir(r"C:\big", 5 * GiB, 10)
    # Still possibly 2 GiB now, so it shrank by at least 3.
    result = ok(snap(taken_at=T0, directories=(gone,)),
                snap(taken_at=T1, directory_ceiling_bytes=2 * GiB))
    (change,) = result.attribution.directories
    assert change.new_bytes is None
    assert change.delta == -3 * GiB and change.exact is False

    # ...and one that could still be its old size shows nothing.
    still = ok(snap(taken_at=T0, directories=(gone,)),
               snap(taken_at=T1, directory_ceiling_bytes=6 * GiB))
    assert still.attribution.directories == ()


def test_a_directory_in_both_lists_is_exact():
    a0 = RetainedDir(r"C:\a", 2 * GiB, 5)
    a1 = RetainedDir(r"C:\a", 5 * GiB, 9)
    (change,) = ok(snap(taken_at=T0, directories=(a0,)),
                   snap(taken_at=T1, directories=(a1,))).attribution.directories
    assert (change.old_bytes, change.new_bytes) == (2 * GiB, 5 * GiB)
    assert change.delta == 3 * GiB and change.exact is True


def test_an_unchanged_directory_is_not_listed():
    d = RetainedDir(r"C:\a", 2 * GiB, 5)
    result = ok(snap(taken_at=T0, directories=(d,)),
                snap(taken_at=T1, directories=(d,)))
    assert result.attribution.directories == ()


def test_directories_match_regardless_of_case():
    old = RetainedDir(r"C:\Users\Bob", 1 * GiB, 1)
    new = RetainedDir(r"c:\users\bob", 3 * GiB, 1)
    (change,) = ok(snap(taken_at=T0, directories=(old,)),
                   snap(taken_at=T1, directories=(new,))).attribution.directories
    assert change.exact is True and change.delta == 2 * GiB
    assert change.path == r"c:\users\bob"          # the newer spelling


def test_changes_are_ordered_by_size_of_movement_in_either_direction():
    old = (RetainedDir(r"C:\small", 1 * GiB, 1), RetainedDir(r"C:\shrank", 9 * GiB, 1))
    new = (RetainedDir(r"C:\small", 2 * GiB, 1), RetainedDir(r"C:\shrank", 3 * GiB, 1))
    result = ok(snap(taken_at=T0, directories=old), snap(taken_at=T1, directories=new))
    assert [c.path for c in result.attribution.directories] == [r"C:\shrank", r"C:\small"]
    assert [c.delta for c in result.attribution.directories] == [-6 * GiB, 1 * GiB]


# ── files: the same rule, with the exact case ────────────────────────────────

def test_a_new_file_is_exact_only_when_the_older_list_dropped_nothing():
    f = RetainedFile(r"C:\vm.vhdx", 30 * GiB)

    exact = ok(snap(taken_at=T0, file_ceiling_bytes=0),
               snap(taken_at=T1, files=(f,))).attribution.files
    assert (exact[0].delta, exact[0].exact) == (30 * GiB, True)

    bounded = ok(snap(taken_at=T0, file_ceiling_bytes=10 * GiB),
                 snap(taken_at=T1, files=(f,))).attribution.files
    assert (bounded[0].delta, bounded[0].exact) == (20 * GiB, False)


def test_a_file_below_the_older_files_ceiling_is_not_reported():
    f = RetainedFile(r"C:\maybe.bin", 4 * GiB)
    result = ok(snap(taken_at=T0, file_ceiling_bytes=5 * GiB),
                snap(taken_at=T1, files=(f,)))
    assert result.attribution.files == ()


# ── extensions ───────────────────────────────────────────────────────────────

def test_extension_deltas_are_exact_and_zero_is_dropped():
    result = ok(snap(taken_at=T0, by_extension={".mp4": 5 * GiB, ".log": 1 * GiB,
                                                ".tmp": 2 * GiB}),
                snap(taken_at=T1, by_extension={".mp4": 9 * GiB, ".log": 1 * GiB,
                                                ".iso": 3 * GiB}))
    got = {c.extension: (c.old_bytes, c.new_bytes, c.delta)
           for c in result.attribution.extensions}
    assert got == {".mp4": (5 * GiB, 9 * GiB, 4 * GiB),
                   ".iso": (0, 3 * GiB, 3 * GiB),
                   ".tmp": (2 * GiB, 0, -2 * GiB)}
    assert ".log" not in got
    assert [c.extension for c in result.attribution.extensions] == [".mp4", ".iso", ".tmp"]


# ── a swapped disk, an unidentified disk, and a scan that stopped early ──────

def test_a_different_volume_is_refused_not_compared():
    result = compare(snap(volume_id=VOL_A, taken_at=T0),
                     snap(volume_id=VOL_B, taken_at=T1))
    assert isinstance(result, Refusal)
    assert result.reason is RefusalReason.DIFFERENT_VOLUME


@pytest.mark.parametrize("which", ["older", "newer", "both"])
def test_an_unidentified_volume_is_never_compared(which):
    """None means unknown, not "the same as another unknown"."""
    o = snap(volume_id=None if which in ("older", "both") else VOL_A, taken_at=T0)
    n = snap(volume_id=None if which in ("newer", "both") else VOL_A, taken_at=T1)
    result = compare(o, n)
    assert isinstance(result, Refusal)
    assert result.reason is RefusalReason.VOLUME_UNIDENTIFIED


def test_the_same_volume_under_a_new_drive_letter_still_compares():
    """The whole point of keying on the GUID rather than the label."""
    result = ok(snap(volume_label="D:", taken_at=T0),
                snap(volume_label="E:", taken_at=T1))
    assert result.attribution is not None


@pytest.mark.parametrize("delta", [timedelta(0), timedelta(days=-1)])
def test_a_second_scan_that_is_not_later_is_refused(delta):
    result = compare(snap(taken_at=T0), snap(taken_at=T0 + delta))
    assert isinstance(result, Refusal)
    assert result.reason is RefusalReason.NOT_NEWER


@pytest.mark.parametrize("side,reason", [
    ("older", RefusalReason.OLDER_INCOMPLETE),
    ("newer", RefusalReason.NEWER_INCOMPLETE),
])
def test_an_incomplete_scan_keeps_the_volume_figure_and_refuses_attribution(side, reason):
    """Windows' own number needs no scan to have finished; *where* does."""
    o = snap(taken_at=T0, used_at_end=100 * GiB)
    n = snap(taken_at=T1, used_at_end=112 * GiB)
    stopped = {"stop_reason": StopReason.TIME_EXHAUSTED}
    if side == "older":
        o = snap(taken_at=T0, used_at_end=100 * GiB, **stopped)
    else:
        n = snap(taken_at=T1, used_at_end=112 * GiB, **stopped)

    result = ok(o, n)
    assert result.used_delta == 12 * GiB
    assert result.attribution is None
    assert result.attribution_refusal.reason is reason


def test_a_comparison_has_an_attribution_or_a_refusal_never_both_or_neither():
    a, b = snap(taken_at=T0), snap(taken_at=T1)
    kwargs = dict(older=a, newer=b, days=7.0, used_delta=0, total_delta=0)
    with pytest.raises(ValueError):
        Comparison(**kwargs, attribution=None, attribution_refusal=None)
    with pytest.raises(ValueError):
        Comparison(**kwargs,
                   attribution=comparison.Attribution(0, 0, 0, (), (), ()),
                   attribution_refusal=Refusal(RefusalReason.NOT_NEWER, "x"))


# ── the three figures ────────────────────────────────────────────────────────

def test_the_three_figures_are_reported_separately_and_not_forced_to_add_up():
    older = snap(taken_at=T0, used_at_end=100 * GiB, measured_bytes=90 * GiB)
    newer = snap(taken_at=T1, used_at_end=140 * GiB, measured_bytes=105 * GiB)
    r = ok(older, newer)
    assert r.used_delta == 40 * GiB
    assert r.attribution.measured_delta == 15 * GiB
    assert r.attribution.residual_delta == 25 * GiB      # (140-105) - (100-90)
    # Here they happen to reconcile. The next case is the one that must not be
    # made to.

    clamped = ok(snap(taken_at=T0, used_at_end=100 * GiB, measured_bytes=90 * GiB),
                 snap(taken_at=T1, used_at_end=130 * GiB, measured_bytes=140 * GiB))
    a = clamped.attribution
    assert clamped.used_delta == 30 * GiB
    assert a.measured_delta == 50 * GiB
    assert a.residual_delta == -10 * GiB                 # residual went to 0
    assert a.measured_delta + a.residual_delta != clamped.used_delta


def test_capacity_and_unreadable_directory_movement_are_reported():
    r = ok(snap(taken_at=T0, volume_total_bytes=500 * GiB,
                permission_denied_directories=10),
           snap(taken_at=T1, volume_total_bytes=600 * GiB,
                permission_denied_directories=14))
    assert r.total_delta == 100 * GiB
    assert r.attribution.unreadable_directories_delta == 4
    assert r.days == pytest.approx(7.0)


# ── building a snapshot from a real report ───────────────────────────────────

def test_only_directories_over_the_floor_are_kept_and_the_root_is_not_one(monkeypatch):
    monkeypatch.setattr(snapshots, "RETENTION_MIN_BYTES", 100 * MiB)
    root = _node("C:/", 10 * GiB,
                 _node("C:/big", 5 * GiB, _node("C:/big/deep", 4 * GiB)),
                 _node("C:/tiny", 10 * MiB))
    s = Snapshot.from_report(_report(root))
    assert [d.path for d in s.directories] == [str(Path("C:/big")),
                                               str(Path("C:/big/deep"))]
    # Nothing was dropped for count, so anything absent was under the floor.
    assert s.directory_ceiling_bytes == 100 * MiB


def test_when_the_cap_excludes_something_the_ceiling_is_the_largest_excluded(monkeypatch):
    monkeypatch.setattr(snapshots, "RETENTION_MIN_BYTES", 10 * MiB)
    monkeypatch.setattr(snapshots, "RETENTION_MAX_DIRS", 2)
    root = _node("C:/", 20 * GiB,
                 _node("C:/a", 9 * GiB), _node("C:/b", 5 * GiB),
                 _node("C:/c", 3 * GiB), _node("C:/d", 1 * GiB))
    s = Snapshot.from_report(_report(root))
    assert [d.allocated_bytes for d in s.directories] == [9 * GiB, 5 * GiB]
    assert s.directory_ceiling_bytes == 3 * GiB      # C:/c could be missing


def test_a_very_deep_tree_does_not_hit_the_recursion_limit(monkeypatch):
    monkeypatch.setattr(snapshots, "RETENTION_MIN_BYTES", 1)
    monkeypatch.setattr(snapshots, "RETENTION_MAX_DIRS", 10_000)   # not what is tested
    node = _node("C:/leaf", 10 * MiB)
    for i in range(3000):
        node = _node(f"C:/d{i}", 10 * MiB + i, node)
    s = Snapshot.from_report(_report(_node("C:/", 20 * GiB, node)))
    assert len(s.directories) == 3001


def test_files_from_a_full_list_are_bounded_by_the_smallest_kept(monkeypatch):
    monkeypatch.setattr(snapshots, "LARGEST_FILES_KEPT", 3)
    files = [FileEntry(Path(f"C:/f{i}"), s, s)
             for i, s in enumerate([9 * GiB, 7 * GiB, 5 * GiB, 4 * GiB, 2 * GiB])]
    s = Snapshot.from_report(_report(_node("C:/", 30 * GiB), largest_files=files))
    assert [f.allocated_bytes for f in s.files] == [9 * GiB, 7 * GiB, 5 * GiB]
    assert s.file_ceiling_bytes == 5 * GiB


def test_files_from_a_list_that_was_not_full_have_a_ceiling_of_zero(monkeypatch):
    """Nothing was dropped -- a different claim from "unknown"."""
    monkeypatch.setattr(snapshots, "LARGEST_FILES_KEPT", 10)
    files = [FileEntry(Path("C:/only"), 3 * GiB, 3 * GiB)]
    s = Snapshot.from_report(_report(_node("C:/", 30 * GiB), largest_files=files))
    assert len(s.files) == 1 and s.file_ceiling_bytes == 0


@windows_only
def test_the_analyser_really_trims_to_the_constant_the_snapshot_relies_on(
        tmp_path, monkeypatch):
    """The file ceiling is only true if the analyser trims to this number.

    A second literal 100 somewhere would let the two drift apart and turn the
    bound into a claim nothing checks, so this proves the constant is the one in
    use rather than only that it exists.
    """
    from polyscour.storage import analyser
    assert snapshots.LARGEST_FILES_KEPT == analyser.LARGEST_FILES_KEPT

    monkeypatch.setattr(analyser, "LARGEST_FILES_KEPT", 2)
    for i in range(5):
        (tmp_path / f"f{i}.bin").write_bytes(b"x" * (100 * (i + 1)))
    total, used, free = volumes.usage_now(tmp_path)
    report = analyse(StorageScanRequest(volume=volumes.Volume(
        root=tmp_path, fstype="NTFS", total_bytes=total, used_bytes=used,
        free_bytes=free)))
    assert [f.allocated_bytes for f in report.largest_files] == [500, 400]


def test_only_named_positive_residual_reasons_are_stored():
    s = Snapshot.from_report(_report(
        _node("C:/", 10 * GiB),
        residual={ResidualReason.SYSTEM_MANAGED: 4 * GiB,
                  ResidualReason.OTHER: 0}))
    assert s.residual == {"system_managed": 4 * GiB}


def test_a_report_without_a_time_zone_becomes_utc():
    s = Snapshot.from_report(_report(_node("C:/", GiB),
                                     finished_at=datetime(2026, 9, 1, 12, 0)))
    assert s.taken_at.tzinfo is not None
    assert s.taken_at.utcoffset() == timedelta(0)


def test_the_volume_identity_travels_from_the_volume_to_the_snapshot():
    assert Snapshot.from_report(_report(_node("C:/", GiB))).volume_id == VOL_A


# ── the stored form ──────────────────────────────────────────────────────────

def _rich() -> Snapshot:
    return snap(
        residual={"system_managed": 3 * GiB}, permission_denied_directories=7,
        directories=(RetainedDir(r"C:\a", 2 * GiB, 4), RetainedDir(r"C:\b", GiB, 1)),
        files=(RetainedFile(r"C:\a\f.bin", GiB),), file_ceiling_bytes=GiB // 2,
        by_extension={".bin": GiB, "": 12})


def test_a_snapshot_survives_a_round_trip_exactly():
    original = _rich()
    assert Snapshot.from_json(original.to_json()) == original


@pytest.mark.parametrize("name,mutate", [
    ("wrong schema", lambda d: d.update(schema=999)),
    ("no schema", lambda d: d.pop("schema")),
    ("missing field", lambda d: d.pop("used_at_end")),
    ("bool as a size", lambda d: d.update(used_at_end=True)),
    ("negative size", lambda d: d.update(measured_bytes=-1)),
    ("float size", lambda d: d.update(measured_bytes=1.5)),
    ("text as a size", lambda d: d.update(entries_examined="many")),
    ("unknown stop reason", lambda d: d.update(stop_reason="exploded")),
    ("naive timestamp", lambda d: d.update(taken_at="2026-09-01T12:00:00")),
    ("garbled timestamp", lambda d: d.update(taken_at="yesterday")),
    ("unknown residual key", lambda d: d.update(residual={"mystery": 5})),
    ("negative residual", lambda d: d.update(residual={"other": -5})),
    ("ragged directory row", lambda d: d.update(directories=[["C:\\a", 5]])),
    ("non-text path", lambda d: d.update(directories=[[7, 5, 1]])),
    ("id of the wrong type", lambda d: d.update(volume_id=12)),
    ("extensions not an object", lambda d: d.update(by_extension=[])),
])
def test_a_snapshot_that_is_not_trustworthy_is_refused_not_repaired(name, mutate):
    """A missing field would compare as zero -- a measurement nobody made."""
    raw = json.loads(_rich().to_json())
    mutate(raw)
    with pytest.raises(SnapshotCorrupt):
        Snapshot.from_json(json.dumps(raw))


@pytest.mark.parametrize("text", ["", "not json", "[]", "null", "42", '"x"'])
def test_things_that_are_not_even_an_object_are_refused(text):
    with pytest.raises(SnapshotCorrupt):
        Snapshot.from_json(text)


# ── a real walk, end to end ──────────────────────────────────────────────────

@windows_only
def test_a_real_scan_becomes_a_snapshot_that_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshots, "RETENTION_MIN_BYTES", 1)
    (tmp_path / "a.bin").write_bytes(b"x" * 1000)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.log").write_bytes(b"y" * 2000)

    measured = volumes.usage_now(tmp_path)
    total, used, free = measured
    volume = volumes.Volume(root=tmp_path, fstype="NTFS", total_bytes=total,
                            used_bytes=used, free_bytes=free, volume_id=VOL_A)
    report = analyse(StorageScanRequest(volume=volume))

    s = Snapshot.from_report(report)
    assert s.is_complete and s.volume_id == VOL_A
    assert [Path(d.path).name for d in s.directories] == ["sub"]
    assert s.by_extension == {".bin": 1000, ".log": 2000}
    assert Snapshot.from_json(s.to_json()) == s


# ── the store ────────────────────────────────────────────────────────────────

def _store(tmp_path, keep=20) -> SnapshotStore:
    return SnapshotStore(tmp_path / "storage_history.sqlite", keep_per_volume=keep)


def _at(days: int, **over) -> Snapshot:
    return snap(taken_at=T0 + timedelta(days=days), **over)


def test_saved_scans_come_back_newest_first(tmp_path):
    store = _store(tmp_path)
    for d in (2, 0, 1):
        assert store.save(_at(d)) is SaveOutcome.SAVED
    got = store.history(VOL_A)
    assert [s.taken_at for s in got.snapshots] == [T0 + timedelta(days=n)
                                                   for n in (2, 1, 0)]
    assert got.unreadable == 0


def test_an_incomplete_scan_is_not_history(tmp_path):
    store = _store(tmp_path)
    outcome = store.save(_at(0, stop_reason=StopReason.TIME_EXHAUSTED))
    assert outcome is SaveOutcome.NOT_COMPLETE
    assert store.history(VOL_A).snapshots == ()


def test_a_scan_of_an_unidentified_volume_is_not_saved_and_says_why(tmp_path):
    store = _store(tmp_path)
    assert store.save(_at(0, volume_id=None)) is SaveOutcome.VOLUME_UNIDENTIFIED
    assert store.history(VOL_A).snapshots == ()


def test_the_store_keeps_the_newest_per_volume_and_touches_no_other(tmp_path):
    store = _store(tmp_path, keep=3)
    for d in range(6):
        store.save(_at(d, volume_id=VOL_A))
    for d in range(2):
        store.save(_at(d, volume_id=VOL_B))

    a = store.history(VOL_A).snapshots
    assert [s.taken_at for s in a] == [T0 + timedelta(days=n) for n in (5, 4, 3)]
    assert len(store.history(VOL_B).snapshots) == 2


def test_clearing_one_volume_or_all_reports_how_many_went(tmp_path):
    store = _store(tmp_path)
    for d in range(3):
        store.save(_at(d, volume_id=VOL_A))
    store.save(_at(0, volume_id=VOL_B))

    assert store.clear(VOL_A) == 3
    assert store.history(VOL_A).snapshots == ()
    assert len(store.history(VOL_B).snapshots) == 1
    assert store.clear() == 1


def test_an_unreadable_row_is_counted_and_never_hidden_or_fatal(tmp_path):
    """Damage must not look like a short past."""
    store = _store(tmp_path)
    store.save(_at(0))
    store.save(_at(2))
    # closing(): `with sqlite3.connect(...)` commits but does not close, and an
    # open handle keeps the file locked on Windows.
    with closing(sqlite3.connect(store.path)) as conn, conn:
        conn.execute("INSERT INTO storage_snapshots "
                     "(volume_id, taken_at, schema_version, payload) "
                     "VALUES (?, ?, 1, ?)",
                     (VOL_A, (T0 + timedelta(days=1)).isoformat(), "{garbage"))
        conn.execute("INSERT INTO storage_snapshots "
                     "(volume_id, taken_at, schema_version, payload) "
                     "VALUES (?, ?, 999, ?)",
                     (VOL_A, (T0 + timedelta(days=3)).isoformat(),
                      '{"schema": 999}'))

    got = store.history(VOL_A)
    assert got.unreadable == 2
    assert [s.taken_at for s in got.snapshots] == [T0 + timedelta(days=2), T0]


def test_a_store_that_has_never_been_written_is_empty_not_an_error(tmp_path):
    got = _store(tmp_path).history(VOL_A)
    assert got.snapshots == () and got.unreadable == 0


def test_keeping_fewer_than_one_is_refused(tmp_path):
    with pytest.raises(ValueError):
        _store(tmp_path, keep=0)


def test_saved_history_feeds_a_comparison_end_to_end(tmp_path):
    store = _store(tmp_path)
    a = RetainedDir(r"C:\Games", 40 * GiB, 900)
    store.save(_at(0, used_at_end=100 * GiB))
    store.save(_at(7, used_at_end=142 * GiB, directories=(a,)))

    newest, previous = store.history(VOL_A).snapshots
    result = ok(previous, newest)
    assert result.used_delta == 42 * GiB
    (change,) = result.attribution.directories
    assert change.path == r"C:\Games" and change.exact is False


# ── the volume identity itself ───────────────────────────────────────────────

def test_a_volume_built_without_an_identity_has_none_not_a_guess():
    v = volumes.Volume(root=Path("C:/"), fstype="NTFS", total_bytes=1,
                       used_bytes=0, free_bytes=1)
    assert v.volume_id is None


@windows_only
def test_real_volumes_carry_a_volume_guid_path():
    found = volumes.fixed_volumes()
    if not found:
        pytest.skip("no fixed volumes enumerated here")
    shape = re.compile(r"^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$")
    ids = [v.volume_id for v in found]
    # A volume may legitimately have none, but on a real Windows machine at
    # least one has, and any that do have the documented shape.
    assert any(i is not None for i in ids)
    assert all(i is None or shape.match(i) for i in ids)
    assert len({i for i in ids if i}) == len([i for i in ids if i])


@windows_only
def test_a_path_that_is_not_a_mount_point_has_no_identity():
    """It fails rather than guessing, which is why callers pass a volume root."""
    assert volumes._volume_id(Path("C:/Windows")) is None
    assert volumes._volume_id(Path("Q:/definitely-not-mounted")) is None


# ── what is kept, and clearing it for real ───────────────────────────────────

def test_a_summary_of_a_store_never_written_says_zero_and_does_not_create_it(tmp_path):
    store = _store(tmp_path)
    s = store.summary()
    assert (s.scans, s.volumes, s.file_bytes) == (0, 0, 0)
    assert not store.path.exists()


def test_the_summary_counts_scans_volumes_and_unreadable_rows_alike(tmp_path):
    store = _store(tmp_path)
    for d in range(3):
        store.save(_at(d, volume_id=VOL_A))
    store.save(_at(0, volume_id=VOL_B))
    with closing(sqlite3.connect(store.path)) as conn, conn:
        conn.execute("INSERT INTO storage_snapshots "
                     "(volume_id, taken_at, schema_version, payload) "
                     "VALUES (?, ?, 1, ?)", (VOL_A, T0.isoformat(), "{garbage"))

    s = store.summary()
    # The damaged row is still a row somebody can clear, so it is counted.
    assert (s.scans, s.volumes) == (5, 2)
    assert s.file_bytes == store.path.stat().st_size > 0


def test_clearing_removes_the_paths_from_the_file_and_not_just_from_the_table(tmp_path):
    """SQLite leaves a deleted row's bytes in a free page until it is reused.

    These rows hold the paths of a person's largest folders. "Cleared" while the
    paths still sit readable in the file would be a claim the file contradicts,
    so this reads the file's bytes -- and shows the check can fail: a plain
    DELETE, which is what a naive clear does, leaves them behind.
    """
    # Searched for without its backslashes: the path is stored as JSON, which
    # doubles them, and a needle that never matched would make this pass for free.
    needle = b"Secret-Project-Folder-XYZ"
    secret = _at(0, directories=(
        RetainedDir(r"C:\Users\me\Secret-Project-Folder-XYZ", 5 * GiB, 1),))

    naive = _store(tmp_path / "naive")
    naive.save(secret)
    assert needle in naive.path.read_bytes()
    with closing(sqlite3.connect(naive.path)) as conn, conn:
        conn.execute("DELETE FROM storage_snapshots")          # no VACUUM
    assert needle in naive.path.read_bytes(), \
        "control: a bare DELETE leaves the path in the file"

    real = _store(tmp_path / "real")
    real.save(secret)
    assert real.clear() == 1
    assert needle not in real.path.read_bytes()
    assert real.history(VOL_A).snapshots == ()


def test_clearing_one_volume_also_vacuums_and_leaves_the_others(tmp_path):
    store = _store(tmp_path)
    store.save(_at(0, volume_id=VOL_A,
                   directories=(RetainedDir(r"C:\Only-On-A-Marker", GiB, 1),)))
    store.save(_at(0, volume_id=VOL_B,
                   directories=(RetainedDir(r"D:\Only-On-B-Marker", GiB, 1),)))
    assert store.clear(VOL_A) == 1

    raw = store.path.read_bytes()
    assert b"Only-On-A-Marker" not in raw
    assert b"Only-On-B-Marker" in raw
    assert len(store.history(VOL_B).snapshots) == 1
