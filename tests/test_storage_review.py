r"""After a scan: snapshot, compare with the last one, and only then keep it.

The order is the thing worth guarding. Saving first would make a scan its own
baseline and every comparison would report that nothing changed -- a confident
zero that is wrong in the most plausible way. So the second-scan test asserts a
non-zero change, which a save-first implementation cannot produce.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import timedelta

from _storage_fixtures import GiB, T0, VOL_A, VOL_B, report
from polyscour.storage.analyser import StopReason
from polyscour.storage.comparison import Comparison, Refusal, RefusalReason
from polyscour.storage.history import SaveOutcome, SnapshotStore
from polyscour.storage.review import review_scan


def _scan(day: int, used: int, **over):
    """A finished scan ``day`` days after T0, with ``used`` GiB in use."""
    return report(finished_at=T0 + timedelta(days=day),
                  used_at_start=used * GiB, used_at_end=used * GiB, **over)


def _store(tmp_path) -> SnapshotStore:
    return SnapshotStore(tmp_path / "storage_history.sqlite")


def test_the_first_scan_has_no_baseline_and_is_kept(tmp_path):
    store = _store(tmp_path)
    r = review_scan(_scan(0, 100), store)

    assert r.baseline is None and r.comparison is None
    assert r.saved is SaveOutcome.SAVED and r.error is None
    assert len(store.history(VOL_A).snapshots) == 1


def test_a_second_scan_is_compared_with_the_first_and_not_with_itself(tmp_path):
    """The order test. Save-before-compare makes this ``used_delta == 0``."""
    store = _store(tmp_path)
    review_scan(_scan(0, 100), store)
    r = review_scan(_scan(7, 112), store)

    assert isinstance(r.comparison, Comparison)
    assert r.comparison.used_delta == 12 * GiB
    assert r.baseline.taken_at == T0
    assert r.saved is SaveOutcome.SAVED
    assert len(store.history(VOL_A).snapshots) == 2


def test_the_baseline_is_the_newest_kept_scan_not_the_oldest(tmp_path):
    store = _store(tmp_path)
    review_scan(_scan(0, 100), store)
    review_scan(_scan(7, 110), store)
    r = review_scan(_scan(14, 125), store)

    assert r.baseline.taken_at == T0 + timedelta(days=7)
    assert r.comparison.used_delta == 15 * GiB


def test_a_scan_that_stopped_early_keeps_the_volume_figure_and_is_not_kept(tmp_path):
    store = _store(tmp_path)
    review_scan(_scan(0, 100), store)
    r = review_scan(_scan(7, 112, stop_reason=StopReason.TIME_EXHAUSTED), store)

    assert isinstance(r.comparison, Comparison)
    assert r.comparison.used_delta == 12 * GiB          # Windows' own number
    assert r.comparison.attribution is None             # but not where
    assert r.saved is SaveOutcome.NOT_COMPLETE
    assert len(store.history(VOL_A).snapshots) == 1     # still just the first


def test_an_unidentified_volume_is_neither_compared_nor_kept_and_the_store_is_untouched(tmp_path):
    store = _store(tmp_path)
    r = review_scan(report(volume_id=None, finished_at=T0), store)

    assert r.saved is SaveOutcome.VOLUME_UNIDENTIFIED
    assert r.baseline is None and r.comparison is None
    assert not store.path.exists()                      # never even opened


def test_another_volumes_history_is_not_a_baseline(tmp_path):
    store = _store(tmp_path)
    review_scan(report(volume_id=VOL_A, finished_at=T0), store)
    r = review_scan(report(volume_id=VOL_B, finished_at=T0 + timedelta(days=7)),
                    store)
    assert r.baseline is None and r.comparison is None
    assert r.saved is SaveOutcome.SAVED


def test_a_clock_that_went_backwards_is_refused_but_the_scan_is_still_kept(tmp_path):
    store = _store(tmp_path)
    review_scan(_scan(7, 100), store)
    r = review_scan(_scan(0, 105), store)

    assert isinstance(r.comparison, Refusal)
    assert r.comparison.reason is RefusalReason.NOT_NEWER
    assert r.saved is SaveOutcome.SAVED


# ── a history fault must never cost a finished scan ──────────────────────────

class _Broken(SnapshotStore):
    """A store that fails where a test says to."""

    def __init__(self, path, *, on_history=None, on_save=None):
        super().__init__(path)
        self._on_history, self._on_save = on_history, on_save

    def history(self, volume_id):
        if self._on_history:
            raise self._on_history
        return super().history(volume_id)

    def save(self, snapshot):
        if self._on_save:
            raise self._on_save
        return super().save(snapshot)


def test_a_store_that_cannot_be_read_is_reported_and_the_scan_survives(tmp_path):
    store = _Broken(tmp_path / "h.sqlite",
                    on_history=sqlite3.OperationalError("database is locked"))
    r = review_scan(_scan(0, 100), store)

    assert r.snapshot is not None
    assert "database is locked" in r.error and "OperationalError" in r.error
    assert r.saved is None                              # unknown, not "saved"
    assert r.comparison is None


def test_a_store_that_cannot_save_still_shows_the_comparison_it_made(tmp_path):
    good = _store(tmp_path)
    review_scan(_scan(0, 100), good)
    store = _Broken(good.path, on_save=sqlite3.OperationalError("disk full"))
    r = review_scan(_scan(7, 112), store)

    assert isinstance(r.comparison, Comparison)         # made before the save
    assert r.comparison.used_delta == 12 * GiB
    assert r.saved is None and "disk full" in r.error


def test_an_unexpected_failure_in_the_store_is_captured_not_raised(tmp_path):
    store = _Broken(tmp_path / "h.sqlite", on_history=RuntimeError("bug"))
    r = review_scan(_scan(0, 100), store)
    assert "RuntimeError" in r.error and r.saved is None


def test_an_unreadable_saved_scan_is_counted_and_the_readable_one_is_the_baseline(tmp_path):
    store = _store(tmp_path)
    review_scan(_scan(0, 100), store)
    with closing(sqlite3.connect(store.path)) as conn, conn:
        conn.execute("INSERT INTO storage_snapshots "
                     "(volume_id, taken_at, schema_version, payload) "
                     "VALUES (?, ?, 1, ?)",
                     (VOL_A, (T0 + timedelta(days=3)).isoformat(), "{garbage"))

    r = review_scan(_scan(7, 112), store)
    assert r.unreadable == 1
    assert r.baseline.taken_at == T0
    assert r.comparison.used_delta == 12 * GiB
