r"""What the Storage screen says, and that the export says the same.

The sentences here are the careful ones -- "at least", "these need not add up",
"first scan", "not kept" -- and each has a test, because a careful sentence that
drifts into a confident one is exactly the failure this product is built against.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _storage_fixtures import GiB, T0, T1, VOL_A, node, report, snap
from polyscour.formatting import human, signed
from polyscour.storage import report as sr
from polyscour.storage.analyser import FileEntry, StopReason
from polyscour.storage.comparison import compare
from polyscour.storage.history import SaveOutcome
from polyscour.storage.review import Review
from polyscour.storage.snapshots import RetainedDir, RetainedFile


def _review(older=None, newer=None, *, saved=SaveOutcome.SAVED, unreadable=0,
            error=None, refuse=None) -> Review:
    newer = newer or snap(taken_at=T1)
    comparison = refuse
    if comparison is None and older is not None:
        comparison = compare(older, newer)
    return Review(snapshot=newer, baseline=older, comparison=comparison,
                  saved=saved, unreadable=unreadable, error=error)


def _local(when) -> str:
    return when.astimezone().strftime("%d %b %Y")


# ── how sizes are written ────────────────────────────────────────────────────

@pytest.mark.parametrize("n,text", [
    (0, "0 bytes"), (1023, "1,023 bytes"), (1536, "1.5 KB"),
    (5 * GiB, "5.0 GB"), (3 * 1024 ** 4, "3.0 TB"),
])
def test_human(n, text):
    assert human(n) == text


@pytest.mark.parametrize("n,text", [
    (12 * GiB, "+12.0 GB"), (-3 * GiB, "-3.0 GB"), (0, "0 bytes"),
    (-5, "-5 bytes"),
])
def test_signed_carries_direction_and_never_prints_a_negative_as_raw_bytes(n, text):
    """``human(-5 * GiB)`` would print '-5,368,709,120 bytes': -5e9 < 1024."""
    assert signed(n) == text


# ── a row is a bound unless it is exact ──────────────────────────────────────

def test_only_a_bound_says_at_least():
    assert sr.ChangeRow("x", 3 * GiB, True).size_text == "+3.0 GB"
    assert sr.ChangeRow("x", 3 * GiB, False).size_text == "at least +3.0 GB"
    assert sr.ChangeRow("x", -3 * GiB, False).size_text == "at least -3.0 GB"


# ── the headline is Windows' number, and the two others are not its parts ────

def test_the_headline_leads_with_windows_figure_and_shows_both_ends():
    older = snap(taken_at=T0, used_at_end=100 * GiB)
    newer = snap(taken_at=T1, used_at_end=112 * GiB)
    s = sr.summarise(_review(older, newer))

    assert s.headline == "+12.0 GB used on C:"
    assert "112.0 GB used, against 100.0 GB 7 days earlier" in s.detail
    assert s.title == f"Since the scan of {_local(T0)}"


def test_unchanged_used_space_is_said_to_be_unchanged():
    s = sr.summarise(_review(snap(taken_at=T0), snap(taken_at=T1)))
    assert s.headline == "Used space on C: is unchanged"


def test_the_two_scan_figures_are_not_presented_as_parts_of_the_headline():
    older = snap(taken_at=T0, used_at_end=100 * GiB, measured_bytes=90 * GiB)
    newer = snap(taken_at=T1, used_at_end=112 * GiB, measured_bytes=110 * GiB)
    where = sr.summarise(_review(older, newer)).attribution

    assert "+20.0 GB" in where and "-8.0 GB" in where
    assert "do not have to add up" in where
    # "+20 of that" against a +12 headline reads as a part bigger than its whole.
    assert "of that" not in where


# ── the cases where nothing can be said, said plainly ────────────────────────

def test_a_first_scan_says_there_is_no_earlier_scan_and_never_that_nothing_changed():
    s = sr.summarise(_review(None))
    assert s.headline is None
    assert "first completed scan of C: that PolyScour has kept" in s.detail
    assert "unchanged" not in (s.detail or "").lower()


def test_a_first_scan_that_was_not_kept_does_not_claim_it_was():
    s = sr.summarise(_review(None, saved=SaveOutcome.NOT_COMPLETE))
    assert s.detail is None
    assert any("not kept" in n for n in s.notes)


def test_a_different_volume_shows_no_change_at_all():
    older = snap(volume_id=r"\\?\Volume{other}" + "\\", taken_at=T0)
    s = sr.summarise(_review(older, snap(taken_at=T1, volume_id=VOL_A)))
    assert s.headline is None and s.folders == ()
    assert "different volumes" in s.detail


def test_a_scan_that_stopped_early_keeps_the_headline_and_says_where_is_unknown():
    older = snap(taken_at=T0, used_at_end=100 * GiB)
    newer = snap(taken_at=T1, used_at_end=112 * GiB,
                 stop_reason=StopReason.TIME_EXHAUSTED)
    s = sr.summarise(_review(older, newer, saved=SaveOutcome.NOT_COMPLETE))

    assert s.headline == "+12.0 GB used on C:"
    assert "did not finish" in s.attribution
    assert "still Windows' own count" in s.attribution
    assert s.folders == () and s.files == ()


# ── rows ─────────────────────────────────────────────────────────────────────

def _grown(n):
    old = tuple(RetainedDir(rf"C:\d{i}", 1 * GiB, 1) for i in range(n))
    new = tuple(RetainedDir(rf"C:\d{i}", (2 + i) * GiB, 1) for i in range(n))
    return (snap(taken_at=T0, directories=old),
            snap(taken_at=T1, directories=new))


def test_folder_rows_are_capped_and_the_biggest_movement_comes_first():
    older, newer = _grown(sr.FOLDER_CHANGE_ROWS + 5)
    rows = sr.summarise(_review(older, newer)).folders
    assert len(rows) == sr.FOLDER_CHANGE_ROWS
    assert rows[0].label == rf"C:\d{sr.FOLDER_CHANGE_ROWS + 4}"
    assert [r.delta for r in rows] == sorted((r.delta for r in rows), reverse=True)


def test_an_empty_extension_is_labelled_not_left_blank():
    older = snap(taken_at=T0, by_extension={"": GiB})
    newer = snap(taken_at=T1, by_extension={"": 3 * GiB})
    (row,) = sr.summarise(_review(older, newer)).extensions
    assert row.label == "(no extension)" and row.exact


# ── notes ────────────────────────────────────────────────────────────────────

def test_the_at_least_explanation_appears_only_when_a_bound_is_shown():
    bounded = snap(taken_at=T1, directories=(RetainedDir(r"C:\new", 5 * GiB, 1),))
    with_bound = sr.summarise(_review(snap(taken_at=T0), bounded))
    assert any("“At least”" in n for n in with_bound.notes)

    exact_old = snap(taken_at=T0, directories=(RetainedDir(r"C:\a", 1 * GiB, 1),))
    exact_new = snap(taken_at=T1, directories=(RetainedDir(r"C:\a", 3 * GiB, 1),))
    without = sr.summarise(_review(exact_old, exact_new))
    assert not any("At least" in n for n in without.notes)


def test_the_retention_limits_are_stated_so_a_missing_folder_is_not_read_as_no_change():
    notes = sr.summarise(_review(snap(taken_at=T0), snap(taken_at=T1))).notes
    assert any("largest" in n and "not shown" in n for n in notes)


def test_unreadable_saved_scans_are_never_silent():
    one = sr.summarise(_review(None, unreadable=1, saved=SaveOutcome.SAVED))
    assert any("1 earlier scan could not be read and was skipped" in n
               for n in one.notes)
    assert "first completed scan" not in (one.detail or "")     # not "first"

    older, newer = snap(taken_at=T0), snap(taken_at=T1)
    two = sr.summarise(_review(older, newer, unreadable=2))
    assert any("2 earlier scans could not be read and were skipped." in n
               for n in two.notes)


def test_a_store_failure_says_the_scan_was_not_kept_only_when_that_is_true():
    lost = sr.summarise(_review(None, saved=None, error="OSError: disk full"))
    assert any("disk full" in n and "This scan was not kept." in n for n in lost.notes)

    kept = sr.summarise(_review(None, saved=SaveOutcome.SAVED, error="x"))
    assert not any("was not kept" in n for n in kept.notes)


def test_an_unidentified_volume_explains_why_it_has_no_history():
    s = sr.summarise(_review(None, saved=SaveOutcome.VOLUME_UNIDENTIFIED))
    assert any("no identity" in n for n in s.notes)


def test_more_or_fewer_unreadable_directories_is_called_out():
    more = sr.summarise(_review(snap(taken_at=T0, permission_denied_directories=1),
                                snap(taken_at=T1, permission_denied_directories=4)))
    assert any("3 more directories could not be opened" in n for n in more.notes)
    fewer = sr.summarise(_review(snap(taken_at=T0, permission_denied_directories=4),
                                 snap(taken_at=T1, permission_denied_directories=1)))
    assert any("3 fewer directories" in n for n in fewer.notes)


def test_a_resized_volume_is_mentioned():
    s = sr.summarise(_review(snap(taken_at=T0, volume_total_bytes=500 * GiB),
                             snap(taken_at=T1, volume_total_bytes=600 * GiB)))
    assert any("size changed by +100.0 GB" in n for n in s.notes)


# ── the export ───────────────────────────────────────────────────────────────

def _full_report():
    r = report(node("C:/", 90 * GiB, node("C:/Games", 60 * GiB),
                    node("C:/Users", 30 * GiB)))
    r.largest_files = [FileEntry(Path(r"C:\Games\big.pak"), 40 * GiB, 40 * GiB)]
    r.by_extension = {".pak": 40 * GiB}
    return r


def test_the_export_says_first_that_it_contains_names_from_this_computer():
    text = sr.render_text(_full_report(), None)
    assert text.splitlines()[2] == ("This report contains file and folder names "
                                    "from this computer.")


def test_the_export_carries_the_paths_and_the_history_the_screen_shows():
    older = snap(taken_at=T0, used_at_end=100 * GiB,
                 directories=(RetainedDir(r"C:\Games", 20 * GiB, 1),))
    newer = snap(taken_at=T1, used_at_end=112 * GiB,
                 directories=(RetainedDir(r"C:\Games", 60 * GiB, 1),
                              RetainedDir(r"C:\Fresh", 5 * GiB, 1)))
    review = _review(older, newer)
    text = sr.render_text(_full_report(), review)
    s = sr.summarise(review)

    assert r"C:\Games" in text and r"C:\Games\big.pak" in text
    assert s.headline in text and s.attribution in text
    # The bound is as much a bound in the file as it is on the screen.
    assert "at least +4.9 GB" in text and r"C:\Fresh" in text
    assert text.endswith("\n")


def test_the_export_without_a_review_has_no_history_section():
    text = sr.render_text(_full_report(), None)
    assert "Since the" not in text and "first completed scan" not in text


def test_the_export_recommends_nothing_and_offers_no_verb():
    """A finding is not a recommendation -- in a file exactly as on the screen."""
    older = snap(taken_at=T0, files=(RetainedFile(r"C:\a.bin", 5 * GiB),))
    newer = snap(taken_at=T1, files=(RetainedFile(r"C:\b.bin", 9 * GiB),))
    text = sr.render_text(_full_report(), _review(older, newer)).lower()
    for word in ("delete", "remove", "clean up", "recommend", "you should",
                 "safe to", "free up"):
        assert word not in text, word


def test_the_export_names_the_scan_status_so_a_partial_one_cannot_pass_as_whole():
    r = _full_report()
    r.stop_reason = StopReason.TIME_EXHAUSTED
    assert "Stopped at the time budget" in sr.render_text(r, None)


def test_a_naive_finish_time_does_not_crash_the_export():
    r = _full_report()
    r.finished_at = T0.replace(tzinfo=None)
    assert "PolyScour storage report" in sr.render_text(r, None)


def test_scan_notes_always_end_with_the_limit_of_the_scan_not_a_fault():
    notes = sr.scan_notes(_full_report())
    assert notes[-1].startswith("This is a limit of the scan")
