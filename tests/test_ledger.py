r"""tests/test_ledger.py — the history file survives being upgraded.

``CREATE TABLE IF NOT EXISTS`` does nothing to a database that already exists,
so every column added after 0.1 shipped needs a migration or the first insert
naming it fails. A history file is the one thing in this product that must
survive an upgrade intact: it is what makes Undo real, and a user whose records
were silently dropped has lost the ability to reverse anything.

The 0.1 schema is reproduced literally below rather than imported. A test that
built the "old" database from the current source would migrate nothing and pass
against any code at all.
"""
from __future__ import annotations

import sqlite3

import pytest

from polyscour.contracts import (ActionResult, ElevationRecord,
                                 OperationOutcome, Skip, SkipReason)
from polyscour.ledger import Ledger

from datetime import datetime, timezone

# Exactly as it shipped: no elevation columns.
_V1_OPERATIONS = """
CREATE TABLE operations (
    operation_id   TEXT PRIMARY KEY,
    started_at     TEXT NOT NULL,
    finished_at    TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    dry_run        INTEGER NOT NULL,
    bytes_freed    INTEGER NOT NULL,
    items_completed INTEGER NOT NULL,
    rule_ids       TEXT NOT NULL,
    summary        TEXT NOT NULL
);
"""


def _v1_database(path):
    conn = sqlite3.connect(path)
    conn.executescript(_V1_OPERATIONS)
    conn.execute(
        "INSERT INTO operations VALUES (?,?,?,?,?,?,?,?,?)",
        ("op-from-0.1", "2026-01-01T10:00:00", "2026-01-01T10:00:04",
         "success", 0, 4096, 12, '["user-temp"]', "12 items removed."))
    conn.commit()
    conn.close()


def _result(**kw):
    now = datetime.now(timezone.utc)
    return ActionResult(operation_id="op-new",
                        outcome=OperationOutcome.SUCCESS,
                        started_at=now, finished_at=now, **kw)


def test_a_0_1_history_still_opens_and_keeps_its_rows(tmp_path):
    """The control: without it, "the migration ran" could mean "the file was
    replaced with an empty one"."""
    path = tmp_path / "history.sqlite"
    _v1_database(path)

    Ledger(path).initialise()

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = list(conn.execute("SELECT * FROM operations"))
    conn.close()

    assert len(rows) == 1
    assert rows[0]["operation_id"] == "op-from-0.1"
    assert rows[0]["summary"] == "12 items removed."


def test_the_elevation_columns_are_added_to_an_existing_database(tmp_path):
    path = tmp_path / "history.sqlite"
    _v1_database(path)

    ledger = Ledger(path)
    ledger.initialise()
    ledger.record(_result(elevation=ElevationRecord(
        requested=True, granted=True, attempted=9, succeeded=7)),
        ["windows-temp"])

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM operations WHERE operation_id = 'op-new'").fetchone()
    old = conn.execute(
        "SELECT * FROM operations WHERE operation_id = 'op-from-0.1'").fetchone()
    conn.close()

    assert (row["elevation_requested"], row["elevation_granted"]) == (1, 1)
    assert (row["elevation_attempted"], row["elevation_succeeded"]) == (9, 7)
    # A row written before the columns existed reads as "no elevation", which
    # is true: 0.1 could not elevate at all.
    assert old["elevation_requested"] == 0


def test_migrating_twice_changes_nothing(tmp_path):
    """Every connection runs it. It has to be idempotent, not merely correct
    the first time."""
    path = tmp_path / "history.sqlite"
    _v1_database(path)

    for _ in range(3):
        Ledger(path).initialise()

    conn = sqlite3.connect(path)
    names = [r[1] for r in conn.execute("PRAGMA table_info(operations)")]
    conn.close()

    assert names.count("elevation_requested") == 1
    assert len(names) == 13


def test_an_operation_records_the_four_elevation_facts_separately(tmp_path):
    """A declined prompt is requested-and-not-granted. One boolean cannot say
    that, and would record a user's refusal as if nothing had been asked."""
    ledger = Ledger(tmp_path / "history.sqlite")
    ledger.initialise()
    ledger.record(_result(
        skips=[Skip(tmp_path / "x", SkipReason.PERMISSION, "", "windows-temp")],
        elevation=ElevationRecord(requested=True, granted=False)),
        ["windows-temp"])

    conn = sqlite3.connect(ledger.path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM operations").fetchone()
    conn.close()

    assert row["elevation_requested"] == 1
    assert row["elevation_granted"] == 0
