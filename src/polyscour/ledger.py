r"""Operation history, reversal records, and the mutation lock.

Every meaningful change PolyScour makes is recorded here, which is what lets
the History view answer "what did this thing do to my machine" and the Undo
Center answer "can I have it back".

The mutation lock
-----------------

The GUI, a future scheduled task, a future CLI and a future elevated helper can
all want to act at once::

    Only one mutating PolyScour operation may hold this lock at a time.
    Scanning may run concurrently; mutation serialises.

It is a **cross-process** file lock, not a ``threading.Lock``, because the
processes above are genuinely separate. PolyShield learned what an in-process
lock buys you here -- nothing -- and learned it the expensive way: two processes
that resolved the lock file to different paths were both handed the lock, at
once, silently, over a SQLite write. Hence one path, derived once, from
``polyscour.paths``.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from polyscour.contracts import ActionResult, OperationOutcome

try:                                  # Windows-only; the product is too.
    import msvcrt
except ImportError:                   # pragma: no cover - non-Windows
    msvcrt = None

_LOCK_TIMEOUT_S = 10.0
_LOCK_RETRY_S = 0.05

_SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
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

-- One row per item that CAN be undone. An operation with no rows here is not
-- broken; it is an operation whose findings were regenerable caches, and the
-- UI says "Not reversible" rather than offering a button that would fail.
CREATE TABLE IF NOT EXISTS reversals (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id   TEXT NOT NULL REFERENCES operations(operation_id),
    original_path  TEXT NOT NULL,
    vault_object   TEXT NOT NULL,
    restored_at    TEXT
);

CREATE INDEX IF NOT EXISTS ix_reversals_op ON reversals(operation_id);

CREATE TABLE IF NOT EXISTS skips (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id   TEXT NOT NULL REFERENCES operations(operation_id),
    path           TEXT NOT NULL,
    reason         TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT ''
);
"""


class LockUnavailable(RuntimeError):
    """Another PolyScour process is already mutating. Report, do not queue."""


class MutationLock:
    """Cross-process exclusion over the ledger and the vault together.

    One lock for both on purpose: a vault write and its ledger row are a single
    logical change, and a lock per store would let a second process interleave
    between them.
    """

    def __init__(self, lock_path: Path) -> None:
        self._path = Path(lock_path)
        self._fd: int | None = None
        self._local = threading.Lock()

    @contextmanager
    def held(self, timeout: float = _LOCK_TIMEOUT_S):
        if not self._local.acquire(timeout=timeout):
            raise LockUnavailable("another operation in this process holds the lock")
        try:
            self._acquire_file(timeout)
            try:
                yield
            finally:
                self._release_file()
        finally:
            self._local.release()

    def _acquire_file(self, timeout: float) -> None:
        if msvcrt is None:                        # pragma: no cover
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + timeout
        fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR)
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                self._fd = fd
                return
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockUnavailable(
                        "another PolyScour process is currently making "
                        "changes; try again in a moment") from None
                time.sleep(_LOCK_RETRY_S)

    def _release_file(self) -> None:
        if self._fd is None:
            return
        try:
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(self._fd)
            self._fd = None


def new_operation_id() -> str:
    """Sortable by time, unique across processes."""
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"


class Ledger:
    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)
        self.lock = MutationLock(self.path.with_suffix(".lock"))

    @contextmanager
    def _conn(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(_SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialise(self) -> None:
        with self._conn():
            pass

    # ── writing ──────────────────────────────────────────────────────────────

    def record(self, result: ActionResult, rule_ids: list[str]) -> None:
        """Write one operation and everything that hangs off it, in one commit.

        A dry run is recorded too. "What would this have done" is a question
        worth being able to answer later, and the row carries the flag so the
        History view can never present a rehearsal as a change.
        """
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO operations VALUES (?,?,?,?,?,?,?,?,?)",
                (result.operation_id,
                 result.started_at.isoformat(timespec="seconds"),
                 result.finished_at.isoformat(timespec="seconds"),
                 result.outcome.value,
                 int(result.dry_run),
                 result.bytes_freed,
                 result.items_completed,
                 json.dumps(sorted(set(rule_ids))),
                 result.summary()))

            conn.executemany(
                "INSERT INTO reversals (operation_id, original_path, vault_object)"
                " VALUES (?,?,?)",
                [(result.operation_id, str(r.original_path), r.vault_object)
                 for r in result.reversals if r.possible])

            conn.executemany(
                "INSERT INTO skips (operation_id, path, reason, detail)"
                " VALUES (?,?,?,?)",
                [(result.operation_id, str(s.path), s.reason.value, s.detail)
                 for s in result.skips])

    def mark_restored(self, operation_id: str, original_path: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE reversals SET restored_at = ? "
                "WHERE operation_id = ? AND original_path = ? "
                "  AND restored_at IS NULL",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 operation_id, original_path))

    # ── reading ──────────────────────────────────────────────────────────────

    def history(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(conn.execute(
                "SELECT * FROM operations ORDER BY started_at DESC LIMIT ?",
                (limit,)))

    def reversals_for(self, operation_id: str) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(conn.execute(
                "SELECT * FROM reversals WHERE operation_id = ? ORDER BY id",
                (operation_id,)))

    def undoable(self) -> list[sqlite3.Row]:
        """Operations with at least one item still sitting in the vault.

        The Undo Center's whole query. An operation whose items have all been
        restored, or purged, correctly stops appearing.
        """
        with self._conn() as conn:
            return list(conn.execute(
                "SELECT o.*, COUNT(r.id) AS pending "
                "FROM operations o JOIN reversals r "
                "  ON r.operation_id = o.operation_id "
                "WHERE r.restored_at IS NULL AND o.dry_run = 0 "
                "GROUP BY o.operation_id "
                "ORDER BY o.started_at DESC"))

    def totals(self) -> dict:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS runs, "
                "       COALESCE(SUM(bytes_freed), 0) AS bytes_freed "
                "FROM operations WHERE dry_run = 0 AND outcome IN (?,?)",
                (OperationOutcome.SUCCESS.value,
                 OperationOutcome.SUCCESS_WITH_SKIPS.value)).fetchone()
            return {"runs": row["runs"], "bytes_freed": row["bytes_freed"]}
