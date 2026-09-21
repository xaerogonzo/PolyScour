r"""The saved scans, so a later scan can be compared with an earlier one.

Its own SQLite file, not the ledger. The ledger records what PolyScour *did* to
this machine; a scan did nothing, and a measurement listed beside an operation
would blur the one distinction the ledger exists to keep. It also stays outside
the cross-process mutation lock, which guards changes to Windows state.
``docs/adr/0008``.

**What is saved is decided here, and refused loudly.** Only a completed scan of an
identifiable volume is history -- anything else cannot serve as a baseline, so
``save`` says which it was via a closed :class:`SaveOutcome` instead of returning
``None`` or raising. A caller has to handle each, and none looks like success.

**A row that cannot be read is counted, not skipped.** ``History.unreadable``
exists so that a store with damage cannot look like a store with a short past.

Callers treat ``sqlite3.Error`` as "no history available" -- never as "nothing
changed".
"""
from __future__ import annotations

import enum
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path

from polyscour.storage.snapshots import (SCHEMA_VERSION, Snapshot,
                                         SnapshotCorrupt)

#: Newest completed scans kept per volume. Bounded so the file cannot grow
#: without limit; older ones are pruned on save.
DEFAULT_KEEP_PER_VOLUME = 20

_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    volume_id      TEXT NOT NULL,
    taken_at       TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    payload        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_storage_volume
    ON storage_snapshots(volume_id, taken_at);
"""


class SaveOutcome(enum.Enum):
    SAVED = "saved"
    #: The scan stopped early. Not history: it covered different territory.
    NOT_COMPLETE = "not_complete"
    #: No volume identity, so no later scan could be shown to be the same disk.
    VOLUME_UNIDENTIFIED = "volume_unidentified"


@dataclass(frozen=True)
class History:
    """Saved scans of one volume, newest first, and how many could not be read."""
    snapshots: tuple[Snapshot, ...]
    unreadable: int


@dataclass(frozen=True)
class Summary:
    """What is kept, for the Settings screen."""
    scans: int
    volumes: int
    file_bytes: int


class SnapshotStore:
    def __init__(self, db_path: Path,
                 keep_per_volume: int = DEFAULT_KEEP_PER_VOLUME) -> None:
        if keep_per_volume < 1:
            raise ValueError("keep_per_volume must be at least 1")
        self.path = Path(db_path)
        self.keep_per_volume = keep_per_volume

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

    def save(self, snapshot: Snapshot) -> SaveOutcome:
        """Keep a completed scan of an identifiable volume; say why otherwise."""
        if not snapshot.is_complete:
            return SaveOutcome.NOT_COMPLETE
        if snapshot.volume_id is None:
            return SaveOutcome.VOLUME_UNIDENTIFIED

        with self._conn() as conn:
            conn.execute(
                "INSERT INTO storage_snapshots "
                "(volume_id, taken_at, schema_version, payload) "
                "VALUES (?, ?, ?, ?)",
                (snapshot.volume_id,
                 # UTC and one format, so the column sorts as text.
                 snapshot.taken_at.astimezone(timezone.utc).isoformat(),
                 SCHEMA_VERSION, snapshot.to_json()))
            # Prune this volume only. Another volume's history is not this
            # save's business, and the newest rows are the ones that stay.
            conn.execute(
                "DELETE FROM storage_snapshots WHERE volume_id = ? AND id NOT IN "
                "(SELECT id FROM storage_snapshots WHERE volume_id = ? "
                " ORDER BY taken_at DESC, id DESC LIMIT ?)",
                (snapshot.volume_id, snapshot.volume_id, self.keep_per_volume))
        return SaveOutcome.SAVED

    def history(self, volume_id: str) -> History:
        """Everything kept for one volume, newest first."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT payload FROM storage_snapshots WHERE volume_id = ? "
                "ORDER BY taken_at DESC, id DESC", (volume_id,)).fetchall()

        snapshots: list[Snapshot] = []
        unreadable = 0
        for row in rows:
            try:
                snapshots.append(Snapshot.from_json(row["payload"]))
            except SnapshotCorrupt:
                unreadable += 1
        return History(tuple(snapshots), unreadable)

    def summary(self) -> "Summary":
        """How much is kept -- without creating the file to find out.

        Counts rows rather than parsing them, so an unreadable scan is still a
        scan somebody can clear.
        """
        if not self.path.exists():
            return Summary(scans=0, volumes=0, file_bytes=0)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n, COUNT(DISTINCT volume_id) AS v "
                "FROM storage_snapshots").fetchone()
        return Summary(scans=row["n"], volumes=row["v"],
                       file_bytes=self.path.stat().st_size)

    def clear(self, volume_id: str | None = None) -> int:
        """Delete saved scans -- one volume's, or all. Returns how many.

        This deletes PolyScour's own measurements and nothing else. It then
        ``VACUUM``s, because SQLite leaves a deleted row's bytes in the file's
        free pages until something reuses them -- and these rows hold the paths
        of the person's largest folders and files. "Cleared" that left the paths
        readable in the file would be a claim the file does not back up.
        """
        with self._conn() as conn:
            if volume_id is None:
                cur = conn.execute("DELETE FROM storage_snapshots")
            else:
                cur = conn.execute(
                    "DELETE FROM storage_snapshots WHERE volume_id = ?",
                    (volume_id,))
            removed = cur.rowcount
        # A second connection: VACUUM cannot run inside the transaction above.
        with self._conn() as conn:
            conn.execute("VACUUM")
        return removed
