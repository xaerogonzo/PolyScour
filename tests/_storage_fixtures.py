"""Builders shared by the storage-history tests.

A module and not a conftest fixture: these are plain constructors a test calls
with the one field it is about, and a fixture would hide which field that is.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from polyscour.storage import snapshots, volumes
from polyscour.storage.analyser import DirectoryNode, StopReason, VolumeReport
from polyscour.storage.snapshots import Snapshot

MiB = 1024 ** 2
GiB = 1024 ** 3
VOL_A = r"\\?\Volume{aaaaaaaa-0000-0000-0000-000000000001}" + "\\"
VOL_B = r"\\?\Volume{bbbbbbbb-0000-0000-0000-000000000002}" + "\\"
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=7)


def snap(**over) -> Snapshot:
    """A complete, plain snapshot; a test overrides only what it is about."""
    fields = dict(
        volume_id=VOL_A, volume_label="C:", fstype="NTFS",
        volume_total_bytes=500 * GiB, taken_at=T0,
        stop_reason=StopReason.COMPLETED,
        used_at_start=100 * GiB, used_at_end=100 * GiB,
        measured_bytes=90 * GiB, residual={},
        permission_denied_directories=0, entries_examined=1000,
        directories=(), directory_ceiling_bytes=snapshots.RETENTION_MIN_BYTES,
        files=(), file_ceiling_bytes=0, by_extension={})
    fields.update(over)
    return Snapshot(**fields)


def node(path: str, size: int, *children: DirectoryNode) -> DirectoryNode:
    return DirectoryNode(Path(path), logical_bytes=size, allocated_bytes=size,
                         file_count=1, children=list(children))


def report(root: DirectoryNode | None = None, *, volume_id: str | None = VOL_A,
           **over) -> VolumeReport:
    """A finished scan of a constructed volume, with a small real-looking tree."""
    vol = volumes.Volume(root=Path("C:/"), fstype="NTFS", total_bytes=500 * GiB,
                         used_bytes=100 * GiB, free_bytes=400 * GiB,
                         volume_id=volume_id)
    if root is None:
        root = node("C:/", 90 * GiB, node("C:/Games", 60 * GiB),
                    node("C:/Users", 30 * GiB))
    fields = dict(volume=vol, root=root, finished_at=T0,
                  used_at_start=100 * GiB, used_at_end=100 * GiB)
    fields.update(over)
    return VolumeReport(**fields)
