r"""Which volumes exist, and how full they are.

Two facts per volume, from two sources, because neither answers both:

* ``psutil.disk_partitions()`` says what is mounted and whether it is fixed.
  Already a dependency — ``cleaning/scanner.py`` uses psutil for the
  browser-open check — so this adds nothing to the install.
* ``shutil.disk_usage()`` says how big it is and how much is used. It reports
  what Windows reports, which is the figure the user sees in Explorer and
  therefore the one worth comparing against.

Removable and network volumes are excluded. Not for safety — nothing here can
touch anything — but because a scan of a network share measures the link rather
than the disk, and a USB stick that is unplugged mid-walk produces a report
about a machine that no longer exists.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Volume:
    """One fixed volume, and what Windows says about its size."""
    root: Path
    fstype: str
    total_bytes: int
    used_bytes: int
    free_bytes: int

    @property
    def label(self) -> str:
        """``C:`` rather than ``C:\\``. What a person calls the drive."""
        return str(self.root).rstrip("\\/")

    @property
    def used_fraction(self) -> float:
        return self.used_bytes / self.total_bytes if self.total_bytes else 0.0


def _usage(root: Path) -> tuple[int, int, int] | None:
    """total, used, free — or None if the volume cannot be measured.

    A drive can be listed and still refuse to answer: an unreadable card
    reader, a disconnected network mapping, an encrypted volume that is locked.
    Returning None rather than zeros keeps "we could not measure this" apart
    from "this is empty", which are opposite facts.
    """
    try:
        usage = shutil.disk_usage(str(root))
    except OSError:
        return None
    return usage.total, usage.used, usage.free


def fixed_volumes() -> list[Volume]:
    """Every fixed volume this machine has, sorted by drive letter.

    Returns an empty list rather than raising when psutil is unavailable. The
    caller renders "no volumes could be enumerated", which is honest; a
    traceback is not more informative to somebody looking at a disk usage
    screen.
    """
    try:
        import psutil
    except ImportError:
        return []

    out: list[Volume] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return []

    for part in partitions:
        # `opts` is a comma-separated string on Windows and contains "fixed"
        # for internal disks. Checked rather than inferred from the drive
        # letter, which says nothing: a USB disk can be D: and so can a second
        # internal one.
        if "fixed" not in part.opts.lower():
            continue
        root = Path(part.mountpoint)
        measured = _usage(root)
        if measured is None:
            continue
        total, used, free = measured
        out.append(Volume(root=root, fstype=part.fstype,
                          total_bytes=total, used_bytes=used, free_bytes=free))

    return sorted(out, key=lambda v: v.label.lower())


def usage_now(root: Path) -> tuple[int, int, int] | None:
    """Re-read one volume's usage. Public because a scan reads it twice.

    A walk of a large drive takes minutes, and the machine keeps writing during
    it. Comparing the analyser's total against a figure captured before the
    walk started would make ordinary background activity look like an error in
    the analyser — so both ends are recorded and the report says how far it
    moved. See docs/adr/0007.
    """
    return _usage(root)
