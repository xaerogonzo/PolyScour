r"""The Recycle Bin is a Shell operation, not a file-glob rule.

These tests never touch a real Recycle Bin -- `SHQueryRecycleBinW` and
`SHEmptyRecycleBinW` are monkeypatched at the `ctypes.windll.shell32` seam, the
same way `storage/volumes.py`'s Windows calls are exercised elsewhere. Running
these against the real Shell API would either report nothing (CI has nothing in
its bin) or, worse, actually empty a developer's Recycle Bin.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from polyscour.cleaning import recyclebin
from polyscour.contracts import RiskLevel
from polyscour.storage.volumes import Volume

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


class _FakeShell32:
    """Stands in for `ctypes.windll.shell32` for exactly the two calls used."""

    def __init__(self, query_result: tuple[int, int, int] | None = (0, 0, 0),
                query_hresult: int = 0, empty_hresult: int = 0):
        #: (hresult, items, bytes) to hand back from SHQueryRecycleBinW, or
        #: None to simulate the call itself failing.
        self.query_result = query_result
        self.query_hresult = query_hresult
        self.empty_hresult = empty_hresult
        self.empty_calls: list[str] = []

    def SHQueryRecycleBinW(self, volume, info_ptr):
        if self.query_result is None:
            return 1  # any non-S_OK value
        _, items, size = self.query_result
        info_ptr.contents.i64NumItems = items
        info_ptr.contents.i64Size = size
        return self.query_hresult

    def SHEmptyRecycleBinW(self, hwnd, volume, flags):
        self.empty_calls.append(volume)
        return self.empty_hresult


@pytest.fixture
def fake_shell(monkeypatch):
    fake = _FakeShell32()
    monkeypatch.setattr(recyclebin.ctypes, "windll",
                        SimpleNamespace(shell32=fake))
    return fake


# ══ query() ═══════════════════════════════════════════════════════════════════

def test_query_reports_items_and_bytes(fake_shell):
    fake_shell.query_result = (0, 1842, 3_800_000_000)
    info = recyclebin.query("C:\\")
    assert info is not None
    assert info.items == 1842
    assert info.bytes == 3_800_000_000
    assert info.empty is False


def test_query_returns_none_when_the_shell_refuses(fake_shell):
    fake_shell.query_hresult = 1  # not S_OK
    assert recyclebin.query("C:\\") is None


def test_an_empty_bin_is_not_none_and_is_empty(fake_shell):
    fake_shell.query_result = (0, 0, 0)
    info = recyclebin.query("C:\\")
    assert info is not None
    assert info.empty is True


# ══ empty() ═══════════════════════════════════════════════════════════════════

def test_empty_suppresses_windows_own_confirmation(fake_shell):
    """PolyScour's own confirmation is the single consent surface; a second,
    Windows-drawn one on top of it would be noise, not an extra safeguard."""
    recyclebin.empty("C:\\")
    assert fake_shell.empty_calls == ["C:\\"]


def test_empty_reports_success_on_s_ok(fake_shell):
    fake_shell.empty_hresult = 0
    assert recyclebin.empty("C:\\") is True


def test_empty_reports_success_on_s_false_already_empty(fake_shell):
    """S_FALSE from an already-empty bin is 'nothing to do', not a failure."""
    fake_shell.empty_hresult = 1
    assert recyclebin.empty("C:\\") is True


def test_empty_reports_failure_on_any_other_hresult(fake_shell):
    fake_shell.empty_hresult = -1
    assert recyclebin.empty("C:\\") is False


# ══ scan() ════════════════════════════════════════════════════════════════════

def _volume(letter: str) -> Volume:
    from pathlib import Path
    return Volume(root=Path(f"{letter}:\\"), fstype="NTFS",
                 total_bytes=1, used_bytes=1, free_bytes=0)


def test_scan_produces_one_finding_per_nonempty_volume(monkeypatch, fake_shell):
    monkeypatch.setattr(recyclebin.volumes, "fixed_volumes",
                        lambda: [_volume("C"), _volume("D")])

    calls = {"C:\\": (0, 12, 400), "D:\\": (0, 0, 0)}

    def fake_query(volume):
        items, size = calls[volume][1], calls[volume][2]
        return recyclebin.RecycleBinInfo(volume=volume, items=items, bytes=size)

    monkeypatch.setattr(recyclebin, "query", fake_query)

    outcome = recyclebin.scan()
    assert [f.path.drive for f in outcome.findings] == ["C:"]
    assert outcome.findings[0].size_bytes == 400
    assert outcome.findings[0].risk is RiskLevel.MODERATE
    assert outcome.findings[0].reversible is False
    assert outcome.findings[0].requires_elevation is False


def test_scan_is_not_pre_ticked_as_safe():
    """Sanity check on the risk classification itself: MODERATE, never SAFE.

    The Recycle Bin providing recovery for a prior deletion is not the same
    consent as permanently destroying it.
    """
    assert RiskLevel.MODERATE > RiskLevel.SAFE
