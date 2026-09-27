r"""Launching a program's own uninstaller. Re-checks; never trusts a stale row.

`subprocess.Popen` is monkeypatched everywhere here -- nothing in this file
ever launches a real process.
"""
from __future__ import annotations

import os

import pytest

from polyscour.uninstall import launcher
from polyscour.uninstall.inventory import Hive, InstalledProgram

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

KEY = r"HKCU\...\Uninstall\{Test}"


def _program(uninstall_string, **kw):
    return InstalledProgram(
        name=kw.pop("name", "Foo"), version="1.0", publisher="Foo Inc",
        install_location="", install_date="", estimated_size_bytes=None,
        uninstall_string=uninstall_string, quiet_uninstall_string="",
        no_remove=kw.pop("no_remove", False), source_registry_key=KEY,
        hive=Hive.HKCU)


def test_a_vetoed_program_is_never_launched(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher.subprocess, "Popen",
                        lambda *a, **k: calls.append((a, k)))

    result = launcher.launch(_program(""))

    assert result.ok is False
    assert calls == []


def test_a_missing_absolute_executable_is_refused_without_launching(
        monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(launcher.subprocess, "Popen",
                        lambda *a, **k: calls.append((a, k)))

    missing = tmp_path / "does-not-exist.exe"
    result = launcher.launch(_program(str(missing)))

    assert result.ok is False
    assert "no longer exists" in result.detail
    assert calls == []


def test_a_bare_name_is_not_checked_for_existence(monkeypatch):
    """MsiExec.exe is resolved by Windows' own search path when launched --
    only an absolute path is checked here, so a bare name reaches Popen."""
    calls = []
    monkeypatch.setattr(launcher.subprocess, "Popen",
                        lambda *a, **k: calls.append((a, k)))

    result = launcher.launch(_program("MsiExec.exe /X{GUID}"))

    assert result.ok is True
    assert calls
    assert calls[0][0][0] == ["MsiExec.exe", "/X{GUID}"]


def test_launch_uses_no_shell(monkeypatch, tmp_path):
    exe = tmp_path / "uninstall.exe"
    exe.write_bytes(b"")  # just needs to exist for the absolute-path check

    calls = []
    monkeypatch.setattr(launcher.subprocess, "Popen",
                        lambda *a, **k: calls.append((a, k)))

    result = launcher.launch(_program(f'"{exe}" /S'))

    assert result.ok is True
    call_args, call_kwargs = calls[0]
    assert call_args[0] == [str(exe), "/S"]
    assert call_kwargs.get("shell", False) is False


def test_a_popen_failure_is_reported_not_raised(monkeypatch, tmp_path):
    exe = tmp_path / "uninstall.exe"
    exe.write_bytes(b"")

    def boom(*a, **k):
        raise OSError("access denied")
    monkeypatch.setattr(launcher.subprocess, "Popen", boom)

    result = launcher.launch(_program(str(exe)))
    assert result.ok is False
    assert "access denied" in result.detail
