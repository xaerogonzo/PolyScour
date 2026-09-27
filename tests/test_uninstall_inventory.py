r"""The Uninstaller's inventory: read-only, and honest about what it filtered.

Everything here runs against throwaway keys under HKCU -- the same technique
tests/test_startup_run32.py uses for the Run/Run32 split. `inventory._ROOT_HANDLE`
is monkeypatched so every hive this module claims to read resolves to a scratch
subtree of HKEY_CURRENT_USER, never a real HKLM or HKCU Uninstall key.
"""
from __future__ import annotations

import os
import uuid
import winreg

import pytest

from polyscour.uninstall import inventory as inv
from polyscour.uninstall.inventory import Hive, describe_install_date, read_inventory

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


def _delete_tree(root, path):
    try:
        with winreg.OpenKey(root, path, access=winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, path + "\\" + child)
    except FileNotFoundError:
        return
    winreg.DeleteKey(root, path)


@pytest.fixture
def scratch(monkeypatch):
    """Three throwaway Uninstall-shaped subtrees under HKCU, one per hive this
    module claims to read. Only the paths that get a subkey created under them
    actually exist; a hive left untouched by a test stays absent -- which
    exercises the "hive missing entirely" path some tests want."""
    base = rf"Software\PolyScourTest-{uuid.uuid4().hex}"
    paths = {
        Hive.HKLM: base + r"\HKLM_Uninstall",
        Hive.HKLM_WOW6432: base + r"\HKLM_WOW6432_Uninstall",
        Hive.HKCU: base + r"\HKCU_Uninstall",
    }
    for hive in Hive:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, paths[hive]).Close()

    monkeypatch.setattr(inv, "_ROOT_HANDLE",
                        {hive: winreg.HKEY_CURRENT_USER for hive in Hive})
    monkeypatch.setattr(inv, "_SUBKEY_PATH", paths)

    yield paths

    for hive in Hive:
        _delete_tree(winreg.HKEY_CURRENT_USER, paths[hive])
    _delete_tree(winreg.HKEY_CURRENT_USER, base)


def _write_program(root_path: str, name: str, **values) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          root_path + "\\" + name) as key:
        for value_name, value in values.items():
            if isinstance(value, int) and not isinstance(value, bool):
                winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value)
            else:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(value))


# ══ Reading a program ═════════════════════════════════════════════════════════

def test_a_program_is_read_with_all_its_recorded_fields(scratch):
    _write_program(scratch[Hive.HKCU], "{Foo}",
                   DisplayName="Foo Editor", DisplayVersion="3.2.1",
                   Publisher="Foo Software", InstallLocation=r"C:\Foo",
                   InstallDate="20240115", EstimatedSize=51200,
                   UninstallString=r'"C:\Foo\uninstall.exe" /S')

    programs = read_inventory().programs
    assert len(programs) == 1
    p = programs[0]
    assert p.name == "Foo Editor"
    assert p.version == "3.2.1"
    assert p.publisher == "Foo Software"
    assert p.install_location == r"C:\Foo"
    assert p.install_date == "20240115"
    assert p.estimated_size_bytes == 51200 * 1024
    assert p.uninstall_string == r'"C:\Foo\uninstall.exe" /S'
    assert p.hive is Hive.HKCU
    assert p.source_registry_key.startswith("HKCU\\")
    assert p.identity == p.source_registry_key


def test_a_program_with_no_display_name_is_skipped(scratch):
    _write_program(scratch[Hive.HKCU], "{Orphan}", UninstallString="x.exe")
    assert read_inventory().programs == []


def test_a_system_component_is_hidden_not_listed(scratch):
    """Windows' own Programs and Features convention, not an invented filter."""
    _write_program(scratch[Hive.HKCU], "{Runtime}",
                   DisplayName="Some Runtime", SystemComponent=1)
    inventory = read_inventory()
    assert inventory.programs == []
    status = inventory.statuses[[s.hive for s in inventory.statuses].index(Hive.HKCU)]
    assert status.hidden_system_component == 1


def test_missing_estimated_size_is_none_not_zero(scratch):
    _write_program(scratch[Hive.HKCU], "{NoSize}", DisplayName="No Size App")
    p = read_inventory().programs[0]
    assert p.estimated_size_bytes is None


def test_no_remove_flag_is_read(scratch):
    _write_program(scratch[Hive.HKCU], "{Fixed}", DisplayName="Fixed Component",
                   NoRemove=1)
    p = read_inventory().programs[0]
    assert p.no_remove is True


def test_quiet_uninstall_string_is_recorded_but_separate(scratch):
    _write_program(scratch[Hive.HKCU], "{Quiet}", DisplayName="Quiet App",
                   UninstallString=r"C:\Quiet\un.exe",
                   QuietUninstallString=r"C:\Quiet\un.exe /quiet")
    p = read_inventory().programs[0]
    assert p.uninstall_string == r"C:\Quiet\un.exe"
    assert p.quiet_uninstall_string == r"C:\Quiet\un.exe /quiet"


# ══ Sorting ════════════════════════════════════════════════════════════════════

def test_sorted_by_size_largest_first_unknown_last(scratch):
    _write_program(scratch[Hive.HKCU], "{Small}", DisplayName="Small",
                   EstimatedSize=100)
    _write_program(scratch[Hive.HKCU], "{Big}", DisplayName="Big",
                   EstimatedSize=100_000)
    _write_program(scratch[Hive.HKCU], "{Unknown}", DisplayName="Unknown")

    names = [p.name for p in read_inventory().programs]
    assert names == ["Big", "Small", "Unknown"]


# ══ Unreadable hives are reported, not silently empty ═════════════════════════

def test_a_hive_whose_key_does_not_exist_is_reported_unread(monkeypatch):
    monkeypatch.setattr(inv, "_ROOT_HANDLE",
                        {hive: winreg.HKEY_CURRENT_USER for hive in Hive})
    monkeypatch.setattr(inv, "_SUBKEY_PATH", {
        hive: rf"Software\PolyScourTest-does-not-exist-{uuid.uuid4().hex}"
        for hive in Hive})

    inventory = read_inventory()
    assert inventory.programs == []
    assert all(s.error for s in inventory.statuses)


# ══ describe_install_date ══════════════════════════════════════════════════════

def test_describe_install_date_formats_yyyymmdd():
    assert describe_install_date("20240115") == "15 Jan 2024"


def test_describe_install_date_passes_through_anything_else():
    """Never invented, never silently dropped -- an unparsable date is shown
    exactly as Windows recorded it."""
    assert describe_install_date("not-a-date") == "not-a-date"
    assert describe_install_date("") == ""
