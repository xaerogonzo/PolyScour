r"""What the Uninstaller may launch. THE AUTHORITY for uninstall commands.

Mirrors the shape of tests/test_gamemode.py's veto tests: cheap, mechanical
questions, not judgements about which programs are worth removing.
"""
from __future__ import annotations

import os

import pytest

from polyscour.uninstall import policy
from polyscour.uninstall.command import UninstallCommand
from polyscour.uninstall.inventory import Hive, InstalledProgram

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

KEY = r"HKCU\...\Uninstall\{Test}"


def _program(uninstall_string=r"C:\Foo\uninstall.exe", no_remove=False):
    return InstalledProgram(
        name="Foo", version="1.0", publisher="Foo Inc",
        install_location=r"C:\Foo", install_date="", estimated_size_bytes=None,
        uninstall_string=uninstall_string, quiet_uninstall_string="",
        no_remove=no_remove, source_registry_key=KEY, hive=Hive.HKCU)


def test_an_unparseable_command_is_vetoed():
    assert policy.veto(_program(uninstall_string=""), None) is not None


def test_a_normal_command_is_not_vetoed():
    command = UninstallCommand(r"C:\Foo\uninstall.exe", (), KEY)
    assert policy.veto(_program(), command) is None


def test_polyscour_will_not_launch_itself():
    command = UninstallCommand(r"C:\PolyScour\PolyScour.exe", ("--elevated-helper",), KEY)
    refusal = policy.veto(_program(), command)
    assert refusal is not None
    assert "PolyScour" in refusal


def test_polyscour_will_not_launch_itself_case_insensitively():
    command = UninstallCommand(r"C:\PolyScour\POLYSCOUR.EXE", (), KEY)
    assert policy.veto(_program(), command) is not None


def test_a_no_remove_program_is_vetoed():
    command = UninstallCommand(r"C:\Foo\uninstall.exe", (), KEY)
    refusal = policy.veto(_program(no_remove=True), command)
    assert refusal is not None
    assert "not removable" in refusal


def test_evaluate_parses_and_vetoes_together():
    command, refusal = policy.evaluate(_program())
    assert command is not None
    assert refusal is None

    command, refusal = policy.evaluate(_program(uninstall_string=""))
    assert command is None
    assert refusal is not None
