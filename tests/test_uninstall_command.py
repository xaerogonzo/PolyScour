r"""Splitting a registry `UninstallString` the way CreateProcess itself would.

No mocking here -- `CommandLineToArgvW` is a real, deterministic Windows API,
and testing against it directly is what proves PolyScour's own quoting
assumptions match Windows' rather than a naive `.split()`.
"""
from __future__ import annotations

import os

import pytest

from polyscour.uninstall.command import parse

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

KEY = r"HKLM\...\Uninstall\{Test}"


def test_a_quoted_path_with_a_flag():
    cmd = parse(r'"C:\Program Files\Foo\uninstall.exe" /S', KEY)
    assert cmd.executable == r"C:\Program Files\Foo\uninstall.exe"
    assert cmd.arguments == ("/S",)
    assert cmd.argv == [r"C:\Program Files\Foo\uninstall.exe", "/S"]


def test_an_unquoted_path_with_a_flag():
    cmd = parse(r"C:\Program Files\Foo\uninstall.exe /S", KEY)
    assert cmd.executable == r"C:\Program"
    assert "Files\\Foo\\uninstall.exe" in cmd.arguments
    # This is exactly why UninstallString cannot be trusted as "the exe path" --
    # an unquoted path with a space is genuinely ambiguous, the same way it
    # would be to CreateProcess. The registered command is simply malformed for
    # this case; PolyScour splits it exactly as Windows would, no worse.


def test_an_msi_invocation():
    cmd = parse(r"MsiExec.exe /X{90140000-0011-0000-0000-0000000FF1CE}", KEY)
    assert cmd.executable == "MsiExec.exe"
    assert cmd.arguments == ("/X{90140000-0011-0000-0000-0000000FF1CE}",)


def test_a_vendor_launcher_with_a_quoted_argument_containing_spaces():
    cmd = parse(r'"C:\Vendor\launcher.exe" "argument with spaces" /quiet', KEY)
    assert cmd.executable == r"C:\Vendor\launcher.exe"
    assert cmd.arguments == ("argument with spaces", "/quiet")


def test_a_bare_executable_with_no_arguments():
    cmd = parse(r"C:\Simple\uninstall.exe", KEY)
    assert cmd.executable == r"C:\Simple\uninstall.exe"
    assert cmd.arguments == ()


def test_an_empty_string_cannot_be_parsed():
    assert parse("", KEY) is None


def test_whitespace_only_cannot_be_parsed():
    assert parse("   ", KEY) is None


def test_the_source_registry_key_travels_with_the_command():
    cmd = parse(r"C:\x\un.exe", KEY)
    assert cmd.source_registry_key == KEY
