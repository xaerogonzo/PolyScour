r"""Installed programs, read from the registry only. Nothing here removes one.

Windows Installer and every other installer register what they installed under
one of three registry locations, each holding one subkey per program:

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall             64-bit
    HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall 32-bit
    HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall             per-user

This module only reads them. ``DisplayName``, ``DisplayVersion``, ``Publisher``,
``InstallLocation``, ``EstimatedSize``, ``InstallDate``, ``UninstallString`` and
``QuietUninstallString`` are Windows' own words, recorded by whatever installed
the program — not PolyScour's judgement about it. There is no writer here, the
same as ``startup/inventory.py``: detection and diagnosis stop at this module,
and the decision to remove anything stays with the person, acting through the
program's own uninstaller (``uninstall/launcher.py``).

The one filter, and what it does not claim
-------------------------------------------

An entry with ``SystemComponent=1`` is skipped — the exact signal Windows' own
Programs and Features uses to hide runtime components (a redistributable, a
driver package) that are not meant to be removed on their own. That is
Windows' convention, not an invented one. An entry with no ``DisplayName`` is
skipped too, because Explorer would not show it either. Nothing else is
filtered, sorted by usefulness, or scored: PolyScour does not decide what
counts as "real" software, only reads what Windows already recorded.

``EstimatedSize`` and ``InstallDate`` are the only two facts Windows reliably
records that could sort this list; there is no generic, reliable "last used"
signal in these registry keys for arbitrary software, so this module does not
invent one.
"""
from __future__ import annotations

import winreg
from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class Hive(Enum):
    """Which of the three registry locations an entry was read from."""
    HKLM = "HKLM"
    HKLM_WOW6432 = "HKLM_WOW6432"
    HKCU = "HKCU"


_ROOT_HANDLE = {
    Hive.HKLM: winreg.HKEY_LOCAL_MACHINE,
    Hive.HKLM_WOW6432: winreg.HKEY_LOCAL_MACHINE,
    Hive.HKCU: winreg.HKEY_CURRENT_USER,
}

_ROOT_PREFIX = {Hive.HKLM: "HKLM", Hive.HKLM_WOW6432: "HKLM", Hive.HKCU: "HKCU"}

_SUBKEY_PATH = {
    Hive.HKLM: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    Hive.HKLM_WOW6432: r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    Hive.HKCU: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
}


@dataclass(frozen=True)
class InstalledProgram:
    """One program Windows recorded as installed. Says nothing about removing it."""
    name: str
    version: str
    publisher: str
    install_location: str
    #: Windows' own ``YYYYMMDD`` string, or "" if absent/unreadable. Kept raw;
    #: see :func:`describe_install_date` for how the view renders it.
    install_date: str
    #: None means "Windows did not record a size", never zero.
    estimated_size_bytes: int | None
    uninstall_string: str
    #: Metadata only — recorded for a possible future automation path, never
    #: invoked by the visible "Run Uninstaller" action. A quiet/unattended
    #: string is not what that button promises.
    quiet_uninstall_string: str
    #: Windows' own ``NoRemove`` flag: the vendor asked Control Panel not to
    #: offer removal at all.
    no_remove: bool
    #: Full path for display, e.g. r"HKLM\...\Uninstall\{GUID}" — named so the
    #: screen states the exact mechanism rather than "some registry entry".
    source_registry_key: str
    hive: Hive

    @property
    def identity(self) -> str:
        return self.source_registry_key


@dataclass
class ReadStatus:
    """How reading one hive's Uninstall key went. ``error`` set means UNREAD."""
    hive: Hive
    error: str | None = None
    listed: int = 0
    hidden_system_component: int = 0


@dataclass
class Inventory:
    programs: list[InstalledProgram] = field(default_factory=list)
    statuses: list[ReadStatus] = field(default_factory=list)


def _value(key, name: str, default=""):
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except OSError:
        return default


def _estimated_size_bytes(key) -> int | None:
    size_kb = _value(key, "EstimatedSize", None)
    if not isinstance(size_kb, int) or isinstance(size_kb, bool) or size_kb <= 0:
        return None
    return size_kb * 1024


def _read_hive(hive: Hive) -> tuple[list[InstalledProgram], int]:
    root = _ROOT_HANDLE[hive]
    subkey_path = _SUBKEY_PATH[hive]
    programs: list[InstalledProgram] = []
    hidden = 0

    with winreg.OpenKey(root, subkey_path) as parent:
        count = winreg.QueryInfoKey(parent)[0]
        for i in range(count):
            try:
                name = winreg.EnumKey(parent, i)
            except OSError:
                continue
            try:
                with winreg.OpenKey(parent, name) as sub:
                    display_name = _value(sub, "DisplayName")
                    if not display_name:
                        continue
                    if _value(sub, "SystemComponent", 0) == 1:
                        hidden += 1
                        continue
                    programs.append(InstalledProgram(
                        name=display_name,
                        version=_value(sub, "DisplayVersion"),
                        publisher=_value(sub, "Publisher"),
                        install_location=_value(sub, "InstallLocation"),
                        install_date=_value(sub, "InstallDate"),
                        estimated_size_bytes=_estimated_size_bytes(sub),
                        uninstall_string=_value(sub, "UninstallString"),
                        quiet_uninstall_string=_value(sub, "QuietUninstallString"),
                        no_remove=bool(_value(sub, "NoRemove", 0)),
                        source_registry_key=f"{_ROOT_PREFIX[hive]}\\{subkey_path}\\{name}",
                        hive=hive,
                    ))
            except OSError:
                continue

    return programs, hidden


def read_inventory() -> Inventory:
    """Every installed program Windows recorded, across all three locations.

    A hive that cannot be opened at all is reported as unread, not as empty —
    the same distinction ``startup/inventory.py`` draws for scheduled tasks and
    services. Sorted by size, largest first, because size is a fact worth
    leading with; nothing here implies which program to remove.
    """
    inventory = Inventory()
    for hive in Hive:
        status = ReadStatus(hive=hive)
        try:
            programs, hidden = _read_hive(hive)
        except OSError as exc:
            status.error = str(exc)
            inventory.statuses.append(status)
            continue
        status.listed = len(programs)
        status.hidden_system_component = hidden
        inventory.programs.extend(programs)
        inventory.statuses.append(status)

    inventory.programs.sort(
        key=lambda p: p.estimated_size_bytes or -1, reverse=True)
    return inventory


def describe_install_date(raw: str) -> str:
    """Windows' ``YYYYMMDD`` as a readable date, or the raw string if it
    isn't that shape — never invented, never silently dropped."""
    if len(raw) == 8 and raw.isdigit():
        try:
            return date(int(raw[:4]), int(raw[4:6]), int(raw[6:8])).strftime(
                "%d %b %Y")
        except ValueError:
            pass
    return raw
