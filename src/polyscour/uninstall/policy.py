r"""What the Uninstaller may launch, and what it will not. THE AUTHORITY for
uninstall commands — the same shape as ``safety/policy.py`` for paths and
``gamemode/policy.py`` for processes: the selection proposes, reviewed code
disposes.

The question this module answers is narrow and mechanical: **can PolyScour
launch the registered uninstall command unambiguously, without its own
elevated helper?** It never asks whether a program is safe to remove — that
decision belongs entirely to the person clicking the button, informed by
Windows' own ``DisplayName``/``Publisher``, not PolyScour's opinion about
either. Nothing here scores, ranks, or recommends a program for removal.
"""
from __future__ import annotations

from polyscour.uninstall.command import UninstallCommand, parse
from polyscour.uninstall.inventory import InstalledProgram

#: Never launched, however its command parses. Case-insensitive match on the
#: executable's own file name, not a full path — an install can move, and
#: named rather than detected is the same choice startup/policy.py makes for
#: PolyScour's own autorun entry: a product that can act on itself has a way
#: to make itself unrecoverable.
_NEVER_LAUNCH = frozenset({"polyscour.exe"})


def _executable_name(command: UninstallCommand) -> str:
    return command.executable.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def veto(program: InstalledProgram, command: UninstallCommand | None) -> str | None:
    """Why this entry's uninstaller may not be launched, or ``None`` if it may.

    Checked once when a row is built and again immediately before launch
    (``uninstall/launcher.py``) — the same "authorise twice" discipline the
    cleaning guard and Game Mode's veto both use, because between listing and
    clicking, the registry value or the file on disk can change.
    """
    if command is None:
        return ("the registered uninstall command could not be parsed as a "
                "command PolyScour can launch safely")

    if _executable_name(command) in _NEVER_LAUNCH:
        return "PolyScour will not launch its own uninstaller from within itself"

    if program.no_remove:
        return "Windows records this program as not removable"

    return None


def evaluate(program: InstalledProgram) -> tuple[UninstallCommand | None, str | None]:
    """Parse a program's registered command and check it, together.

    The one place this pairing happens, so the view (which shows the reason)
    and the launcher (which acts on it) can never disagree about what a
    program's command parses to.
    """
    command = parse(program.uninstall_string, program.source_registry_key)
    return command, veto(program, command)
