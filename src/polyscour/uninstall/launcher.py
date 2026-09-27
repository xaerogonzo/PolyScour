r"""Launching a program's own registered uninstaller. Nothing else.

PolyScour removes nothing itself here: it starts the vendor's own
``UninstallString``, unelevated, and steps out of the way. The vendor's
uninstaller may then request its own administrator rights through its own UAC
prompt — exactly as if the person had launched it from Control Panel — and
PolyScour neither grants nor blocks that. What PolyScour does not do is
elevate *itself* to launch it, and does not wait for it, track its progress,
or record anything about what it does: this is not a mutation PolyScour is
making, so there is nothing here for the ledger to hold.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from polyscour.uninstall import policy
from polyscour.uninstall.inventory import InstalledProgram


@dataclass(frozen=True)
class LaunchResult:
    ok: bool
    detail: str


def launch(program: InstalledProgram) -> LaunchResult:
    """Re-parse and re-check before launching — never trust a stale row.

    Between the inventory being read and this being clicked, the registry
    value could have changed or the executable could have vanished. Both are
    re-verified here, not assumed from what the view displayed a moment ago —
    the same reason the cleaning guard re-authorises immediately before acting
    rather than trusting the scan's verdict.
    """
    command, refusal = policy.evaluate(program)
    if refusal:
        return LaunchResult(False, refusal)

    exe_path = Path(command.executable)
    # A bare name (e.g. "MsiExec.exe") is resolved by Windows' own search path
    # when launched — only an *absolute* path is checked for existence here,
    # the same distinction subprocess/CreateProcess itself makes.
    if exe_path.is_absolute() and not exe_path.exists():
        return LaunchResult(
            False, f"{command.executable} no longer exists on this machine")

    try:
        subprocess.Popen(command.argv, shell=False)
    except OSError as exc:
        return LaunchResult(False, str(exc))

    return LaunchResult(
        True, "Launched. PolyScour does not track its progress or wait for "
             "it to finish.")
