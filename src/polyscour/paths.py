r"""Where PolyScour's files live.

The generic resolution lives in ``polybedrock.paths``; this module makes the two
decisions that are PolyScour's rather than the substrate's -- the application
name, and the data scope.

Why ``"user"`` and not ``"machine"``
------------------------------------

PolyShield uses ``%ProgramData%``, and for a good reason: its Windows service
runs as ``LocalService`` and must resolve the *same* directory the GUI does,
or the cross-process lock files stop protecting anything.

PolyScour has an elevated helper, and still no privileged *writer*. Everything
that touches the vault, the ledger and the settings runs as the logged-in user,
so ``%LOCALAPPDATA%`` is both correct and gets sound ACLs with nothing to
configure.

``%ProgramData%`` was originally deferred to "alongside the installer". The
helper arrived and the deferral was re-examined, which is when the premise fell
over: PolyShield's tree is a boundary because a LocalSystem *service* owns the
protected subtrees and its GUI only reads them. PolyScour's vault is written by
the unelevated GUI on every clean. A principal cannot be walled off from
itself -- an ACL letting PolyScour write its own history lets anything else
running as the user write it too.

So this stays ``"user"``, and stops being described as temporary. See
``docs/adr/0005-the-vault-stays-user-scoped.md``, which supersedes the migration
section of ``docs/adr/0001-vault-location.md`` (the citation here previously
named 0002, which is a different decision entirely).
"""
from __future__ import annotations

import sys
from pathlib import Path

from polybedrock import paths as _wf

APP_NAME = "PolyScour"
DATA_DIR_ENV = "POLYSCOUR_DATA_DIR"

_wf.configure(app_name=APP_NAME, data_dir_env=DATA_DIR_ENV, data_scope="user")

# Re-exported so callers have one import for paths rather than two.
app_root = _wf.app_root
config_dir = _wf.config_dir
logs_dir = _wf.logs_dir
state_dir = _wf.state_dir
is_frozen = _wf.is_frozen


def vault_dir() -> Path:
    """Staged deletions, restorable until purged.

    Deliberately under the data root rather than beside the executable: an
    installed build cannot write next to itself without elevation.
    """
    return app_root() / "vault"


def ledger_path() -> Path:
    """The operation history, and the reversal records that make Undo real."""
    return app_root() / "history.sqlite"


def resource_root() -> Path:
    r"""Where files that *ship with the program* live. Read-only, disposable.

    The other half of the distinction ``polybedrock.paths`` opens with:
    RESOURCE ships with the build and may sit in a temporary extraction
    directory that vanishes on exit; DATA must survive a restart. Nothing
    durable may ever be resolved from here.

    Derived from ``__file__``, and the level differs between a checkout and a
    build because a build has no ``src/`` level:

        checkout    src/polyscour/paths.py   -> parents[2] is the repo root
        build       polyscour/paths.py       -> parents[1] is the bundle root

    Not from ``sys.executable``, which is the obvious answer and is wrong.
    PolyShield measured it: in a Nuitka *standalone* build that names
    ``<dist>/App.dist/python.exe``, a file which does not exist. Its parent
    happens to be right, so a ``sys.executable`` version works by luck while
    resting on a path to nothing. The module tree also survives *onefile*,
    where the extracted modules and their data land in the same temporary
    directory.

    **Not provable by any unit test in this suite.** The discrepancy lives in a
    ``__file__`` layout that exists only inside a real compiled build, so
    ``tools/build_probe.py`` is what actually checks it -- the same way
    PolyShield found its own off-by-one.
    """
    here = Path(__file__).resolve()
    return here.parents[1] if is_frozen() else here.parents[2]


def running_executable() -> Path:
    r"""The binary the user actually launched. **Never** ``sys.executable``.

    Measured inside a real onefile build, not reasoned about:

        sys.executable              %TEMP%\onefile_<n>\python.exe
        sys.argv[0]                 <install>\PolyScour.exe
        __compiled__.original_argv0 <install>\PolyScour.exe

    Why this is a security property and not a tidiness one
    ------------------------------------------------------

    The onefile extraction directory lives under ``%LOCALAPPDATA%\Temp`` and is
    **writable by the user** — measured too. Elevating ``sys.executable`` would
    therefore hand ``ShellExecute("runas", ...)`` a path that anything running
    as that user can replace between extraction and the consent prompt. The
    prompt would say PolyScour, and the code that ran as administrator would be
    whatever was swapped in.

    That is exactly the escalation T15's program-directory ACLs exist to
    prevent, defeated by pointing the launcher somewhere else entirely. See
    T23.

    ``original_argv0`` is preferred over ``sys.argv[0]`` because onefile
    re-executes the extracted binary: ``argv[0]`` can then be the temporary
    copy, while ``original_argv0`` stays the executable that was launched.
    """
    if is_frozen():
        compiled = globals().get("__compiled__", None)
        original = getattr(compiled, "original_argv0", None)
        return Path(original or sys.argv[0]).resolve()
    return Path(sys.executable).resolve()


def rules_dir() -> Path:
    """Cleaner rule files.

    Data only, and never authority -- what a rule is *permitted* to touch lives
    in ``polyscour.safety.policy``, which is code. See that module for why.

    A **resource**, so an installed build carries these inside the binary
    rather than beside it. That is not merely convenient: adding a rule already
    requires a reviewed ``PolicyEntry`` in code, so a rules directory an
    administrator could edit in place would offer the appearance of
    configurability with none of the authority -- and would hand T1 an easier
    target than it deserves.
    """
    return resource_root() / "rules" / "cleaners"
