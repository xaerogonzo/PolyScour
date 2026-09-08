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


def rules_dir() -> Path:
    """Cleaner rule files.

    Data only, and never authority -- what a rule is *permitted* to touch lives
    in ``polyscour.safety.policy``, which is code. See that module for why.
    """
    return Path(__file__).resolve().parents[2] / "rules" / "cleaners"
