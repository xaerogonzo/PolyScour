r"""PolyScour's settings.

The atomic-write and cross-process locking implementation lives in
``polybedrock.settings``; what stays here is what is PolyScour's -- where the file
sits and what a missing key means.
"""
from __future__ import annotations

import sys

from polybedrock import settings as _impl

from polyscour import paths

DEFAULTS: dict = {
    # Display
    "display_theme_preset": "classic",
    "display_content_size": 13,

    # Cleaning
    #: Dry run is the default. A user who wants to change the machine says so,
    #: which keeps the destructive path explicit at every level of the stack
    #: rather than only in the confirmation dialog.
    "default_to_dry_run": True,
    "disabled_rules": [],

    #: Paths PolyScour must never touch, on top of the built-in denylist.
    #: The denylist is not configurable -- an exclusion can only ever add
    #: protection, never remove it.
    "exclusions": [],

    # Vault
    "vault_retention_days": 30,
    "vault_max_bytes": 2 * 1024 ** 3,

    # Integrations
    "polyshield_tile_enabled": True,
}

_impl.configure(paths.config_dir() / "settings.json", DEFAULTS)

# This module *is* polybedrock.settings -- see ui/core/ps_run.py in PolyShield for
# why the alias is a module replacement rather than a re-export. Nothing defined
# below this line would ever be bound, so nothing is.
sys.modules[__name__] = _impl
