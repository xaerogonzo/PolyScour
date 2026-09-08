r"""PolyScour — a transparent, evidence-based Windows maintenance suite.

The version lives here so that exactly one Python expression answers "which
PolyScour is this?", and so that a frozen build can answer it at all.

Why there is a literal at the bottom of this file
-------------------------------------------------

``importlib.metadata`` reads the installed distribution's metadata, which a
Nuitka build does not carry -- the payload contains the *package*, not the
``.dist-info`` directory that describes it. So a compiled PolyScour asking
``version("polyscour")`` raises ``PackageNotFoundError``, and the fallback is
what actually ships to users.

That makes the literal a second editable copy of a number that must have one
authority, which is the exact shape of the bug this file exists to close:
``pyproject.toml`` said ``0.1.0.dev0`` while ``installer/polyscour.iss`` said
``0.2.0`` and a ``v0.2.0`` tag existed, because nothing ever opened both files.

So ``tests/test_version.py`` opens both. The literal is permitted to exist; it
is not permitted to disagree.
"""
from __future__ import annotations

#: The authority is ``pyproject.toml``. This is the value a frozen build falls
#: back to, and a test asserts the two are equal -- see the module docstring.
_FALLBACK_VERSION = "0.2.0"


def _detect_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("polyscour")
    except PackageNotFoundError:
        # Frozen. Expected, not exceptional -- see the module docstring.
        return _FALLBACK_VERSION


__version__ = _detect_version()

__all__ = ["__version__"]
