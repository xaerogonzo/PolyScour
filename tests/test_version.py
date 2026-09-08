r"""One version number, and the files that must agree about it.

There is no interesting logic here. There is a *claim* -- "this is PolyScour
0.2.0" -- repeated in four places that had no mechanical relationship to each
other:

    pyproject.toml          0.1.0.dev0
    installer/polyscour.iss 0.2.0
    README.md badge         0.1 development
    git tag                 v0.2.0

Nothing opened two of those files at once, so nothing could notice. That is the
same shape as the missing ``LICENSE`` that ``build.ps1`` caught only once a
build step had to *open the file*, and the same shape as ``sys.frozen``: a
claim about the world with no reader.

So this module opens them.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml has no top-level version"
    return match.group(1)


def test_the_frozen_fallback_matches_pyproject():
    r"""The literal in ``__init__.py`` is what a compiled build reports.

    ``importlib.metadata`` cannot answer inside a Nuitka build -- the payload
    carries the package, not its ``.dist-info`` -- so ``_FALLBACK_VERSION`` is
    the number that reaches users. It is a hand-maintained copy, which is
    exactly what drifts, so it is compared rather than trusted.

    Compared against the *literal* and not against ``polyscour.__version__``:
    an editable install caches its metadata, so ``__version__`` reports the
    version at install time and would fail this test for a reason that says
    nothing about the source.
    """
    from polyscour import _FALLBACK_VERSION

    assert _FALLBACK_VERSION == _pyproject_version(), (
        "src/polyscour/__init__.py's _FALLBACK_VERSION has drifted from "
        "pyproject.toml. pyproject.toml is the authority.")


def test_the_installer_default_matches_pyproject():
    r"""``polyscour.iss``'s fallback ``AppVersion``.

    ``build.ps1`` passes ``/DAppVersion`` from ``pyproject.toml``, so a normal
    build cannot disagree. This covers the other path -- somebody running ISCC
    directly, which is how ``PolyScour-Setup-0.2.0.exe`` came to exist while
    ``pyproject.toml`` still said ``0.1.0.dev0``.
    """
    text = (_ROOT / "installer" / "polyscour.iss").read_text(encoding="utf-8")
    match = re.search(r'#define\s+AppVersion\s+"([^"]+)"', text)
    assert match, "polyscour.iss has no AppVersion define"

    assert match.group(1) == _pyproject_version(), (
        "installer/polyscour.iss's fallback AppVersion has drifted from "
        "pyproject.toml.")


def test_the_installer_takes_an_override():
    """Without ``#ifndef``, ``/DAppVersion`` is silently ignored by ISCC.

    That failure is invisible: the build succeeds and produces an installer
    carrying the stale literal, which is the bug with an extra step rather
    than a fix for it.
    """
    text = (_ROOT / "installer" / "polyscour.iss").read_text(encoding="utf-8")
    assert "#ifndef AppVersion" in text, (
        "polyscour.iss must guard its AppVersion define with #ifndef, or "
        "build.ps1's /DAppVersion does nothing at all.")


def test_the_readme_badge_matches_pyproject():
    """The badge is a claim to a reader, so it is a claim worth checking."""
    text = (_ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"!\[Status\]\(https://img\.shields\.io/badge/status-([^-)]+)",
                      text)
    if not match:
        pytest.skip("no status badge in README.md")

    declared = match.group(1).replace("%20", " ")
    version = _pyproject_version()
    short = ".".join(version.split(".")[:2])
    assert short in declared, (
        f"README badge says {declared!r} while pyproject.toml says {version!r}")
