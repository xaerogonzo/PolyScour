"""tests/test_substrate_contract.py — the PolyBedrock surface PolyScour calls.

Why this exists, precisely
--------------------------

PolyBedrock's CI runs PolyScour's suite as a gated consumer, so that a change
to the shared substrate cannot silently break this application. That gate was
tested by breaking it on purpose: ``polybedrock.win_security.get_system_health``
was renamed on a throwaway branch, and **every job stayed green** —
PolyBedrock's own 22 tests do not cover it, and PolyScour's 125 never imported
``win_security`` at all.

The gate was working. It just had nothing to catch, because a consumer gate
proves *the consumer's tests pass*, not *the consumer works*. `get_system_health`
has exactly one call site — ``DashboardView._gather()`` — which runs on a worker
thread, and ``_render`` turns any exception into a polite "Could not read system
health". So the breakage was invisible in the suite **and** soft at runtime: the
dashboard would simply have stopped showing health, forever, with no error
anyone would chase.

What this asserts, and what it does not
---------------------------------------

That every name PolyScour reaches for across the package boundary still exists
and is still callable. That is a **rename-and-removal** guard, not a behaviour
guard: a function whose semantics changed while keeping its name passes here,
and should be caught by the test covering the feature that uses it.

Deliberately cheap — nothing here calls into PowerShell, touches the registry
or opens a window. It is meant to run everywhere, in milliseconds, as the
tripwire that makes the consumer gate mean something.
"""
from __future__ import annotations

import importlib

import pytest


#: Every attribute PolyScour reaches for across the boundary, with the call
#: site that justifies it. Kept explicit rather than discovered by scanning the
#: source: a scanner that silently matched nothing would turn this file into a
#: test that passes by examining an empty population, which is the failure mode
#: it exists to prevent.
SURFACE: list[tuple[str, str, str]] = [
    # (module, attribute, who calls it)
    ("polybedrock.paths", "configure",           "polyscour.paths"),
    ("polybedrock.paths", "app_root",            "polyscour.paths"),
    ("polybedrock.paths", "config_dir",          "polyscour.paths"),
    ("polybedrock.paths", "state_dir",           "polyscour.paths"),
    ("polybedrock.paths", "logs_dir",            "polyscour.paths"),
    ("polybedrock.paths", "is_frozen",           "polyscour.paths"),

    ("polybedrock.settings", "configure",        "polyscour.settings"),
    ("polybedrock.settings", "load",             "app, clean_view, settings_view"),
    ("polybedrock.settings", "get",              "app, clean_view, settings_view"),
    ("polybedrock.settings", "set_value",        "settings_view"),

    ("polybedrock.win_security", "get_system_health",
                                                 "DashboardView._gather"),

    ("polybedrock.ui.theme", "init",             "app"),
    ("polybedrock.ui.theme", "configure",        "app"),
    ("polybedrock.ui.theme", "init_colors",      "app"),
    ("polybedrock.ui.theme", "apply_ctk_palette", "app"),
    ("polybedrock.ui.theme", "color",            "every view"),
    ("polybedrock.ui.theme", "get",              "every view"),
]

#: The uishot harness is a separate boundary with its own entry points.
UISHOT_SURFACE: list[tuple[str, str, str]] = [
    ("polybedrock.ui.uishot", "SceneRegistry",   "tools/uishot/scenes.py"),
    ("polybedrock.ui.uishot", "CaptureError",    "tools/uishot/__init__.py"),
    ("polybedrock.ui.uishot", "DesktopUnavailable", "tools/uishot/__init__.py"),
    ("polybedrock.ui.uishot", "Shot",            "tools/uishot/__init__.py"),
    ("polybedrock.ui.uishot.session", "TkSession", "tools/uishot/session.py"),
    ("polybedrock.ui.uishot.session", "is_supported", "tools/uishot/session.py"),
]


def test_the_surface_list_is_not_empty():
    """A table that quietly became empty would make every test below vacuous.

    The manager's own guards learned this the hard way: a check that reports a
    clean result over a population of zero is not a clean result.
    """
    assert len(SURFACE) >= 17
    assert len(UISHOT_SURFACE) >= 6


@pytest.mark.parametrize("module_name, attribute, caller",
                         [(m, a, c) for m, a, c in SURFACE],
                         ids=[f"{m.split('.')[-1]}.{a}" for m, a, _ in SURFACE])
def test_polyscour_can_still_reach_what_it_calls(module_name, attribute, caller):
    module = importlib.import_module(module_name)
    assert hasattr(module, attribute), (
        f"{module_name}.{attribute} is gone, and {caller} calls it. "
        f"Either PolyBedrock removed or renamed it, or this table is stale — "
        f"and one of those is a broken PolyScour."
    )
    assert callable(getattr(module, attribute)), \
        f"{module_name}.{attribute} exists but is no longer callable"


@pytest.mark.parametrize("module_name, attribute, caller",
                         [(m, a, c) for m, a, c in UISHOT_SURFACE],
                         ids=[f"{m.split('.')[-1]}.{a}" for m, a, _ in UISHOT_SURFACE])
def test_the_capture_harness_surface_survives(module_name, attribute, caller):
    module = importlib.import_module(module_name)
    assert hasattr(module, attribute), (
        f"{module_name}.{attribute} is gone, and {caller} imports it."
    )


def test_the_harness_submodules_import():
    """``cli`` is a sub*module*, not an attribute of the package.

    ``from polybedrock.ui.uishot import cli`` works by importing it, so
    ``hasattr(pkg, "cli")`` is False until something already has — which is why
    it needs importing rather than probing. Caught by this table's first run.
    """
    for name in ("polybedrock.ui.uishot.cli",
                 "polybedrock.ui.uishot.capture",
                 "polybedrock.ui.uishot.desktop"):
        assert importlib.import_module(name) is not None


def test_the_namespace_package_serves_both_distributions():
    """`polybedrock` is PEP 420; both halves must contribute.

    An install that lost one of them presents as a confusing ImportError deep
    in a view rather than as a packaging problem, which is what this names.
    """
    import polybedrock
    import polybedrock.ui

    assert not hasattr(polybedrock, "__file__") or polybedrock.__file__ is None, \
        "polybedrock has an __init__.py — that shadows the other distribution"
    importlib.import_module("polybedrock.win_security")   # core half
    importlib.import_module("polybedrock.ui.theme")       # ui half
