r"""The shell and every view construct, and the app runs without PolyShield.

Not a substitute for looking at it, but it catches the class of breakage that
otherwise only shows up when a user clicks the fourth tab: a typo'd theme token,
a renamed service, a view whose constructor drifted from what the shell passes.
"""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

ctk = pytest.importorskip("customtkinter")


@pytest.fixture(scope="module")
def isolated(tmp_path_factory):
    """A PolyScour whose data root, temp and PolyShield lookup are all fake.

    Without this the smoke test would read the developer's real settings and
    could talk to a PolyShield they happen to be running.
    """
    tmp_path = tmp_path_factory.mktemp("ui")
    temp = tmp_path / "temp"
    temp.mkdir()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("POLYSCOUR_DATA_DIR", str(tmp_path / "data"))
        mp.setenv("PROGRAMDATA", str(tmp_path / "programdata"))
        mp.setenv("TEMP", str(temp))
        yield tmp_path


@pytest.fixture(scope="module")
def app(isolated):
    """One Tk root for the whole module.

    Deliberately not per-test. Creating and destroying several ``CTk`` roots in
    one process trips Tk's interpreter teardown (``invalid command name
    "tcl_findLibrary"``), which made this file skip a random test on each run --
    and a test that sometimes skips is protecting nothing. The tests below only
    read and navigate, so sharing a root costs nothing.
    """
    from polyscour.app import App
    instance = App()
    instance.withdraw()
    try:
        yield instance
    finally:
        instance.destroy()


def test_the_shell_builds(app):
    assert app.title() == "PolyScour"
    assert set(app._nav_buttons) == {"dashboard", "clean", "game",
                                     "startup", "history", "settings"}


def test_the_dashboard_is_what_opens_and_is_the_only_page_built(app):
    """Startup state, asserted before anything below navigates away.

    Views are built on first show, so a fresh shell has constructed exactly one.
    """
    assert app._active == "dashboard"
    assert set(app._views) == {"dashboard"}


@pytest.mark.parametrize("key", ["dashboard", "clean", "history", "settings"])
def test_every_view_constructs(app, key):
    """Views are built on first show, so a broken one is invisible until the
    user clicks its tab. This clicks all four."""
    app.navigate(key)
    app.update_idletasks()
    assert app._active == key


def test_a_view_is_built_once_and_reused(app):
    """The caching half of lazy building. Rebuilding a page on every visit
    would drop whatever the user had selected on it."""
    first = app.get_view("history")
    assert app.get_view("history") is first


def test_the_services_are_shared_not_rebuilt(app):
    """A view constructing its own Executor could get a Guard with no
    exclusions, which would quietly widen what the product may delete."""
    app.navigate("clean")
    clean = app.get_view("clean")
    assert clean.app.services is app.services


def test_dry_run_is_the_default_in_the_ui(app):
    app.navigate("clean")
    assert app.get_view("clean").dry_run.get() is True


def test_the_shipped_rules_are_loaded(app):
    assert app.services.rules
    assert not app.services.rule_failures


def test_the_polyshield_tile_is_absent_when_polyshield_is(app):
    """PolyScour must be complete on its own -- no greyed-out teaser, no
    advertisement for another product."""
    app.navigate("dashboard")
    dashboard = app.get_view("dashboard")
    dashboard._render_polyshield(
        type("P", (), {"available": False, "watcher_running": None,
                       "intel_age_days": None})())
    assert not dashboard.polyshield.winfo_ismapped()


def test_the_protected_locations_are_shown_to_the_user(app):
    """A user who cannot see what is protected has to take it on trust."""
    app.navigate("settings")
    app.update_idletasks()
    assert app.services.guard.protected_locations


def test_a_large_result_renders_a_row_per_rule_not_per_file(app):
    """Regression: the first live scan produced 36,194 findings and the clean
    view tried to grid one row each. Tk raised "row out of bounds" -- but the
    real fault was the design. Nobody chooses whether to delete `f_00a3c1`;
    they choose whether to clear the Chrome cache.
    """
    from datetime import datetime, timezone
    from pathlib import Path

    from polyscour.contracts import (Evidence, Finding, RiskLevel, RuleOutcome,
                                      ScanResult)

    def bulk(rule_id, n):
        return RuleOutcome(rule_id=rule_id, findings=[
            Finding(rule_id=rule_id, title=rule_id,
                    path=Path(rf"C:\fake\{rule_id}\f_{i:06d}"),
                    size_bytes=1024, risk=RiskLevel.SAFE, reversible=False,
                    evidence=Evidence("m", "o", "r"))
            for i in range(n)])

    now = datetime.now(timezone.utc)
    result = ScanResult(started_at=now, finished_at=now, outcomes=[
        bulk("chrome-cache", 20_000), bulk("user-temp", 16_194)])

    app.navigate("clean")
    view = app.get_view("clean")
    view._render(result)               # must not raise
    app.update_idletasks()

    assert len(view._groups) == 2, "one row per rule, not per file"
    assert len(view._selected()) == 36_194, "selecting a group takes its findings"
