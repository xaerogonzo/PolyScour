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
    assert set(app._nav_buttons) == {"dashboard", "clean", "storage", "game",
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


# ── the Storage screen ───────────────────────────────────────────────────────
#
# Real widgets, a fake disk: `analyse` is replaced by a constructed report, the
# store lives in tmp_path, and the shell's thread hop runs inline. What is under
# test is the wiring -- scan -> review -> render -> export -- and the invariant
# that nothing on the screen acts on a finding.

def _labels(widget) -> list[str]:
    out = []
    for child in widget.winfo_children():
        if isinstance(child, ctk.CTkLabel):
            out.append(child.cget("text"))
        out.extend(_labels(child))
    return out


def _buttons(widget) -> list[str]:
    out = []
    for child in widget.winfo_children():
        if isinstance(child, ctk.CTkButton):
            out.append(child.cget("text"))
        out.extend(_buttons(child))
    return out


@pytest.fixture
def storage(app, tmp_path, monkeypatch):
    """The Storage view, fresh: no report, export off, its own empty store."""
    from polyscour.storage.history import SnapshotStore
    from polyscour.views import storage_view

    app.navigate("storage")
    view = app.get_view("storage")
    if not hasattr(view, "_scan_button"):
        pytest.skip("no fixed volumes were enumerated on this machine")

    monkeypatch.setattr(app.services, "storage_history",
                        SnapshotStore(tmp_path / "storage_history.sqlite"))
    def inline(work, done):
        # The contract of App.run_off_thread: a failure in `work` reaches the
        # callback as (None, exc). Letting it escape would leave the view
        # mid-scan, and every later test would inherit that.
        try:
            result = work()
        except Exception as exc:                            # noqa: BLE001
            done(None, exc)
        else:
            done(result, None)

    monkeypatch.setattr(app, "run_off_thread", inline)
    view._cancel = None
    view._scan_button.configure(text="Scan")
    view._report = view._review = None
    view._set_export_enabled(False)
    view._status.configure(text="")
    return view, storage_view


def _scan(storage, monkeypatch, *, day=0, used=100, **over):
    from datetime import timedelta

    from _storage_fixtures import GiB, T0, report

    view, sv = storage
    finished = report(finished_at=T0 + timedelta(days=day),
                      used_at_start=used * GiB, used_at_end=used * GiB, **over)
    monkeypatch.setattr(sv, "analyse", lambda request, cancel: finished)
    view._start()
    return view


def test_the_report_buttons_are_off_until_a_scan_exists_and_on_after(storage, monkeypatch):
    view, _ = storage
    assert view._copy_button.cget("state") == "disabled"
    assert view._save_button.cget("state") == "disabled"

    _scan(storage, monkeypatch)
    assert view._copy_button.cget("state") == "normal"
    assert view._save_button.cget("state") == "normal"


def test_a_failed_scan_leaves_export_off_and_says_so(storage, monkeypatch):
    view, sv = storage

    def boom(request, cancel):
        raise OSError("disk went away")

    monkeypatch.setattr(sv, "analyse", boom)
    view._start()
    assert "Scan failed" in view._status.cget("text")
    assert view._copy_button.cget("state") == "disabled"
    assert view._cancel is None


def test_a_second_scan_shows_what_changed_since_the_first(storage, monkeypatch):
    view = _scan(storage, monkeypatch, day=0, used=100)
    assert any("first completed scan" in t for t in _labels(view._body))

    _scan(storage, monkeypatch, day=7, used=112)
    assert "+12.0 GB used on C:" in _labels(view._body)


def test_the_screen_and_the_export_say_the_same_thing(storage, monkeypatch):
    from polyscour.storage import report as sr

    _scan(storage, monkeypatch, day=0, used=100)
    view = _scan(storage, monkeypatch, day=7, used=112)
    s = sr.summarise(view._review)

    assert s.headline in _labels(view._body)
    assert s.headline in view._text()
    assert s.attribution in view._text()


def test_a_history_fault_loses_neither_the_scan_nor_the_truth_about_it(storage, monkeypatch, app):
    def locked(volume_id):
        import sqlite3
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(app.services.storage_history, "history", locked)
    view = _scan(storage, monkeypatch)

    texts = " ".join(_labels(view._body))
    assert "accounted for" in texts                         # the scan survived
    assert "Saved history could not be used" in texts       # and the fault is said
    assert view._copy_button.cget("state") == "normal"


def test_copy_puts_the_report_on_the_clipboard_and_warns_about_names(storage, monkeypatch, app):
    import tkinter

    view = _scan(storage, monkeypatch)
    view._copy()
    try:
        clip = app.clipboard_get()
    except tkinter.TclError:
        pytest.skip("this session has no usable clipboard")

    assert clip == view._text()
    assert "PolyScour storage report" in clip
    assert "names from this computer" in view._status.cget("text")


def test_save_writes_the_report_where_the_person_chose(storage, monkeypatch, tmp_path):
    from _storage_fixtures import T0

    view = _scan(storage, monkeypatch)
    target = tmp_path / "chosen.txt"
    offered = []
    monkeypatch.setattr(view, "_choose_path",
                        lambda name: offered.append(name) or str(target))
    view._save()

    assert target.read_text(encoding="utf-8") == view._text()
    assert offered == [f"polyscour-storage-C-{T0.astimezone():%Y%m%d}.txt"]
    assert str(target) in view._status.cget("text")


def test_cancelling_the_save_dialog_writes_nothing_and_says_nothing(storage, monkeypatch, tmp_path):
    view = _scan(storage, monkeypatch)
    monkeypatch.setattr(view, "_choose_path", lambda name: None)
    before = set(tmp_path.iterdir())
    view._status.configure(text="")
    view._save()
    assert set(tmp_path.iterdir()) == before
    assert view._status.cget("text") == ""


def test_a_path_that_cannot_be_written_is_reported_not_raised(storage, monkeypatch, tmp_path):
    view = _scan(storage, monkeypatch)
    monkeypatch.setattr(view, "_choose_path", lambda name: str(tmp_path))  # a directory
    view._save()
    assert view._status.cget("text").startswith("Could not save the report")


def test_no_control_on_the_screen_acts_on_a_finding(storage, monkeypatch):
    """The invariant this screen exists to keep, checked on the real widgets.

    Two buttons sit beside Scan and they act on the *report*. Nothing inside the
    results -- no row, no card -- may be a button at all.
    """
    _scan(storage, monkeypatch, day=0, used=100)
    view = _scan(storage, monkeypatch, day=7, used=112)

    assert _buttons(view._body) == []
    assert sorted(_buttons(view._controls)) == ["Copy report", "Save report…",
                                                "Scan"]


def test_the_services_keep_storage_history_apart_from_the_ledger(app):
    """A scan did nothing to this machine, and the ledger is what PolyScour did.
    A snapshot listed beside an operation would blur the distinction the ledger
    exists to keep (adr/0008)."""
    history = app.services.storage_history
    assert history.path.name == "storage_history.sqlite"
    assert history.path != app.services.ledger.path


# ── Settings: the saved Storage scans ────────────────────────────────────────

@pytest.fixture
def saved_scans(app, tmp_path, monkeypatch):
    """The Settings view, pointed at a store of its own."""
    from polyscour.storage.history import SnapshotStore

    app.navigate("settings")
    view = app.get_view("settings")
    store = SnapshotStore(tmp_path / "storage_history.sqlite")
    monkeypatch.setattr(app.services, "storage_history", store)
    monkeypatch.setattr(view, "_confirm_clear_history", lambda: True)
    return view, store


def _keep(store, *, days=(0, 1), volume=None):
    from datetime import timedelta

    from _storage_fixtures import T0, VOL_A, snap

    for d in days:
        store.save(snap(taken_at=T0 + timedelta(days=d),
                        volume_id=volume or VOL_A))


def test_settings_says_when_nothing_is_saved_and_offers_nothing_to_clear(saved_scans):
    view, _ = saved_scans
    view._refresh_history()
    assert view._history_label.cget("text") == "No saved scans."
    assert view._clear_history_button.cget("state") == "disabled"


def test_settings_counts_what_is_kept(saved_scans):
    from _storage_fixtures import VOL_B

    view, store = saved_scans
    _keep(store, days=(0, 1))
    _keep(store, days=(0,), volume=VOL_B)
    view._refresh_history()

    text = view._history_label.cget("text")
    assert text.startswith("3 saved scans of 2 volumes")
    assert view._clear_history_button.cget("state") == "normal"


def test_settings_notices_scans_saved_after_it_was_built(saved_scans):
    view, store = saved_scans
    view._refresh_history()
    assert view._history_label.cget("text") == "No saved scans."
    _keep(store, days=(0,))
    view.on_show()                                   # what navigating here does
    assert view._history_label.cget("text").startswith("1 saved scan of 1 volume")


def test_declining_the_confirmation_clears_nothing(saved_scans, monkeypatch):
    view, store = saved_scans
    _keep(store)
    monkeypatch.setattr(view, "_confirm_clear_history", lambda: False)
    view._clear_history()
    assert store.summary().scans == 2


def test_confirming_clears_everything_and_says_how_many(saved_scans, app):
    view, store = saved_scans
    _keep(store, days=(0, 1, 2))
    view._clear_history()

    assert store.summary().scans == 0
    assert app.status.cget("text") == "3 saved scans cleared."
    assert view._history_label.cget("text") == "No saved scans."


def test_a_failed_clear_says_so_and_does_not_pretend_the_store_is_empty(saved_scans, app, monkeypatch):
    view, store = saved_scans
    _keep(store)

    def locked(volume_id=None):
        raise OSError("file is locked")

    monkeypatch.setattr(store, "clear", locked)
    view._clear_history()

    assert app.status.cget("text") == "Could not clear saved scans: file is locked"
    assert view._history_label.cget("text").startswith("2 saved scans")


def test_a_store_that_cannot_be_read_is_not_shown_as_empty(saved_scans, monkeypatch):
    import sqlite3

    view, store = saved_scans

    def broken():
        raise sqlite3.DatabaseError("file is not a database")

    monkeypatch.setattr(store, "summary", broken)
    view._refresh_history()
    assert "could not be read" in view._history_label.cget("text")
    assert view._history_label.cget("text") != "No saved scans."
    assert view._clear_history_button.cget("state") == "normal"   # so it can be fixed


# ── Clean: the pointer to Storage ────────────────────────────────────────────

@pytest.fixture
def clean_screen(app, monkeypatch):
    app.navigate("clean")
    view = app.get_view("clean")
    # The real `_scan` runs -- it is the verification re-scan a cleanup triggers,
    # and whether it disturbs the pointer is part of what is tested. Only the
    # hop to a worker thread is stubbed, so nothing walks this machine.
    monkeypatch.setattr(app, "run_off_thread", lambda work, done: None)
    view.storage_hint.grid_remove()
    return view


def _cleanup(*, dry_run: bool):
    from datetime import datetime, timezone

    from polyscour.contracts import ActionResult, OperationOutcome

    now = datetime.now(timezone.utc)
    return ActionResult(operation_id="op", outcome=OperationOutcome.SUCCESS,
                        started_at=now, finished_at=now, bytes_freed=5_000_000,
                        items_completed=3, dry_run=dry_run)


def _hint_shown(view) -> bool:
    return bool(view.storage_hint.grid_info())      # {} once grid_remove()d


def test_the_storage_pointer_is_absent_until_something_was_cleaned(clean_screen):
    assert not _hint_shown(clean_screen)


def test_a_real_cleanup_points_at_storage(clean_screen):
    clean_screen._cleaned(_cleanup(dry_run=False), None)
    assert _hint_shown(clean_screen)


def test_a_dry_run_and_a_failed_cleanup_do_not(clean_screen):
    clean_screen._cleaned(_cleanup(dry_run=True), None)
    assert not _hint_shown(clean_screen)
    clean_screen._cleaned(None, OSError("could not finish"))
    assert not _hint_shown(clean_screen)


def test_the_pointer_survives_the_verification_scan_and_not_the_next_one_you_ask_for(clean_screen):
    clean_screen._cleaned(_cleanup(dry_run=False), None)   # calls _scan(), as it does live
    assert _hint_shown(clean_screen)

    clean_screen._scan_clicked()                           # the Scan button
    assert not _hint_shown(clean_screen)


def test_the_pointer_says_what_cleaning_covers_and_makes_no_claim_about_the_disk(clean_screen):
    labels = " ".join(_labels(clean_screen.storage_hint))
    assert "only covers what PolyScour's rules are allowed to remove" in labels
    assert "Storage shows where the rest of the disk went" in labels
    # Evidence is Storage's job; this screen has none, so it asserts none.
    for claim in ("mostly", "cache", "junk", "wasted", "should"):
        assert claim not in labels.lower()


def test_open_storage_navigates_and_does_nothing_else(clean_screen, app, monkeypatch):
    seen = []
    monkeypatch.setattr(app, "navigate", lambda key: seen.append(key))
    (button,) = [w for w in clean_screen.storage_hint.winfo_children()
                 if isinstance(w, ctk.CTkButton)]
    button.invoke()
    assert seen == ["storage"]


# ── Startup: the view-only inventory ─────────────────────────────────────────

def _inventory_fixture():
    from polyscour.startup.inventory import (Inventory, InventoryEntry, Source,
                                             SourceStatus)
    from polyscour.startup.manager import TargetState

    def e(source, name, state="enabled"):
        return InventoryEntry(source, name, f"mechanism of {name}",
                              rf"C:\Vendor\{name}.exe", rf"C:\Vendor\{name}.exe",
                              TargetState.PRESENT, "SYSTEM", state)

    return Inventory(
        entries=[e(Source.SCHEDULED_TASK, "Updater"), e(Source.SERVICE, "Agent")],
        statuses=[SourceStatus(Source.STARTUP_FOLDER),
                  SourceStatus(Source.RUN_ONCE, error="access denied"),
                  SourceStatus(Source.SCHEDULED_TASK, listed=1,
                               in_windows_folder=42),
                  SourceStatus(Source.SERVICE, listed=1, in_windows_folder=83)])


@pytest.fixture
def startup_screen(app, monkeypatch):
    from polyscour.views import startup_view

    view = app.get_view("startup")
    monkeypatch.setattr(startup_view, "list_items", lambda: [])
    monkeypatch.setattr(startup_view, "read_inventory", _inventory_fixture)

    def inline(work, done):
        try:
            result = work()
        except Exception as exc:                            # noqa: BLE001
            done(None, exc)
        else:
            done(result, None)

    monkeypatch.setattr(app, "run_off_thread", inline)
    return view


def _texts(view):
    def walk(w):
        yield w
        for c in w.winfo_children():
            yield from walk(c)
    return [w.cget("text") for w in walk(view.list)
            if isinstance(w, ctk.CTkLabel)]


def test_the_inventory_names_its_sources_and_what_it_left_out(startup_screen):
    startup_screen.refresh()
    text = "\n".join(_texts(startup_screen))
    assert "Also starts with Windows — view only" in text
    assert "Updater" in text and "Agent" in text
    # Counted, not silently absent.
    assert "42 others, whose programs are all inside the Windows folder, are not listed" in text
    assert "83 others, whose programs are all inside the Windows folder, are not listed" in text


def test_an_unread_source_says_so_and_is_not_shown_as_none_found(startup_screen):
    startup_screen.refresh()
    text = "\n".join(_texts(startup_screen))
    assert "Could not read all of this: access denied" in text
    # The source that WAS read and is empty says so; the unread one must not.
    assert text.count("None found.") == 1


def test_the_inventory_has_no_switch_and_no_advice(startup_screen):
    startup_screen.refresh()
    def walk(w):
        yield w
        for c in w.winfo_children():
            yield from walk(c)
    kinds = {type(w).__name__ for w in walk(startup_screen.list)}
    assert "CTkSwitch" not in kinds and "CTkButton" not in kinds
    text = "\n".join(_texts(startup_screen)).lower()
    for word in ("recommend", "safe to", "should disable", "unnecessary", "bloat"):
        # The one sentence that names the word does so to disclaim it.
        assert word not in text.replace("nothing below is a recommendation", "")


def test_a_failed_inventory_read_is_reported_not_left_as_loading(startup_screen,
                                                                 monkeypatch):
    from polyscour.views import startup_view

    def boom():
        raise RuntimeError("no luck")
    monkeypatch.setattr(startup_view, "read_inventory", boom)
    startup_screen.refresh()
    text = "\n".join(_texts(startup_screen))
    assert "Could not read these: no luck" in text
    assert "Reading scheduled tasks" not in text


def test_a_late_answer_for_a_rebuilt_list_is_dropped(startup_screen, app, monkeypatch):
    """Refreshing twice while the first read is in flight must not paint the
    section twice."""
    pending = []
    monkeypatch.setattr(app, "run_off_thread",
                        lambda work, done: pending.append((work, done)))
    startup_screen.refresh()
    startup_screen.refresh()
    assert len(pending) == 2
    for work, done in pending:              # the stale one answers first
        done(work(), None)
    text = _texts(startup_screen)
    assert text.count("Also starts with Windows — view only") == 1
    assert sum("Updater" == t for t in text) == 1

import types  # noqa: E402


# ── Startup: one request per row, and the row tells the truth afterwards ─────

class _Registry:
    """A stand-in for the registry the list is read from, so a test can say
    what is *true* independently of what a row remembers."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def items(self):
        from polybedrock.startup import RunEntry

        from polyscour.startup.manager import StartupItem, TargetState
        entry = RunEntry(hive_name="HKLM_WOW6432", key_path="k",
                         value_name="Mouse", raw_value=r"C:\m.exe",
                         target_path=r"C:\m.exe", scope="machine")
        return [StartupItem(entry=entry, enabled=self.enabled,
                            has_approval_record=True, target=TargetState.PRESENT)]


@pytest.fixture
def machine_row(app, monkeypatch):
    """The Startup view with one machine-wide row and a request we control.

    ``pending`` collects (work, done) pairs instead of running them, which is
    what an unanswered UAC prompt looks like from here.
    """
    from polyscour.views import startup_view

    registry = _Registry(enabled=True)
    view = app.get_view("startup")
    monkeypatch.setattr(startup_view, "list_items", registry.items)
    monkeypatch.setattr(startup_view, "read_inventory", _inventory_fixture)
    pending, applied, cancels = [], [], []
    monkeypatch.setattr(app, "run_off_thread",
                        lambda work, done: pending.append((work, done)))

    def fake_apply(item, enabled, ledger, cancel=None):
        applied.append(enabled)
        cancels.append(cancel)
        return types.SimpleNamespace(changed=True, reason="", elevated=True)
    monkeypatch.setattr(startup_view.service, "apply_change", fake_apply)
    view._pending.clear()
    view.refresh()
    pending.clear()                       # drop the inventory read
    view._cancel_events = cancels
    return view, registry, pending, applied


def _walk(w):
    yield w
    for c in w.winfo_children():
        yield from _walk(c)


def _the_switch(view):
    (switch,) = [w for w in _walk(view.list) if isinstance(w, ctk.CTkSwitch)]
    return switch


def _answer(pending, index, result=None, error=None):
    work, done = pending[index]
    done(result if result is not None else work(), error)


def test_the_switch_is_locked_while_an_administrator_request_is_pending(machine_row):
    view, _, pending, _ = machine_row
    switch = _the_switch(view)
    assert switch.cget("state") == "normal"          # the control
    switch._variable.set(False)
    view._toggle(_Registry().items()[0], switch._variable)
    assert _the_switch(view).cget("state") == "disabled"
    assert len(pending) == 1


def test_a_second_click_while_pending_sends_nothing_and_changes_nothing(machine_row):
    view, registry, pending, applied = machine_row
    item = registry.items()[0]
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(item, var)                          # the first click
    var.set(True)                                    # the impatient second one
    view._toggle(item, var)
    assert len(pending) == 1, "a second request was started"
    assert var.get() is True                         # back where the row was
    _answer(pending, 0)
    assert applied == [False], "only the first request may reach the service"


def test_the_lock_is_released_when_the_answer_arrives(machine_row):
    view, registry, pending, _ = machine_row
    item = registry.items()[0]
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(item, var)
    registry.enabled = False                         # the helper wrote it
    _answer(pending, 0)
    assert view._pending == set()
    assert _the_switch(view).cget("state") == "normal"
    assert _the_switch(view)._variable.get() is False


def test_the_lock_survives_a_refresh_that_happens_while_pending(machine_row):
    """Another row's change (or the user leaving and returning) rebuilds the
    list. The rebuilt row must still be locked."""
    view, registry, pending, _ = machine_row
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(registry.items()[0], var)
    view.refresh()
    assert _the_switch(view).cget("state") == "disabled"


def test_a_refused_change_shows_what_the_registry_says_not_what_the_row_remembered(
        machine_row):
    """The reported bug: the registry said disabled while the switch said
    enabled. A refusal must not leave the row on its old memory."""
    view, registry, pending, _ = machine_row
    item = registry.items()[0]                       # remembered: enabled
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(item, var)
    registry.enabled = False                         # it landed regardless
    refused = types.SimpleNamespace(changed=False, reason="already in that state",
                                    elevated=False)
    _answer(pending, 0, result=refused)
    assert _the_switch(view)._variable.get() is False
    assert "already in that state" in view.status.cget("text")


def test_a_failed_request_also_re_reads_the_registry_and_unlocks(machine_row):
    view, registry, pending, _ = machine_row
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(registry.items()[0], var)
    registry.enabled = False
    _answer(pending, 0, result=None, error=RuntimeError("helper crashed"))
    assert view._pending == set()
    assert _the_switch(view).cget("state") == "normal"
    assert _the_switch(view)._variable.get() is False
    assert "helper crashed" in view.status.cget("text")


def test_a_user_entry_is_not_locked_or_left_pending(app, monkeypatch):
    """The control: only requests that wait for a prompt need a lock."""
    from polybedrock.startup import RunEntry

    from polyscour.startup.manager import StartupItem, TargetState
    from polyscour.views import startup_view

    entry = RunEntry(hive_name="HKCU", key_path="k", value_name="Tool",
                     raw_value=r"C:\t.exe", target_path=r"C:\t.exe", scope="user")
    item = StartupItem(entry=entry, enabled=True, has_approval_record=True,
                       target=TargetState.PRESENT)
    view = app.get_view("startup")
    monkeypatch.setattr(startup_view, "list_items", lambda: [item])
    monkeypatch.setattr(startup_view, "read_inventory", _inventory_fixture)
    monkeypatch.setattr(app, "run_off_thread", lambda work, done: None)
    calls = []
    monkeypatch.setattr(
        startup_view.service, "apply_change",
        lambda it, en, led: calls.append(en) or types.SimpleNamespace(
            changed=True, reason="", elevated=False))
    view._pending.clear()
    view.refresh()
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(item, var)
    assert calls == [False] and view._pending == set()


# ── Startup: the wait is visible, and can be cancelled ───────────────────────

_WAIT_HINT = "Waiting for the Windows administrator prompt"


def _cancel_button(view):
    (button,) = [w for w in _walk(view.list)
                 if isinstance(w, ctk.CTkButton)
                 and w.cget("text") in ("Cancel", "Cancelling…")]
    return button


def _start_request(view, registry):
    item = registry.items()[0]
    var = _the_switch(view)._variable
    var.set(False)
    view._toggle(item, var)
    return item


def test_a_row_offers_no_cancel_and_no_wait_message_until_a_request_is_pending(
        machine_row):
    view, _, _, _ = machine_row
    assert _cancel_button(view).winfo_manager() == ""      # built, not shown
    assert _WAIT_HINT not in "\n".join(_texts(view))


def test_a_pending_row_says_what_it_is_waiting_for_and_offers_cancel(machine_row):
    view, registry, _, _ = machine_row
    _start_request(view, registry)
    assert _cancel_button(view).winfo_manager() == "grid"
    text = "\n".join(_texts(view))
    assert _WAIT_HINT in text and "taskbar" in text


def test_a_rebuilt_row_still_shows_the_wait_and_its_way_out(machine_row):
    view, registry, _, _ = machine_row
    _start_request(view, registry)
    view.refresh()
    assert _cancel_button(view).winfo_manager() == "grid"
    assert _WAIT_HINT in "\n".join(_texts(view))


def test_cancel_sets_the_event_the_service_receives_and_says_what_it_promises(
        machine_row):
    view, registry, pending, _ = machine_row
    item = _start_request(view, registry)
    event = view._cancels[item.identity]
    assert not event.is_set()

    _cancel_button(view).invoke()

    assert event.is_set()
    button = _cancel_button(view)
    assert button.cget("text") == "Cancelling…"
    assert button.cget("state") == "disabled"                 # once is enough
    assert "nothing will be changed" in view.status.cget("text")
    _answer(pending, 0)                                       # runs the service
    assert view._cancel_events[0] is event, (
        "the service was not handed the screen's own cancel event")


def test_the_wait_and_the_cancel_state_end_with_the_answer(machine_row):
    view, registry, pending, _ = machine_row
    item = _start_request(view, registry)
    _cancel_button(view).invoke()
    refused = types.SimpleNamespace(
        changed=False, reason="cancelled before it started, so nothing was changed",
        elevated=False)
    _answer(pending, 0, result=refused)
    assert view._cancels == {} and view._pending == set()
    assert _cancel_button(view).winfo_manager() == ""
    assert _WAIT_HINT not in "\n".join(_texts(view))
    assert "nothing was changed" in view.status.cget("text")
    assert _the_switch(view).cget("state") == "normal"
    assert item.identity not in view._pending


def test_cancel_with_nothing_pending_does_nothing(machine_row):
    view, registry, _, _ = machine_row
    view._cancel(registry.items()[0].identity)               # must not raise
    assert view._cancels == {}
