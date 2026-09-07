r"""tests/test_startup.py — the switch, the refusals, and what undo checks.

Three properties carry the Startup Manager.

**Absence of an approval record means enabled.** Most `Run` values have no
record at all. A reader that required one would report healthy entries as
unknown, and the fix for that misreading would be to invent a state.

**The ledger row is written before the registry.** Dying in between shows a
change in History that did not happen — visible and correctable. The reverse
order would alter the machine with nothing to say so.

**Undo is not "flip it back".** Between disabling an entry and undoing it, an
installer can rewrite the `Run` value to launch something else. Re-enabling it
then restores a decision the user never made, under PolyScour's name — so the
recorded `raw_value` is compared and a mismatch refuses.
"""
from __future__ import annotations

import pytest

from polybedrock.startup import RunEntry

from polyscour.ledger import Ledger
from polyscour.startup import service
from polyscour.startup.manager import StartupItem, TargetState
from polyscour.startup.policy import veto


RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def entry(name="Updater", value=r"C:\Vendor\updater.exe", hive="HKCU",
          scope="user", target=r"C:\Vendor\updater.exe"):
    return RunEntry(hive_name=hive, key_path=RUN, value_name=name,
                    raw_value=value, target_path=target, scope=scope)


def item(enabled=True, recorded=True, target_state=TargetState.PRESENT, **kw):
    return StartupItem(entry=entry(**kw), enabled=enabled,
                       has_approval_record=recorded, target=target_state)


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    led.initialise()
    return led


# ── the policy ──────────────────────────────────────────────────────────────

def test_a_user_entry_may_be_changed():
    """The control: without it every refusal below could be a blanket no."""
    assert veto(item()) is None


def test_machine_wide_entries_are_refused_with_the_reason():
    reason = veto(item(hive="HKLM", scope="machine"))
    assert reason and "administrator" in reason


def test_polyscour_will_not_disable_its_own_entry():
    reason = veto(item(name="PolyScour"))
    assert reason and "its own" in reason


def test_an_unnamed_entry_is_refused():
    reason = veto(item(name=""))
    assert reason and "cannot be addressed" in reason


# ── the ordering ────────────────────────────────────────────────────────────

class _Recorder:
    """A ledger that remembers the ORDER of what happened to it."""

    def __init__(self):
        self.events: list[str] = []
        self.rows: dict[int, dict] = {}
        self._next = 1

    def record_startup_change(self, identity, value_name, raw_value,
                              was_enabled, now_enabled):
        rid = self._next
        self._next += 1
        self.rows[rid] = dict(id=rid, identity=identity, value_name=value_name,
                              raw_value=raw_value, was_enabled=was_enabled,
                              now_enabled=now_enabled, reverted_at=None)
        self.events.append(f"record:{value_name}")
        return rid

    def mark_startup_reverted(self, row_id):
        self.rows[row_id]["reverted_at"] = "now"
        self.events.append(f"reverted:{row_id}")


def test_the_ledger_row_is_written_before_the_registry(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(service, "set_enabled",
                        lambda it, en: rec.events.append(f"write:{it.name}"))

    result = service.apply_change(item(enabled=True), False, rec)

    assert result.changed is True
    assert rec.events == ["record:Updater", "write:Updater"], (
        "a registry change recorded after the fact is one History cannot show")


def test_a_refused_entry_is_neither_recorded_nor_written(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(service, "set_enabled",
                        lambda it, en: rec.events.append("write"))

    result = service.apply_change(item(hive="HKLM", scope="machine"), False, rec)

    assert result.changed is False
    assert rec.events == []


def test_a_refused_write_closes_its_own_row(monkeypatch):
    """Otherwise History asserts a change the registry rejected."""
    rec = _Recorder()

    def boom(it, en):
        raise OSError("access is denied")

    monkeypatch.setattr(service, "set_enabled", boom)
    result = service.apply_change(item(enabled=True), False, rec)

    assert result.changed is False
    assert "refused the write" in result.reason
    assert rec.rows[1]["reverted_at"] is not None


def test_setting_a_state_it_is_already_in_does_nothing(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(service, "set_enabled",
                        lambda it, en: rec.events.append("write"))

    result = service.apply_change(item(enabled=False), False, rec)

    assert result.changed is False
    assert result.reason == "already in that state"
    assert rec.events == [], "a no-op must not leave a row in History"


def test_the_veto_runs_again_at_write_time(monkeypatch):
    """The list a user is looking at was built earlier, and the registry is
    shared — an entry can have moved hive since. Same reason authorize() is
    called twice."""
    rec = _Recorder()
    monkeypatch.setattr(service, "set_enabled",
                        lambda it, en: rec.events.append("write"))

    service.apply_change(item(hive="HKLM", scope="machine"), False, rec)
    assert rec.events == []


# ── undo ────────────────────────────────────────────────────────────────────

def test_undo_puts_the_switch_back(ledger, monkeypatch):
    it = item(enabled=True)
    row_id = ledger.record_startup_change(it.identity, it.name,
                                          it.entry.raw_value, True, False)
    disabled = item(enabled=False)
    monkeypatch.setattr(service, "list_items", lambda: [disabled])
    written: list[bool] = []
    monkeypatch.setattr(service, "set_enabled",
                        lambda i, en: written.append(en))

    row = ledger.startup_changes()[0]
    result = service.undo(row, ledger)

    assert result.undone is True
    assert written == [True], "undo must restore the state it recorded"
    assert ledger.last_startup_change(it.identity) is None


def test_undo_refuses_when_the_entry_now_launches_something_else(ledger,
                                                                monkeypatch):
    """The property that matters most here.

    An installer rewriting the Run value between the change and the undo is
    ordinary. Re-enabling it anyway would restore a decision nobody made, using
    PolyScour's name to do it.
    """
    it = item(enabled=True)
    ledger.record_startup_change(it.identity, it.name, r"C:\Vendor\updater.exe",
                                 True, False)
    meddled = item(enabled=False, value=r"C:\Somewhere\else.exe")
    monkeypatch.setattr(service, "list_items", lambda: [meddled])
    monkeypatch.setattr(service, "set_enabled",
                        lambda i, en: pytest.fail("wrote over a changed entry"))

    result = service.undo(ledger.startup_changes()[0], ledger)

    assert result.undone is False
    assert "has changed since" in result.reason
    assert ledger.last_startup_change(it.identity) is not None, (
        "the record must stay open — the change is still outstanding")


def test_undo_closes_the_row_when_the_entry_is_gone(ledger, monkeypatch):
    it = item()
    ledger.record_startup_change(it.identity, it.name, it.entry.raw_value,
                                 True, False)
    monkeypatch.setattr(service, "list_items", lambda: [])

    result = service.undo(ledger.startup_changes()[0], ledger)

    assert result.undone is False
    assert "no longer exists" in result.reason
    assert ledger.last_startup_change(it.identity) is None, (
        "nothing to put back, so the record is settled rather than retried")


# ── the ledger's own behaviour ──────────────────────────────────────────────

def test_the_ledger_remembers_what_the_entry_launched(ledger):
    """Captured at the time, because that is what undo compares against."""
    ledger.record_startup_change(r"HKCU\...\Run\A", "A", r"C:\a.exe", True, False)
    row = ledger.startup_changes()[0]
    assert row["raw_value"] == r"C:\a.exe"
    assert row["was_enabled"] == 1 and row["now_enabled"] == 0


def test_reverted_changes_drop_out_of_the_outstanding_query(ledger):
    rid = ledger.record_startup_change(r"HKCU\...\Run\A", "A", r"C:\a.exe",
                                       True, False)
    assert ledger.last_startup_change(r"HKCU\...\Run\A") is not None
    ledger.mark_startup_reverted(rid)
    assert ledger.last_startup_change(r"HKCU\...\Run\A") is None
