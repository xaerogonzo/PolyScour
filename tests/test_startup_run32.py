r"""tests/test_startup_run32.py -- the 32-bit machine-wide Run key has its own record.

Windows keeps the approval byte for ``HKLM\SOFTWARE\WOW6432Node\...\Run`` values
under ``StartupApproved\Run32``, **not** ``StartupApproved\Run``. Observed on a
real machine: the one 32-bit entry's record is in ``Run32`` and absent from
``Run``. Before this was fixed:

* reading looked in ``Run``, so a 32-bit entry disabled in Task Manager was
  shown as enabled -- the screen stated a false fact; and
* the elevated helper only knew the 64-bit key, so a change to a 32-bit entry
  was refused with "not a machine-wide startup entry" (or, if a same-named value
  existed in both views, wrote the wrong record).

Everything here runs against **throwaway keys under HKCU**. The helper's
``HKEY_LOCAL_MACHINE`` is pointed at HKCU and its key names at scratch paths, so
no real Run or StartupApproved key is ever read for writing or written.
"""
from __future__ import annotations

import json
import sys
import types
import uuid
import winreg

import pytest

from polybedrock.startup import RunEntry

from polyscour.elevation import helper
from polyscour.elevation.protocol import (MalformedRequest, Operation, Request)
from polyscour.startup import manager, service
from polyscour.startup.manager import StartupItem, TargetState

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="Windows-only product")

RAW64 = r"C:\Vendor64\tool.exe"
RAW32 = r"C:\Vendor32\tool.exe"


def _delete_tree(root, path):
    try:
        with winreg.OpenKey(root, path, access=winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, path + "\\" + child)
    except FileNotFoundError:
        return
    winreg.DeleteKey(root, path)


@pytest.fixture
def scratch(monkeypatch):
    """Scratch Run/Run32 and their approval keys, under HKCU only."""
    base = rf"Software\PolyScourTest-{uuid.uuid4().hex}"
    k = types.SimpleNamespace(
        run=base + r"\Run", run32=base + r"\Run32Src",
        ap=base + r"\Approved\Run", ap32=base + r"\Approved\Run32")
    for path in (k.run, k.run32, k.ap, k.ap32):
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, path).Close()

    proxy = types.SimpleNamespace(**{n: getattr(winreg, n) for n in dir(winreg)
                                     if not n.startswith("__")})
    proxy.HKEY_LOCAL_MACHINE = winreg.HKEY_CURRENT_USER
    monkeypatch.setattr(helper, "winreg", proxy)
    monkeypatch.setattr(helper, "_MACHINE_KEYS",
                        {False: (k.run, k.ap), True: (k.run32, k.ap32)})

    monkeypatch.setattr(manager, "_HIVES", {"HKCU": winreg.HKEY_CURRENT_USER,
                                            "HKLM": winreg.HKEY_CURRENT_USER})
    monkeypatch.setattr(manager, "_APPROVED", k.ap)
    monkeypatch.setattr(manager, "_APPROVED_32", k.ap32)
    yield k
    _delete_tree(winreg.HKEY_CURRENT_USER, base)


def put(path, name, data, kind=winreg.REG_SZ):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path,
                        access=winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, kind, data)


def get(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def blob(state):
    return bytes([state]) + bytes(11)


def machine_request(name="Tool", enabled=False, raw=RAW64, wow6432=False):
    return Request(Operation.SET_MACHINE_STARTUP_APPROVAL,
                   {"value_name": name, "enabled": enabled,
                    "expected_raw_value": raw, "wow6432": wow6432})


# ── reading ──────────────────────────────────────────────────────────────────

def test_a_32_bit_entry_reads_its_state_from_run32(scratch):
    put(scratch.ap32, "Tool", blob(0x03), winreg.REG_BINARY)
    assert manager.read_approvals("HKLM_WOW6432") == {"Tool": False}


def test_a_64_bit_entry_still_reads_run(scratch):
    """The control: the fix must not have moved every machine entry."""
    put(scratch.ap, "Tool", blob(0x03), winreg.REG_BINARY)
    assert manager.read_approvals("HKLM") == {"Tool": False}
    assert manager.read_approvals("HKCU") == {"Tool": False}


def test_each_view_ignores_the_other_views_record(scratch):
    put(scratch.ap, "Tool", blob(0x03), winreg.REG_BINARY)        # 64-bit: off
    put(scratch.ap32, "Tool", blob(0x02), winreg.REG_BINARY)      # 32-bit: on
    assert manager.read_approvals("HKLM") == {"Tool": False}
    assert manager.read_approvals("HKLM_WOW6432") == {"Tool": True}


def test_a_32_bit_entry_disabled_in_task_manager_is_listed_as_disabled(
        scratch, monkeypatch):
    """The user-visible bug, end to end through ``list_items``."""
    put(scratch.ap32, "Tool", blob(0x03), winreg.REG_BINARY)
    entry = RunEntry(hive_name="HKLM_WOW6432", key_path=scratch.run32,
                     value_name="Tool", raw_value=RAW32, target_path=RAW32,
                     scope="machine")
    monkeypatch.setattr(manager, "iter_run_entries", lambda: [entry])
    (item,) = manager.list_items()
    assert item.enabled is False and item.has_approval_record is True


def test_a_32_bit_entry_with_no_record_is_enabled(scratch, monkeypatch):
    entry = RunEntry(hive_name="HKLM_WOW6432", key_path=scratch.run32,
                     value_name="Tool", raw_value=RAW32, target_path=RAW32,
                     scope="machine")
    monkeypatch.setattr(manager, "iter_run_entries", lambda: [entry])
    (item,) = manager.list_items()
    assert item.enabled is True and item.has_approval_record is False


def test_the_real_machine_reads_the_key_windows_wrote(monkeypatch):
    """Read-only, against the real registry: for every real 32-bit entry, the
    state shown is what is recorded in Run32, whichever way it is set."""
    real = [e for e in manager.iter_run_entries()
            if e.hive_name == "HKLM_WOW6432"]
    if not real:
        pytest.skip("no 32-bit machine-wide Run values on this machine")
    recorded = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            manager._APPROVED_32) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                recorded[name] = value[0] != 0x03
    except OSError:
        pass
    for item in manager.list_items():
        if item.entry.hive_name == "HKLM_WOW6432":
            assert item.enabled == recorded.get(item.name, True)


# ── the user-hive write is unchanged ─────────────────────────────────────────

def test_a_user_entry_is_still_written_to_run(scratch):
    entry = RunEntry(hive_name="HKCU", key_path=scratch.run, value_name="Tool",
                     raw_value=RAW64, target_path=RAW64, scope="user")
    item = StartupItem(entry=entry, enabled=True, has_approval_record=False,
                       target=TargetState.PRESENT)
    manager.set_enabled(item, False)
    assert get(scratch.ap, "Tool")[0] == 0x03
    assert get(scratch.ap32, "Tool") is None


# ── the helper, per view ─────────────────────────────────────────────────────

def test_a_32_bit_request_writes_run32_and_not_run(scratch):
    put(scratch.run32, "Tool", RAW32)
    response = helper.handle(machine_request(raw=RAW32, wow6432=True))
    assert response.ok, response.detail
    assert get(scratch.ap32, "Tool")[0] == 0x03
    assert get(scratch.ap, "Tool") is None, "wrote the record of the other view"


def test_a_64_bit_request_writes_run_and_not_run32(scratch):
    put(scratch.run, "Tool", RAW64)
    response = helper.handle(machine_request(raw=RAW64, wow6432=False))
    assert response.ok, response.detail
    assert get(scratch.ap, "Tool")[0] == 0x03
    assert get(scratch.ap32, "Tool") is None


def test_a_32_bit_request_needs_the_value_to_exist_in_the_32_bit_run_key(scratch):
    """A same-named 64-bit value must not license a 32-bit record."""
    put(scratch.run, "Tool", RAW64)
    response = helper.handle(machine_request(raw=RAW64, wow6432=True))
    assert response.ok is False and response.refused_by == "policy"
    assert get(scratch.ap32, "Tool") is None and get(scratch.ap, "Tool") is None


def test_a_64_bit_request_needs_the_value_to_exist_in_the_64_bit_run_key(scratch):
    put(scratch.run32, "Tool", RAW32)
    response = helper.handle(machine_request(raw=RAW32, wow6432=False))
    assert response.ok is False and response.refused_by == "policy"
    assert get(scratch.ap32, "Tool") is None and get(scratch.ap, "Tool") is None


def test_a_name_in_both_views_is_only_written_in_the_one_asked_for(scratch):
    put(scratch.run, "Tool", RAW64)
    put(scratch.run32, "Tool", RAW32)
    put(scratch.ap, "Tool", blob(0x02), winreg.REG_BINARY)
    response = helper.handle(machine_request(raw=RAW32, wow6432=True))
    assert response.ok, response.detail
    assert get(scratch.ap32, "Tool")[0] == 0x03
    assert get(scratch.ap, "Tool") == blob(0x02), "the 64-bit record changed"


def test_a_changed_32_bit_target_is_refused(scratch):
    put(scratch.run32, "Tool", r"C:\Vendor32\swapped.exe")
    response = helper.handle(machine_request(raw=RAW32, wow6432=True))
    assert response.ok is False and "changed since" in response.detail
    assert get(scratch.ap32, "Tool") is None


def test_the_read_back_looks_in_the_view_that_was_written(scratch):
    """If it looked in the other view it would see 'absent = enabled' and
    report a successful disable as 'still enabled'."""
    put(scratch.run32, "Tool", RAW32)
    put(scratch.ap, "Tool", blob(0x02), winreg.REG_BINARY)   # a decoy, 64-bit
    assert helper._read_machine_approval("Tool", True) is True   # no 32 record
    put(scratch.ap32, "Tool", blob(0x03), winreg.REG_BINARY)
    assert helper._read_machine_approval("Tool", True) is False
    assert helper._read_machine_approval("Tool", False) is True  # decoy view


def test_the_helper_can_write_exactly_two_approval_keys():
    """A guard on the design: the boolean chooses between two fixed pairs and
    there is nothing else it can select."""
    assert set(helper._MACHINE_KEYS) == {False, True}
    approvals = {pair[1] for pair in helper._MACHINE_KEYS.values()}
    assert len(approvals) == 2
    assert {a.rsplit("\\", 1)[1] for a in approvals} == {"Run", "Run32"}
    assert helper._MACHINE_KEYS[True][0].split("\\")[1] == "WOW6432Node"


# ── the protocol ─────────────────────────────────────────────────────────────

def params(**over):
    p = {"value_name": "Tool", "enabled": False, "expected_raw_value": RAW32,
         "wow6432": True}
    p.update(over)
    return json.dumps({"operation": "set_machine_startup_approval", "params": p})


def test_the_request_parses_with_the_view_named():
    assert Request.from_json(params()).params["wow6432"] is True


def test_a_request_that_does_not_say_which_view_is_refused():
    p = json.loads(params())
    del p["params"]["wow6432"]
    with pytest.raises(MalformedRequest, match="missing parameter"):
        Request.from_json(json.dumps(p))


@pytest.mark.parametrize("bad", ["true", 1, 0, None, "HKLM_WOW6432"])
def test_the_view_is_a_boolean_and_nothing_is_coerced_to_it(bad):
    with pytest.raises(MalformedRequest, match="must be a boolean"):
        Request.from_json(params(wow6432=bad))


# ── what the GUI side asks for ───────────────────────────────────────────────

def _machine_item(hive, key_path):
    entry = RunEntry(hive_name=hive, key_path=key_path, value_name="Tool",
                     raw_value=RAW32, target_path=RAW32, scope="machine")
    return StartupItem(entry=entry, enabled=True, has_approval_record=False,
                       target=TargetState.PRESENT)


@pytest.mark.parametrize("hive,expected", [("HKLM_WOW6432", True),
                                           ("HKLM", False)])
def test_the_view_is_derived_from_the_entry_not_chosen_by_the_caller(
        monkeypatch, hive, expected):
    asked = []

    def fake_request(operation, **kw):
        asked.append(kw)
        return types.SimpleNamespace(ok=True, detail="")

    import polyscour.elevation.client as client
    monkeypatch.setattr(client, "request", fake_request)
    assert service._write(_machine_item(hive, "any"), False) is True
    assert asked[0]["wow6432"] is expected


# ── a cancelled request is refused, wherever the cancel arrives ──────────────

def _control(tmp_path, *, cancelled):
    request = tmp_path / "request.json"
    request.write_text("{}", encoding="utf-8")
    if cancelled:
        (tmp_path / "cancel").write_text("1", encoding="utf-8")
    return helper._Control(request)


def test_a_request_cancelled_before_the_helper_starts_is_refused_and_writes_nothing(
        scratch, tmp_path):
    """The user cancels while the UAC prompt is still up and answers it later.
    The helper that then starts must find the sentinel and do nothing."""
    put(scratch.run32, "Tool", RAW32)
    response = helper.handle(machine_request(raw=RAW32, wow6432=True),
                             _control(tmp_path, cancelled=True))
    assert response.ok is False and response.refused_by == "policy"
    assert "cancelled" in response.detail
    assert get(scratch.ap32, "Tool") is None and get(scratch.ap, "Tool") is None


def test_the_same_request_uncancelled_is_written(scratch, tmp_path):
    """The control for the test above: without it the refusal could be a
    blanket no."""
    put(scratch.run32, "Tool", RAW32)
    response = helper.handle(machine_request(raw=RAW32, wow6432=True),
                             _control(tmp_path, cancelled=False))
    assert response.ok, response.detail
    assert get(scratch.ap32, "Tool")[0] == 0x03


def test_a_cancel_that_arrives_after_validation_still_stops_the_write(scratch):
    """Everything before the write is a few registry reads, but the last look
    is immediately before the write, not only at the top."""
    put(scratch.run32, "Tool", RAW32)

    class Late:
        def __init__(self):
            self.looks = 0

        def cancelled(self):
            self.looks += 1
            return self.looks >= 2          # clear at the top, set before the write

    late = Late()
    response = helper.handle(machine_request(raw=RAW32, wow6432=True), late)
    assert response.ok is False and "cancelled" in response.detail
    assert late.looks == 2
    assert get(scratch.ap32, "Tool") is None


def test_the_service_passes_the_cancel_event_to_the_helper_and_closes_the_row(
        monkeypatch):
    """The screen owns the Event; the service must hand that same object to the
    client, and a refused request must leave History saying nothing changed."""
    import threading

    import polyscour.elevation.client as client
    seen = {}

    def fake_request(operation, cancel=None, **kw):
        seen["cancel"] = cancel
        return types.SimpleNamespace(
            ok=False, detail="cancelled before it started, so nothing was changed")

    monkeypatch.setattr(client, "request", fake_request)

    class Ledger:
        def __init__(self):
            self.events = []

        def record_startup_change(self, *a, **k):
            self.events.append("record")
            return 1

        def mark_startup_reverted(self, row_id):
            self.events.append(f"reverted:{row_id}")

    ledger, event = Ledger(), threading.Event()
    item = _machine_item("HKLM_WOW6432", "any")
    result = service.apply_change(item, False, ledger, event)
    assert seen["cancel"] is event
    assert result.changed is False and "cancelled" in result.reason
    assert ledger.events == ["record", "reverted:1"]
