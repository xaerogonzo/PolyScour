r"""Creating, enabling and removing a schedule: validation and ordering.

`scheduling.task` is monkeypatched throughout -- this file is about the
validation and ordering logic in `service.py`, not about Task Scheduler
itself (see tests/test_scheduling_task.py for that, against the real thing).
"""
from __future__ import annotations

import json
import os

import pytest

from polyscour.contracts import RiskLevel
from polyscour.scheduling import service, store, task
from polyscour.scheduling.consent import Frequency, Trigger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    import polyscour.scheduling.consent as consent_module
    directory = tmp_path / "rules"
    directory.mkdir()
    monkeypatch.setattr(consent_module.paths, "rules_dir", lambda: directory)
    monkeypatch.setattr(service.paths, "rules_dir", lambda: directory)
    return directory


def _write_rule(directory, filename, **overrides):
    rule = {
        "id": overrides.pop("id", "user-temp"), "name": "User temp",
        "description": "d", "category": "Temporary files", "risk": "low",
        "root_families": ["user_temp"], "patterns": ["*"],
    }
    rule.update(overrides)
    (directory / filename).write_text(json.dumps(rule), encoding="utf-8")


@pytest.fixture
def schedules_file(tmp_path, monkeypatch):
    path = tmp_path / "schedules.json"
    monkeypatch.setattr(store.paths, "schedules_path", lambda: path)
    return path


@pytest.fixture
def fake_task(monkeypatch):
    calls = {"create": [], "remove": [], "set_enabled": []}
    monkeypatch.setattr(task, "create",
                        lambda sid, trig: calls["create"].append((sid, trig)) or (True, ""))
    monkeypatch.setattr(task, "remove",
                        lambda sid: calls["remove"].append(sid) or (True, ""))
    monkeypatch.setattr(task, "set_enabled",
                        lambda sid, en: calls["set_enabled"].append((sid, en)) or (True, ""))
    return calls


def test_create_schedule_refuses_an_empty_selection(rules_dir, schedules_file,
                                                      fake_task):
    with pytest.raises(service.ScheduleRefused):
        service.create_schedule([], Trigger(Frequency.DAILY, "03:00"))
    assert fake_task["create"] == []


def test_create_schedule_refuses_an_elevation_requiring_rule(
        rules_dir, schedules_file, fake_task):
    _write_rule(rules_dir, "windows-temp.json", id="windows-temp",
               root_families=["windows_temp"], requires_elevation=True,
               expected_scope="system_cache")

    with pytest.raises(service.ScheduleRefused):
        service.create_schedule(["windows-temp"],
                                Trigger(Frequency.DAILY, "03:00"))
    assert fake_task["create"] == []


def test_create_schedule_computes_maximum_risk_from_the_selection(
        rules_dir, schedules_file, fake_task):
    _write_rule(rules_dir, "user-temp.json", id="user-temp", risk="low")
    _write_rule(rules_dir, "chrome-cache.json", id="chrome-cache", risk="safe",
               root_families=["browser_cache_chrome"])

    schedule = service.create_schedule(
        ["user-temp", "chrome-cache"], Trigger(Frequency.DAILY, "03:00"))

    assert schedule.maximum_risk is RiskLevel.LOW


def test_create_schedule_persists_only_after_the_task_exists(
        rules_dir, schedules_file, monkeypatch):
    _write_rule(rules_dir, "user-temp.json")
    order = []
    monkeypatch.setattr(task, "create",
                        lambda sid, trig: order.append("task") or (True, ""))
    real_save = store.save
    monkeypatch.setattr(store, "save",
                        lambda s: order.append("store") or real_save(s))

    service.create_schedule(["user-temp"], Trigger(Frequency.DAILY, "03:00"))

    assert order == ["task", "store"]


def test_create_schedule_never_persists_if_the_task_fails(
        rules_dir, schedules_file, monkeypatch):
    _write_rule(rules_dir, "user-temp.json")
    monkeypatch.setattr(task, "create", lambda sid, trig: (False, "boom"))

    with pytest.raises(service.ScheduleRefused, match="boom"):
        service.create_schedule(["user-temp"], Trigger(Frequency.DAILY, "03:00"))

    assert store.load_all() == []


def test_create_schedule_never_marks_elevation_allowed(
        rules_dir, schedules_file, fake_task):
    _write_rule(rules_dir, "user-temp.json")
    schedule = service.create_schedule(
        ["user-temp"], Trigger(Frequency.DAILY, "03:00"))
    assert schedule.elevation_allowed is False


def test_set_enabled_updates_both_the_task_and_the_record(
        rules_dir, schedules_file, fake_task):
    _write_rule(rules_dir, "user-temp.json")
    schedule = service.create_schedule(
        ["user-temp"], Trigger(Frequency.DAILY, "03:00"))

    updated = service.set_enabled(schedule.id, False)

    assert updated.enabled is False
    assert (schedule.id, False) in fake_task["set_enabled"]
    assert store.get(schedule.id).enabled is False


def test_set_enabled_refuses_an_unknown_schedule(schedules_file, fake_task):
    with pytest.raises(service.ScheduleRefused):
        service.set_enabled("does-not-exist", True)


def test_remove_schedule_removes_the_task_before_the_record(
        rules_dir, schedules_file, monkeypatch):
    _write_rule(rules_dir, "user-temp.json")
    monkeypatch.setattr(task, "create", lambda sid, trig: (True, ""))
    schedule = service.create_schedule(
        ["user-temp"], Trigger(Frequency.DAILY, "03:00"))

    order = []
    monkeypatch.setattr(task, "remove",
                        lambda sid: order.append("task") or (True, ""))
    real_delete = store.delete
    monkeypatch.setattr(store, "delete",
                        lambda sid: order.append("store") or real_delete(sid))

    result = service.remove_schedule(schedule.id)

    assert result.ok is True
    assert order == ["task", "store"]
    assert store.load_all() == []


def test_remove_schedule_keeps_the_record_if_the_task_cannot_be_removed(
        rules_dir, schedules_file, monkeypatch):
    _write_rule(rules_dir, "user-temp.json")
    monkeypatch.setattr(task, "create", lambda sid, trig: (True, ""))
    schedule = service.create_schedule(
        ["user-temp"], Trigger(Frequency.DAILY, "03:00"))

    monkeypatch.setattr(task, "remove", lambda sid: (False, "access denied"))

    result = service.remove_schedule(schedule.id)

    assert result.ok is False
    assert store.get(schedule.id) is not None


def test_remove_schedule_of_an_unknown_id_is_a_no_op_success(schedules_file, fake_task):
    result = service.remove_schedule("does-not-exist")
    assert result.ok is True
