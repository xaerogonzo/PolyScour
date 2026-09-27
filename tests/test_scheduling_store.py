r"""schedules.json: the schedule's own stored data, round-tripped exactly.

Never authority -- see tests/test_scheduling_consent.py for the checks that
actually decide what a schedule may do.
"""
from __future__ import annotations

import os

import pytest

from polyscour.contracts import RiskLevel
from polyscour.scheduling import store
from polyscour.scheduling.consent import Frequency, Schedule, Trigger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def schedules_file(tmp_path, monkeypatch):
    path = tmp_path / "schedules.json"
    monkeypatch.setattr(store.paths, "schedules_path", lambda: path)
    return path


def _schedule(schedule_id="s1", **overrides) -> Schedule:
    base = dict(
        id=schedule_id, enabled=True,
        trigger=Trigger(Frequency.WEEKLY, "03:30", "SUN"),
        rule_ids=("user-temp", "chrome-cache"),
        rule_definition_hashes={"user-temp": "a" * 64, "chrome-cache": "b" * 64},
        policy_version=1, maximum_risk=RiskLevel.SAFE, elevation_allowed=False,
        created_by_user=True, created_at=store.now_iso(),
        task_name=rf"\PolyScour\ScheduledClean-{schedule_id}")
    base.update(overrides)
    return Schedule(**base)


def test_load_all_is_empty_when_the_file_does_not_exist(schedules_file):
    assert store.load_all() == []


def test_save_then_load_round_trips_every_field(schedules_file):
    original = _schedule()
    store.save(original)

    [loaded] = store.load_all()

    assert loaded == original


def test_save_replaces_by_id_rather_than_duplicating(schedules_file):
    store.save(_schedule("s1", enabled=True))
    store.save(_schedule("s1", enabled=False))

    loaded = store.load_all()

    assert len(loaded) == 1
    assert loaded[0].enabled is False


def test_get_finds_one_schedule_by_id(schedules_file):
    store.save(_schedule("s1"))
    store.save(_schedule("s2"))

    assert store.get("s2").id == "s2"
    assert store.get("does-not-exist") is None


def test_delete_removes_and_returns_the_schedule(schedules_file):
    store.save(_schedule("s1"))

    removed = store.delete("s1")

    assert removed.id == "s1"
    assert store.load_all() == []


def test_delete_of_an_unknown_schedule_returns_none_and_changes_nothing(
        schedules_file):
    store.save(_schedule("s1"))

    removed = store.delete("does-not-exist")

    assert removed is None
    assert len(store.load_all()) == 1


def test_a_daily_trigger_has_no_day_of_week(schedules_file):
    original = _schedule(trigger=Trigger(Frequency.DAILY, "09:00"))
    store.save(original)

    [loaded] = store.load_all()

    assert loaded.trigger.day_of_week is None
    assert loaded.trigger.frequency is Frequency.DAILY


def test_an_unreadable_file_is_treated_as_no_schedules(schedules_file):
    schedules_file.write_text("{not valid json", encoding="utf-8")
    assert store.load_all() == []
