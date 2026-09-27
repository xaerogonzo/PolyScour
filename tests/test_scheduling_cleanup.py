r"""What the uninstaller runs before removing PolyScour.exe.

`scheduling.service.remove_schedule` is monkeypatched throughout -- this file
is about `cleanup.py`'s own behaviour (iterate every recorded schedule,
never fail the process), not about Task Scheduler itself.
"""
from __future__ import annotations

import os

import pytest

from polyscour.contracts import RiskLevel
from polyscour.scheduling import cleanup, service, store
from polyscour.scheduling.consent import Frequency, Schedule, Trigger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


def _schedule(schedule_id: str) -> Schedule:
    return Schedule(
        id=schedule_id, enabled=True, trigger=Trigger(Frequency.DAILY, "03:00"),
        rule_ids=("user-temp",), rule_definition_hashes={"user-temp": "a" * 64},
        policy_version=1, maximum_risk=RiskLevel.LOW, elevation_allowed=False,
        created_by_user=True, created_at="2026-01-01T00:00:00+00:00",
        task_name=rf"\PolyScour\ScheduledClean-{schedule_id}")


@pytest.fixture
def schedules_file(tmp_path, monkeypatch):
    path = tmp_path / "schedules.json"
    monkeypatch.setattr(store.paths, "schedules_path", lambda: path)
    return path


def test_remove_all_removes_every_schedule(schedules_file, monkeypatch):
    store.save(_schedule("s1"))
    store.save(_schedule("s2"))
    removed = []
    monkeypatch.setattr(
        service, "remove_schedule",
        lambda sid: removed.append(sid) or service.RemovalResult(True, ""))

    failures = cleanup.remove_all()

    assert sorted(removed) == ["s1", "s2"]
    assert failures == 0


def test_remove_all_with_no_schedules_does_nothing(schedules_file):
    assert cleanup.remove_all() == 0


def test_remove_all_counts_failures_but_keeps_going(schedules_file, monkeypatch):
    store.save(_schedule("s1"))
    store.save(_schedule("s2"))
    monkeypatch.setattr(
        service, "remove_schedule",
        lambda sid: service.RemovalResult(sid != "s1", "boom" if sid == "s1" else ""))

    failures = cleanup.remove_all()

    assert failures == 1


def test_main_always_exits_zero_even_when_something_failed(
        schedules_file, monkeypatch):
    store.save(_schedule("s1"))
    monkeypatch.setattr(service, "remove_schedule",
                        lambda sid: service.RemovalResult(False, "boom"))

    assert cleanup.main([]) == 0
