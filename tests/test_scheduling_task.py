r"""Windows Task Scheduler integration. Runs against real, throwaway tasks.

Every task created here lives under `\PolyScour\ScheduledClean-<uuid>`, the
same folder a real installation uses, and is always removed in a `finally` --
the same "real but contained and cleaned up" approach
tests/test_startup_run32.py uses for the registry. A uuid-named task cannot
collide with anything a real installation created.

`schtasks /query /xml` is deliberately never asserted against here for values
longer than a short path -- see docs/gotchas/windows-subprocess.md #7 for the
measured corruption that makes it unreliable. Verification goes through
`Get-ScheduledTask` instead (`scheduling/task.py::verify`), which is exactly
what is being tested.
"""
from __future__ import annotations

import os
import uuid

import pytest

from polyscour.scheduling import task
from polyscour.scheduling.consent import Frequency, Trigger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def schedule_id():
    sid = uuid.uuid4().hex
    yield sid
    task.remove(sid)      # best-effort cleanup even if a test never created it


def test_create_then_verify_a_daily_task(schedule_id):
    ok, detail = task.create(schedule_id, Trigger(Frequency.DAILY, "03:00"))
    assert ok, detail

    ok, detail = task.verify(schedule_id)
    assert ok, detail


def test_create_then_verify_a_weekly_task(schedule_id):
    ok, detail = task.create(
        schedule_id, Trigger(Frequency.WEEKLY, "03:00", "SUN"))
    assert ok, detail

    ok, detail = task.verify(schedule_id)
    assert ok, detail


def test_verify_fails_for_a_task_that_was_never_created(schedule_id):
    ok, detail = task.verify(schedule_id)
    assert ok is False
    assert "could not be found" in detail


def test_remove_of_an_already_absent_task_is_success(schedule_id):
    ok, detail = task.remove(schedule_id)
    assert ok is True


def test_set_enabled_false_then_true(schedule_id):
    task.create(schedule_id, Trigger(Frequency.DAILY, "03:00"))

    ok, detail = task.set_enabled(schedule_id, False)
    assert ok, detail

    ok, detail = task.set_enabled(schedule_id, True)
    assert ok, detail


def test_verify_rejects_a_task_pointed_at_a_different_program(schedule_id):
    """Integrity check: the runner must not trust a task that was altered
    outside PolyScour, even though the task is unelevated either way."""
    task.create(schedule_id, Trigger(Frequency.DAILY, "03:00"))

    # Repoint the task at something else, exactly the way a user or another
    # local process could with Task Scheduler's own UI.
    changed = task._run_schtasks(
        ["/change", "/tn", task.task_name(schedule_id),
        "/tr", '"C:\\Windows\\System32\\notepad.exe"'])
    assert changed.returncode == 0

    ok, detail = task.verify(schedule_id)

    assert ok is False
    assert "different program" in detail


def test_remove_after_create_leaves_no_task_behind(schedule_id):
    task.create(schedule_id, Trigger(Frequency.DAILY, "03:00"))

    ok, _ = task.remove(schedule_id)
    assert ok is True

    ok, detail = task.verify(schedule_id)
    assert ok is False
    assert "could not be found" in detail
