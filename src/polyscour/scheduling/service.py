r"""Creating, changing and removing a schedule: the veto, the task, the record.

The order, and why it is this way round
-----------------------------------------

    validate selection  ->  create the Task Scheduler task  ->  persist

Persisting only after the task exists means a failure to create the task
never leaves behind a schedule that claims to run but has nothing scheduling
it. The reverse order would risk exactly that: a `schedules.json` entry
naming a task that was never actually created.

Removal is the mirror image: the task is removed before the record is,
so a failure to remove the task is visible (the schedule still shows up,
still refusable to remove again) rather than silently orphaning a Task
Scheduler entry `schedules.json` no longer remembers.
"""
from __future__ import annotations

from dataclasses import dataclass

from polyscour.cleaning import rules as rules_module
from polyscour import paths
from polyscour.scheduling import store, task
from polyscour.scheduling.consent import (
    Schedule,
    Trigger,
    eligible_rule_ids,
    rule_definition_hashes,
)
from polyscour.safety import policy as safety_policy


class ScheduleRefused(Exception):
    """The selection could not become a schedule, and says why."""


@dataclass(frozen=True)
class RemovalResult:
    ok: bool
    detail: str


def create_schedule(rule_ids: list[str], trigger: Trigger) -> Schedule:
    """Validate a selection and create the schedule, in that order.

    Raises :class:`ScheduleRefused` rather than returning a half-built
    schedule -- there is no partial success to represent here, only "this
    selection was never eligible" or "the task could not be created".
    """
    eligible = set(eligible_rule_ids())
    chosen = list(dict.fromkeys(rule_ids))     # de-duplicate, keep order
    if not chosen:
        raise ScheduleRefused("choose at least one rule")
    ineligible = [r for r in chosen if r not in eligible]
    if ineligible:
        raise ScheduleRefused(
            f"not eligible for scheduling (needs administrator rights, or "
            f"does not exist): {', '.join(ineligible)}")

    loaded, _ = rules_module.load_all(paths.rules_dir())
    by_id = {r.id: r for r in loaded}
    maximum_risk = max(by_id[r].risk for r in chosen)

    schedule_id = store.new_schedule_id()
    ok, detail = task.create(schedule_id, trigger)
    if not ok:
        raise ScheduleRefused(f"could not create the scheduled task: {detail}")

    schedule = Schedule(
        id=schedule_id, enabled=True, trigger=trigger,
        rule_ids=tuple(chosen),
        rule_definition_hashes=rule_definition_hashes(chosen),
        policy_version=safety_policy.POLICY_VERSION, maximum_risk=maximum_risk,
        elevation_allowed=False, created_by_user=True,
        created_at=store.now_iso(), task_name=task.task_name(schedule_id))
    store.save(schedule)
    return schedule


def set_enabled(schedule_id: str, enabled: bool) -> Schedule:
    """Flip a schedule's switch, at both levels that matter.

    The Task Scheduler task is disabled too, not only the stored flag --
    belt and suspenders, the same reasoning `guard.authorize()` being called
    twice is: disabling a schedule should mean the task genuinely stops
    firing, not merely that the runner would refuse it if it ever ran.
    Disabling never cancels a run already in progress; it only prevents the
    *next* scheduled trigger.
    """
    schedule = store.get(schedule_id)
    if schedule is None:
        raise ScheduleRefused("no such schedule")

    task.set_enabled(schedule_id, enabled)   # best-effort; the stored flag is
                                              # what the runner itself checks
    updated = Schedule(**{**schedule.__dict__, "enabled": enabled})
    store.save(updated)
    return updated


def remove_schedule(schedule_id: str) -> RemovalResult:
    """Remove the task, then the record. See the module docstring for order."""
    schedule = store.get(schedule_id)
    if schedule is None:
        return RemovalResult(True, "already removed")

    ok, detail = task.remove(schedule_id)
    if not ok:
        return RemovalResult(False, f"could not remove the scheduled task: {detail}")

    store.delete(schedule_id)
    return RemovalResult(True, "")
