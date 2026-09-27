r"""Reading and writing ``schedules.json``.

This is the schedule's own stored data — never authority. See
``scheduling/consent.py::verify`` for the checks that actually decide what a
schedule may do; this module only persists what was recorded, the same
"configuration is not authority" separation ``safety/policy.py`` draws
between a rule file and the code that decides what it may touch.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from polyscour import paths
from polyscour.contracts import RiskLevel
from polyscour.scheduling.consent import Frequency, Schedule, Trigger


def new_schedule_id() -> str:
    return uuid.uuid4().hex


def _to_dict(schedule: Schedule) -> dict:
    d = asdict(schedule)
    d["trigger"] = {"frequency": schedule.trigger.frequency.value,
                    "time": schedule.trigger.time,
                    "day_of_week": schedule.trigger.day_of_week}
    d["maximum_risk"] = schedule.maximum_risk.name
    return d


def _from_dict(d: dict) -> Schedule:
    trigger_raw = d["trigger"]
    trigger = Trigger(frequency=Frequency(trigger_raw["frequency"]),
                      time=trigger_raw["time"],
                      day_of_week=trigger_raw.get("day_of_week"))
    return Schedule(
        id=d["id"], enabled=bool(d["enabled"]), trigger=trigger,
        rule_ids=tuple(d["rule_ids"]),
        rule_definition_hashes=dict(d["rule_definition_hashes"]),
        policy_version=int(d["policy_version"]),
        maximum_risk=RiskLevel[d["maximum_risk"]],
        elevation_allowed=bool(d.get("elevation_allowed", False)),
        created_by_user=bool(d.get("created_by_user", True)),
        created_at=str(d["created_at"]),
        task_name=str(d["task_name"]))


def load_all() -> list[Schedule]:
    """Every stored schedule, or an empty list if there are none or the file
    cannot be read. An unreadable file is not distinguished from "no
    schedules" here because there is nothing actionable to do with the
    difference — the caller either creates a fresh one or sees an empty list
    either way — unlike a cleaning rule's ceilings, where the distinction
    changes what happens to real files.
    """
    path = paths.schedules_path()
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[Schedule] = []
    for entry in raw.get("schedules", []):
        try:
            out.append(_from_dict(entry))
        except (KeyError, ValueError, TypeError):
            continue
    return out


def _save_all(schedules: list[Schedule]) -> None:
    path = paths.schedules_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"schedules": [_to_dict(s) for s in schedules]},
                         indent=2)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)


def save(schedule: Schedule) -> None:
    """Insert or replace one schedule, by id."""
    schedules = [s for s in load_all() if s.id != schedule.id]
    schedules.append(schedule)
    _save_all(schedules)


def get(schedule_id: str) -> Schedule | None:
    for s in load_all():
        if s.id == schedule_id:
            return s
    return None


def delete(schedule_id: str) -> Schedule | None:
    """Remove and return the schedule, or ``None`` if it was not there.

    Callers that also own a Task Scheduler task for this schedule (see
    ``scheduling/task.py``) are responsible for removing that task too — this
    function only ever touches ``schedules.json``.
    """
    schedules = load_all()
    remaining = [s for s in schedules if s.id != schedule_id]
    removed = next((s for s in schedules if s.id == schedule_id), None)
    if removed is not None:
        _save_all(remaining)
    return removed


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
