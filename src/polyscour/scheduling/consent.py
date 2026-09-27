r"""What a schedule consented to, and whether that consent still holds.

**Consent binds to the exact reviewed rule definitions, not their ids.** A
rule id alone is not what a person reviewed in Settings — the JSON behind it
can change later — so each ``Schedule`` stores a canonical digest of every
rule it covers, taken at creation time, and this module re-derives that
digest from the *current* rule file before every unattended run. A mismatch
refuses that rule rather than running a definition nobody ever saw.

This is the same principle ``safety/policy.py`` states for paths — "a rule
file is data, and data is untrusted" — applied to the schedule's own stored
consent rather than to the rule file alone.

Two separate refusal shapes
----------------------------

A changed rule definition refuses **that rule only** — a three-rule schedule
with one changed definition still runs the other two. A policy-version
regression (``safety.policy.POLICY_VERSION`` has moved past what this
schedule recorded) refuses the **whole schedule**: it is not a per-rule fact,
and a change here means the authority every rule in the schedule operates
under has changed, not just one of them.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from polyscour import paths
from polyscour.cleaning import rules as rules_module
from polyscour.contracts import RiskLevel
from polyscour.safety import policy as safety_policy


class Frequency(Enum):
    DAILY = "daily"
    WEEKLY = "weekly"


WEEKDAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


@dataclass(frozen=True)
class Trigger:
    frequency: Frequency
    #: 24-hour "HH:MM", validated by the caller that builds one.
    time: str
    #: One of WEEKDAYS; required if and only if frequency is WEEKLY.
    day_of_week: str | None = None

    def describe(self) -> str:
        if self.frequency is Frequency.DAILY:
            return f"Daily at {self.time}"
        return f"Every {self.day_of_week.title()} at {self.time}"


@dataclass(frozen=True)
class Schedule:
    """A schedule's stored consent envelope.

    Everything here is what was reviewed and agreed to at creation time — it
    is data, and data is not authority (see :func:`verify`). In particular,
    ``elevation_allowed`` is recorded for the record and the UI; the runner
    that actually executes a schedule never reads it to decide whether to
    elevate, because the answer is always no, unconditionally, at the code
    level (``scheduling/runner.py``).
    """
    id: str
    enabled: bool
    trigger: Trigger
    rule_ids: tuple[str, ...]
    #: rule_id -> canonical SHA-256 of its definition at consent time.
    rule_definition_hashes: dict[str, str]
    policy_version: int
    maximum_risk: RiskLevel
    elevation_allowed: bool
    created_by_user: bool
    created_at: str
    #: The exact Task Scheduler path this schedule owns. See scheduling/task.py.
    task_name: str

    def describe(self) -> str:
        n = len(self.rule_ids)
        return (f"{self.trigger.describe()} — {n} rule{'s' if n != 1 else ''}, "
               f"up to {self.maximum_risk.label.lower()} risk")


def canonical_rule_digest(raw: dict) -> str:
    """SHA-256 of a rule's canonical serialisation.

    Sorted keys and no incidental whitespace, so a purely cosmetic edit to a
    rule file (reformatting, key order, trailing whitespace) does not force a
    needless re-consent, while any change to what the rule actually says
    does.
    """
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def current_rule_source(rule_id: str) -> dict | None:
    """The raw JSON for a rule that still exists and still validates.

    Read directly from disk rather than through the parsed ``Rule``: the
    digest must reflect exactly what is written in the file, canonicalised —
    not PolyScour's internal representation of it. ``None`` covers "no file
    declares this id" and "it exists but no longer validates against its
    policy" identically: either way, this rule cannot be scheduled.
    """
    directory = paths.rules_dir()
    if not directory.is_dir():
        return None
    for f in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if raw.get("id") != rule_id:
            continue
        try:
            rules_module.parse(raw)
        except rules_module.RuleError:
            return None
        return raw
    return None


def eligible_rule_ids() -> list[str]:
    """Rule ids a schedule may ever be created for.

    Excludes anything ``requires_elevation`` — a scheduled run never
    elevates, full stop (``scheduling/runner.py``), so offering an
    elevation-requiring rule would just silently accomplish nothing for it
    every single run.
    """
    loaded, _ = rules_module.load_all(paths.rules_dir())
    return sorted(r.id for r in loaded if not r.requires_elevation)


def rule_definition_hashes(rule_ids: list[str]) -> dict[str, str]:
    """The consent envelope's hash map, computed once at creation time."""
    out: dict[str, str] = {}
    for rule_id in rule_ids:
        raw = current_rule_source(rule_id)
        if raw is not None:
            out[rule_id] = canonical_rule_digest(raw)
    return out


@dataclass(frozen=True)
class VerifyResult:
    """What running this schedule right now is actually permitted to do."""
    runnable_rule_ids: tuple[str, ...]
    refused: dict[str, str]              # rule_id -> reason
    schedule_refused: str | None = None  # set only for a whole-schedule refusal

    @property
    def ok(self) -> bool:
        return self.schedule_refused is None and bool(self.runnable_rule_ids)


def verify(schedule: Schedule) -> VerifyResult:
    """Re-derive authority from the current rule files and policy version.

    Never trusts what the schedule itself claims — every check here recomputes
    the current fact and compares it against what was recorded at consent.

    Reads ``safety_policy.POLICY_VERSION`` through the module, not as a bound
    name imported once — a real version bump only ever takes effect between
    process launches (it is a code change, shipped in a new release), but a
    live attribute lookup is what makes that fact checkable by a test within
    one process, rather than only trustworthy by argument.
    """
    if safety_policy.POLICY_VERSION > schedule.policy_version:
        return VerifyResult((), {}, (
            "the safety policy has changed since this schedule was created "
            "and it must be reviewed again before it can run"))

    runnable: list[str] = []
    refused: dict[str, str] = {}
    for rule_id in schedule.rule_ids:
        raw = current_rule_source(rule_id)
        if raw is None:
            refused[rule_id] = "the rule no longer exists or no longer loads"
            continue
        current_digest = canonical_rule_digest(raw)
        expected = schedule.rule_definition_hashes.get(rule_id)
        if current_digest != expected:
            refused[rule_id] = (
                "the rule's definition has changed since this schedule was "
                "created and it must be reviewed again")
            continue
        runnable.append(rule_id)

    return VerifyResult(tuple(runnable), refused)
