r"""Loading cleaner rules. Data in, validated intent out.

A rule file is data and is treated as untrusted. Loading one therefore does two
different jobs, and conflating them would defeat the design:

1. **Parse and validate the shape.** Is this well-formed JSON with the fields a
   rule needs?
2. **Reconcile it against the trust policy.** Does a reviewed ``PolicyEntry``
   exist for this id, and does the rule stay *within* it?

Authority only narrows. A rule may declare fewer root families than its policy
permits, tighter ceilings, or a smaller scope. It can never declare more, and an
attempt to is a load-time failure rather than something noticed at delete time.

Note what a rule cannot express at all: a path. Locations are named symbolically
and resolved only by ``polyscour.safety.policy``. That is why editing a rule
file cannot widen what it reaches.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from polyscour.contracts import RiskLevel
from polyscour.safety.policy import (
    Operation,
    PolicyEntry,
    PolicyViolation,
    RootFamily,
    Scope,
    entry_for,
)

_REQUIRED = {"id", "name", "description", "category", "risk",
             "root_families", "patterns"}


class RuleError(Exception):
    """A rule file is malformed, or asks for more than its policy grants."""


@dataclass(frozen=True)
class Rule:
    """A validated rule, already reconciled with its policy entry."""
    id: str
    name: str
    description: str
    category: str
    risk: RiskLevel
    families: tuple[RootFamily, ...]
    patterns: tuple[str, ...]
    conditions: tuple[str, ...]
    min_age_days: int
    scope: Scope
    max_candidates: int
    max_bytes: int
    max_depth: int
    #: Derived from the policy, never from the file. A rule cannot promise the
    #: user an undo that its permissions do not actually allow.
    operation: Operation
    requires_elevation: bool

    @property
    def reversible(self) -> bool:
        return self.operation is Operation.VAULT


def _risk(raw: str) -> RiskLevel:
    try:
        return RiskLevel[raw.strip().upper()]
    except KeyError:
        raise RuleError(
            f"unknown risk {raw!r}; expected one of "
            f"{[r.name.lower() for r in RiskLevel]}") from None


def _families(raw: list, entry: PolicyEntry, rule_id: str) -> tuple[RootFamily, ...]:
    try:
        declared = {RootFamily(v) for v in raw}
    except ValueError as exc:
        raise RuleError(
            f"rule {rule_id!r} names an unknown root family: {exc}. Families are "
            f"defined in polyscour.safety.policy, which is code -- a rule "
            f"cannot introduce a new location.") from None

    if not declared:
        raise RuleError(f"rule {rule_id!r} declares no root family")

    ungranted = declared - entry.families
    if ungranted:
        raise RuleError(
            f"rule {rule_id!r} claims root families its policy does not grant: "
            f"{sorted(f.value for f in ungranted)}. Authority narrows as it "
            f"flows outward; it never widens. Add them to the PolicyEntry in "
            f"polyscour.safety.policy if that is genuinely intended.")
    return tuple(sorted(declared, key=lambda f: f.value))


def _ceiling(raw: dict, key: str, cap: int, rule_id: str) -> int:
    """A rule may lower a ceiling. It may not raise one."""
    if key not in raw:
        return cap
    value = raw[key]
    if not isinstance(value, int) or value <= 0:
        raise RuleError(f"rule {rule_id!r}: {key} must be a positive integer")
    if value > cap:
        raise RuleError(
            f"rule {rule_id!r} sets {key}={value:,}, above the {cap:,} its "
            f"policy permits. A rule may be stricter than its policy, never "
            f"looser.")
    return value


def _floor(raw: dict, key: str, floor: int, rule_id: str) -> int:
    """A rule may raise a floor. It may not lower one.

    The mirror image of :func:`_ceiling`, and refusing rather than clamping for
    the same reason: a rule file that tries to loosen its policy is not a rule
    with a typo, and silently correcting it would hide the attempt.
    """
    value = raw.get(key, floor)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuleError(
            f"rule {rule_id!r}: {key} must be a non-negative integer")
    if value < floor:
        raise RuleError(
            f"rule {rule_id!r} sets {key}={value}, below the {floor} its "
            f"policy requires. A rule may be stricter than its policy, never "
            f"looser.")
    return value


def _scope(raw: str | None, entry: PolicyEntry, rule_id: str) -> Scope:
    if raw is None:
        return entry.scope
    try:
        declared = Scope(raw)
    except ValueError:
        raise RuleError(
            f"rule {rule_id!r}: unknown scope {raw!r}") from None
    # Scope is descriptive rather than ordered, so the only check that means
    # anything is agreement with the reviewed entry.
    if declared is not entry.scope:
        raise RuleError(
            f"rule {rule_id!r} declares scope {declared.value!r} but its policy "
            f"records {entry.scope.value!r}. The scope is what a scan is checked "
            f"against; the two disagreeing means one of them is wrong.")
    return declared


def parse(raw: dict) -> Rule:
    """Validate one rule dict against its policy entry."""
    missing = _REQUIRED - raw.keys()
    if missing:
        raise RuleError(f"rule is missing required fields: {sorted(missing)}")

    rule_id = raw["id"]
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleError("rule id must be a non-empty string")

    try:
        entry = entry_for(rule_id)
    except PolicyViolation as exc:
        raise RuleError(str(exc)) from exc

    patterns = tuple(raw["patterns"])
    if not patterns:
        raise RuleError(f"rule {rule_id!r} declares no patterns")

    limits = raw.get("limits", {})
    if not isinstance(limits, dict):
        raise RuleError(f"rule {rule_id!r}: limits must be an object")

    # A policy entry grants exactly one operation in 0.1. If that ever becomes
    # several, the rule will have to say which -- and it will still have to be
    # one the policy already granted.
    if len(entry.operations) != 1:
        raise RuleError(
            f"rule {rule_id!r}: its policy grants {len(entry.operations)} "
            f"operations; the rule format cannot yet express which to use")
    operation = next(iter(entry.operations))

    return Rule(
        id=rule_id,
        name=raw["name"],
        description=raw["description"],
        category=raw["category"],
        risk=_risk(raw["risk"]),
        families=_families(raw["root_families"], entry, rule_id),
        patterns=patterns,
        conditions=tuple(raw.get("conditions", [])),
        min_age_days=_floor(raw, "min_age_days", entry.min_age_days, rule_id),
        scope=_scope(raw.get("expected_scope"), entry, rule_id),
        max_candidates=_ceiling(limits, "max_candidates", entry.max_candidates, rule_id),
        max_bytes=_ceiling(limits, "max_bytes", entry.max_bytes, rule_id),
        max_depth=_ceiling(limits, "max_depth", entry.max_depth, rule_id),
        operation=operation,
        requires_elevation=bool(raw.get("requires_elevation", False)),
    )


def load_file(path: Path) -> Rule:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleError(f"{path.name} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise RuleError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleError(f"{path.name} must contain a JSON object")
    return parse(raw)


def load_all(directory: Path) -> tuple[list[Rule], list[tuple[Path, RuleError]]]:
    """Load every rule in a directory.

    Returns the rules that loaded and the ones that did not, rather than raising
    on the first failure: one malformed rule must not silently disable the other
    eight, and the failures are worth showing rather than swallowing.
    """
    directory = Path(directory)
    rules: list[Rule] = []
    failures: list[tuple[Path, RuleError]] = []
    if not directory.is_dir():
        return rules, failures
    for f in sorted(directory.glob("*.json")):
        try:
            rules.append(load_file(f))
        except RuleError as exc:
            failures.append((f, exc))
    return rules, failures
