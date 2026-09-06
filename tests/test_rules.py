r"""Rule loading. The half of "configuration is not authority" that runs early.

The guard is the backstop; these tests cover the front stop -- a rule that asks
for more than its policy grants must fail to *load*, not merely fail to act.
"""
from __future__ import annotations

import json

import pytest

from polyscour import paths
from polyscour.cleaning.rules import Rule, RuleError, load_all, load_file, parse
from polyscour.safety.policy import POLICY, Operation, Scope


def base(**overrides) -> dict:
    """A valid user-temp rule, before the test breaks one field of it."""
    raw = {
        "id": "user-temp",
        "name": "User temporary files",
        "description": "d",
        "category": "Temporary files",
        "risk": "low",
        "root_families": ["user_temp"],
        "patterns": ["*"],
    }
    raw.update(overrides)
    return raw


# ══ The shipped rules ═════════════════════════════════════════════════════════

def test_every_shipped_rule_loads():
    rules, failures = load_all(paths.rules_dir())
    assert not failures, [(f.name, str(e)) for f, e in failures]
    assert rules


def test_every_shipped_rule_has_a_policy_entry():
    """The invariant that makes a rule file safe to treat as data."""
    rules, _ = load_all(paths.rules_dir())
    for rule in rules:
        assert rule.id in POLICY


def test_the_slice_exercises_both_reversibility_branches():
    """0.1 ships one vaulted rule on purpose: a delete-only rule set would leave
    the entire undo path untested until 0.2."""
    rules, _ = load_all(paths.rules_dir())
    ops = {r.operation for r in rules}
    assert Operation.DELETE in ops
    assert Operation.VAULT in ops, "no rule exercises the vault"


def test_no_shipped_rule_contains_a_path():
    """Locations are symbolic. A rule file that cannot name a path cannot widen
    its own reach by editing one."""
    for f in sorted(paths.rules_dir().glob("*.json")):
        raw = json.loads(f.read_text(encoding="utf-8"))
        blob = json.dumps(raw).lower()
        for marker in (":\\", ":/", "%localappdata%", "%temp%", "%appdata%",
                       "%systemroot%", "..\\", "../"):
            assert marker not in blob, f"{f.name} names a path ({marker!r})"


def test_a_reversible_rule_is_the_one_that_vaults():
    rules, _ = load_all(paths.rules_dir())
    for rule in rules:
        assert rule.reversible is (rule.operation is Operation.VAULT)


# ══ Authority narrows, never widens ═══════════════════════════════════════════

def test_a_rule_with_no_policy_entry_will_not_load():
    with pytest.raises(RuleError, match="no entry in the trust policy"):
        parse(base(id="rule-i-just-made-up"))


def test_a_rule_cannot_claim_a_family_its_policy_withholds():
    """The core attack: a rule declaring a family it was never granted."""
    with pytest.raises(RuleError, match="does not grant"):
        parse(base(root_families=["user_temp", "browser_cache_chrome"]))


def test_a_rule_cannot_invent_a_root_family():
    """Families are defined in code. There is no way to express a new location
    in a rule file at all."""
    with pytest.raises(RuleError, match="unknown root family"):
        parse(base(root_families=["my_documents"]))


def test_a_rule_cannot_raise_a_ceiling():
    cap = POLICY["user-temp"].max_candidates
    with pytest.raises(RuleError, match="above the"):
        parse(base(limits={"max_candidates": cap + 1}))


def test_a_rule_may_lower_a_ceiling():
    """Stricter is always allowed. That direction is the safe one."""
    rule = parse(base(limits={"max_candidates": 10}))
    assert rule.max_candidates == 10


def test_omitted_ceilings_fall_back_to_the_policy():
    rule = parse(base())
    assert rule.max_candidates == POLICY["user-temp"].max_candidates


def test_a_rule_cannot_disagree_with_its_policy_about_scope():
    """The scope is what a scan gets checked against; the two disagreeing means
    one of them is wrong, and silently trusting either would hide it."""
    with pytest.raises(RuleError, match="but its policy records"):
        parse(base(expected_scope=Scope.SYSTEM_CACHE.value))


def test_the_operation_comes_from_the_policy_not_the_file():
    """A rule cannot promise the user an undo its permissions do not allow."""
    rule = parse(base())
    assert rule.operation is Operation.DELETE
    assert rule.reversible is False


# ══ Malformed input ═══════════════════════════════════════════════════════════

@pytest.mark.parametrize("missing", ["id", "name", "risk", "root_families", "patterns"])
def test_missing_required_fields_are_refused(missing):
    raw = base()
    del raw[missing]
    with pytest.raises(RuleError, match="missing required fields"):
        parse(raw)


def test_an_unknown_risk_is_refused():
    with pytest.raises(RuleError, match="unknown risk"):
        parse(base(risk="apocalyptic"))


def test_a_rule_with_no_patterns_is_refused():
    """An empty pattern list would match nothing, but it reads like a mistake
    and the failure should be at load time rather than a silently empty scan."""
    with pytest.raises(RuleError, match="no patterns"):
        parse(base(patterns=[]))


def test_invalid_json_names_the_file(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuleError, match="broken.json is not valid JSON"):
        load_file(bad)


def test_one_bad_rule_does_not_disable_the_others(tmp_path):
    """A malformed rule must not silently take the working ones down with it."""
    (tmp_path / "good.json").write_text(json.dumps(base()), encoding="utf-8")
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")

    rules, failures = load_all(tmp_path)

    assert [r.id for r in rules] == ["user-temp"]
    assert len(failures) == 1
    assert failures[0][0].name == "bad.json"


def test_an_empty_directory_is_not_an_error(tmp_path):
    assert load_all(tmp_path) == ([], [])
