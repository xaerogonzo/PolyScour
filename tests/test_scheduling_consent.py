r"""Consent binds to the exact reviewed rule definitions, not their ids.

The canonical digest, the per-rule and whole-schedule refusal shapes, and the
policy-version regression check -- all pure logic, no Task Scheduler involved.
"""
from __future__ import annotations

import json
import os

import pytest

from polyscour.contracts import RiskLevel
from polyscour.scheduling import consent
from polyscour.scheduling.consent import Frequency, Schedule, Trigger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    directory = tmp_path / "rules"
    directory.mkdir()
    monkeypatch.setattr(consent.paths, "rules_dir", lambda: directory)
    return directory


def _write_rule(directory, filename: str, **overrides) -> dict:
    rule = {
        "id": overrides.pop("id", "user-temp"),
        "name": "User temporary files", "description": "d",
        "category": "Temporary files", "risk": "low",
        "root_families": ["user_temp"], "patterns": ["*"],
    }
    rule.update(overrides)
    (directory / filename).write_text(json.dumps(rule), encoding="utf-8")
    return rule


def _schedule(**overrides) -> Schedule:
    base = dict(
        id="s1", enabled=True,
        trigger=Trigger(Frequency.DAILY, "03:00"),
        rule_ids=("user-temp",),
        rule_definition_hashes={},
        policy_version=consent.safety_policy.POLICY_VERSION,
        maximum_risk=RiskLevel.LOW, elevation_allowed=False,
        created_by_user=True, created_at="2026-01-01T00:00:00+00:00",
        task_name=r"\PolyScour\ScheduledClean-s1")
    base.update(overrides)
    return Schedule(**base)


# ══ canonical_rule_digest ═══════════════════════════════════════════════════

def test_digest_is_stable_across_key_order_and_formatting():
    a = {"id": "x", "risk": "low", "patterns": ["*"]}
    b = json.loads('{"patterns": ["*"], "risk":   "low",   "id": "x"}')
    assert consent.canonical_rule_digest(a) == consent.canonical_rule_digest(b)


def test_digest_changes_with_any_content_change():
    a = {"id": "x", "risk": "low"}
    b = {"id": "x", "risk": "moderate"}
    assert consent.canonical_rule_digest(a) != consent.canonical_rule_digest(b)


# ══ eligible_rule_ids ═══════════════════════════════════════════════════════

def test_a_rule_requiring_elevation_is_never_eligible(rules_dir):
    _write_rule(rules_dir, "user-temp.json", id="user-temp")
    _write_rule(rules_dir, "windows-temp.json", id="windows-temp",
               root_families=["windows_temp"], requires_elevation=True,
               expected_scope="system_cache")
    assert consent.eligible_rule_ids() == ["user-temp"]


# ══ current_rule_source ═════════════════════════════════════════════════════

def test_current_rule_source_is_none_for_a_missing_rule(rules_dir):
    assert consent.current_rule_source("nope") is None


def test_current_rule_source_is_none_for_a_rule_that_no_longer_validates(rules_dir):
    _write_rule(rules_dir, "bad.json", id="bad", risk="not-a-real-risk")
    assert consent.current_rule_source("bad") is None


# ══ verify(): per-rule and whole-schedule refusal ═══════════════════════════

def test_verify_runs_a_rule_whose_digest_still_matches(rules_dir):
    raw = _write_rule(rules_dir, "user-temp.json")
    digest = consent.canonical_rule_digest(raw)
    schedule = _schedule(rule_definition_hashes={"user-temp": digest})

    result = consent.verify(schedule)

    assert result.runnable_rule_ids == ("user-temp",)
    assert result.refused == {}
    assert result.schedule_refused is None
    assert result.ok is True


def test_verify_refuses_only_the_rule_whose_definition_changed(rules_dir):
    _write_rule(rules_dir, "user-temp.json")
    _write_rule(rules_dir, "chrome-cache.json", id="chrome-cache", risk="safe",
               root_families=["browser_cache_chrome"])
    schedule = _schedule(
        rule_ids=("user-temp", "chrome-cache"),
        rule_definition_hashes={"user-temp": "0" * 64,   # deliberately wrong
                                "chrome-cache": consent.canonical_rule_digest(
                                    consent.current_rule_source("chrome-cache"))})

    result = consent.verify(schedule)

    assert result.runnable_rule_ids == ("chrome-cache",)
    assert "user-temp" in result.refused
    assert result.schedule_refused is None


def test_verify_refuses_a_rule_that_no_longer_exists(rules_dir):
    schedule = _schedule(rule_definition_hashes={"user-temp": "irrelevant"})
    result = consent.verify(schedule)
    assert result.runnable_rule_ids == ()
    assert "no longer exists" in result.refused["user-temp"]


def test_a_policy_version_regression_refuses_the_whole_schedule(
        rules_dir, monkeypatch):
    raw = _write_rule(rules_dir, "user-temp.json")
    digest = consent.canonical_rule_digest(raw)
    schedule = _schedule(rule_definition_hashes={"user-temp": digest},
                         policy_version=consent.safety_policy.POLICY_VERSION)

    monkeypatch.setattr(consent.safety_policy, "POLICY_VERSION",
                        consent.safety_policy.POLICY_VERSION + 1)

    result = consent.verify(schedule)

    assert result.runnable_rule_ids == ()
    assert result.schedule_refused is not None
    assert result.ok is False


def test_a_policy_version_that_only_moved_forward_is_fine_if_recorded_equal(
        rules_dir):
    """A schedule created against the current version must still run."""
    raw = _write_rule(rules_dir, "user-temp.json")
    digest = consent.canonical_rule_digest(raw)
    schedule = _schedule(rule_definition_hashes={"user-temp": digest},
                         policy_version=consent.safety_policy.POLICY_VERSION)
    result = consent.verify(schedule)
    assert result.ok is True
