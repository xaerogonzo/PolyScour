r"""What happens when Task Scheduler invokes --scheduled-clean <id>.

`scheduling.task.verify` and `scheduling.consent.verify` are monkeypatched
throughout: this file is about the runner's own order of checks and its
handling of each outcome, not about Task Scheduler or the rule files
themselves.
"""
from __future__ import annotations

import os

import pytest

from polyscour.scheduling import runner, store, task
from polyscour.scheduling.consent import Frequency, Schedule, Trigger, VerifyResult
from polyscour.contracts import RiskLevel

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


def _schedule(**overrides) -> Schedule:
    base = dict(
        id="s1", enabled=True, trigger=Trigger(Frequency.DAILY, "03:00"),
        rule_ids=("user-temp",), rule_definition_hashes={"user-temp": "a" * 64},
        policy_version=1, maximum_risk=RiskLevel.LOW, elevation_allowed=False,
        created_by_user=True, created_at="2026-01-01T00:00:00+00:00",
        task_name=r"\PolyScour\ScheduledClean-s1")
    base.update(overrides)
    return Schedule(**base)


@pytest.fixture
def no_data_dir(tmp_path, monkeypatch):
    """Real paths.vault_dir()/ledger_path() point at a throwaway root, so a
    run that reaches the executor never touches a real vault or ledger."""
    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path))


def test_no_such_schedule_is_an_error(no_data_dir):
    assert runner.run("does-not-exist") == 1


def test_a_disabled_schedule_does_nothing(no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule(enabled=False))
    called = []
    monkeypatch.setattr(task, "verify", lambda sid: called.append(sid) or (True, ""))

    assert runner.run("s1") == 0
    assert called == []          # never even asked Task Scheduler


def test_a_task_integrity_failure_refuses_the_run(no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule())
    monkeypatch.setattr(task, "verify", lambda sid: (False, "tampered"))

    from polyscour.scheduling import consent as consent_module
    consent_called = []
    monkeypatch.setattr(consent_module, "verify",
                        lambda s: consent_called.append(s) or VerifyResult((), {}))

    assert runner.run("s1") == 1
    assert consent_called == []   # never reached the consent check


def test_a_whole_schedule_refusal_stops_before_scanning(no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule())
    monkeypatch.setattr(task, "verify", lambda sid: (True, ""))

    from polyscour.scheduling import consent as consent_module
    monkeypatch.setattr(consent_module, "verify",
                        lambda s: VerifyResult((), {}, "policy moved on"))

    scan_called = []
    import polyscour.cleaning.scanner as scanner_module
    monkeypatch.setattr(scanner_module.Scanner, "scan",
                        lambda self, rules, cancel: scan_called.append(rules))

    assert runner.run("s1") == 1
    assert scan_called == []


def test_nothing_runnable_after_per_rule_refusal_is_a_clean_no_op(
        no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule())
    monkeypatch.setattr(task, "verify", lambda sid: (True, ""))

    from polyscour.scheduling import consent as consent_module
    monkeypatch.setattr(
        consent_module, "verify",
        lambda s: VerifyResult((), {"user-temp": "definition changed"}))

    assert runner.run("s1") == 0


def test_a_successful_run_scans_and_executes_without_elevation(
        no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule())
    monkeypatch.setattr(task, "verify", lambda sid: (True, ""))

    from polyscour.scheduling import consent as consent_module
    monkeypatch.setattr(consent_module, "verify",
                        lambda s: VerifyResult(("user-temp",), {}))

    from polyscour.contracts import Evidence, Finding, ScanResult, RuleOutcome
    from datetime import datetime, timezone
    finding = Finding(rule_id="user-temp", title="t", path=__import__("pathlib").Path("C:\\x"),
                      size_bytes=1, risk=RiskLevel.LOW, reversible=False,
                      evidence=Evidence("m", "o", "r"))
    fake_result = ScanResult(started_at=datetime.now(timezone.utc),
                             finished_at=datetime.now(timezone.utc),
                             outcomes=[RuleOutcome(rule_id="user-temp",
                                                   findings=[finding])])

    import polyscour.cleaning.scanner as scanner_module
    monkeypatch.setattr(scanner_module.Scanner, "scan",
                        lambda self, rules, cancel: fake_result)

    executed_plans = []

    class _FakeExecutor:
        def __init__(self, *a, **k):
            self.allow_elevation = k.get("allow_elevation", False)

        def execute(self, plan, cancel):
            executed_plans.append((plan, self.allow_elevation))
            from polyscour.contracts import ActionResult, OperationOutcome
            return ActionResult(operation_id="op1",
                                outcome=OperationOutcome.SUCCESS,
                                started_at=datetime.now(timezone.utc),
                                finished_at=datetime.now(timezone.utc),
                                items_completed=1, bytes_freed=1)

    import polyscour.scheduling.runner as runner_module
    monkeypatch.setattr(
        "polyscour.cleaning.executor.Executor", _FakeExecutor)

    assert runner.run("s1") == 0
    assert len(executed_plans) == 1
    plan, allow_elevation = executed_plans[0]
    assert plan.dry_run is False
    assert allow_elevation is False    # never even asked to allow it


def test_nothing_found_is_a_clean_no_op_without_executing(
        no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get", lambda sid: _schedule())
    monkeypatch.setattr(task, "verify", lambda sid: (True, ""))

    from polyscour.scheduling import consent as consent_module
    monkeypatch.setattr(consent_module, "verify",
                        lambda s: VerifyResult(("user-temp",), {}))

    from polyscour.contracts import ScanResult
    from datetime import datetime, timezone
    empty_result = ScanResult(started_at=datetime.now(timezone.utc),
                              finished_at=datetime.now(timezone.utc))

    import polyscour.cleaning.scanner as scanner_module
    monkeypatch.setattr(scanner_module.Scanner, "scan",
                        lambda self, rules, cancel: empty_result)

    executed = []
    monkeypatch.setattr("polyscour.cleaning.executor.Executor.execute",
                        lambda self, plan, cancel: executed.append(plan))

    assert runner.run("s1") == 0
    assert executed == []


def test_main_catches_any_unhandled_exception(no_data_dir, monkeypatch):
    monkeypatch.setattr(store, "get",
                        lambda sid: (_ for _ in ()).throw(RuntimeError("boom")))
    assert runner.main(["s1"]) == 1


def test_main_requires_a_schedule_id():
    assert runner.main([]) == 2
