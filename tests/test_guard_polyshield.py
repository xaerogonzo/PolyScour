r"""What PolyShield's answer is allowed to change: only ever *less*.

A recorded detection at a path makes the guard leave it alone. Everything else
-- no PolyShield, a refusal, "no recorded detection" -- changes nothing, and no
answer of any kind can make PolyScour act on more than it could before. The
last of those is tested, not argued: it is the property that lets the elevated
helper ask at all.
"""
from __future__ import annotations

import os
import threading
import time

import pytest

from polyscour import paths
from polyscour.cleaning import rules as rules_module
from polyscour.cleaning.executor import Executor, _skips_from
from polyscour.cleaning.planner import plan
from polyscour.cleaning.scanner import Scanner
from polyscour.contracts import (Evidence, Finding, OperationOutcome, RiskLevel,
                                 SkipReason, classify, Skip)
from polyscour.elevation import helper
from polyscour.elevation.protocol import Operation, Request
from polyscour.integrations import polyshield
from polyscour.integrations.polyshield import PathAdvisor, PathStatus, UNKNOWN_PATH
from polyscour.ledger import Ledger
from polyscour.safety.guard import Guard, GuardRefusal, PolyShieldFlagged
from polyscour.vault import Vault

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


class Ask:
    """A scripted PolyShield: which paths have a detection at or beneath them."""

    def __init__(self, detections=(), *, down=False):
        self.detections = [os.path.normcase(str(d)) for d in detections]
        self.down = down
        self.calls: list[str] = []

    def __call__(self, path: str):
        self.calls.append(path)
        if self.down:
            return None
        norm = os.path.normcase(path)
        flagged = any(d == norm or d.startswith(norm.rstrip("\\") + "\\")
                      for d in self.detections)
        return PathStatus(False, flagged)


@pytest.fixture
def temp_root(monkeypatch, tmp_path):
    root = tmp_path / "temp"
    root.mkdir()
    monkeypatch.setenv("TEMP", str(root))
    return root.resolve()


def advisor_for(*detections, down=False):
    ask = Ask(detections, down=down)
    return PathAdvisor(ask), ask


def user_temp_rule():
    return rules_module.load_file(paths.rules_dir() / "user-temp.json")


def make(directory, names):
    """Files old enough to be candidates: ``user-temp`` ignores anything
    younger than a day, so a freshly written file would never be scanned."""
    old = time.time() - 3 * 86400
    out = []
    for n in names:
        f = directory / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x" * 5, encoding="utf-8")
        os.utime(f, (old, old))
        out.append(f)
    return out


def finding(path):
    return Finding(rule_id="user-temp", title="t", path=path,
                   size_bytes=path.stat().st_size if path.exists() else 0,
                   risk=RiskLevel.LOW, reversible=False,
                   evidence=Evidence("m", "o", "r"))


def executor(tmp_path, guard):
    return Executor(vault=Vault(tmp_path / "vault"),
                    ledger=Ledger(tmp_path / "history.sqlite"), guard=guard)


# ══ the guard link ════════════════════════════════════════════════════════════

def test_a_bare_guard_never_asks_anyone(temp_root, monkeypatch):
    """Default off: every existing ``Guard()`` stays hermetic."""
    monkeypatch.setattr(polyshield, "_ask_path",
                        lambda p: pytest.fail("a Guard with no advisor asked"))
    [f] = make(temp_root, ["a.tmp"])

    guard = Guard()
    guard.begin()
    assert guard.authorize("user-temp", f, _delete()) == f


def _delete():
    from polyscour.safety.policy import Operation as PolicyOperation
    return PolicyOperation.DELETE


def test_a_recorded_detection_makes_the_guard_leave_it_alone(temp_root):
    [bad] = make(temp_root, ["evil.exe"])
    advisor, _ = advisor_for(bad)
    guard = Guard(advisor=advisor)
    guard.begin()

    with pytest.raises(PolyShieldFlagged) as caught:
        guard.authorize("user-temp", bad, _delete())

    assert isinstance(caught.value, GuardRefusal)    # refuses even if unknown
    assert str(bad) in str(caught.value)


def test_a_clean_answer_changes_nothing(temp_root):
    [f] = make(temp_root, ["fine.tmp"])
    advisor, _ = advisor_for()                       # no detections anywhere
    guard = Guard(advisor=advisor)
    guard.begin()
    assert guard.authorize("user-temp", f, _delete()) == f


def test_silence_changes_nothing(temp_root):
    """UNKNOWN proceeds. An optional integration that could stop the cleaner
    would no longer be optional."""
    [f] = make(temp_root, ["fine.tmp"])
    advisor, _ = advisor_for(down=True)
    guard = Guard(advisor=advisor)
    guard.begin()
    assert guard.authorize("user-temp", f, _delete()) == f


def test_a_refusal_from_polyshield_changes_nothing(temp_root):
    [f] = make(temp_root, ["fine.tmp"])
    guard = Guard(advisor=PathAdvisor(lambda p: UNKNOWN_PATH))
    guard.begin()
    assert guard.authorize("user-temp", f, _delete()) == f


def test_the_advisor_is_the_last_link_and_is_not_asked_about_refused_paths(
        temp_root, tmp_path):
    """A path outside the permitted root is refused by containment, and there
    is no reason to tell PolyShield about a path PolyScour was never going to
    touch."""
    outsider = tmp_path / "elsewhere.txt"
    outsider.write_text("mine", encoding="utf-8")
    advisor, ask = advisor_for()
    guard = Guard(advisor=advisor)
    guard.begin()

    with pytest.raises(GuardRefusal) as caught:
        guard.authorize("user-temp", outsider, _delete())

    assert not isinstance(caught.value, PolyShieldFlagged)
    assert ask.calls == []


def test_begin_gives_the_advisor_a_fresh_operation(temp_root):
    [f] = make(temp_root, ["a.tmp"])
    advisor, ask = advisor_for()
    guard = Guard(advisor=advisor)
    guard.begin()
    guard.authorize("user-temp", f, _delete())
    assert advisor.queries == 1

    guard.begin()

    assert advisor.queries == 0


# ══ cannot widen ══════════════════════════════════════════════════════════════

def test_no_answer_can_make_the_guard_permit_more(temp_root, tmp_path):
    """The property that makes it safe for the elevated helper to ask.

    An advisor that claims *everything* is clean -- what an impostor on the
    port would say -- must not let the guard accept a path it refused anyway.
    The advisor is consulted after every other link has said yes, and may only
    take that back.
    """
    outsider = tmp_path / "elsewhere.txt"
    outsider.write_text("mine", encoding="utf-8")
    liar = Guard(advisor=PathAdvisor(lambda p: PathStatus(True, False)))
    liar.begin()

    with pytest.raises(GuardRefusal):
        liar.authorize("user-temp", outsider, _delete())


# ══ the scanner: withheld, counted, cheap ═════════════════════════════════════

def scan(guard):
    return Scanner(guard=guard).scan([user_temp_rule()], threading.Event())


def test_a_flagged_file_is_never_offered_but_is_counted(temp_root):
    files = make(temp_root, [f"f{i}.tmp" for i in range(20)])
    bad = files[7]
    advisor, _ = advisor_for(bad)

    result = scan(Guard(advisor=advisor))

    [outcome] = result.outcomes
    assert bad not in {f.path for f in result.findings}
    assert len(result.findings) == 19
    assert outcome.withheld_by_polyshield == 1
    assert outcome.skipped_paths == 0        # not folded into ordinary refusals


def test_without_polyshield_the_scan_is_exactly_what_it_was(temp_root):
    make(temp_root, [f"f{i}.tmp" for i in range(20)])
    advisor, ask = advisor_for(down=True)

    result = scan(Guard(advisor=advisor))

    assert len(result.findings) == 20
    assert result.outcomes[0].withheld_by_polyshield == 0
    assert len(ask.calls) == 1               # the latch: it stopped asking


def test_a_clean_tree_costs_one_question_not_one_per_file(temp_root):
    """The efficiency that makes the integration usable at all. 300 files in
    nested folders; PolyShield has nothing recorded under the root."""
    make(temp_root, [f"d{i % 6}/e{i % 4}/f{i}.tmp" for i in range(300)])
    advisor, ask = advisor_for()

    result = scan(Guard(advisor=advisor))

    assert len(result.findings) == 300
    assert advisor.queries == 1, ask.calls[:5]


def test_one_detection_costs_its_own_chain_not_the_whole_tree(temp_root):
    files = make(temp_root, [f"d{i % 6}/f{i}.tmp" for i in range(300)])
    bad = files[0]                                    # in d0
    advisor, ask = advisor_for(bad)

    result = scan(Guard(advisor=advisor))

    assert result.outcomes[0].withheld_by_polyshield == 1
    # root, d0, every file in d0 (50), and the other five directories:
    # nowhere near 300.
    assert advisor.queries < 70, advisor.queries
    assert len(result.findings) == 299


# ══ the executor: the second call is what makes a late detection count ═══════

def test_a_flagged_file_survives_a_real_run_and_the_run_reads_as_clean(
        temp_root, tmp_path):
    files = make(temp_root, [f"f{i}.tmp" for i in range(5)])
    bad = files[2]
    advisor, _ = advisor_for(bad)
    ex = executor(tmp_path, Guard(advisor=advisor))

    result = ex.execute(plan([finding(f) for f in files], dry_run=False))

    assert bad.exists()
    assert [f.exists() for f in files].count(False) == 4
    [skip] = result.skips
    assert skip.reason is SkipReason.FLAGGED_BY_POLYSHIELD
    assert skip.reason.is_benign
    assert result.hard_failures == []
    assert result.outcome is OperationOutcome.SUCCESS_WITH_SKIPS


def test_a_dry_run_reports_it_too_and_still_removes_nothing(temp_root, tmp_path):
    files = make(temp_root, ["a.tmp", "b.tmp"])
    advisor, _ = advisor_for(files[0])
    ex = executor(tmp_path, Guard(advisor=advisor))

    result = ex.execute(plan([finding(f) for f in files], dry_run=True))

    assert all(f.exists() for f in files)
    assert result.items_completed == 1
    assert result.skips[0].reason is SkipReason.FLAGGED_BY_POLYSHIELD


def test_a_detection_recorded_after_the_scan_still_protects_the_file(
        temp_root, tmp_path):
    """The guard is called twice on purpose. Between the scan and the delete
    PolyShield may record something; the delete asks afresh, because
    ``execute`` begins a new operation and so a new cache."""
    [f] = make(temp_root, ["late.exe"])
    ask = Ask()
    advisor = PathAdvisor(ask)
    guard = Guard(advisor=advisor)
    scanned = scan(guard)
    assert [x.path for x in scanned.findings] == [f]          # clean at scan time

    ask.detections.append(os.path.normcase(str(f)))            # ...then flagged
    result = executor(tmp_path, guard).execute(plan(scanned.findings, dry_run=False))

    assert f.exists()
    assert result.skips[0].reason is SkipReason.FLAGGED_BY_POLYSHIELD


def test_negative_control_without_the_advisor_the_same_file_is_deleted(
        temp_root, tmp_path):
    """Proves the tests above can fail: remove the link and the file goes."""
    files = make(temp_root, ["a.tmp", "evil.exe"])
    ex = executor(tmp_path, Guard())                           # no advisor

    ex.execute(plan([finding(f) for f in files], dry_run=False))

    assert not files[1].exists()


def test_a_benign_flagged_skip_is_not_a_failure():
    skips = [Skip(__import__("pathlib").Path("x"), SkipReason.FLAGGED_BY_POLYSHIELD, "d", "r")]
    assert classify(1, 0, skips) is OperationOutcome.SUCCESS_WITH_SKIPS


# ══ the elevated helper ═══════════════════════════════════════════════════════

def batch(rule_id="user-temp"):
    return helper.handle(Request(
        operation=Operation.DELETE_APPROVED_PATHS_FOR_RULE,
        params={"rule_id": rule_id, "exclusions": []}))


def test_the_helper_leaves_a_flagged_file_alone_and_says_why(
        temp_root, monkeypatch):
    files = make(temp_root, ["a.tmp", "b.tmp", "evil.exe"])
    advisor, _ = advisor_for(files[2])
    monkeypatch.setattr(helper, "PathAdvisor", lambda: advisor)

    response = batch()

    assert response.ok is True
    assert files[2].exists()
    assert not files[0].exists() and not files[1].exists()
    assert response.data["deleted"] == 2
    assert response.data["skip_counts"] == {"flagged_by_polyshield": 1}


def test_the_helpers_report_round_trips_as_a_benign_skip(temp_root, monkeypatch):
    """``_skips_from`` turns an unknown reason into ERROR, which is *not* benign
    -- so a flagged skip crossing the process boundary would have turned a
    clean run into a failed one if the enum did not know the word."""
    files = make(temp_root, ["evil.exe"])
    advisor, _ = advisor_for(files[0])
    monkeypatch.setattr(helper, "PathAdvisor", lambda: advisor)

    skips = _skips_from(batch().data)

    assert [s.reason for s in skips] == [SkipReason.FLAGGED_BY_POLYSHIELD]
    assert all(s.reason.is_benign for s in skips)


def test_the_helper_with_no_polyshield_deletes_exactly_what_it_did_before(
        temp_root, monkeypatch):
    files = make(temp_root, ["a.tmp", "b.tmp"])
    advisor, _ = advisor_for(down=True)
    monkeypatch.setattr(helper, "PathAdvisor", lambda: advisor)

    response = batch()

    assert response.data["deleted"] == 2
    assert response.data["skip_counts"] == {}


def test_the_single_path_operation_asks_too(temp_root, monkeypatch):
    [bad] = make(temp_root, ["evil.exe"])
    advisor, _ = advisor_for(bad)
    monkeypatch.setattr(helper, "PathAdvisor", lambda: advisor)

    response = helper.handle(Request(
        operation=Operation.DELETE_APPROVED_PATH,
        params={"rule_id": "user-temp", "path": str(bad)}))

    assert response.ok is False and response.refused_by == "guard"
    assert bad.exists()


# ══ the switch reaches everything that runs as the user ═══════════════════════

def test_the_app_wires_one_switch_into_both_of_its_advisors(monkeypatch, tmp_path):
    from polyscour import app as app_module

    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path / "data"))
    services = app_module.Services()

    assert services.guard._advisor._enabled is app_module._path_checks_on
    assert services.annotator._enabled is app_module._path_checks_on


@pytest.mark.parametrize("setting", [True, False])
def test_the_apps_guard_follows_the_setting(monkeypatch, tmp_path, temp_root, setting):
    """Real ``Services``, real setting, a PolyShield that flags everything."""
    from polyscour import app as app_module

    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(app_module.cfg, "get",
                        lambda key, *a: setting if key == "polyshield_path_checks" else [])
    monkeypatch.setattr(polyshield, "_ask_path", lambda p: PathStatus(False, True))
    [f] = make(temp_root, ["a.tmp"])

    guard = app_module.Services().guard
    guard.begin()
    if setting:
        with pytest.raises(PolyShieldFlagged):
            guard.authorize("user-temp", f, _delete())
    else:
        assert guard.authorize("user-temp", f, _delete()) == f


def test_the_scheduled_runner_builds_its_guard_with_the_same_switch(monkeypatch, tmp_path):
    import polyscour.safety.guard as guard_module
    from polyscour import settings as cfg
    from polyscour.scheduling import consent, runner, store, task
    from polyscour.scheduling.consent import Frequency, Schedule, Trigger, VerifyResult

    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path))
    sched = Schedule(id="s1", enabled=True, trigger=Trigger(Frequency.DAILY, "03:00"),
                     rule_ids=("user-temp",), rule_definition_hashes={"user-temp": "a"},
                     policy_version=1, maximum_risk=RiskLevel.LOW,
                     elevation_allowed=False, created_by_user=True,
                     created_at="2026-01-01T00:00:00+00:00", task_name="x")
    monkeypatch.setattr(store, "get", lambda sid: sched)
    monkeypatch.setattr(task, "verify", lambda sid: (True, ""))
    monkeypatch.setattr(consent, "verify", lambda s: VerifyResult(("user-temp",), {}))

    built = []
    real_guard = guard_module.Guard
    monkeypatch.setattr(guard_module, "Guard",
                        lambda **kw: built.append(kw) or real_guard(**kw))
    from polyscour.cleaning import scanner as scanner_module
    from polyscour.contracts import ScanResult
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(scanner_module.Scanner, "scan",
                        lambda self, rules, cancel: ScanResult(now, now))

    runner.run("s1")

    gate = built[0]["advisor"]._enabled
    monkeypatch.setattr(cfg, "get", lambda key, *a: False)
    assert gate() is False
    monkeypatch.setattr(cfg, "get", lambda key, *a: True)
    assert gate() is True
