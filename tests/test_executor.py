r"""The only code that removes anything. Tested accordingly.

The two properties that would be worst to get wrong, and are easiest to break
later by accident:

* a dry run must write **nothing** -- asserted by snapshotting the tree, not by
  trusting a flag
* nothing is **forced** -- a locked or read-only file is skipped and survives,
  and no code path exists that would clear the way
"""
from __future__ import annotations

import os
import stat
import subprocess
import threading

import pytest

from polyscour.cleaning.executor import Executor
from polyscour.cleaning.planner import plan
from polyscour.contracts import (
    Evidence,
    Finding,
    OperationOutcome,
    RiskLevel,
    Skip,
    SkipReason,
    classify,
)
from polyscour.ledger import Ledger
from polyscour.safety.guard import Guard
from polyscour.vault import Vault

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def temp_root(monkeypatch, tmp_path):
    root = tmp_path / "temp"
    root.mkdir()
    monkeypatch.setenv("TEMP", str(root))
    return root.resolve()


@pytest.fixture
def dumps_root(monkeypatch, tmp_path):
    """The CRASH_DUMPS family -- the one reversible rule in 0.1."""
    local = tmp_path / "local"
    root = local / "CrashDumps"
    root.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    return root.resolve()


@pytest.fixture
def executor(tmp_path):
    return Executor(vault=Vault(tmp_path / "vault"),
                    ledger=Ledger(tmp_path / "history.sqlite"),
                    guard=Guard())


def finding(path, rule_id="user-temp", risk=RiskLevel.LOW, reversible=False):
    return Finding(rule_id=rule_id, title="t", path=path,
                   size_bytes=path.stat().st_size if path.exists() else 0,
                   risk=risk, reversible=reversible,
                   evidence=Evidence("m", "o", "r"))


def snapshot(root):
    return {p.relative_to(root): p.stat().st_size
            for p in root.rglob("*") if p.is_file()}


# ══ Dry run ═══════════════════════════════════════════════════════════════════

def test_a_dry_run_writes_nothing(executor, temp_root):
    """Asserted by comparing the tree before and after, not by trusting a flag."""
    for n in range(5):
        (temp_root / f"f{n}.tmp").write_text("x" * (n + 1), encoding="utf-8")
    before = snapshot(temp_root)

    result = executor.execute(plan([finding(p) for p in temp_root.iterdir()],
                                   dry_run=True))

    assert snapshot(temp_root) == before
    assert result.dry_run is True
    assert result.items_completed == 5
    assert result.outcome is OperationOutcome.SUCCESS


def test_a_dry_run_reports_what_would_be_freed(executor, temp_root):
    (temp_root / "a.tmp").write_text("12345", encoding="utf-8")
    result = executor.execute(plan([finding(temp_root / "a.tmp")], dry_run=True))
    assert result.bytes_freed == 5
    assert "would be removed" in result.summary()


def test_a_dry_run_still_runs_the_guard(executor, temp_root, tmp_path):
    """The point of a rehearsal is to find out what would happen, including
    which items the guard would refuse."""
    outsider = tmp_path / "elsewhere.txt"
    outsider.write_text("mine", encoding="utf-8")

    result = executor.execute(plan([finding(outsider)], dry_run=True))

    assert result.items_completed == 0
    assert result.skips[0].reason is SkipReason.REFUSED_BY_GUARD


# ══ Deleting ══════════════════════════════════════════════════════════════════

def test_a_real_run_removes_the_file(executor, temp_root):
    victim = temp_root / "a.tmp"
    victim.write_text("junk", encoding="utf-8")

    result = executor.execute(plan([finding(victim)], dry_run=False))

    assert not victim.exists()
    assert result.outcome is OperationOutcome.SUCCESS
    assert result.bytes_freed == 4


def test_the_bytes_reported_match_the_bytes_removed(executor, temp_root):
    sizes = [10, 200, 3000]
    for i, s in enumerate(sizes):
        (temp_root / f"f{i}.tmp").write_text("x" * s, encoding="utf-8")

    result = executor.execute(plan([finding(p) for p in temp_root.iterdir()],
                                   dry_run=False))

    assert result.bytes_freed == sum(sizes)


# ══ Nothing is forced ═════════════════════════════════════════════════════════

def test_a_locked_file_is_skipped_and_survives(executor, temp_root):
    """A browser or an antivirus holding a handle is the normal case on a live
    machine, not an obstacle to overcome."""
    victim = temp_root / "locked.tmp"
    victim.write_text("in use", encoding="utf-8")

    with victim.open("r", encoding="utf-8"):
        result = executor.execute(plan([finding(victim)], dry_run=False))

    assert victim.exists(), "a locked file must survive"
    assert result.outcome is OperationOutcome.SUCCESS_WITH_SKIPS
    assert result.skips[0].reason is SkipReason.LOCKED
    assert result.skips[0].reason.is_benign


def test_a_read_only_file_is_skipped_rather_than_cleared(executor, temp_root):
    """Clearing the read-only bit to get past this would be forcing."""
    victim = temp_root / "ro.tmp"
    victim.write_text("protected", encoding="utf-8")
    os.chmod(victim, stat.S_IREAD)
    try:
        result = executor.execute(plan([finding(victim)], dry_run=False))
        assert victim.exists()
        assert result.skips[0].reason is SkipReason.PERMISSION
    finally:
        os.chmod(victim, stat.S_IWRITE)


def test_one_locked_file_does_not_stop_the_others(executor, temp_root):
    locked = temp_root / "locked.tmp"
    locked.write_text("in use", encoding="utf-8")
    for n in range(3):
        (temp_root / f"free{n}.tmp").write_text("junk", encoding="utf-8")

    findings = [finding(p) for p in sorted(temp_root.iterdir())]
    with locked.open("r", encoding="utf-8"):
        result = executor.execute(plan(findings, dry_run=False))

    assert result.items_completed == 3
    assert locked.exists()


def test_a_file_that_vanished_is_benign(executor, temp_root):
    victim = temp_root / "a.tmp"
    victim.write_text("junk", encoding="utf-8")
    f = finding(victim)
    victim.unlink()

    result = executor.execute(plan([f], dry_run=False))

    # Not FAILED: nothing was achieved, but nothing went wrong either.
    assert result.outcome is OperationOutcome.SUCCESS_WITH_SKIPS
    assert result.items_completed == 0
    assert result.skips[0].reason is SkipReason.VANISHED
    assert result.skips[0].reason.is_benign


# ══ TOCTOU ════════════════════════════════════════════════════════════════════

def test_a_junction_planted_after_the_scan_is_refused_at_execution(
        executor, temp_root, tmp_path):
    """The race the second guard call exists to lose.

    The scan approved a real directory; between then and now another process
    replaced it with a junction pointing somewhere valuable.
    """
    real = temp_root / "cache"
    real.mkdir()
    victim = real / "a.tmp"
    victim.write_text("junk", encoding="utf-8")
    f = finding(victim)

    # ... time passes, and something swaps the directory out from under us.
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "a.tmp").write_text("years of work", encoding="utf-8")
    victim.unlink()
    real.rmdir()
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(real), str(precious)],
                          capture_output=True, text=True)
    if made.returncode != 0:
        pytest.skip("could not create a junction on this machine")

    result = executor.execute(plan([f], dry_run=False))

    assert (precious / "a.tmp").read_text(encoding="utf-8") == "years of work"
    assert result.skips[0].reason is SkipReason.REFUSED_BY_GUARD
    assert not result.skips[0].reason.is_benign, \
        "a guard refusal is a bug or an attack, never a routine skip"


def test_a_guard_refusal_degrades_the_outcome(executor, temp_root, tmp_path):
    good = temp_root / "a.tmp"
    good.write_text("junk", encoding="utf-8")
    outsider = tmp_path / "elsewhere.txt"
    outsider.write_text("mine", encoding="utf-8")

    result = executor.execute(
        plan([finding(good), finding(outsider)], dry_run=False))

    assert result.outcome is OperationOutcome.PARTIALLY_COMPLETED
    assert outsider.exists()


# ══ The vault path ════════════════════════════════════════════════════════════

def test_a_vaulted_rule_stores_before_it_removes(executor, dumps_root):
    dump = dumps_root / "crash.dmp"
    dump.write_text("stack trace", encoding="utf-8")

    result = executor.execute(
        plan([finding(dump, rule_id="crash-dumps", risk=RiskLevel.MODERATE,
                      reversible=True)], dry_run=False))

    assert not dump.exists()
    assert result.outcome is OperationOutcome.SUCCESS
    assert len(result.reversals) == 1
    assert result.reversals[0].possible


def test_a_vaulted_operation_can_be_undone(executor, dumps_root):
    """The whole point of the reversible branch, end to end."""
    dump = dumps_root / "crash.dmp"
    dump.write_text("stack trace", encoding="utf-8")

    result = executor.execute(
        plan([finding(dump, rule_id="crash-dumps", risk=RiskLevel.MODERATE,
                      reversible=True)], dry_run=False))
    assert not dump.exists()

    notes = executor.restore(result.operation_id)

    assert dump.exists()
    assert dump.read_text(encoding="utf-8") == "stack trace"
    assert notes == ["crash.dmp: restored"]


def test_a_deleted_rule_records_no_reversal(executor, temp_root):
    """user-temp deletes outright. The UI must not offer an undo that would
    fail."""
    victim = temp_root / "a.tmp"
    victim.write_text("junk", encoding="utf-8")

    result = executor.execute(plan([finding(victim)], dry_run=False))

    assert result.reversals == []


# ══ Cancellation ══════════════════════════════════════════════════════════════

def test_cancelling_leaves_completed_items_completed(executor, temp_root):
    for n in range(5):
        (temp_root / f"f{n}.tmp").write_text("junk", encoding="utf-8")
    findings = [finding(p) for p in sorted(temp_root.iterdir())]

    cancel = threading.Event()
    cancel.set()                       # cancelled before the first item

    result = executor.execute(plan(findings, dry_run=False), cancel=cancel)

    assert result.outcome is OperationOutcome.CANCELLED
    assert result.items_completed == 0
    assert len(list(temp_root.iterdir())) == 5


def test_a_cancelled_vault_run_writes_no_partial_manifest(executor, dumps_root):
    """A manifest is written once at the end, so a cancellation leaves either a
    complete one or none -- never a half-written one a restore would trust."""
    dump = dumps_root / "crash.dmp"
    dump.write_text("stack", encoding="utf-8")
    f = finding(dump, rule_id="crash-dumps", risk=RiskLevel.MODERATE,
                reversible=True)

    cancel = threading.Event()
    cancel.set()
    result = executor.execute(plan([f], dry_run=False), cancel=cancel)

    assert executor.vault.manifest(result.operation_id) is None
    assert dump.exists()


# ══ The outcome taxonomy ══════════════════════════════════════════════════════

def test_a_clean_run_is_success():
    assert classify(3, 3, []) is OperationOutcome.SUCCESS


def test_benign_skips_do_not_make_a_run_a_failure(tmp_path):
    """100 planned / 93 deleted / 7 locked is SUCCESS_WITH_SKIPS. Collapsing
    that into FAILED would train users to ignore the result."""
    skips = [Skip(tmp_path / "x", SkipReason.LOCKED)] * 7
    assert classify(100, 93, skips) is OperationOutcome.SUCCESS_WITH_SKIPS


def test_an_unexpected_failure_degrades_the_outcome(tmp_path):
    skips = [Skip(tmp_path / "x", SkipReason.ERROR, "who knows")]
    assert classify(10, 9, skips) is OperationOutcome.PARTIALLY_COMPLETED


def test_achieving_nothing_is_not_by_itself_a_failure(tmp_path):
    """The one file you selected being open in a browser is not a fault, and
    reporting it as one sends the user looking for a problem that is not there."""
    skips = [Skip(tmp_path / "x", SkipReason.LOCKED)]
    assert classify(1, 0, skips) is OperationOutcome.SUCCESS_WITH_SKIPS


def test_going_wrong_and_achieving_nothing_is_a_failure(tmp_path):
    """FAILED is reserved for exactly this: something broke, and no part of the
    plan was carried out."""
    skips = [Skip(tmp_path / "x", SkipReason.REFUSED_BY_GUARD, "junction")]
    assert classify(1, 0, skips) is OperationOutcome.FAILED


def test_an_empty_plan_is_not_a_failure():
    assert classify(0, 0, []) is OperationOutcome.SUCCESS


def test_cancellation_outranks_everything(tmp_path):
    skips = [Skip(tmp_path / "x", SkipReason.ERROR)]
    assert classify(10, 2, skips, cancelled=True) is OperationOutcome.CANCELLED


@pytest.mark.parametrize("outcome,clean", [
    (OperationOutcome.SUCCESS, True),
    (OperationOutcome.SUCCESS_WITH_SKIPS, True),
    (OperationOutcome.PARTIALLY_COMPLETED, False),
    (OperationOutcome.FAILED, False),
    (OperationOutcome.CANCELLED, False),
])
def test_is_clean_matches_the_taxonomy(outcome, clean):
    assert outcome.is_clean is clean


# ══ The ledger ════════════════════════════════════════════════════════════════

def test_every_run_is_recorded(executor, temp_root):
    (temp_root / "a.tmp").write_text("junk", encoding="utf-8")
    result = executor.execute(plan([finding(temp_root / "a.tmp")], dry_run=False))

    rows = executor.ledger.history()

    assert len(rows) == 1
    assert rows[0]["operation_id"] == result.operation_id
    assert rows[0]["dry_run"] == 0


def test_a_dry_run_is_recorded_as_a_rehearsal(executor, temp_root):
    """"What would this have done" is worth answering later, and the History
    view must never present a rehearsal as a change."""
    (temp_root / "a.tmp").write_text("junk", encoding="utf-8")
    executor.execute(plan([finding(temp_root / "a.tmp")], dry_run=True))

    assert executor.ledger.history()[0]["dry_run"] == 1
    assert executor.ledger.totals()["bytes_freed"] == 0


def test_only_vaulted_operations_appear_as_undoable(executor, temp_root, dumps_root):
    (temp_root / "a.tmp").write_text("junk", encoding="utf-8")
    executor.execute(plan([finding(temp_root / "a.tmp")], dry_run=False))

    dump = dumps_root / "crash.dmp"
    dump.write_text("stack", encoding="utf-8")
    vaulted = executor.execute(
        plan([finding(dump, rule_id="crash-dumps", risk=RiskLevel.MODERATE,
                      reversible=True)], dry_run=False))

    undoable = executor.ledger.undoable()

    assert [r["operation_id"] for r in undoable] == [vaulted.operation_id]


def test_a_restored_operation_stops_being_undoable(executor, dumps_root):
    dump = dumps_root / "crash.dmp"
    dump.write_text("stack", encoding="utf-8")
    result = executor.execute(
        plan([finding(dump, rule_id="crash-dumps", risk=RiskLevel.MODERATE,
                      reversible=True)], dry_run=False))
    assert executor.ledger.undoable()

    executor.restore(result.operation_id)

    assert executor.ledger.undoable() == []
