r"""tests/test_elevation.py — what the helper refuses.

The threat model (docs/THREAT_MODEL.md, "The elevated helper") was written
before any of this code. These tests are that specification turned into
assertions, and the ones that matter are all refusals: a helper that performs
its operations correctly but can be talked into performing them on the wrong
target is worse than no helper, because it is a privilege-escalation tool with
a maintenance UI.

**The load-bearing property: the helper does not believe its caller.** Every
request arrives in a file the unelevated user can write, so it is
attacker-controlled by construction. The tests below hand it exactly the
requests an attacker would.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from polyscour.elevation import helper
from polyscour.elevation.protocol import (MalformedRequest, Operation, Request,
                                          Response)

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="the helper is Windows-only")


def req(operation=Operation.DELETE_APPROVED_PATH, **params):
    return Request(operation=operation, params=params)


# ── the protocol refuses shapes it does not define ──────────────────────────

def test_a_known_operation_with_the_right_parameters_parses():
    """The control: without it every refusal below could be a blanket no."""
    parsed = Request.from_json(json.dumps({
        "operation": "delete_approved_path",
        "params": {"rule_id": "windows-temp", "path": r"C:\Windows\Temp\a.tmp"}}))
    assert parsed.operation is Operation.DELETE_APPROVED_PATH


def test_an_unknown_operation_is_refused():
    """The closed set is the design. An operation nobody reviewed cannot run."""
    with pytest.raises(MalformedRequest, match="unknown operation"):
        Request.from_json(json.dumps({"operation": "run_powershell",
                                      "params": {"script": "whoami"}}))


def test_an_extra_parameter_is_refused_not_ignored():
    """Ignoring the overlap is how a request gets interpreted as something it
    is not: the sender and the helper would disagree and both proceed."""
    with pytest.raises(MalformedRequest, match="unexpected parameter"):
        Request.from_json(json.dumps({
            "operation": "delete_approved_path",
            "params": {"rule_id": "windows-temp", "path": "x", "force": True}}))


def test_a_missing_parameter_is_refused():
    with pytest.raises(MalformedRequest, match="missing parameter"):
        Request.from_json(json.dumps({"operation": "delete_approved_path",
                                      "params": {"rule_id": "windows-temp"}}))


def test_a_wrongly_typed_parameter_is_refused_rather_than_coerced():
    """Coercion is how "1" becomes True and a refusal becomes an approval."""
    with pytest.raises(MalformedRequest, match="must be a boolean"):
        Request.from_json(json.dumps({
            "operation": "set_machine_startup_approval",
            "params": {"value_name": "Thing", "enabled": 1}}))


def test_an_empty_string_parameter_is_refused():
    with pytest.raises(MalformedRequest, match="must not be empty"):
        Request.from_json(json.dumps({
            "operation": "delete_approved_path",
            "params": {"rule_id": "windows-temp", "path": "   "}}))


def test_the_operation_set_is_small_and_named():
    """A guard on the design itself. If this list grows, someone reviewed it;
    if it grows to include something generic, this test is where to argue."""
    assert {o.value for o in Operation} == {
        "delete_approved_path", "set_machine_startup_approval"}
    assert not any("command" in o.value or "script" in o.value
                   or "exec" in o.value for o in Operation), \
        "a generic operation defeats the closed set"


# ── the helper re-authorises, at privilege ──────────────────────────────────

def test_a_path_outside_the_rules_roots_is_refused_by_the_guard(tmp_path):
    """The request is well-formed and the rule is real. It is still refused,
    because the path is not somewhere that rule may touch."""
    victim = tmp_path / "important.txt"
    victim.write_text("keep me", encoding="utf-8")

    response = helper.handle(req(rule_id="windows-temp", path=str(victim)))

    assert response.ok is False
    assert response.refused_by == "guard"
    assert victim.exists(), "the helper deleted a file outside the rule's roots"


def test_an_unknown_rule_id_is_refused(tmp_path):
    """The rule id narrows what is allowed; it never grants anything. A rule
    with no reviewed policy entry cannot be used to reach anywhere."""
    victim = tmp_path / "important.txt"
    victim.write_text("keep me", encoding="utf-8")

    response = helper.handle(req(rule_id="not-a-real-rule", path=str(victim)))

    assert response.ok is False
    assert response.refused_by == "guard"
    assert victim.exists()


def test_a_windows_directory_is_refused(tmp_path):
    """The denylist, reached through the same chain the unelevated app uses."""
    response = helper.handle(req(rule_id="windows-temp",
                                 path=r"C:\Windows\System32\kernel32.dll"))
    assert response.ok is False
    assert response.refused_by == "guard"


def test_the_helper_refuses_directories_outright(tmp_path, monkeypatch):
    """A recursive delete at administrator privilege, driven by a path from an
    untrusted caller, is the most dangerous thing this could offer — and
    nothing needs it, because the executor sends individual files."""
    a_dir = tmp_path / "somewhere"
    a_dir.mkdir()

    # Approve it at the guard so the *directory* rule is what refuses, not
    # containment. This isolates the property under test.
    monkeypatch.setattr(helper.Guard, "authorize",
                        lambda self, rule_id, target, op: a_dir)

    response = helper.handle(req(rule_id="windows-temp", path=str(a_dir)))

    assert response.ok is False
    assert response.refused_by == "helper"
    assert "directories" in response.detail
    assert a_dir.exists()


def test_an_approved_file_is_actually_deleted(tmp_path, monkeypatch):
    """The control for the refusals above: with the guard satisfied, the
    operation does happen. Without this they could all pass against a helper
    that does nothing at all."""
    doomed = tmp_path / "cache.tmp"
    doomed.write_text("junk", encoding="utf-8")
    monkeypatch.setattr(helper.Guard, "authorize",
                        lambda self, rule_id, target, op: doomed)

    response = helper.handle(req(rule_id="windows-temp", path=str(doomed)))

    assert response.ok is True
    assert not doomed.exists()


def test_an_already_absent_file_is_success_not_failure(tmp_path, monkeypatch):
    """It is the outcome the caller wanted. Reporting failure would make a
    successful clean look broken."""
    gone = tmp_path / "gone.tmp"
    monkeypatch.setattr(helper.Guard, "authorize",
                        lambda self, rule_id, target, op: gone)

    response = helper.handle(req(rule_id="windows-temp", path=str(gone)))
    assert response.ok is True
    assert "absent" in response.detail


# ── the machine-startup operation ───────────────────────────────────────────

def test_a_startup_name_with_no_machine_entry_is_refused():
    """Refuses to *create* an approval record. Writing one for a name with no
    matching Run value produces the orphan records that already litter real
    machines — and at administrator privilege, on a caller-supplied name, it
    would let a compromised GUI write arbitrary values into a machine key."""
    response = helper.handle(req(
        operation=Operation.SET_MACHINE_STARTUP_APPROVAL,
        value_name="NoSuchEntryPolyScourTest", enabled=False))

    assert response.ok is False
    assert response.refused_by == "policy"


# ── main(): reading a request, answering beside it ──────────────────────────

def test_main_writes_a_response_next_to_the_request(tmp_path):
    request_path = tmp_path / "request.json"
    request_path.write_text(req(rule_id="windows-temp",
                                path=str(tmp_path / "x.tmp")).to_json(),
                            encoding="utf-8")

    code = helper.main([str(request_path)])

    response_path = tmp_path / "request.json.response"
    assert response_path.exists(), "a caller with no response cannot report"
    assert code == 1                      # refused by the guard, as it should be
    assert Response.from_json(response_path.read_text()).ok is False


def test_main_answers_a_malformed_request_rather_than_crashing(tmp_path):
    """A crash leaves the caller with nothing to read and no way to tell a
    refusal from a failure."""
    request_path = tmp_path / "request.json"
    request_path.write_text("{not json", encoding="utf-8")

    helper.main([str(request_path)])

    response = Response.from_json(
        (tmp_path / "request.json.response").read_text())
    assert response.ok is False
    assert response.refused_by == "protocol"


def test_an_unreadable_response_reads_as_failure():
    """The client cannot distinguish "refused" from "crashed before writing",
    and must not try: both mean the privileged work did not verifiably happen."""
    assert Response.from_json("garbage").ok is False


# ── the executor asks only when it has been told it may ─────────────────────

def _one_file_plan(tmp_path):
    """A plan whose single finding lives inside %TEMP%, so the guard approves it
    and the delete is what fails rather than the authorisation."""
    import os
    from polyscour.contracts import ActionPlan, Evidence, Finding, RiskLevel

    root = Path(os.environ["TEMP"]) / "polyscour-elev-test"
    root.mkdir(parents=True, exist_ok=True)
    target = root / "locked.tmp"
    target.write_text("junk", encoding="utf-8")
    f = Finding(rule_id="user-temp", title="t", path=target,
                size_bytes=target.stat().st_size, risk=RiskLevel.LOW,
                reversible=False, evidence=Evidence("m", "o", "r"))
    return ActionPlan(findings=[f], dry_run=False), target


def _executor(tmp_path, **kw):
    from polyscour.cleaning.executor import Executor
    from polyscour.ledger import Ledger
    from polyscour.vault import Vault

    led = Ledger(tmp_path / "l.db")
    led.initialise()
    return Executor(vault=Vault(tmp_path / "v"), ledger=led, **kw)


def test_an_ordinary_executor_can_never_raise_a_uac_prompt(tmp_path, monkeypatch):
    """docs/THREAT_MODEL.md: elevation is never requested speculatively.

    Driven through a real permission failure rather than asserted from the
    flag — a test that only checked `allow_elevation is False` would pass
    against an executor that ignored it.
    """
    from polyscour.cleaning.executor import Executor
    from polyscour.contracts import SkipReason
    import polyscour.elevation.client as client

    plan, target = _one_file_plan(tmp_path)
    try:
        monkeypatch.setattr(Executor, "_remove",
                            staticmethod(lambda path: (_ for _ in ()).throw(
                                PermissionError("permission denied"))))
        monkeypatch.setattr(client, "request",
                            lambda *a, **k: pytest.fail("asked for elevation"))

        result = _executor(tmp_path).execute(plan)

        assert [s.reason for s in result.skips] == [SkipReason.PERMISSION]
        assert result.items_completed == 0
    finally:
        target.unlink(missing_ok=True)


def test_an_opted_in_executor_does_ask(tmp_path, monkeypatch):
    """The control for the test above: the flag is what makes the difference,
    so both directions have to be exercised."""
    from polyscour.cleaning.executor import Executor
    import polyscour.elevation.client as client

    plan, target = _one_file_plan(tmp_path)
    try:
        monkeypatch.setattr(Executor, "_remove",
                            staticmethod(lambda path: (_ for _ in ()).throw(
                                PermissionError("permission denied"))))
        asked: list = []
        monkeypatch.setattr(client, "request",
                            lambda op, **kw: asked.append(kw) or Response(True, "deleted"))

        result = _executor(tmp_path, allow_elevation=True).execute(plan)

        assert asked, "the opted-in executor did not consult the helper"
        assert asked[0]["rule_id"] == "user-temp"
        assert result.items_completed == 1
        assert result.skips == []
    finally:
        target.unlink(missing_ok=True)


def test_the_helper_is_asked_only_for_permission_failures(tmp_path, monkeypatch):
    from polyscour.cleaning.executor import Executor
    from polyscour.ledger import Ledger
    from polyscour.vault import Vault

    led = Ledger(tmp_path / "l.db")
    led.initialise()
    ex = Executor(vault=Vault(tmp_path / "v"), ledger=led, allow_elevation=True)

    doomed = tmp_path / "x.tmp"
    doomed.write_text("junk", encoding="utf-8")

    asked: list[dict] = []
    import polyscour.elevation.client as client
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: asked.append(kw) or Response(True, "deleted"))

    size = ex._remove_elevated("windows-temp", doomed)

    assert size == len("junk"), "the size must be read before the delete"
    assert asked == [{"rule_id": "windows-temp", "path": str(doomed)}], (
        "the helper is told the rule and the path and nothing else -- no "
        "approval, no decision it could take on trust")


def test_a_declined_prompt_leaves_the_original_skip(tmp_path, monkeypatch):
    """A user who said no should see "needs administrator rights", not a
    second, stranger error."""
    from polyscour.cleaning.executor import Executor
    from polyscour.ledger import Ledger
    from polyscour.vault import Vault

    led = Ledger(tmp_path / "l.db")
    led.initialise()
    ex = Executor(vault=Vault(tmp_path / "v"), ledger=led, allow_elevation=True)

    doomed = tmp_path / "x.tmp"
    doomed.write_text("junk", encoding="utf-8")

    import polyscour.elevation.client as client
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: Response(False, "administrator rights "
                                                  "were not granted", "user"))

    assert ex._remove_elevated("windows-temp", doomed) is None
