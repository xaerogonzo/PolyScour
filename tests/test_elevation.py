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
import time
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
            "params": {"value_name": "Thing", "enabled": 1,
                       "expected_raw_value": r"C:\Thing\thing.exe"}}))


def test_an_empty_string_parameter_is_refused():
    with pytest.raises(MalformedRequest, match="must not be empty"):
        Request.from_json(json.dumps({
            "operation": "delete_approved_path",
            "params": {"rule_id": "windows-temp", "path": "   "}}))


def test_the_operation_set_is_small_and_named():
    """A guard on the design itself. If this list grows, someone reviewed it;
    if it grows to include something generic, this test is where to argue."""
    assert {o.value for o in Operation} == {
        "delete_approved_path",
        "delete_approved_paths_for_rule",
        "set_machine_startup_approval"}
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
        value_name="NoSuchEntryPolyScourTest", enabled=False,
        expected_raw_value=r"C:\nowhere\nothing.exe"))

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

def _one_file_plan(tmp_path, monkeypatch):
    """A plan with one finding the guard is made to approve.

    The authorisation is stubbed rather than satisfied for real. Writing into
    the machine's %TEMP% so the `user-temp` rule would approve it made the test
    depend on how that path resolves — and it resolved differently on CI, where
    the guard refused before the delete was ever attempted and the test failed
    against working code. The property here is "does the executor consult the
    helper for a permission failure", not "does the guard approve %TEMP%",
    which has its own tests.
    """
    from polyscour.cleaning.executor import Executor
    from polyscour.contracts import ActionPlan, Evidence, Finding, RiskLevel

    target = tmp_path / "locked.tmp"
    target.write_text("junk", encoding="utf-8")
    monkeypatch.setattr(Executor, "_authorise", lambda self, finding: target)

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


def _raises_permission(monkeypatch):
    from polyscour.cleaning.executor import Executor

    def boom(path):
        raise PermissionError("permission denied")

    monkeypatch.setattr(Executor, "_remove", staticmethod(boom))


def test_an_ordinary_executor_can_never_raise_a_uac_prompt(tmp_path, monkeypatch):
    """docs/THREAT_MODEL.md: elevation is never requested speculatively.

    Driven through a real permission failure rather than asserted from the
    flag — a test that only checked ``allow_elevation is False`` would pass
    against an executor that ignored it.
    """
    from polyscour.contracts import SkipReason
    import polyscour.elevation.client as client

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    monkeypatch.setattr(client, "request",
                        lambda *a, **k: pytest.fail("asked for elevation"))

    result = _executor(tmp_path).execute(plan)

    assert [s.reason for s in result.skips] == [SkipReason.PERMISSION]
    assert result.items_completed == 0


def test_an_opted_in_executor_does_ask(tmp_path, monkeypatch):
    """The control for the test above: the flag is what makes the difference,
    so both directions have to be exercised."""
    import polyscour.elevation.client as client
    from polyscour.elevation.protocol import Operation

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    asked: list = []

    def answer(op, **kw):
        asked.append((op, kw))
        return Response(True, "deleted 1 of 1",
                        data={"rule_id": kw["rule_id"], "deleted": 1,
                              "bytes_freed": 4, "candidates": 1,
                              "skips": [], "skip_counts": {}, "stopped": ""})

    monkeypatch.setattr(client, "request", answer)

    result = _executor(tmp_path, allow_elevation=True).execute(plan)

    assert asked, "the opted-in executor did not consult the helper"
    op, kw = asked[0]
    assert op is Operation.DELETE_APPROVED_PATHS_FOR_RULE
    assert result.items_completed == 1
    assert result.skips == []


def test_the_helper_is_told_a_rule_and_never_a_path(tmp_path, monkeypatch):
    """The property docs/adr/0004 exists for.

    The batched operation is *narrower* than the per-file one because the
    caller cannot name a target at all. If a path ever appears in this request
    that stops being true, and the helper is back to being asked to trust
    something it was handed.
    """
    import polyscour.elevation.client as client

    plan, target = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    asked: list[dict] = []
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: asked.append(kw) or Response(
                            True, "", data={"rule_id": kw["rule_id"]}))

    _executor(tmp_path, allow_elevation=True).execute(plan)

    assert asked, "the helper was never consulted"
    sent = asked[0]
    assert set(sent) == {"rule_id", "exclusions", "cancel"}
    assert sent["rule_id"] == "user-temp"
    assert str(target) not in repr(sent), (
        "the request named a path; the whole point of the batched operation "
        "is that it cannot")


def test_the_user_exclusions_travel_with_the_request(tmp_path, monkeypatch):
    """Without this, an exclusion is honoured unelevated and ignored elevated.

    The helper cannot read the invoking user's settings — under `runas` its
    %LOCALAPPDATA% need not be the same profile — so if the executor does not
    send them, the setting quietly means two different things depending on
    which privilege level reached the file.
    """
    import polyscour.elevation.client as client
    from polyscour.safety.guard import Guard

    protected = tmp_path / "keep"
    protected.mkdir()

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    asked: list[dict] = []
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: asked.append(kw) or Response(
                            True, "", data={"rule_id": kw["rule_id"]}))

    ex = _executor(tmp_path, allow_elevation=True,
                   guard=Guard(exclusions=[protected]))
    ex.execute(plan)

    assert asked, "the helper was never consulted"
    assert [Path(p) for p in asked[0]["exclusions"]] == [protected.resolve()]


def test_the_helper_is_asked_only_for_permission_failures(tmp_path, monkeypatch):
    """A locked file is in use. Administrator rights do not open it, so
    offering to elevate for one would be selling a privilege that cannot
    help — and would spend a UAC prompt to achieve nothing."""
    from polyscour.cleaning.executor import Executor
    import polyscour.elevation.client as client

    plan, _ = _one_file_plan(tmp_path, monkeypatch)

    def locked(path):
        exc = OSError("in use")
        exc.winerror = 32          # ERROR_SHARING_VIOLATION
        raise exc

    monkeypatch.setattr(Executor, "_remove", staticmethod(locked))
    monkeypatch.setattr(client, "request",
                        lambda *a, **k: pytest.fail("asked for elevation"))

    result = _executor(tmp_path, allow_elevation=True).execute(plan)

    from polyscour.contracts import SkipReason
    assert [s.reason for s in result.skips] == [SkipReason.LOCKED]
    assert result.elevation.requested is False


def test_a_declined_prompt_leaves_the_original_skip(tmp_path, monkeypatch):
    """A user who said no should see "needs administrator rights", not a
    second, stranger error."""
    from polyscour.contracts import SkipReason
    import polyscour.elevation.client as client

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: Response(False, "administrator rights "
                                                  "were not granted", "user"))

    result = _executor(tmp_path, allow_elevation=True).execute(plan)

    assert [s.reason for s in result.skips] == [SkipReason.PERMISSION]
    assert result.items_completed == 0


def test_history_distinguishes_requested_granted_and_succeeded(tmp_path,
                                                               monkeypatch):
    """"elevated: yes" would be untrue in both common failure paths.

    A declined prompt is requested-and-not-granted. A helper that ran and
    partly failed is granted-and-incomplete. One boolean cannot say either.
    """
    import polyscour.elevation.client as client

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: Response(False, "administrator rights "
                                                  "were not granted", "user"))

    declined = _executor(tmp_path, allow_elevation=True).execute(plan)

    assert declined.elevation.requested is True
    assert declined.elevation.granted is False
    assert declined.elevation.happened is False
    assert "not granted" in declined.elevation.describe()


def test_a_permission_skip_is_never_silently_dropped(tmp_path, monkeypatch):
    """The elevated pass rebuilds the skip list, and rebuilding by exclusion is
    how an item disappears.

    A file that was not deleted and is not reported is worse than one reported
    as failed: the user is told nothing and has no reason to look.
    """
    from polyscour.contracts import SkipReason
    import polyscour.elevation.client as client

    plan, _ = _one_file_plan(tmp_path, monkeypatch)
    _raises_permission(monkeypatch)

    # A helper that refuses. The skip has to survive.
    monkeypatch.setattr(client, "request",
                        lambda op, **kw: Response(False, "the guard said no",
                                                  "guard"))

    result = _executor(tmp_path, allow_elevation=True).execute(plan)

    assert [s.reason for s in result.skips] == [SkipReason.PERMISSION]


def test_cancelling_mid_pass_keeps_the_skips_of_rules_never_reached(
        tmp_path, monkeypatch):
    """Two rules, cancelled after the first. The second rule's items were
    never attempted, so they must still be reported as needing rights."""
    import threading

    from polyscour.cleaning.executor import Executor
    from polyscour.contracts import (ActionPlan, Evidence, Finding, RiskLevel,
                                     Skip, SkipReason)
    import polyscour.elevation.client as client

    cancel = threading.Event()
    ex = _executor(tmp_path, allow_elevation=True)

    def answer(op, **kw):
        cancel.set()          # stop before the second rule is reached
        return Response(True, "", data={"rule_id": kw["rule_id"], "deleted": 0,
                                        "candidates": 0, "skips": [],
                                        "skip_counts": {}})

    monkeypatch.setattr(client, "request", answer)

    skips = [Skip(tmp_path / "a", SkipReason.PERMISSION, "", "user-temp"),
             Skip(tmp_path / "b", SkipReason.PERMISSION, "", "windows-temp")]
    _, _, kept, record = ex._elevated_pass(skips, 0, 0, cancel)

    remaining = {s.rule_id for s in kept if s.reason is SkipReason.PERMISSION}
    assert "windows-temp" in remaining, (
        "the rule that was never reached lost its skip")
    assert record.requested is True


def test_a_permission_skip_with_no_rule_id_survives(tmp_path, monkeypatch):
    """There is no rule to ask the helper about, so there is nothing to retry
    — and therefore nothing that justifies removing it from the report."""
    import threading

    from polyscour.contracts import Skip, SkipReason
    import polyscour.elevation.client as client

    monkeypatch.setattr(client, "request",
                        lambda *a, **k: pytest.fail("asked about no rule"))

    ex = _executor(tmp_path, allow_elevation=True)
    skips = [Skip(tmp_path / "a", SkipReason.PERMISSION, "denied", "")]
    _, _, kept, _ = ex._elevated_pass(skips, 0, 0, threading.Event())

    assert [s.reason for s in kept] == [SkipReason.PERMISSION]


# ── the batched delete: what one consent covers ─────────────────────────────

@pytest.fixture
def user_temp(monkeypatch, tmp_path):
    """A USER_TEMP root this test owns, so `user-temp` resolves somewhere safe."""
    root = tmp_path / "temp"
    root.mkdir()
    monkeypatch.setenv("TEMP", str(root))
    return root.resolve()


def _batch(rule_id="user-temp", exclusions=(), control=None):
    return helper.handle(
        req(operation=Operation.DELETE_APPROVED_PATHS_FOR_RULE,
            rule_id=rule_id, exclusions=[str(e) for e in exclusions]),
        control)


def test_the_batch_deletes_what_the_rule_permits(user_temp):
    """The control. Without it every refusal below could be a blanket no."""
    for name in ("a.tmp", "b.tmp", "c.tmp"):
        (user_temp / name).write_text("junk", encoding="utf-8")

    response = _batch()

    assert response.ok is True
    assert response.data["deleted"] == 3
    assert list(user_temp.iterdir()) == []


def test_an_excluded_path_is_refused_even_at_privilege(user_temp):
    """The negative control for the privilege boundary.

    Before exclusions travelled with the request the helper built a Guard with
    none, so this file — explicitly protected by its owner — was honoured on
    the unelevated path and deleted here. The setting meant two different
    things depending on which privilege level reached the file.
    """
    keep = user_temp / "keep"
    keep.mkdir()
    protected = keep / "important.tmp"
    protected.write_text("mine", encoding="utf-8")
    doomed = user_temp / "junk.tmp"
    doomed.write_text("junk", encoding="utf-8")

    response = _batch(exclusions=[keep])

    assert response.ok is True
    assert protected.exists(), "an exclusion was ignored at administrator privilege"
    assert not doomed.exists(), "nothing was deleted, so this proves nothing"
    assert any(s["reason"] == "refused_by_guard" for s in response.data["skips"])


def test_an_exclusion_protects_descendants_not_just_the_literal_path(user_temp):
    """A user excluding a folder is excluding a region, not a string."""
    keep = user_temp / "keep" / "deeper" / "deeper still"
    keep.mkdir(parents=True)
    protected = keep / "important.tmp"
    protected.write_text("mine", encoding="utf-8")

    _batch(exclusions=[user_temp / "keep"])

    assert protected.exists()


@pytest.mark.parametrize("shape", [
    r"{root}\keep",
    r"{root}\keep" + "\\",
    r"{root}\KEEP",
    r"{root}\.\keep",
    r"{root}\other\..\keep",
])
def test_an_exclusion_is_canonicalised_before_it_is_compared(user_temp, shape):
    """Written the way a person would type it, in five ways.

    The comparison happens on resolved paths, so none of these should be the
    difference between a file surviving and not.
    """
    keep = user_temp / "keep"
    keep.mkdir()
    (user_temp / "other").mkdir()
    protected = keep / "important.tmp"
    protected.write_text("mine", encoding="utf-8")

    _batch(exclusions=[shape.format(root=user_temp)])

    assert protected.exists(), f"{shape} did not protect its target"


def test_an_unknown_rule_is_refused_and_nothing_is_walked(user_temp):
    """The caller supplies no path, so the rule id is the only thing it can
    lie about. A rule with no reviewed policy entry is not a rule."""
    (user_temp / "a.tmp").write_text("junk", encoding="utf-8")

    response = _batch(rule_id="delete-everything")

    assert response.ok is False
    assert response.refused_by == "policy"
    assert (user_temp / "a.tmp").exists()


def test_the_age_floor_comes_from_the_policy_not_the_rule_file(user_temp,
                                                               monkeypatch):
    r"""The rule file is data the caller could have rewritten.

    C:\Windows\Temp is a working directory for installers, so "everything,
    including what was written a minute ago" is a materially different
    operation from the one the user was shown — and the number that decides
    which one this is has to come from reviewed code.
    """
    from dataclasses import replace
    from polyscour.safety import policy

    entry = replace(policy.POLICY["user-temp"], min_age_days=7)
    monkeypatch.setitem(policy.POLICY, "user-temp", entry)

    fresh = user_temp / "written-just-now.tmp"
    fresh.write_text("junk", encoding="utf-8")

    response = _batch()

    assert fresh.exists(), "a file younger than the policy floor was deleted"
    assert response.data["deleted"] == 0


def test_cancelling_stops_the_batch_and_completed_items_stand(user_temp):
    """Cancellation is a real outcome, not a failure: what was deleted is
    deleted, and the response says how much."""
    for i in range(20):
        (user_temp / f"f{i}.tmp").write_text("junk", encoding="utf-8")

    class _StopAfterFirst:
        def __init__(self):
            self.checks = 0

        def cancelled(self):
            self.checks += 1
            return self.checks > 1

        def beat(self, done):
            pass

    response = _batch(control=_StopAfterFirst())

    assert response.data["stopped"] == "cancelled"
    assert response.data["deleted"] == 1
    assert len(list(user_temp.iterdir())) == 19


# ── the client leaves nothing behind, on any path ───────────────────────────

@pytest.fixture
def staging(monkeypatch, tmp_path):
    """Point `tempfile.mkdtemp` at a directory this test can inspect."""
    import tempfile as _tempfile

    area = tmp_path / "staging"
    area.mkdir()
    monkeypatch.setattr(_tempfile, "tempdir", str(area))
    return area


def _leftovers(area):
    return [p.name for p in area.iterdir()]


@pytest.mark.parametrize("scenario", [
    "success", "refusal", "declined", "crashed", "timeout", "unreadable",
])
def test_the_staging_directory_is_removed_on_every_path(staging, monkeypatch,
                                                        scenario):
    """One directory per elevated operation, forever, is the kind of leak
    nobody notices until it is thousands — and the paths that leak are the
    error ones, which are exactly the paths nobody exercises by hand."""
    import polyscour.elevation.client as client

    def launch(request_path):
        response = request_path.with_suffix(".json.response")
        if scenario == "success":
            response.write_text(Response(True, "deleted").to_json(),
                                encoding="utf-8")
        elif scenario == "refusal":
            response.write_text(Response(False, "no", "guard").to_json(),
                                encoding="utf-8")
        elif scenario == "unreadable":
            response.write_text("{not json", encoding="utf-8")
        elif scenario == "declined":
            return False
        elif scenario == "crashed":
            raise OSError("ShellExecute failed")
        return True

    monkeypatch.setattr(client, "_launch", launch)
    monkeypatch.setattr(client, "_TIMEOUT_S", 0.3)
    monkeypatch.setattr(client, "_POLL_S", 0.05)

    response = client.request(Operation.DELETE_APPROVED_PATH,
                              rule_id="user-temp", path=r"C:\Temp\x.tmp")

    assert isinstance(response, Response), "request() must never raise"
    assert _leftovers(staging) == [], (
        f"the {scenario} path left its staging directory behind")


def test_a_long_batch_does_not_time_out_while_it_reports_progress(staging,
                                                                  monkeypatch):
    """The timeout is a *silence* timeout, and this is why.

    A fixed duration would make the GUI conclude the helper is dead and
    re-scan while an elevated process is still deleting files — which is the
    one genuinely dangerous failure available here.
    """
    import threading as _threading
    import polyscour.elevation.client as client

    def launch(request_path):
        progress = request_path.with_name("progress")
        response = request_path.with_suffix(".json.response")

        def work():
            # Longer than the silence timeout, in steps shorter than it.
            for done in range(6):
                time.sleep(0.05)
                progress.write_text(str(done), encoding="utf-8")
            response.write_text(
                Response(True, "deleted 6").to_json(), encoding="utf-8")

        _threading.Thread(target=work, daemon=True).start()
        return True

    monkeypatch.setattr(client, "_launch", launch)
    monkeypatch.setattr(client, "_TIMEOUT_S", 0.15)
    monkeypatch.setattr(client, "_POLL_S", 0.01)

    response = client.request(Operation.DELETE_APPROVED_PATH,
                              rule_id="user-temp", path=r"C:\Temp\x.tmp")

    assert response.ok is True, "a helper that was reporting progress timed out"


def test_a_silent_helper_still_times_out(staging, monkeypatch):
    """The control for the test above. A deadline that never expires is not a
    deadline, and a user who walks away must not leave a thread blocked."""
    import polyscour.elevation.client as client

    monkeypatch.setattr(client, "_launch", lambda p: True)
    monkeypatch.setattr(client, "_TIMEOUT_S", 0.2)
    monkeypatch.setattr(client, "_POLL_S", 0.02)

    response = client.request(Operation.DELETE_APPROVED_PATH,
                              rule_id="user-temp", path=r"C:\Temp\x.tmp")

    assert response.ok is False
    assert "did not answer in time" in response.detail
