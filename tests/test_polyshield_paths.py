r"""PATH_STATUS: asking PolyShield about one path, cheaply and without ever
depending on the answer.

The fake service below runs PolyShield's **real** ``_path_status`` logic, copied
verbatim from its PR #35 (``polyshield_service.py``), rather than replying with
canned booleans -- so normalisation, "a directory is flagged by a detection
beneath it" and "a sibling sharing a name prefix does not match" are the real
behaviours, not this file's idea of them.

Three things are asserted throughout, because they are the whole design:

* **UNKNOWN is never False.** No reply, a refusal, a wrong shape: all UNKNOWN.
* **UNKNOWN blocks nothing and clears nothing.**
* **It stays cheap.** A scan must not become one socket round trip per file.
"""
from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

from polyscour.integrations import polyshield
from polyscour.integrations.polyshield import (UNKNOWN_PATH, PathAdvisor,
                                               PathStatus, describe_path,
                                               path_status)

from _polyshield_fake import PathService   # one copy; see its docstring

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


@pytest.fixture
def service(monkeypatch, tmp_path):
    """Factory: start a service and point the client at it, token and all."""
    started: list[PathService] = []

    def start(**kwargs):
        state = tmp_path / "programdata" / "PolyShield" / "state"
        state.mkdir(parents=True, exist_ok=True)
        (state / "service_token.txt").write_text("s3cret", encoding="utf-8")
        monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "programdata"))
        svc = PathService(**kwargs)
        monkeypatch.setattr(polyshield, "_PORT", svc.port)
        started.append(svc)
        return svc

    yield start
    for svc in started:
        svc.close()


# ══ path_status(): one question ═══════════════════════════════════════════════

def test_a_clear_answer_is_read_through(service):
    svc = service(watched=[r"C:\Users\me\Downloads"],
                  detections=[r"C:\Users\me\Downloads\evil.exe"])

    assert path_status(r"C:\Users\me\Downloads") == PathStatus(True, True)
    assert path_status(r"C:\Users\me\Downloads\evil.exe") == PathStatus(True, True)
    assert path_status(r"C:\Users\me\Downloads\fine.txt") == PathStatus(True, False)
    assert path_status(r"C:\Elsewhere") == PathStatus(False, False)


def test_the_request_carries_the_path_and_the_token(service):
    svc = service()
    path_status(r"C:\Temp\x")

    assert svc.seen == [{"cmd": "PATH_STATUS", "path": r"C:\Temp\x",
                         "token": "s3cret"}]


def test_a_sibling_sharing_a_name_prefix_is_not_flagged(service):
    """PolyShield's rule, asserted here because the guard relies on it: a
    detection under ``C:\\Temp\\app`` must not condemn ``C:\\Temp\\app2``."""
    service(detections=[r"C:\Temp\app\bad.exe"])

    assert path_status(r"C:\Temp\app").flagged is True
    assert path_status(r"C:\Temp\app2").flagged is False


def test_a_refusal_is_unknown_not_clear(service):
    """PolyShield refuses a relative path with ``ok: false`` rather than
    answering ``flagged: false``. That has to arrive as UNKNOWN."""
    service()

    assert path_status("relative\\path") == UNKNOWN_PATH
    assert path_status("relative\\path").flagged is None


@pytest.mark.parametrize("reply", [
    {"ok": True},                                           # fields missing
    {"ok": True, "watched": "yes", "flagged": "no"},        # not booleans
    {"ok": True, "watched": 1, "flagged": 0},               # truthy is not bool
    {"ok": False, "watched": False, "flagged": False},      # refused, but says no
    {"watched": False, "flagged": False},                   # no ok at all
])
def test_a_reply_of_the_wrong_shape_is_unknown(service, reply):
    service(reply=reply)
    assert path_status(r"C:\Temp\x") == UNKNOWN_PATH


def test_a_non_json_reply_is_unknown(service):
    service(raw=b"I am not PolyShield\n")
    assert path_status(r"C:\Temp\x") == UNKNOWN_PATH


def test_no_polyshield_is_unknown_and_never_connects(monkeypatch):
    """No token means no conversation: the client does not even connect, so it
    cannot be answered by whatever else is listening on the port."""
    called = []
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: called.append(a))

    assert path_status(r"C:\Temp\x") == UNKNOWN_PATH
    assert called == []


def test_nothing_listening_is_unknown(monkeypatch, tmp_path):
    state = tmp_path / "pd" / "PolyShield" / "state"
    state.mkdir(parents=True)
    (state / "service_token.txt").write_text("t", encoding="utf-8")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()                     # a port with nobody on it
    monkeypatch.setattr(polyshield, "_PORT", port)

    assert path_status(r"C:\Temp\x") == UNKNOWN_PATH


# ══ the elevated helper can ask, so a hostile listener must cost bounded time ═

def test_an_endless_reply_without_a_newline_is_cut_off(service):
    service(raw=b"A" * (polyshield._MAX_REPLY * 4))

    started = time.monotonic()
    assert polyshield._send("PATH_STATUS", path=r"C:\x") is None
    assert time.monotonic() - started < 2.0


def test_a_listener_that_drips_bytes_is_bounded_by_a_total_deadline(service):
    """A per-recv timeout resets on every byte, so one byte every 0.2s would
    never time out. The deadline is on the whole reply."""
    service(slow=True)

    started = time.monotonic()
    assert polyshield._send("PATH_STATUS", timeout=0.8, path=r"C:\x") is None
    assert time.monotonic() - started < 2.5


def test_extra_fields_cannot_override_the_command_or_the_token(service):
    svc = service()

    # ``cmd`` cannot even be passed twice -- Python refuses at the call.
    with pytest.raises(TypeError):
        polyshield._send("PATH_STATUS", path=r"C:\x", cmd="START_WATCHER")

    # ``token`` can reach ``fields``, so the real one has to be written last.
    polyshield._send("PATH_STATUS", path=r"C:\x", token="forged")

    assert svc.seen[0]["cmd"] == "PATH_STATUS"
    assert svc.seen[0]["token"] == "s3cret"


# ══ the client can only ask questions ═════════════════════════════════════════

_READ_ONLY = {"PING", "STATUS", "GET_INTEL_STATUS", "PATH_STATUS"}


def _commands_in(source: str) -> set[str]:
    return set(re.findall(r'_send\(\s*"([A-Z_]+)"', source))


def test_the_client_can_only_ever_send_read_only_commands():
    """Checked statically as well as by behaviour: PolyShield being installed
    must not silently grant PolyScour a way to make it *act*."""
    source = Path(polyshield.__file__).read_text(encoding="utf-8")
    assert _commands_in(source) <= _READ_ONLY
    assert "PATH_STATUS" in _commands_in(source)       # the check is not vacuous


def test_the_static_check_can_fail():
    """Negative control: plant an action verb and prove the check sees it."""
    planted = ('reply = _send("PING")\nreply = _send("PATH_STATUS", path=p)\n'
               'reply = _send("QUARANTINE", path=p)\n')
    assert not _commands_in(planted) <= _READ_ONLY


# ══ PathAdvisor: cheap, per-operation, and it never needs the answer ══════════

class CountingAsk:
    """Stands in for the socket: an answer table plus a call log."""

    def __init__(self, table=None, *, default=PathStatus(False, False),
                 down=False):
        self.table = {os.path.normcase(k): v for k, v in (table or {}).items()}
        self.default, self.down, self.calls = default, down, []

    def __call__(self, path: str):
        self.calls.append(path)
        if self.down:
            return None
        return self.table.get(os.path.normcase(path), self.default)


def test_the_same_path_is_asked_once():
    ask = CountingAsk({r"C:\a": PathStatus(True, False)})
    advisor = PathAdvisor(ask)

    for _ in range(50):
        assert advisor.status(r"C:\a") == PathStatus(True, False)

    assert ask.calls == [r"C:\a"]
    assert advisor.queries == 1


def test_the_cache_is_case_insensitive_like_windows_paths():
    ask = CountingAsk()
    advisor = PathAdvisor(ask)
    advisor.status(r"C:\Temp\X")
    advisor.status(r"c:\temp\x")
    assert advisor.queries == 1


def test_begin_starts_a_fresh_operation():
    ask = CountingAsk()
    advisor = PathAdvisor(ask)
    advisor.status(r"C:\a")

    advisor.begin()
    assert advisor.queries == 0
    advisor.status(r"C:\a")

    assert len(ask.calls) == 2      # asked again: no answer outlives its operation


def test_silence_stops_the_asking_for_the_rest_of_the_operation():
    """The latch. Without it a machine with no PolyShield pays a lookup per
    file for an answer that cannot change mid-scan."""
    ask = CountingAsk(down=True)
    advisor = PathAdvisor(ask)

    results = {advisor.status(rf"C:\f{i}") for i in range(500)}

    assert results == {UNKNOWN_PATH}
    assert len(ask.calls) == 1


def test_begin_lets_a_later_operation_try_again():
    ask = CountingAsk(down=True)
    advisor = PathAdvisor(ask)
    advisor.status(r"C:\a")
    ask.down = False
    advisor.begin()

    assert advisor.status(r"C:\a") == PathStatus(False, False)


def test_a_refused_path_does_not_latch_the_whole_operation():
    """UNKNOWN for one odd path is not the service being gone."""
    ask = CountingAsk({r"C:\odd": UNKNOWN_PATH}, default=PathStatus(False, True))
    advisor = PathAdvisor(ask)

    assert advisor.status(r"C:\odd") == UNKNOWN_PATH
    assert advisor.status(r"C:\fine") == PathStatus(False, True)


# ── flagged_within: directories before files ─────────────────────────────────

ROOT = Path(r"C:\Temp")


def test_a_clean_root_answers_for_the_whole_tree_in_one_question():
    """The point of asking top-down. ``flagged`` means "a detection here or
    beneath", so if the root says no, nothing under it can be flagged."""
    ask = CountingAsk(default=PathStatus(False, False))
    advisor = PathAdvisor(ask)

    results = {advisor.flagged_within(ROOT, ROOT / f"d{i % 7}" / f"f{i}.tmp")
               for i in range(2000)}

    assert results == {False}
    assert advisor.queries == 1


def test_only_the_flagged_chain_is_walked():
    bad = ROOT / "sub" / "evil.exe"
    ask = CountingAsk({
        str(ROOT): PathStatus(False, True),
        str(ROOT / "sub"): PathStatus(False, True),
        str(bad): PathStatus(False, True),
    }, default=PathStatus(False, False))
    advisor = PathAdvisor(ask)

    assert advisor.flagged_within(ROOT, bad) is True
    # A sibling of the flagged directory costs one question (its directory),
    # and every one of its files costs none.
    other = [advisor.flagged_within(ROOT, ROOT / "other" / f"f{i}") for i in range(300)]
    assert set(other) == {False}
    assert advisor.queries == 3 + 1


def test_a_file_beside_a_detection_is_asked_about_individually():
    ask = CountingAsk({
        str(ROOT): PathStatus(False, True),
        str(ROOT / "sub"): PathStatus(False, True),
        str(ROOT / "sub" / "evil.exe"): PathStatus(False, True),
    }, default=PathStatus(False, False))
    advisor = PathAdvisor(ask)

    assert advisor.flagged_within(ROOT, ROOT / "sub" / "evil.exe") is True
    assert advisor.flagged_within(ROOT, ROOT / "sub" / "fine.txt") is False


def test_unknown_at_any_level_is_unknown_overall():
    advisor = PathAdvisor(CountingAsk(down=True))
    assert advisor.flagged_within(ROOT, ROOT / "a" / "b") is None


def test_a_target_outside_the_root_is_just_asked_about_directly():
    ask = CountingAsk({r"D:\elsewhere\x": PathStatus(False, True)})
    advisor = PathAdvisor(ask)

    assert advisor.flagged_within(ROOT, Path(r"D:\elsewhere\x")) is True
    assert ask.calls == [r"D:\elsewhere\x"]


# ══ describe_path: facts, never advice ════════════════════════════════════════

def test_a_flagged_folder_and_a_flagged_file_are_worded_differently():
    assert "in or beneath this folder" in describe_path(
        PathStatus(False, True), folder=True)
    assert "for this file" in describe_path(PathStatus(False, True), folder=False)


def test_watched_alone_is_a_plain_statement_of_fact():
    assert describe_path(PathStatus(True, False), folder=True) == \
        "PolyShield monitors this location"


@pytest.mark.parametrize("status", [PathStatus(False, False), UNKNOWN_PATH,
                                    PathStatus(None, False)])
def test_nothing_known_means_no_label_at_all(status):
    """Not "PolyShield found nothing here": it only has a capped log, and a
    label saying so would read as a clearance."""
    assert describe_path(status, folder=True) == ""


def test_the_wording_never_reads_as_advice():
    text = describe_path(PathStatus(True, True), folder=True).lower()
    for word in ("remove", "delete", "suspicious", "malware", "dangerous",
                 "safe", "recommend", "should", "clean"):
        assert word not in text


# ══ the acceptance criterion: identical in every state, over a real socket ════

def _scan_a_temp_tree(monkeypatch, tmp_path, advisor):
    """Twenty aged files in nested folders, scanned with ``user-temp``."""
    from polyscour import paths as ps_paths
    from polyscour.cleaning import rules as rules_module
    from polyscour.cleaning.scanner import Scanner
    from polyscour.safety.guard import Guard

    root = tmp_path / "scan-temp"
    root.mkdir()
    monkeypatch.setenv("TEMP", str(root))
    old = time.time() - 3 * 86400
    files = []
    for i in range(20):
        f = root / f"d{i % 4}" / f"f{i}.tmp"
        f.parent.mkdir(exist_ok=True)
        f.write_text("x", encoding="utf-8")
        os.utime(f, (old, old))
        files.append(f.resolve())
    rule = rules_module.load_file(ps_paths.rules_dir() / "user-temp.json")
    result = Scanner(guard=Guard(advisor=advisor)).scan([rule], threading.Event())
    return files, result


@pytest.mark.parametrize("state", ["absent", "old_protocol", "garbage",
                                   "nothing_listening", "present_and_clean"])
def test_the_scan_is_identical_whenever_polyshield_has_nothing_to_say(
        state, service, monkeypatch, tmp_path):
    """Absent, too old to know PATH_STATUS, answering nonsense, gone, or simply
    holding no detections: the same twenty files are offered, none withheld.
    This is "PolyShield must never become a hidden dependency", asserted."""
    if state == "old_protocol":
        service(reply={"ok": False, "error": "Unknown command: PATH_STATUS"})
    elif state == "garbage":
        service(raw=b"I am not PolyShield\n")
    elif state == "present_and_clean":
        service()
    elif state == "nothing_listening":
        service()
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        monkeypatch.setattr(polyshield, "_PORT", dead.getsockname()[1])
        dead.close()
    # "absent": the conftest guard already left no token anywhere.

    advisor = PathAdvisor()
    files, result = _scan_a_temp_tree(monkeypatch, tmp_path, advisor)

    assert sorted(f.path for f in result.findings) == sorted(files)
    assert result.outcomes[0].withheld_by_polyshield == 0


def test_an_old_polyshield_is_asked_once_per_operation_not_once_per_file(
        service, monkeypatch, tmp_path):
    svc = service(reply={"ok": False, "error": "Unknown command: PATH_STATUS"})

    files, result = _scan_a_temp_tree(monkeypatch, tmp_path, PathAdvisor())

    assert len(result.findings) == 20
    assert len(svc.paths_asked) == 1        # the root answered UNKNOWN, once


def test_a_detection_over_a_real_socket_withholds_exactly_that_file(
        service, monkeypatch, tmp_path):
    """The positive case, through the real client and PolyShield's real logic."""
    # Detections are named by path, so the service needs the tree first.
    root = tmp_path / "scan-temp"
    bad = (root / "d1" / "f5.tmp")
    svc = service(detections=[bad])

    files, result = _scan_a_temp_tree(monkeypatch, tmp_path, PathAdvisor())

    withheld = {f for f in files if f.name == "f5.tmp"}
    assert result.outcomes[0].withheld_by_polyshield == 1
    assert {f.path for f in result.findings} == set(files) - withheld
    # root, d1, and its files -- plus the three other directories: far fewer
    # than one per file would be, and bounded by the flagged chain.
    assert len(svc.paths_asked) < 20


# ══ the person's switch ═══════════════════════════════════════════════════════

def test_a_disabled_advisor_asks_nothing_and_knows_nothing():
    asked = []
    advisor = PathAdvisor(lambda p: asked.append(p) or PathStatus(True, True),
                          enabled=lambda: False)

    assert advisor.status(r"C:\a") == UNKNOWN_PATH
    assert advisor.flagged_within(ROOT, ROOT / "x" / "y") is None
    assert asked == [] and advisor.queries == 0


def test_the_switch_is_read_at_each_question_so_no_restart_is_needed():
    on = [False]
    asked = []
    advisor = PathAdvisor(lambda p: asked.append(p) or PathStatus(False, True),
                          enabled=lambda: on[0])

    assert advisor.status(r"C:\a") == UNKNOWN_PATH
    on[0] = True
    assert advisor.status(r"C:\a").flagged is True       # asked now
    on[0] = False
    assert advisor.status(r"C:\b") == UNKNOWN_PATH       # and off again
    assert asked == [r"C:\a"]


def test_off_is_the_same_as_polyshield_not_being_there(service, monkeypatch, tmp_path):
    """The promise in the Settings text: with the switch off the scan is what it
    would be with no PolyShield at all, even with one running and flagging."""
    root = tmp_path / "scan-temp"
    svc = service(detections=[root / "d1" / "f5.tmp"])

    files, result = _scan_a_temp_tree(monkeypatch, tmp_path,
                                      PathAdvisor(enabled=lambda: False))

    assert len(result.findings) == 20
    assert result.outcomes[0].withheld_by_polyshield == 0
    assert svc.seen == []                                # not one question


# ══ the fake is PolyShield's code, and stays so ═══════════════════════════════

_POLYSHIELD_CHECKOUT = Path(r"D:\Random Projects\KicomAI_Project")


def _polyshield_source() -> str | None:
    """PolyShield's merged ``polyshield_service.py``, if this machine has a
    checkout that knows ``PATH_STATUS``; else None. Read through ``git show`` so a
    checkout sitting on some other branch is not disturbed."""
    import subprocess
    for ref in ("origin/master", "HEAD"):
        done = subprocess.run(
            ["git", "-C", str(_POLYSHIELD_CHECKOUT), "show", f"{ref}:polyshield_service.py"],
            capture_output=True, text=True, encoding="utf-8")
        if done.returncode == 0 and "_path_status" in done.stdout:
            return done.stdout
    return None


def test_the_fake_still_matches_polyshields_real_code():
    """If PolyShield changes what ``flagged`` means, a green suite here would
    otherwise be a green suite about a fake. Compares the three functions as ASTs
    with docstrings stripped, so wording and formatting never fail it -- only a
    change in behaviour does. Skipped, not passed, where there is nothing to
    compare against (CI, or no checkout)."""
    import ast
    import _polyshield_fake

    real = _polyshield_source()
    if real is None:
        pytest.skip("no PolyShield checkout with PATH_STATUS on this machine")

    wanted = {"_norm_path", "_is_at_or_under", "_path_status"}

    def shape(source):
        out = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.FunctionDef) and node.name in wanted:
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(
                        getattr(body[0], "value", None), ast.Constant) and                         isinstance(body[0].value.value, str):
                    body = body[1:]
                out[node.name] = ast.dump(ast.Module(body=body, type_ignores=[]))
        return out

    ours = shape(Path(_polyshield_fake.__file__).read_text(encoding="utf-8"))
    theirs = shape(real)
    assert set(theirs) == wanted, "PolyShield no longer has these functions"
    assert ours == theirs


def test_the_drift_check_can_fail():
    """Negative control: change one operator in a copy and the comparison sees it."""
    import ast
    src = "def _path_status(path):\n    return path == 'a'\n"
    mutated = "def _path_status(path):\n    return path != 'a'\n"
    assert ast.dump(ast.parse(src)) != ast.dump(ast.parse(mutated))


