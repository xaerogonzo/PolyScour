r"""PolyShield must never become a hidden dependency of PolyScour.

Three states, and PolyScour is fully functional in all of them. This is the
acceptance criterion the whole optional-integration design exists to satisfy, so
it is asserted rather than assumed.
"""
from __future__ import annotations

import json
import socket
import threading

import pytest

from polyscour.integrations import polyshield


@pytest.fixture(autouse=True)
def _no_real_polyshield(monkeypatch, tmp_path):
    """Never talk to a PolyShield the developer happens to be running."""
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "programdata"))


class FakeService:
    """A stand-in that speaks PolyShield's protocol, or deliberately does not."""

    def __init__(self, responses: dict, *, garbage: bool = False):
        self.responses = responses
        self.garbage = garbage
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(4)
        self.seen: list[dict] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    data = conn.recv(4096)
                    if not data:
                        continue
                    request = json.loads(data.decode().split("\n", 1)[0])
                    self.seen.append(request)
                    if self.garbage:
                        conn.sendall(b"I am not PolyShield\n")
                        continue
                    reply = self.responses.get(request.get("cmd"), {"ok": False})
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                except Exception:
                    continue

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def with_token(monkeypatch, tmp_path):
    """PolyShield writes its shared secret when the service first starts."""
    state = tmp_path / "programdata" / "PolyShield" / "state"
    state.mkdir(parents=True)
    (state / "service_token.txt").write_text("s3cret", encoding="utf-8")
    return state


# ══ PolyShield absent ═════════════════════════════════════════════════════════

def test_absent_polyshield_is_reported_not_raised():
    """An integration that could throw would let an optional component take the
    dashboard down with it."""
    assert polyshield.is_available() is False
    posture = polyshield.security_posture()
    assert posture.available is False
    assert posture.detail


def test_no_token_means_no_conversation(monkeypatch):
    """Without the shared secret there is nothing to authenticate with, so the
    client does not even connect -- and cannot be answered by whatever else may
    be listening on the port."""
    called = []
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: called.append(a))
    assert polyshield.is_available() is False
    assert called == []


def test_intel_freshness_is_none_when_absent():
    assert polyshield.intel_freshness() is None


# ══ PolyShield present ════════════════════════════════════════════════════════

def test_a_running_polyshield_answers(monkeypatch, with_token):
    svc = FakeService({
        "PING": {"ok": True},
        "STATUS": {"ok": True, "watcher_running": True},
        "GET_INTEL_STATUS": {"ok": True, "age_days": 2},
    })
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        assert polyshield.is_available() is True
        posture = polyshield.security_posture()
        assert posture.available is True
        assert posture.watcher_running is True
        assert posture.intel_age_days == 2
    finally:
        svc.close()


def test_the_token_is_sent_with_every_command(monkeypatch, with_token):
    svc = FakeService({"PING": {"ok": True}})
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        polyshield.is_available()
    finally:
        svc.close()
    assert svc.seen[0]["token"] == "s3cret"


def test_the_client_only_ever_asks_questions(monkeypatch, with_token):
    """No code path from PolyScour asks PolyShield to *act*. PolyShield being
    installed must not silently grant PolyScour new authority."""
    svc = FakeService({
        "PING": {"ok": True},
        "STATUS": {"ok": True, "watcher_running": True},
        "GET_INTEL_STATUS": {"ok": True, "age_days": 1},
    })
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        polyshield.is_available()
        polyshield.security_posture()
        polyshield.intel_freshness()
    finally:
        svc.close()

    assert {r["cmd"] for r in svc.seen} <= {"PING", "STATUS", "GET_INTEL_STATUS"}


# ══ PolyShield present but wrong ══════════════════════════════════════════════

def test_something_else_on_the_port_is_not_a_degraded_yes(monkeypatch, with_token):
    """localhost is not a trust boundary. An unexpected shape means 'no
    PolyShield', never a partial success."""
    svc = FakeService({}, garbage=True)
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        assert polyshield.is_available() is False
        assert polyshield.security_posture().available is False
    finally:
        svc.close()


def test_a_service_that_refuses_us_is_unavailable(monkeypatch, with_token):
    """A wrong token gets ok:False, which must read as unavailable rather than
    as a service that is there but shy."""
    svc = FakeService({"PING": {"ok": False, "error": "unauthorized"}})
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        assert polyshield.is_available() is False
    finally:
        svc.close()


def test_a_non_dict_reply_is_refused(monkeypatch, with_token):
    svc = FakeService({"PING": ["not", "a", "dict"]})
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        assert polyshield.is_available() is False
    finally:
        svc.close()


# ══ The acceptance criterion ══════════════════════════════════════════════════

def test_polyscour_works_identically_in_all_three_states(monkeypatch, with_token):
    """Absent, present, and installed-but-unresponsive. The product must not
    behave differently in any way except that one tile appears."""
    from polyscour import paths
    from polyscour.cleaning.rules import load_all
    from polyscour.safety.guard import Guard

    def core_still_works():
        rules, failures = load_all(paths.rules_dir())
        return bool(rules) and not failures and bool(Guard().protected_locations)

    assert core_still_works()                      # absent

    svc = FakeService({"PING": {"ok": True}, "STATUS": {"ok": True}})
    monkeypatch.setattr(polyshield, "_PORT", svc.port)
    try:
        assert polyshield.is_available() is True
        assert core_still_works()                  # present
    finally:
        svc.close()

    assert polyshield.is_available() is False      # crashed mid-session
    assert core_still_works()
