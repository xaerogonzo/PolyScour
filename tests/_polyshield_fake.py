r"""A scripted PolyShield service: PolyShield's REAL ``_path_status``, over a socket.

One copy, used by ``tests/test_polyshield_paths.py`` and by ``tools/drive`` (which
starts it so a scripted run of the real window has a PolyShield to ask). It lives
in ``tests/`` because the tests were its first user; ``tools/drive`` adds that
directory to its path to import it.

The three functions below are copied **verbatim** from PolyShield's
``polyshield_service.py`` at commit ab8c925 (their PR #35), not re-imagined -- so
normalisation, "a directory is flagged by a detection beneath it" and "a sibling
sharing a name prefix does not match" are the real behaviours. That they have not
drifted is checked by ``test_the_fake_still_matches_polyshields_real_code`` whenever
a PolyShield checkout with ``PATH_STATUS`` is on this machine.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time

_MAX_QUERY_PATH = 32767


def _norm_path(value: str) -> str:
    p = os.path.normcase(os.path.normpath(value))
    return p.rstrip("\\/") if len(p) > 3 else p


def _is_at_or_under(child: str, parent: str) -> bool:
    if child == parent:
        return True
    return child.startswith(parent.rstrip("\\/") + os.sep)


def _path_status(path, watched_folders, events) -> dict:
    if (not isinstance(path, str) or not path or "\0" in path
            or len(path) > _MAX_QUERY_PATH):
        return {"ok": False, "error": "invalid path"}
    if not os.path.isabs(path):
        return {"ok": False, "error": "path must be absolute"}

    target = _norm_path(path)
    watched = any(
        isinstance(f, str) and f and _is_at_or_under(target, _norm_path(f))
        for f in (watched_folders or ())
    )
    flagged = any(
        isinstance(e.get("path"), str) and e["path"]
        and _is_at_or_under(_norm_path(e["path"]), target)
        for e in events
    )
    return {"ok": True, "watched": watched, "flagged": flagged}


class PathService:
    """A localhost service speaking PolyShield's protocol for PATH_STATUS."""

    def __init__(self, *, watched=(), detections=(), reply=None, raw=None,
                 slow=False):
        self.watched = list(watched)
        self.events = [{"path": str(p)} for p in detections]
        self.reply = reply          # a fixed dict, bypassing the real logic
        self.raw = raw              # raw bytes to send instead of a reply
        self.slow = slow
        self.seen: list[dict] = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        with conn:
            try:
                data = conn.recv(65536)
                request = json.loads(data.decode().split("\n", 1)[0])
                self.seen.append(request)
                if self.slow:
                    for _ in range(100):
                        conn.sendall(b"x")
                        time.sleep(0.2)
                    return
                if self.raw is not None:
                    conn.sendall(self.raw)
                    return
                if self.reply is not None:
                    reply = self.reply
                else:
                    reply = _path_status(request.get("path"), self.watched,
                                         self.events)
                conn.sendall(json.dumps(reply).encode() + b"\n")
            except (OSError, ValueError):
                return

    @property
    def paths_asked(self):
        return [r.get("path") for r in self.seen if r.get("cmd") == "PATH_STATUS"]

    def close(self):
        self._stop.set()
        self.sock.close()
