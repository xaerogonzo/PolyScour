r"""Drive the REAL PolyScour window from a script, and keep the evidence.

    POLYSCOUR_DRIVE=<scenario.json> POLYSCOUR_DATA_DIR=<sandbox> python -m polyscour.entry

Normally launched by ``tools/drive`` (which builds the sandbox), not by hand.

Why this is inside the app and not a harness that builds its own window: a harness
is a *parallel construction* of the thing under test -- a different theme, fonts and
DPI -- so every measurement is of a window no user has. And it must never drive the
machine's mouse or keyboard: that needs focus for every step, makes the machine
unusable for the run, and a stray click lands in another application. Steps run
here, inside the process, on Tk's own timer. (``docs/adr/0016``; the pattern and
its nine hard-won rules are TokenSave Manager's ``templates/drive/README.md``, and
``ledger.py`` beside this file is that template's ledger, unchanged.)

PolyScour deletes files, so a way to script it needs more guard rails than the
template's, and they are the reason this file differs from it:

* **It refuses to run against anything but a sandbox.** ``POLYSCOUR_DATA_DIR`` must
  be set, so a drive can never open the real vault, ledger or settings. It is also
  inert in a frozen build: it is a development tool, and an installed program has
  no business accepting a script from its environment.
* **It can only press an allowlist of buttons.** Scanning and previewing; never
  "Clean selected", "Run Uninstaller", "Retry as administrator", "Remove" or
  "Create schedule". A script that names anything else fails that step. Pressing
  more is a code change that goes through review, not a line in a JSON file --
  "configuration is not authority", applied to the test tool.
* **A script with a key or a step it does not know is refused before anything
  runs**, not silently ignored. Ignoring an argument means proceeding on the
  overlap between what the author meant and what this understood.

A run is evidence, not a demonstration: reaching the last line proves only that. The
verdict is what the app said about itself (``expect_clean``) and what each
``expect`` found.
"""
from __future__ import annotations

import atexit
import json
import os
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

from polyscour.drive import ledger as drive_ledger

ENV_SCRIPT = "POLYSCOUR_DRIVE"
#: Set by ``tools/drive`` when it started a scripted PolyShield. Read here, and
#: only here, so the production client never grows a port override.
ENV_POLYSHIELD_PORT = "POLYSCOUR_DRIVE_POLYSHIELD_PORT"

_LEDGER = None
_DEFAULT_AFTER_MS = 400

#: The only things a script may press, matched on the WHOLE label (a substring
#: match would let "Scan" press "Scanning..." and, worse, let a short word match
#: a destructive button). Everything here reads or previews; nothing changes the
#: machine.
CLICKABLE = frozenset({
    "scan", "scan for things to clean", "cancel", "preview", "open storage",
})
#: Checkboxes a script may flip. Both only change what is *asked for*, never what
#: is done.
TOGGLEABLE = frozenset({
    "ask polyshield about paths", "dry run (change nothing)",
    "start every cleanup as a dry run",
})

_COMMON = {"do", "after_ms"}
_STEP_KEYS = {
    "wait": set(),
    "navigate": {"view"},
    "click": {"text", "view"},
    "toggle": {"text", "value", "view"},
    "expect": {"id", "check", "text", "view", "key", "equals", "at_most", "within_ms"},
    "expect_clean": {"settle_ms"},
    "log_report": set(),
    "quit": set(),
}
_TOP_KEYS = {"steps", "visible", "report"}


class DriveRefused(SystemExit):
    """The drive will not run. A non-zero exit, so no one mistakes it for a pass."""

    def __init__(self, reason: str) -> None:
        super().__init__(2)
        self.reason = reason
        _say("drive: REFUSED -- %s" % reason)


def _say(message: str) -> None:
    """Print without the console's encoding being able to stop the run.

    A cp1252 console cannot encode a check mark; the UnicodeEncodeError would be
    raised inside a step, escape the timer chain, and look exactly like the app
    hanging -- a diagnostic dying on the glyphs of the thing it diagnoses.
    """
    try:
        print(message, flush=True)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        print(message.encode(enc, "replace").decode(enc), flush=True)


def requested() -> str | None:
    return os.environ.get(ENV_SCRIPT) or None


def _gates() -> None:
    """Refuse, before anything is built, unless this is a sandboxed source run."""
    from polyscour import paths

    if paths.is_frozen():
        raise DriveRefused("this is a built program; the drive is a development "
                           "tool and is inert in one")
    if not os.environ.get(paths.DATA_DIR_ENV, "").strip():
        raise DriveRefused(
            "%s is not set. A drive must run against a throwaway data directory "
            "so it can never open your real vault, ledger or settings "
            "(tools/drive sets this up)" % paths.DATA_DIR_ENV)


def load(path: str) -> dict:
    """Read and validate a scenario, or raise :class:`DriveRefused`."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DriveRefused("cannot read %s: %s" % (path, exc))
    scenario = {"steps": raw} if isinstance(raw, list) else raw
    if not isinstance(scenario, dict) or not isinstance(scenario.get("steps"), list):
        raise DriveRefused("%s is not a list of steps, or an object with 'steps'" % path)
    unknown = set(scenario) - _TOP_KEYS
    if unknown:
        raise DriveRefused("unknown scenario key(s) %s" % sorted(unknown))
    for number, step in enumerate(scenario["steps"], start=1):
        problem = _problem(step)
        if problem:
            raise DriveRefused("step %d: %s" % (number, problem))
    if not scenario["steps"] or scenario["steps"][-1].get("do") != "quit":
        # Without it a hidden window waits for a script that has ended, forever.
        raise DriveRefused("a scenario must end with a 'quit' step")
    return scenario


def _problem(step) -> str | None:
    if not isinstance(step, dict):
        return "is not an object"
    name = step.get("do")
    if name not in _STEP_KEYS:
        return "unknown step %r" % (name,)
    extra = set(step) - _STEP_KEYS[name] - _COMMON
    if extra:
        return "%s: unknown key(s) %s" % (name, sorted(extra))
    return None


def begin(app=None) -> None:
    """Listen from launch, so startup diagnostics are on the record.

    Called as early as a Tk root allows. Refuses (exits 2) if the drive is
    requested but not safe to run, rather than letting an ordinary window open on
    a hidden desktop and wait for a script that will never come.
    """
    global _LEDGER
    if not requested() or _LEDGER is not None:
        return
    _gates()
    load(requested())                 # a bad script is refused before anything runs
    _LEDGER = drive_ledger.Ledger()
    _LEDGER.install()
    if app is not None:
        _LEDGER.install_tk(app)


def start_if_requested(app):
    if not requested():
        return None
    scenario = load(requested())
    port = os.environ.get(ENV_POLYSHIELD_PORT, "").strip()
    if port.isdigit():
        from polyscour.integrations import polyshield
        polyshield._PORT = int(port)
    if scenario.get("visible") is False:
        try:
            app.withdraw()
        except tk.TclError:
            pass
    driver = Driver(app, scenario["steps"], ledger=_LEDGER, script=requested(),
                    report=scenario.get("report"))
    driver.start()
    return driver


def user_objects() -> int:
    """USER objects (windows, menus, ...) this process holds. Windows allows 10,000.

    Every Tk widget is a window, and a CustomTkinter widget is several, so a screen
    that builds a row per item spends this budget faster than it looks -- and the
    failure when it runs out is not "out of handles" but an unrelated-looking
    ``No more menus can be allocated`` somewhere else. The first drive of this app
    found Game Mode spending ~7,500 of them on one machine.
    """
    import ctypes
    kernel, user = ctypes.windll.kernel32, ctypes.windll.user32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p      # a 64-bit pseudo-handle
    user.GetGuiResources.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    user.GetGuiResources.restype = ctypes.c_uint
    return int(user.GetGuiResources(kernel.GetCurrentProcess(), 1))   # GR_USEROBJECTS


def _walk(widget):
    yield widget
    try:
        children = widget.winfo_children()
    except tk.TclError:
        return
    for child in children:
        yield from _walk(child)


def _text(widget) -> str:
    try:
        return str(widget.cget("text"))
    except (tk.TclError, AttributeError, ValueError):
        return ""


class Driver:
    def __init__(self, app, steps, *, ledger=None, script=None, report=None) -> None:
        self._app, self._steps, self._index = app, steps, 0
        # Never None: a hand-built driver gets a ledger that listens to nothing.
        self._ledger = ledger if ledger is not None else drive_ledger.Ledger()
        self._script, self._report_path = script, report
        self._run_id = drive_ledger.new_run_id()
        self._started = time.time()
        self._hold, self._hold_ms = None, 500

    def start(self) -> None:
        self._ledger.start_drive()
        atexit.register(self._finalize, "exit")      # only if there is no `quit`
        self._app.after(600, self._run_next)

    def _run_next(self) -> None:
        """Do a step AND arm the next. ``step()`` alone arms nothing, which is
        what a test stepping by hand wants (a timer leaked per step corrupted a
        whole suite once, in the project this pattern came from)."""
        if self._hold is not None:
            if self._hold():
                self._app.after(self._hold_ms, self._run_next)
                return
            self._hold, self._hold_ms = None, 500
        if not self.step():
            return
        last = self._steps[self._index - 1]
        self._app.after(int(last.get("after_ms", _DEFAULT_AFTER_MS)), self._run_next)

    def step(self) -> bool:
        if self._index >= len(self._steps):
            return False
        step = self._steps[self._index]
        self._index += 1
        name = str(step.get("do", ""))
        try:
            getattr(self, "_do_" + name)(step)
        except Exception as exc:                              # noqa: BLE001
            # A failed step is a failure OF THE RUN, not a printed remark, and it
            # must not strand the `quit` that ends the run.
            self._ledger.step_failed(self._index, name, str(exc), exc)
        return True

    # -- looking at the window ----------------------------------------------

    def _scope(self, step):
        """The widgets a step may look at: one named view, else the active one,
        else (before any view exists) the whole window."""
        key = step.get("view") or getattr(self._app, "_active", None)
        view = getattr(self._app, "_views", {}).get(key) if key else None
        return view if view is not None else self._app

    def _find(self, step, kind, wanted: frozenset, exact: str):
        label = str(step.get("text", "")).strip().lower()
        if not label:
            raise ValueError("'text' is required")
        if label not in wanted:
            raise PermissionError(
                "%r is not something a drive may %s. Pressing more is a code change "
                "(polyscour/drive/driver.py), not a line in a script" % (
                    step.get("text"), exact))
        for widget in _walk(self._scope(step)):
            if isinstance(widget, kind) and _text(widget).strip().lower() == label:
                return widget
        raise LookupError("no %s labelled %r in %r" % (
            kind.__name__, step.get("text"), step.get("view") or "the active view"))

    # -- steps ----------------------------------------------------------------

    def _do_wait(self, step) -> None:
        pass

    def _do_navigate(self, step) -> None:
        view = str(step.get("view", ""))
        self._app.navigate(view)
        _say("drive: navigate -> %s" % view)

    def _do_click(self, step) -> None:
        import customtkinter as ctk

        button = self._find(step, ctk.CTkButton, CLICKABLE, "press")
        if str(button.cget("state")) == "disabled":
            raise RuntimeError("%r is disabled" % step.get("text"))
        label = _text(button)             # read BEFORE: invoke may destroy it
        button.invoke()
        _say("drive: click -> %r" % label)

    def _do_toggle(self, step) -> None:
        import customtkinter as ctk

        if not isinstance(step.get("value"), bool):
            raise ValueError("'value' must be true or false")
        box = self._find(step, ctk.CTkCheckBox, TOGGLEABLE, "flip")
        if bool(box.get()) != step["value"]:
            box.toggle()                  # runs the box's own command, as a click does
        _say("drive: toggle %r -> %s" % (_text(box), step["value"]))

    def _check(self, step):
        check = str(step.get("check", ""))
        if check in ("widget_text", "no_widget_text"):
            text = str(step.get("text", ""))
            if not text:
                raise ValueError("'text' is required")
            hit = next((_text(w) for w in _walk(self._scope(step))
                        if text.lower() in _text(w).lower()), "")
            return (bool(hit) if check == "widget_text" else not hit), hit
        if check == "setting":
            from polyscour import settings as cfg
            actual = cfg.get(str(step.get("key", "")))
            return actual == step.get("equals"), actual
        if check == "user_objects":
            if not isinstance(step.get("at_most"), int):
                raise ValueError("'at_most' must be a whole number")
            actual = user_objects()
            return actual <= step["at_most"], actual
        if check == "view_active":
            actual = getattr(self._app, "_active", None)
            return actual == step.get("view"), actual
        if check == "diagnostic_contains":   # the LIVE ledger, never a file
            return self._ledger.contains(str(step.get("text", ""))), self._ledger.summary()
        raise ValueError("unknown check %r" % check)

    def _do_expect(self, step) -> None:
        """Assert state, polling: Tk state settles asynchronously. Failure is
        permanent -- a later success never erases it."""
        ident = str(step.get("id") or "%s:%s" % (step.get("check"), step.get("text")
                                                 or step.get("key") or step.get("view")))
        within = int(step.get("within_ms", 0))
        began = time.monotonic()

        def poll() -> bool:
            elapsed = int((time.monotonic() - began) * 1000)
            try:
                ok, actual = self._check(step)
            except Exception as exc:                          # noqa: BLE001
                self._ledger.expect(ident, False, expected=step, actual=None,
                                    elapsed_ms=elapsed, reason="check raised: %s" % exc)
                return False
            if ok:
                self._ledger.expect(ident, True, expected=step, actual=actual,
                                    elapsed_ms=elapsed)
                _say("drive: expect %s -- ok (%d ms)" % (ident, elapsed))
                return False
            if elapsed >= within:
                self._ledger.expect(ident, False, expected=step, actual=actual,
                                    elapsed_ms=elapsed,
                                    reason="not satisfied within %d ms" % within)
                _say("drive: expect %s -- FAILED" % ident)
                return False
            return True

        if poll():
            self._hold, self._hold_ms = poll, 100

    def _do_expect_clean(self, step) -> None:
        """Nothing wrong so far AND quiet for ``settle_ms``. Without the wait a
        callback that throws 200 ms after this check passes it, and the run is
        still not clean."""
        settle = int(step.get("settle_ms", 1000))
        began = time.monotonic()

        def poll() -> bool:
            elapsed = int((time.monotonic() - began) * 1000)
            if self._ledger.drive_diagnostics():
                self._ledger.expect("expect_clean", False, expected="no diagnostics",
                                    actual=self._ledger.summary(), elapsed_ms=elapsed,
                                    reason=self._ledger.summary())
                return False
            if elapsed >= settle:
                self._ledger.expect("expect_clean", True, expected="no diagnostics",
                                    actual="none", elapsed_ms=elapsed)
                return False
            return True

        if poll():
            self._hold, self._hold_ms = poll, 100

    def _do_log_report(self, step) -> None:
        _say("drive: startup -- " + self._ledger.summary(drive_ledger.STARTUP))
        _say("drive: drive   -- " + self._ledger.summary(drive_ledger.DRIVE))

    # -- ending ---------------------------------------------------------------

    def _finalize(self, reason: str) -> dict:
        """Uninstall hooks, snapshot, write the report ONCE, before any exit."""
        first = not self._ledger.finalized
        report = self._ledger.finalize(lambda: drive_ledger.build_report(
            self._ledger, script=self._script, run_id=self._run_id,
            started=self._started, reason=reason, shots=[]))
        if first and self._script:
            path = self._report_path or str(Path(self._script).with_suffix(".report.json"))
            try:
                drive_ledger.write_report_atomically(path, report)
                _say("drive: report -> %s" % path)
            except (OSError, ValueError, TypeError) as exc:
                _say("drive: could not write %s: %s" % (path, exc))
        return report

    def _do_quit(self, step) -> None:
        code = 0 if self._finalize("quit")["passed"] else 1
        _say("drive: %s (exit %d)" % ("PASSED" if code == 0 else "FAILED", code))
        if self._script:
            # Exit NOW, not on a timer. The template destroys the window and arms
            # a 0.2 s ``os._exit``, but destroying the window lets the main loop
            # return and the process leave with status 0 first -- a failed run
            # exiting 0, which is the one thing a verdict must never do. Everything
            # that matters (report, flush) has been done by this point.
            self._exit_now(code)
        try:                  # a hand-built driver must never exit the test runner
            self._app.destroy()
        except tk.TclError:
            pass

    @staticmethod
    def _exit_now(code: int) -> None:
        # os._exit skips interpreter shutdown (and flushing), and is the only way
        # to end a run a background thread would otherwise hold open.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except (OSError, ValueError):
                pass
        os._exit(code)
