r"""Every shipped drive scenario, run through the real launcher in a real window.

These start the actual app (withdrawn, in a throwaway sandbox) and read its
verdict -- so they are slower than the rest of the suite, and they are the
tests that would have caught a bug only a running window shows.

The verdict is the *report's*, and the launcher exits 0/1/2/3 (passed / failed /
refused / could not run). ``must_fail.json`` is the control the pattern asks for:
a script that cannot pass. A check that cannot say no is not a check.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools" / "drive" / "__main__.py"
SCENARIOS = ROOT / "tools" / "drive" / "scenarios"

#: The whole-app walks take ~25 s each because they read this machine's real
#: state (the dashboard's PowerShell health check, the registry, the process
#: list). Local gates, like the golden-image check: skipped when ``CI`` is set,
#: forced with ``POLYSCOUR_DRIVE_FULL=1``. The control, the refusal and the
#: PolyShield scenarios -- the ones about a specific behaviour -- always run.
WHOLE_APP_WALK = pytest.mark.skipif(
    bool(os.environ.get("CI")) and not os.environ.get("POLYSCOUR_DRIVE_FULL"),
    reason="a ~25 s walk over this machine's real state; local gate, "
           "set POLYSCOUR_DRIVE_FULL=1 to force")


def drive(tmp_path, scenario: str | dict):
    """Run a scenario (a shipped one by name, or a dict) from a temp copy, so the
    report it writes never lands in the repository."""
    path = tmp_path / "scenario.json"
    if isinstance(scenario, str):
        shutil.copy(SCENARIOS / scenario, path)
    else:
        path.write_text(json.dumps(scenario), encoding="utf-8")
    done = subprocess.run([sys.executable, str(LAUNCHER), str(path), "--timeout", "200"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=260, cwd=str(ROOT))
    report = path.with_suffix(".report.json")
    verdict = json.loads(report.read_text(encoding="utf-8")) if report.exists() else None
    return done, verdict


def test_the_control_scenario_fails_and_says_why(tmp_path):
    """A drive that cannot fail proves nothing. This one must exit 1, and the
    report must name the expectation that was not met."""
    done, verdict = drive(tmp_path, "must_fail.json")

    assert done.returncode == 1, done.stdout + done.stderr
    assert verdict["passed"] is False
    assert any("a screen that does not exist" in json.dumps(e)
               for e in verdict["expectations"]), verdict


@WHOLE_APP_WALK
def test_every_screen_opens_and_the_app_stays_quiet(tmp_path):
    done, verdict = drive(tmp_path, "smoke.json")

    assert done.returncode == 0, done.stdout + done.stderr
    assert verdict["passed"] is True


def test_a_planted_polyshield_detection_is_left_out_and_the_switch_brings_it_back(tmp_path):
    """The manual check, automated: a real scan in the real window, against a
    PolyShield that really answers (its real matching logic, over a socket), then
    the setting turned off in Settings and the scan repeated."""
    done, verdict = drive(tmp_path, "polyshield_detection.json")

    assert done.returncode == 0, done.stdout + done.stderr
    passed = {e["id"] for e in verdict["expectations"] if e["passed"]}
    assert "scan finished with the detection withheld" in passed
    assert "with the switch off all twenty are offered" in passed


def test_the_detection_scenario_cannot_pass_without_the_check(tmp_path):
    """Negative control for the scenario above, without touching product code:
    the same scan with no detection planted must fail its first expectation."""
    scenario = json.loads((SCENARIOS / "polyshield_detection.json").read_text(encoding="utf-8"))
    scenario["setup"]["polyshield"]["detections"] = []
    # The scan takes well under a second, so there is no reason for the control to
    # wait out the shipped 30 s allowance before failing.
    for step in scenario["steps"]:
        if step.get("within_ms") == 30000:
            step["within_ms"] = 4000

    done, verdict = drive(tmp_path, scenario)

    assert done.returncode == 1, done.stdout + done.stderr
    failed = {e["id"] for e in verdict["expectations"] if not e["passed"]}
    assert "scan finished with the detection withheld" in failed


@WHOLE_APP_WALK
def test_no_screen_spends_the_per_process_window_budget(tmp_path):
    done, verdict = drive(tmp_path, "handle_budget.json")
    assert done.returncode == 0, done.stdout


def test_a_scenario_that_is_not_understood_is_refused_before_a_window_opens(tmp_path):
    done, verdict = drive(tmp_path, {"steps": [{"do": "format_disk"}, {"do": "quit"}]})

    assert done.returncode == 2
    assert "unknown step" in done.stdout
    assert verdict is None                       # nothing ran, so nothing was reported


# ══ the screens that shipped after 0.3.0 ══════════════════════════════════════
#
# Each passing scenario has a negative control beside it: the same script with
# the thing it is about taken away must FAIL on the expectation that names it.

def _shipped(name: str) -> dict:
    return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))


def _ids(verdict, passed: bool) -> set:
    return {e["id"] for e in verdict["expectations"] if e["passed"] is passed}


def test_a_planted_recycle_bin_is_offered_unticked_and_worded_as_permanent(tmp_path):
    done, verdict = drive(tmp_path, "recycle_bin.json")

    assert done.returncode == 0, done.stdout + done.stderr
    assert "it is never pre-ticked: nothing is selected" in _ids(verdict, True)


def test_without_a_planted_bin_the_drive_sees_none_not_this_machines(tmp_path):
    """Negative control, and the proof the sandbox covers the bin: this
    machine's real bins may well hold things, and the drive must still see none."""
    scenario = _shipped("recycle_bin.json")
    del scenario["setup"]["recycle_bin"]
    for step in scenario["steps"]:
        if step.get("within_ms") == 30000:
            step["within_ms"] = 4000

    done, verdict = drive(tmp_path, scenario)

    assert done.returncode == 1, done.stdout + done.stderr
    failed = _ids(verdict, False)
    assert "the Recycle Bin is offered as its own row" in failed
    assert "the row says it cannot be undone" in failed


def test_a_planted_schedule_record_is_listed_with_its_controls(tmp_path):
    done, verdict = drive(tmp_path, "schedules.json")

    assert done.returncode == 0, done.stdout + done.stderr
    assert "the planted schedule record is listed" in _ids(verdict, True)


def test_without_a_planted_schedule_the_list_is_empty(tmp_path):
    scenario = _shipped("schedules.json")
    del scenario["setup"]["schedules"]
    for step in scenario["steps"]:
        if step.get("within_ms"):
            step["within_ms"] = 1500

    done, verdict = drive(tmp_path, scenario)

    assert done.returncode == 1, done.stdout + done.stderr
    failed = _ids(verdict, False)
    # Only these two: "Remove" was tried as a third and passed with no record
    # planted -- the word is elsewhere on the screen, and widget_text is a
    # substring match. The press itself is covered by the refusal test below.
    assert {"the planted schedule record is listed", "so the empty state is not shown"} <= failed


def test_nothing_on_these_screens_that_acts_can_be_pressed_by_a_drive(tmp_path):
    """Create schedule / Remove go to the REAL Task Scheduler, which no sandbox
    covers, behind a typed CREATE; Run Uninstaller starts a vendor's program
    behind a typed UNINSTALL; Clean selected empties a bin behind a typed CLEAN.
    Each press must be refused -- a failed step, so the run exits 1 -- and the
    planted record must still be there afterwards."""
    scenario = _shipped("schedules.json")
    scenario["steps"] = [
        {"do": "navigate", "view": "settings"},
        {"do": "click", "text": "Create schedule", "view": "settings"},
        {"do": "click", "text": "Remove", "view": "settings"},
        {"do": "expect", "id": "the record is still listed", "check": "widget_text",
         "text": "Every Sun at 04:30", "within_ms": 3000},
        {"do": "navigate", "view": "clean"},
        {"do": "click", "text": "Clean selected", "view": "clean"},
        {"do": "navigate", "view": "uninstall"},
        {"do": "click", "text": "Run Uninstaller", "view": "uninstall"},
        {"do": "quit"},
    ]

    done, verdict = drive(tmp_path, scenario)

    assert done.returncode == 1, done.stdout + done.stderr
    report = json.dumps(verdict)
    for label in ("Create schedule", "Remove", "Clean selected", "Run Uninstaller"):
        assert "%r is not something a drive may press" % label in report, label
    assert "the record is still listed" in _ids(verdict, True)


def _uninstall_key_names() -> tuple[set, set]:
    """(hidden, listed) subkey names under the three Uninstall keys, read here
    with winreg directly rather than through the module under test."""
    import winreg

    hidden, listed = set(), set()
    for root, path in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")):
        try:
            parent = winreg.OpenKey(root, path)
        except OSError:
            continue
        with parent:
            for i in range(winreg.QueryInfoKey(parent)[0]):
                name = winreg.EnumKey(parent, i)
                try:
                    with winreg.OpenKey(parent, name) as sub:
                        try:
                            winreg.QueryValueEx(sub, "DisplayName")
                        except OSError:
                            continue
                        try:
                            system = winreg.QueryValueEx(sub, "SystemComponent")[0] == 1
                        except OSError:
                            system = False
                except OSError:
                    continue
                (hidden if system else listed).add(name)
    # A key name shown anywhere, as part of any other, cannot be asserted absent.
    hidden = {h for h in hidden if h.startswith("{") and not any(
        h.lower() in other.lower() for other in listed)}
    listed = {n for n in listed if n.startswith("{")}
    return hidden, listed


@WHOLE_APP_WALK
def test_the_uninstall_list_renders_and_launches_nothing(tmp_path):
    """Reads this machine's real registry (read-only), so a local gate."""
    done, verdict = drive(tmp_path, "uninstall.json")

    assert done.returncode == 0, done.stdout + done.stderr
    assert "SystemComponent entries are counted, not shown" in _ids(verdict, True)


@WHOLE_APP_WALK
def test_a_system_component_on_this_machine_is_not_listed_and_the_check_can_see(tmp_path):
    """The hidden entry is THIS machine's, found independently; the negative
    control is a listed entry put through the same absence check, which must fail."""
    hidden, listed = _uninstall_key_names()
    if not hidden or not listed:
        pytest.skip("this machine has no GUID-named SystemComponent / listed entry")
    hidden_key, listed_key = sorted(hidden)[0], sorted(listed)[0]

    scenario = _shipped("uninstall.json")
    scenario["steps"][-3:-3] = [
        {"do": "expect", "id": "the hidden entry is absent", "check": "no_widget_text",
         "text": hidden_key},
        {"do": "expect", "id": "control: a listed entry is absent", "check": "no_widget_text",
         "text": listed_key},
    ]

    done, verdict = drive(tmp_path, scenario)

    assert done.returncode == 1, done.stdout + done.stderr      # the control's doing
    assert "the hidden entry is absent" in _ids(verdict, True)
    assert _ids(verdict, False) == {"control: a listed entry is absent"}
