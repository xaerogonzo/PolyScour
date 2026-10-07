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
@pytest.mark.xfail(strict=True, reason=(
    "Game Mode builds one row per running process and spends ~7,500 of Windows' "
    "10,000 USER objects on one machine (found by this driver). Remove this marker "
    "when that screen's cost is bounded; strict=True makes the fix force it."))
def test_no_screen_spends_the_per_process_window_budget(tmp_path):
    done, verdict = drive(tmp_path, "handle_budget.json")
    assert done.returncode == 0, done.stdout


def test_a_scenario_that_is_not_understood_is_refused_before_a_window_opens(tmp_path):
    done, verdict = drive(tmp_path, {"steps": [{"do": "format_disk"}, {"do": "quit"}]})

    assert done.returncode == 2
    assert "unknown step" in done.stdout
    assert verdict is None                       # nothing ran, so nothing was reported
