r"""Run a scripted drive of the REAL PolyScour window, in a sandbox.

    venv\Scripts\python.exe tools\drive\__main__.py tools\drive\scenarios\smoke.json
    venv\Scripts\python.exe tools\drive\__main__.py <scenario> --keep     # keep the sandbox

No mouse, no keyboard, no focus: the app runs a script from *inside* its own
process (``polyscour/drive/driver.py``), so the machine stays yours while it runs.
Exit codes: 0 passed, 1 failed, 2 refused (bad scenario, or an unsafe setup),
3 the run timed out or could not start. A run that "reached its last line" is not
a pass; the verdict is the report's.

What this launcher adds around the app, and why it is here and not in the app:

* **A sandbox for everything the app could touch.** ``POLYSCOUR_DATA_DIR`` (vault,
  ledger, settings), ``TEMP``/``TMP``, ``LOCALAPPDATA``, ``APPDATA``,
  ``USERPROFILE`` and ``PROGRAMDATA`` all point at a throwaway directory, so a scan
  looks at the files the scenario planted and nothing of yours -- and no PolyShield
  token is visible unless the scenario asks for a scripted one.
* **Planting.** The scenario's ``setup`` is interpreted *here*, never by the app: a
  script running inside the program can look and press an allowlist of buttons,
  but it cannot create files, and "write files wherever the JSON says" is not a
  capability worth giving it.
* **A scripted PolyShield** (``tests/_polyshield_fake.py``: PolyShield's real
  ``_path_status`` logic over a real socket) when ``setup.polyshield`` is present.

Scenario shape::

    {"setup": {"temp_files": {"count": 20, "age_days": 3, "subdirs": 4},
               "polyshield": {"detections": ["d1/f5.tmp"], "watched": []}},
     "visible": false,
     "steps": [ ... ends with {"do": "quit"} ... ]}
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))            # the scripted PolyShield lives here

_SETUP_KEYS = {"temp_files", "polyshield"}
_TEMP_KEYS = {"count", "age_days", "subdirs"}
_POLYSHIELD_KEYS = {"detections", "watched"}


def refuse(message: str) -> int:
    print("drive: REFUSED -- %s" % message)
    return 2


def _check_setup(setup) -> str | None:
    if not isinstance(setup, dict) or set(setup) - _SETUP_KEYS:
        return "unknown setup key(s) %s" % sorted(set(setup) - _SETUP_KEYS if isinstance(setup, dict) else setup)
    temp = setup.get("temp_files", {})
    if set(temp) - _TEMP_KEYS:
        return "unknown temp_files key(s) %s" % sorted(set(temp) - _TEMP_KEYS)
    shield = setup.get("polyshield", {})
    if set(shield) - _POLYSHIELD_KEYS:
        return "unknown polyshield key(s) %s" % sorted(set(shield) - _POLYSHIELD_KEYS)
    for rel in [*shield.get("detections", []), *shield.get("watched", [])]:
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            return "%r must be a path inside the sandbox's temp folder" % rel
    return None


def build_sandbox(setup: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="polyscour-drive-")).resolve()
    dirs = {name: root / name for name in
            ("data", "temp", "local", "roaming", "profile", "programdata")}
    for d in dirs.values():
        d.mkdir()

    spec = setup.get("temp_files")
    if spec:
        old = time.time() - float(spec.get("age_days", 3)) * 86400
        subdirs = max(1, int(spec.get("subdirs", 1)))
        for i in range(int(spec.get("count", 0))):
            f = dirs["temp"] / f"d{i % subdirs}" / f"f{i}.tmp"
            f.parent.mkdir(exist_ok=True)
            f.write_text("x" * 16, encoding="utf-8")
            os.utime(f, (old, old))             # old enough that user-temp offers it
    return {"root": root, **dirs}


def start_polyshield(setup: dict, sandbox: dict):
    shield = setup.get("polyshield")
    if shield is None:
        return None
    from _polyshield_fake import PathService

    state = sandbox["programdata"] / "PolyShield" / "state"
    state.mkdir(parents=True)
    (state / "service_token.txt").write_text("drive-token", encoding="utf-8")
    temp = sandbox["temp"]
    return PathService(
        detections=[temp / rel for rel in shield.get("detections", [])],
        watched=[temp / rel for rel in shield.get("watched", [])])


def child_env(sandbox: dict, service) -> dict:
    env = dict(os.environ)
    env.update({
        "POLYSCOUR_DATA_DIR": str(sandbox["data"]),
        "TEMP": str(sandbox["temp"]), "TMP": str(sandbox["temp"]),
        "LOCALAPPDATA": str(sandbox["local"]), "APPDATA": str(sandbox["roaming"]),
        "USERPROFILE": str(sandbox["profile"]),
        "PROGRAMDATA": str(sandbox["programdata"]),
        "POLYSCOUR_DRIVE": str(sandbox["root"] / "scenario.json"),
    })
    env.pop("POLYSCOUR_DRIVE_POLYSHIELD_PORT", None)
    if service is not None:
        env["POLYSCOUR_DRIVE_POLYSHIELD_PORT"] = str(service.port)
    return env


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("scenario")
    ap.add_argument("--keep", action="store_true", help="keep the sandbox afterwards")
    ap.add_argument("--timeout", type=int, default=150, help="seconds before the run is killed")
    args = ap.parse_args(argv)

    path = Path(args.scenario).resolve()
    try:
        scenario = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return refuse("cannot read %s: %s" % (path, exc))
    if not isinstance(scenario, dict) or "steps" not in scenario:
        return refuse("%s must be an object with 'steps'" % path)
    unknown = set(scenario) - {"setup", "steps", "visible", "report"}
    if unknown:
        return refuse("unknown scenario key(s) %s" % sorted(unknown))
    setup = scenario.get("setup", {})
    problem = _check_setup(setup)
    if problem:
        return refuse(problem)

    from polyscour.drive import driver
    for number, step in enumerate(scenario["steps"], start=1):
        bad = driver._problem(step)
        if bad:
            return refuse("step %d: %s" % (number, bad))

    sandbox = build_sandbox(setup)
    service = None
    try:
        service = start_polyshield(setup, sandbox)
        report = scenario.get("report") or str(path.with_suffix(".report.json"))
        app_side = {"steps": scenario["steps"],
                    "visible": scenario.get("visible", False), "report": report}
        (sandbox["root"] / "scenario.json").write_text(json.dumps(app_side), encoding="utf-8")
        Path(report).unlink(missing_ok=True)       # never read a previous run's verdict

        print("drive: sandbox %s" % sandbox["root"])
        try:
            done = subprocess.run(
                [sys.executable, "-m", "polyscour.entry"], cwd=str(ROOT),
                env=child_env(sandbox, service), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=args.timeout)
        except subprocess.TimeoutExpired as exc:
            print((exc.stdout or "") if isinstance(exc.stdout, str) else "")
            print("drive: TIMED OUT after %ds -- killed" % args.timeout)
            return 3

        print(done.stdout.rstrip())
        if done.returncode not in (0, 1):
            print("drive: the app exited %d without a verdict\n%s"
                  % (done.returncode, done.stderr.strip()[-800:]))
            return 3 if done.returncode != 2 else 2
        if not Path(report).exists():
            print("drive: no report was written, so there is no verdict")
            return 3
        verdict = json.loads(Path(report).read_text(encoding="utf-8"))
        passed = bool(verdict.get("passed"))
        print("drive: %s -- %s" % ("PASSED" if passed else "FAILED", report))
        # The REPORT is the verdict. The exit code must agree with it; if it does
        # not, trust neither and say so rather than let a failure pass quietly.
        if (done.returncode == 0) != passed:
            print("drive: the exit code (%d) disagrees with the report -- not trusting it"
                  % done.returncode)
            return 3
        return 0 if passed else 1
    finally:
        if service is not None:
            service.close()
        if args.keep:
            print("drive: kept %s" % sandbox["root"])
        else:
            shutil.rmtree(sandbox["root"], ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
