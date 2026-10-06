r"""The live driver: a way to script the real window that cannot hurt anything.

PolyScour deletes files, so a way to drive it from a script needs more guard
rails than the pattern it was copied from. What is asserted here is those rails:

* the ledger is TokenSave Manager's, unchanged (a hash pins it);
* a script with a key or a step the driver does not know is refused before
  anything runs, and so is one that never ends;
* it refuses to start against anything but a sandbox, and in a built program;
* the launcher's sandbox really does cover everything the app could touch.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

from polyscour.drive import driver, ledger as drive_ledger

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

ROOT = Path(__file__).resolve().parents[1]
#: TokenSave Manager's ``templates/drive/drive_ledger.py``, LF-normalised. The
#: same pin DerivaMath keeps: the pattern's README says add channels AROUND the
#: ledger, never fork it.
PINNED_SHA256 = "4a28435587aacc416034f5803309dcb20b541600fd70398d6f5b2824715a8c24"
MANAGER_COPY = Path(r"D:\Claude Co worker\Token Save Manager Source"
                    r"\templates\drive\drive_ledger.py")


def normalised(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def test_the_ledger_is_the_managers_unchanged():
    ours = Path(drive_ledger.__file__)
    assert hashlib.sha256(normalised(ours)).hexdigest() == PINNED_SHA256


def test_the_ledger_matches_the_managers_copy_when_it_can_be_compared():
    if not MANAGER_COPY.exists():
        pytest.skip("TokenSave Manager's template is not on this machine")
    assert normalised(Path(drive_ledger.__file__)) == normalised(MANAGER_COPY)


def test_the_pin_can_fail():
    """Negative control: one changed byte is a different hash."""
    body = normalised(Path(drive_ledger.__file__))
    assert hashlib.sha256(body + b" ").hexdigest() != PINNED_SHA256


# ══ scenarios are validated before anything runs ══════════════════════════════

def write(tmp_path, scenario) -> str:
    path = tmp_path / "s.json"
    path.write_text(json.dumps(scenario), encoding="utf-8")
    return str(path)


QUIT = {"do": "quit"}


def test_a_valid_scenario_loads(tmp_path):
    scenario = driver.load(write(tmp_path, {"steps": [{"do": "navigate", "view": "clean"}, QUIT]}))
    assert len(scenario["steps"]) == 2


def test_a_bare_list_is_a_scenario_too(tmp_path):
    assert driver.load(write(tmp_path, [QUIT]))["steps"] == [QUIT]


@pytest.mark.parametrize("scenario, why", [
    ({"steps": [QUIT], "setup": {}}, "unknown scenario key"),
    ({"steps": [{"do": "reformat_c_drive"}, QUIT]}, "unknown step"),
    ({"steps": [{"do": "navigate", "view": "clean", "force": True}, QUIT]}, "unknown key"),
    ({"steps": [{"do": "navigate", "view": "clean"}]}, "must end with a 'quit'"),
    ({"steps": []}, "must end with a 'quit'"),
    ({"steps": ["navigate", QUIT]}, "is not an object"),
    ({"nope": 1}, "is not a list of steps"),
    ("a string", "is not a list of steps"),
])
def test_a_script_the_driver_does_not_understand_is_refused(tmp_path, scenario, why, capsys):
    """Ignoring an argument means proceeding on the overlap between what the
    author meant and what this understood."""
    with pytest.raises(SystemExit) as caught:
        driver.load(write(tmp_path, scenario))
    assert caught.value.code == 2
    assert why in capsys.readouterr().out


def test_a_file_that_is_not_json_is_refused(tmp_path):
    bad = tmp_path / "s.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        driver.load(str(bad))
    assert caught.value.code == 2


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        driver.load(str(tmp_path / "nowhere.json"))


# ══ the gates ═════════════════════════════════════════════════════════════════

def test_it_refuses_without_a_sandbox(monkeypatch, capsys):
    """The one thing that must never happen: a drive opening the real vault,
    ledger or settings."""
    monkeypatch.delenv("POLYSCOUR_DATA_DIR", raising=False)
    with pytest.raises(SystemExit) as caught:
        driver._gates()
    assert caught.value.code == 2
    assert "POLYSCOUR_DATA_DIR" in capsys.readouterr().out


def test_it_runs_with_a_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path))
    driver._gates()                      # does not raise


def test_it_is_inert_in_a_built_program(monkeypatch, tmp_path, capsys):
    """A development tool: an installed program has no business accepting a
    script from its environment."""
    from polybedrock import paths as bedrock_paths
    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(bedrock_paths, "_FROZEN_OVERRIDE", True)
    with pytest.raises(SystemExit) as caught:
        driver._gates()
    assert caught.value.code == 2
    assert "built program" in capsys.readouterr().out


def test_without_the_variable_nothing_is_even_considered(monkeypatch):
    monkeypatch.delenv("POLYSCOUR_DRIVE", raising=False)
    assert driver.requested() is None
    assert driver.begin(None) is None and driver.start_if_requested(None) is None


# ══ what a script may press ═══════════════════════════════════════════════════

@pytest.mark.parametrize("label", [
    "Clean selected", "Run Uninstaller", "Retry 3 as administrator", "Remove",
    "Create schedule", "Clear saved scans", "Save report…", "Cancel the cleanup"])
def test_nothing_that_changes_the_machine_is_on_the_allowlist(label):
    assert label.strip().lower() not in driver.CLICKABLE


def test_the_allowlist_is_whole_labels_not_substrings():
    """So "Scan" can never be satisfied by "Scanning…", and a short word cannot
    stand in for a destructive button."""
    assert all(" " in w or w.isalpha() for w in driver.CLICKABLE)
    assert "scanning…" not in driver.CLICKABLE and "clean" not in driver.CLICKABLE


# ══ the launcher: a sandbox that covers everything ════════════════════════════

def launcher():
    spec = importlib.util.spec_from_file_location(
        "drive_launcher", ROOT / "tools" / "drive" / "__main__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sandbox():
    import shutil
    module = launcher()
    box = module.build_sandbox({"temp_files": {"count": 6, "age_days": 3, "subdirs": 2}})
    yield module, box
    shutil.rmtree(box["root"], ignore_errors=True)


def test_every_directory_the_app_could_touch_is_inside_the_sandbox(sandbox):
    module, box = sandbox
    env = module.child_env(box, None)
    for name in ("POLYSCOUR_DATA_DIR", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA",
                 "USERPROFILE", "PROGRAMDATA"):
        assert Path(env[name]).resolve().is_relative_to(box["root"]), name


def test_planted_files_are_old_enough_to_be_offered_and_where_asked(sandbox):
    _, box = sandbox
    files = sorted(box["temp"].rglob("*.tmp"))
    assert len(files) == 6
    assert {f.parent.name for f in files} == {"d0", "d1"}
    assert all(time.time() - f.stat().st_mtime > 2 * 86400 for f in files)


def test_no_polyshield_token_is_visible_unless_the_scenario_asks(sandbox):
    module, box = sandbox
    assert module.start_polyshield({}, box) is None
    assert not list(box["programdata"].rglob("service_token*"))


def test_a_scripted_polyshield_writes_its_token_inside_the_sandbox(sandbox):
    module, box = sandbox
    service = module.start_polyshield({"polyshield": {"detections": ["d1/f1.tmp"]}}, box)
    try:
        assert (box["programdata"] / "PolyShield" / "state" / "service_token.txt").exists()
        assert module.child_env(box, service)["POLYSCOUR_DRIVE_POLYSHIELD_PORT"] == str(service.port)
    finally:
        service.close()


@pytest.mark.parametrize("setup", [
    {"format": "c:"}, {"temp_files": {"path": "C:\\"}}, {"polyshield": {"token": "x"}},
    {"polyshield": {"detections": ["..\\..\\Windows\\x"]}},
    {"polyshield": {"detections": ["C:\\Windows\\x"]}},
])
def test_the_launcher_refuses_a_setup_it_does_not_understand_or_that_escapes(setup):
    assert launcher()._check_setup(setup) is not None


def test_a_good_setup_is_accepted():
    assert launcher()._check_setup(
        {"temp_files": {"count": 3}, "polyshield": {"detections": ["d1/f5.tmp"]}}) is None


# ══ the console channel ═══════════════════════════════════════════════════════

def test_the_console_records_whole_lines_and_a_trailing_partial_one():
    console = driver.Console()
    console.feed("stdout", "first\nsec")
    console.feed("stdout", "ond\nthird")
    assert [e["line"] for e in console.lines("stdout")] == ["first", "second", "third"]


def test_the_console_keeps_streams_apart():
    console = driver.Console()
    console.feed("stderr", "boom\n")
    console.feed("log", "INFO x: hello\n")
    assert console.contains("boom", "stderr") and not console.contains("boom", "stdout")
    assert console.contains("HELLO") and console.contains("hello", "log")


def test_a_full_console_says_what_it_dropped():
    """A bounded tail that hid its own start would let "no such text" pass on lines
    it never saw, so the loss is a number in the report."""
    console = driver.Console()
    console.MAX_LINES = 3
    console.feed("stdout", "".join("line %d\n" % i for i in range(5)))
    assert console.dropped == 2 and console.to_dict()["dropped"] == 2
    assert not console.contains("line 0") and console.contains("line 4")


def test_the_tee_passes_through_records_and_restores(capsys):
    import sys
    console = driver.Console()
    console.install()
    try:
        print("to the real console")
        print("to stderr", file=sys.stderr)
        import logging
        logging.getLogger("t").warning("a record")
    finally:
        console.uninstall()
    out = capsys.readouterr()
    assert "to the real console" in out.out and "to stderr" in out.err
    assert console.contains("to the real console", "stdout")
    assert console.contains("to stderr", "stderr")
    assert console.contains("a record", "log")
    print("after")                                         # restored: not recorded
    assert not console.contains("after")


def test_the_tee_survives_a_stream_that_is_none():
    console = driver.Console()
    tee = driver._Tee(console, "stdout", None)             # pythonw has no stdout
    assert tee.write("quiet\n") == 6 and console.contains("quiet")
    tee.flush()
