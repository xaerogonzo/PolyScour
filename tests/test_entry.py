r"""tests/test_entry.py — the command line of a program that runs as administrator.

An installed PolyScour is one executable that is two programs. Which one runs is
decided by one argument, before anything else happens, so this is a privilege
boundary in the same sense the request file is — and it gets tested like one:
mostly refusals, and one control proving the refusals are not blanket.

The tests that matter here are the ones that would have caught a bug that only
appears once the thing is installed. There was one: ``_helper_command`` tested
``sys.frozen``, which **Nuitka does not set**, so a compiled build would have
taken the source branch and asked ``PolyScour.exe`` to run ``-m polyscour.entry``.
Every development run would have passed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from polybedrock import paths as bedrock_paths

from polyscour import entry
from polyscour.elevation.client import _helper_command
from polyscour.elevation.protocol import Operation, Request, Response

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="Windows-only product")


@pytest.fixture
def frozen(monkeypatch):
    """Pretend to be a compiled build, in either direction."""
    def set_frozen(value):
        monkeypatch.setattr(bedrock_paths, "_FROZEN_OVERRIDE", value)
    return set_frozen


# ── which program runs ──────────────────────────────────────────────────────

def test_no_arguments_starts_the_application(monkeypatch):
    """The control. A shortcut and a double-click both produce no arguments,
    and that is the only case decided implicitly."""
    started = []
    import polyscour.app as app
    monkeypatch.setattr(app, "main", lambda: started.append(True) or 0)

    assert entry.main([]) == 0
    assert started == [True]


def test_the_helper_flag_runs_the_helper_and_not_the_application(monkeypatch):
    import polyscour.app as app
    import polyscour.elevation.helper as helper

    monkeypatch.setattr(app, "main",
                        lambda: pytest.fail("started the GUI at privilege"))
    seen = []
    monkeypatch.setattr(helper, "main", lambda argv: seen.append(argv) or 0)

    assert entry.main(["--elevated-helper", r"C:\Tmp\request.json"]) == 0
    assert seen == [[r"C:\Tmp\request.json"]]


@pytest.mark.parametrize("args", [
    ["--help"],
    ["--elevated-helper-x", "r.json"],
    ["-elevated-helper", "r.json"],
    ["--ELEVATED-HELPER", "r.json"],
    ["--run-powershell", "whoami"],
    ["r.json"],
    ["", "r.json"],
])
def test_an_unrecognised_argument_is_refused_not_ignored(args, monkeypatch):
    """Ignoring an argument means proceeding on the overlap between what the
    caller meant and what this understood — the same mistake
    ``Request.from_json`` refuses to make about parameters.

    ``--elevated-helper-x`` and a case variant are in the list because an
    exact-string comparison is what is being asserted: a prefix match or a
    case-insensitive one would accept these.
    """
    import polyscour.app as app
    monkeypatch.setattr(app, "main",
                        lambda: pytest.fail(f"{args} started the GUI"))

    assert entry.main(args) == 2


def test_the_helper_flag_with_the_wrong_number_of_paths_is_refused():
    """Validation stays in one place — the helper already refuses this — but
    the entry point must not paper over it by picking one of them."""
    assert entry.main(["--elevated-helper"]) == 2
    assert entry.main(["--elevated-helper", "a.json", "b.json"]) == 2


# ── the two modes name something that exists ────────────────────────────────

def test_the_source_command_names_this_interpreter_and_the_entry_module(frozen):
    frozen(False)
    executable, args = _helper_command(Path(r"C:\Tmp\request.json"))

    assert Path(executable).name.lower().startswith("python")
    assert "-m polyscour.entry" in args
    assert "--elevated-helper" in args


def test_the_frozen_command_names_the_executable_itself(frozen):
    """The bug this file exists for.

    Nuitka does not set ``sys.frozen``; it injects ``__compiled__``. Testing
    the wrong flag meant a compiled build would have run
    ``PolyScour.exe -m polyscour.entry ...`` — an argument the executable
    refuses — and nothing in development would ever have shown it.
    """
    frozen(True)
    executable, args = _helper_command(Path(r"C:\Tmp\request.json"))

    assert executable == sys.executable
    assert "-m " not in args, (
        "a compiled build was told to run a module; it has no interpreter")
    assert args.startswith("--elevated-helper ")


def test_the_two_modes_disagree(frozen):
    """A predicate that always answered the same way would satisfy both of the
    tests above separately. This is the one that notices."""
    frozen(False)
    source = _helper_command(Path(r"C:\Tmp\r.json"))
    frozen(True)
    compiled = _helper_command(Path(r"C:\Tmp\r.json"))

    assert source != compiled


def test_a_request_path_with_spaces_survives_the_command_line(frozen):
    """%LOCALAPPDATA% contains a space on any machine whose user name does."""
    frozen(True)
    _, args = _helper_command(Path(r"C:\Users\A B\AppData\Local\Temp\r.json"))
    assert '"C:\\Users\\A B\\AppData\\Local\\Temp\\r.json"' in args


# ── the elevated process does not load a GUI ────────────────────────────────

def test_the_elevated_branch_never_imports_the_gui(tmp_path):
    r"""Run it for real, in a subprocess, and look at what got loaded.

    ``app.py`` imports CustomTkinter at module scope, and importing that
    imports Tk and Tcl. Dispatching the helper from there would put a GUI
    toolkit inside an elevated process — tens of thousands of lines running as
    administrator to delete one file, in a program whose threat model says the
    elevated part is deliberately small.

    Asserted in a subprocess because pytest has already imported CustomTkinter
    for the UI tests, so checking ``sys.modules`` in-process would prove
    nothing at all.
    """
    request = tmp_path / "request.json"
    request.write_text(Request(
        operation=Operation.DELETE_APPROVED_PATH,
        params={"rule_id": "no-such-rule", "path": str(tmp_path / "x")},
    ).to_json(), encoding="utf-8")

    probe = (
        "import sys\n"
        "from polyscour.entry import main\n"
        f"code = main(['--elevated-helper', {str(request)!r}])\n"
        "gui = {'customtkinter', 'tkinter', 'PIL', 'pystray'}\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in gui)\n"
        "print(repr((code, loaded)))\n"
    )
    done = subprocess.run([sys.executable, "-c", probe],
                          capture_output=True, text=True, timeout=120)

    assert done.returncode == 0, done.stderr
    code, loaded = eval(done.stdout.strip())
    assert loaded == [], f"the elevated branch imported {loaded}"

    # And it really did the work rather than exiting early: an unknown rule is
    # a refusal, and the refusal was written out where a client would find it.
    # "guard" rather than "policy" because the single-path operation reaches
    # the policy lookup through authorize(), which reports the chain link that
    # said no.
    response = Response.from_json(
        request.with_suffix(".json.response").read_text(encoding="utf-8"))
    assert response.ok is False
    assert response.refused_by == "guard"
    assert code == 1, "a refusal is a non-zero exit"


# ── the data root does not move ─────────────────────────────────────────────

def test_the_data_root_is_user_scoped_in_both_modes(frozen, monkeypatch):
    """docs/adr/0005: the vault stays in %LOCALAPPDATA%.

    Freezing must not quietly relocate a user's vault and ledger. Asserted in
    both modes, so "installed builds are different" cannot creep back in
    without this failing.
    """
    monkeypatch.delenv("POLYSCOUR_DATA_DIR", raising=False)
    from polyscour import paths

    frozen(False)
    source_root = paths.app_root()
    frozen(True)
    frozen_root = paths.app_root()

    assert source_root == frozen_root
    assert "ProgramData" not in str(frozen_root)


def test_the_data_dir_override_still_wins_when_frozen(frozen, monkeypatch,
                                                      tmp_path):
    """It is what keeps the suite and tools/uishot off the real vault, and it
    must not be a source-only convenience."""
    from polyscour import paths

    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(tmp_path / "elsewhere"))
    frozen(True)

    assert paths.app_root() == tmp_path / "elsewhere"


# ── resources vs data ───────────────────────────────────────────────────────

def test_the_rules_are_found_in_a_checkout(frozen):
    """The control. Everything below is about the frozen case, and none of it
    means anything if the ordinary one is broken."""
    frozen(False)
    from polyscour import paths

    assert paths.rules_dir().is_dir()
    assert sorted(p.name for p in paths.rules_dir().glob("*.json"))


def test_a_build_looks_one_level_shallower_for_its_resources(frozen):
    r"""A build has no ``src/`` level, so the same expression walks one
    directory too high.

    Asserted as a *relationship* rather than a literal path, because the
    literal differs between a checkout and a build and only one of them exists
    here. PolyShield hit this exact off-by-one and its docstring says what
    caught it: a probe run inside a real build, because no unit test can.
    """
    from polyscour import paths

    frozen(False)
    source = paths.resource_root()
    frozen(True)
    built = paths.resource_root()

    assert built == source / "src", (
        "the frozen resource root is not one level below the checkout root; "
        "the level adjustment and the source layout have diverged")


def test_the_rules_live_under_the_resource_root_in_both_modes(frozen):
    """They ship with the program, so they belong to the disposable half."""
    from polyscour import paths

    for mode in (False, True):
        frozen(mode)
        assert paths.rules_dir().is_relative_to(paths.resource_root())


def test_the_data_root_is_never_under_the_resource_root(frozen, monkeypatch):
    r"""The failure that silently destroys a vault.

    A onefile extraction directory is deleted when the process exits. A data
    root resolved underneath it would lose every file a user believed was
    recoverable — and would do so quietly, because the vault would look empty
    rather than missing.
    """
    monkeypatch.delenv("POLYSCOUR_DATA_DIR", raising=False)
    from polyscour import paths

    for mode in (False, True):
        frozen(mode)
        assert not paths.app_root().is_relative_to(paths.resource_root())


def test_the_probe_reports_a_durable_path_under_the_extraction_directory(
        frozen, monkeypatch, tmp_path):
    """The probe is the build gate, so its findings need a test of their own.

    Driven by pointing the data root *inside* the resource root, which is the
    shape of the real failure.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_probe", Path(__file__).resolve().parents[1] / "tools" / "build_probe.py")
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)

    from polyscour import paths

    frozen(False)
    monkeypatch.setenv("POLYSCOUR_DATA_DIR", str(paths.resource_root() / "data"))

    report = probe.collect(expect_frozen=False)

    assert report["ok"] is False
    assert any("underneath the resource root" in f for f in report["findings"])


def test_the_probe_is_clean_on_an_ordinary_checkout(frozen, monkeypatch):
    """The control for the test above: it must not report everything."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_probe", Path(__file__).resolve().parents[1] / "tools" / "build_probe.py")
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)

    monkeypatch.delenv("POLYSCOUR_DATA_DIR", raising=False)
    frozen(False)

    report = probe.collect(expect_frozen=False)

    assert report["ok"] is True, report["findings"]
    assert report["rule_files"], "the checkout could not find its own rules"


# ── the third program ───────────────────────────────────────────────────────

def test_the_supervisor_flag_runs_the_supervisor_and_not_the_application(
        monkeypatch):
    import polyscour.app as app
    import polyscour.gamemode.supervisor as supervisor

    monkeypatch.setattr(app, "main",
                        lambda: pytest.fail("started the GUI to supervise"))
    seen = []
    monkeypatch.setattr(supervisor, "main", lambda argv: seen.append(argv) or 0)

    assert entry.main(["--supervise-game-mode", "4321", "1.5"]) == 0
    assert seen == [["4321", "1.5"]]


@pytest.mark.parametrize("args", [
    ["--supervise-game-mode-x", "1", "2"],
    ["--SUPERVISE-GAME-MODE", "1", "2"],
    ["-supervise-game-mode", "1", "2"],
])
def test_a_near_miss_of_the_supervisor_flag_is_still_unknown(args, monkeypatch):
    """Adding a second flag must not turn the comparison into a prefix match."""
    import polyscour.app as app
    monkeypatch.setattr(app, "main",
                        lambda: pytest.fail(f"{args} started the GUI"))

    assert entry.main(args) == 2


def test_the_supervisor_branch_never_imports_the_gui(tmp_path):
    """Same property as the elevated branch, for the same reason.

    This one may outlive the window by seconds; there is no sense keeping Tk
    loaded to resume a process.
    """
    probe = (
        "import sys\n"
        "from polyscour.entry import main\n"
        # A pid that cannot exist, so it exits without waiting on anything.
        "code = main(['--supervise-game-mode', '0', '1.0'])\n"
        "gui = {'customtkinter', 'tkinter', 'PIL', 'pystray'}\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in gui)\n"
        "print(repr((code, loaded)))\n"
    )
    done = subprocess.run([sys.executable, "-c", probe],
                          capture_output=True, text=True, timeout=120)

    assert done.returncode == 0, done.stderr
    code, loaded = eval(done.stdout.strip())
    assert code == 2, "a pid of 0 should have been refused"
    assert loaded == [], f"the supervisor branch imported {loaded}"


def test_child_argv_is_the_one_place_the_frozen_question_is_asked(frozen):
    """Three callers now re-invoke this program. The frozen/source distinction
    has already been got wrong once; it is asked in one place so it cannot be
    got wrong differently in each."""
    from polyscour.entry import (HELPER_FLAG, SUPERVISOR_FLAG, child_argv)

    frozen(False)
    assert child_argv(HELPER_FLAG, "r.json")[:3] == [
        sys.executable, "-m", "polyscour.entry"]

    from polyscour import paths

    frozen(True)
    assert child_argv(SUPERVISOR_FLAG, "1", "2.0") == [
        str(paths.running_executable()), SUPERVISOR_FLAG, "1", "2.0"]



# ── what gets elevated ──────────────────────────────────────────────────────

def test_a_frozen_child_is_launched_from_the_real_executable(frozen,
                                                             monkeypatch):
    r"""T23. Measured inside a real onefile build, not reasoned about:

        sys.executable              %TEMP%\onefile_<n>\python.exe
        __compiled__.original_argv0 <install>\PolyScour.exe

    One of the callers of ``child_argv`` elevates what it is handed, and the
    extraction directory is writable by the user. Naming ``sys.executable``
    there would let anything running as that user replace the binary between
    extraction and the consent prompt — with PolyScour's name on the dialog.
    """
    from polyscour import paths
    from polyscour.entry import HELPER_FLAG, child_argv

    fake_exe = Path(r"C:\Program Files\PolyScour\PolyScour.exe")
    monkeypatch.setattr(paths, "running_executable", lambda: fake_exe)
    frozen(True)

    argv = child_argv(HELPER_FLAG, "r.json")

    assert argv[0] == str(fake_exe)
    assert "Temp" not in argv[0]


def test_elevation_is_refused_when_the_image_sits_somewhere_writable(
        frozen, monkeypatch, tmp_path):
    """Defence in depth behind running_executable().

    The bug this guards against shipped in a form nothing could catch from
    source. If it ever comes back, this makes it fail closed instead of
    escalating.
    """
    import polyscour.elevation.client as client

    writable = tmp_path / "onefile_12345"
    writable.mkdir()
    exe = writable / "python.exe"
    exe.write_text("not really", encoding="utf-8")

    frozen(True)
    monkeypatch.setattr(client, "_helper_command",
                        lambda path: (str(exe), "--elevated-helper x"))
    monkeypatch.setattr(
        client, "ShellExecuteW_should_never_be_reached", None, raising=False)

    assert client._is_safe_to_elevate(exe) is False


def test_an_administrator_only_directory_is_safe_to_elevate(frozen):
    """The control. A check that refuses everything protects nothing, and
    would take the feature down instead of the attack."""
    import polyscour.elevation.client as client

    frozen(True)
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidate = program_files / "Windows Defender" / "MsMpEng.exe"
    if not candidate.parent.is_dir():
        pytest.skip("no administrator-only directory available to test with")

    assert client._is_safe_to_elevate(candidate) is True


def test_a_source_checkout_is_never_refused(frozen):
    """Running from source elevates the venv's python.exe, which is
    user-writable by construction. That is a development posture, and T15
    already says a release must be installed rather than unzipped."""
    import polyscour.elevation.client as client

    frozen(False)
    assert client._is_safe_to_elevate(Path(sys.executable)) is True
