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
