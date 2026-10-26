r"""The command line (adr/0017): read-only, GUI-free, and honest about what it
could not read.

The properties that matter are negative ones -- it creates nothing, imports no
toolkit, never calls an unread rule empty -- so most of what follows is a check
that something did NOT happen. Each of those has a control somewhere that shows
the check can fail; a negative assertion that cannot fail is the kind of test
that passes for the wrong reason.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from polyscour import cli, entry, paths
from polyscour.contracts import (Evidence, Finding, RiskLevel, RuleOutcome,
                                 ScanResult)
from polyscour.ledger import Ledger


# ── builders ─────────────────────────────────────────────────────────────────

def _finding(rule_id="cache-a", path="C:/x/a.tmp", size=2048, *,
             risk=RiskLevel.SAFE, reversible=False, admin=False,
             mechanism="user_temp"):
    return Finding(rule_id=rule_id, title="a file", path=Path(path),
                   size_bytes=size, risk=risk, reversible=reversible,
                   requires_elevation=admin,
                   evidence=Evidence(mechanism=mechanism, observation="1 file",
                                     rationale="regenerated on demand"))


def _result(*outcomes, cancelled=False):
    now = datetime(2026, 10, 26, 12, 0, 0)
    return ScanResult(started_at=now, finished_at=now,
                      outcomes=list(outcomes), cancelled=cancelled)


def _rules(*ids):
    return [SimpleNamespace(id=i, name=f"Rule {i}") for i in ids]


@pytest.fixture
def scan_stub(monkeypatch):
    """Replace the two seams that touch the machine; record what they got."""
    calls = {}

    def install(result, rules=("cache-a", "cache-b"), disabled=(), failures=()):
        loaded = _rules(*rules)
        monkeypatch.setattr(cli, "_load_rules",
                            lambda: (loaded, list(failures), set(disabled)))

        def collect(chosen, include_bin):
            calls["chosen"] = [r.id for r in chosen]
            calls["include_bin"] = include_bin
            return result
        monkeypatch.setattr(cli, "_collect_scan", collect)
        return calls
    return install


def _run(argv):
    out = io.StringIO()
    code = cli.main(argv, out=out)
    return code, out.getvalue()


# ── scan: rendering and exit codes ───────────────────────────────────────────

def test_a_clean_scan_says_nothing_was_changed_and_exits_zero(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [_finding(size=4096)])))
    code, text = _run(["scan"])
    assert code == cli.EXIT_OK
    assert "Read-only: nothing was changed" in text
    assert "Rule cache-a (cache-a)" in text
    assert "Safe risk" in text and "Not reversible" in text
    assert "Reads: user_temp" in text        # the mechanism, as the rule states it


def test_an_aborted_rule_is_not_reported_as_nothing_found(scan_stub):
    """The exact silent failure the project exists to avoid: unread != empty."""
    scan_stub(_result(RuleOutcome("cache-a", [], aborted=True,
                                  abort_reason="matched 842,000 files")))
    code, text = _run(["scan"])
    assert code == cli.EXIT_PARTIAL
    assert "NOT READ" in text and "842,000" in text
    assert "Nothing found" not in text


def test_a_rule_with_no_findings_and_no_fault_is_nothing_found(scan_stub):
    """The control for the test above: the words are not simply never printed."""
    scan_stub(_result(RuleOutcome("cache-a", [])))
    code, text = _run(["scan"])
    assert code == cli.EXIT_OK and "Nothing found." in text


def test_a_rule_file_that_did_not_load_makes_the_run_partial(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [])),
              failures=[(Path("bad.json"), ValueError("no patterns"))])
    code, text = _run(["scan"])
    assert code == cli.EXIT_PARTIAL
    assert "NOT READ: rule file bad.json" in text


def test_a_cancelled_scan_is_partial_and_says_so(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", []), cancelled=True))
    code, text = _run(["scan"])
    assert code == cli.EXIT_PARTIAL and "NOT FINISHED" in text


def test_the_administrator_count_is_a_fact_and_nothing_is_requested(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [_finding(admin=True)])))
    _, text = _run(["scan"])
    assert "1 need administrator rights. This command never asks" in text


def test_polyshield_withheld_items_are_counted_not_hidden(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [], withheld_by_polyshield=3)))
    _, text = _run(["scan"])
    assert "3 left out: PolyShield has a recorded detection" in text


def test_mixed_reversibility_is_not_rounded_to_either_answer(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [
        _finding(reversible=True), _finding(path="C:/x/b", reversible=False)])))
    _, text = _run(["scan"])
    assert "1 of 2 recoverable from the vault" in text


def test_paths_are_listed_only_on_request(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [_finding(path="C:/x/secret.tmp")])))
    assert "secret.tmp" not in _run(["scan"])[1]
    assert "secret.tmp" in _run(["scan", "--list"])[1]


def test_json_is_a_stable_document_with_every_path(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [_finding(path="C:/x/secret.tmp",
                                                       size=10)])))
    code, text = _run(["scan", "--json"])
    doc = json.loads(text)
    assert code == cli.EXIT_OK
    assert doc["schema"] == cli.SCHEMA and doc["read_only"] is True
    assert doc["total_bytes"] == 10 and doc["total_findings"] == 1
    rule = doc["rules"][0]
    assert rule["aborted"] is False and rule["finding_count"] == 1
    found = rule["findings"][0]
    assert found["path"].endswith("secret.tmp")
    assert found["risk"] == "safe" and found["reversible"] is False
    assert found["evidence"]["mechanism"] == "user_temp"


def test_json_marks_an_aborted_rule_and_exits_partial(scan_stub):
    scan_stub(_result(RuleOutcome("cache-a", [], aborted=True,
                                  abort_reason="too many")))
    code, text = _run(["scan", "--json"])
    doc = json.loads(text)
    assert code == cli.EXIT_PARTIAL
    assert doc["rules"][0]["aborted"] is True
    assert doc["rules"][0]["abort_reason"] == "too many"


# ── scan: choosing rules ─────────────────────────────────────────────────────

def test_the_default_scan_honours_rules_disabled_in_settings(scan_stub):
    calls = scan_stub(_result(), disabled={"cache-b"})
    _run(["scan"])
    assert calls["chosen"] == ["cache-a"] and calls["include_bin"] is True


def test_naming_a_disabled_rule_is_refused_not_a_way_around_settings(
        scan_stub, capsys):
    calls = scan_stub(_result(), disabled={"cache-b"})
    code, _ = _run(["scan", "--rule", "cache-b"])
    assert code == cli.EXIT_USAGE and "chosen" not in calls
    assert "disabled in Settings" in capsys.readouterr().err


def test_an_unknown_rule_is_refused_and_the_known_ones_are_named(
        scan_stub, capsys):
    scan_stub(_result())
    code, _ = _run(["scan", "--rule", "nope"])
    err = capsys.readouterr().err
    assert code == cli.EXIT_USAGE
    assert "unknown rule: nope" in err and "cache-a" in err and "recycle-bin" in err


def test_naming_rules_scans_just_those_and_not_the_recycle_bin(scan_stub):
    calls = scan_stub(_result())
    _run(["scan", "--rule", "cache-b", "--rule", "cache-b"])
    assert calls["chosen"] == ["cache-b"] and calls["include_bin"] is False


def test_the_recycle_bin_can_be_named_on_its_own(scan_stub):
    calls = scan_stub(_result())
    _run(["scan", "--rule", "recycle-bin"])
    assert calls["chosen"] == [] and calls["include_bin"] is True


# ── history ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger_file(tmp_path, monkeypatch):
    path = tmp_path / "data" / "ledger.sqlite"
    monkeypatch.setattr(paths, "ledger_path", lambda: path)
    return path


def _seed(path, *, dry_run=False, started="2026-10-20T09:00:00"):
    Ledger(path).initialise()
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO operations (operation_id, started_at, finished_at,"
        " outcome, dry_run, bytes_freed, items_completed, rule_ids, summary)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (f"op-{started}", started, started, "success", int(dry_run),
         5 * 1024 ** 2, 12, json.dumps(["user-temp", "pip-cache"]),
         "Cleaned 12 item(s)."))
    conn.commit()
    conn.close()


def test_history_with_no_ledger_says_so_and_creates_nothing(ledger_file):
    code, text = _run(["history"])
    assert code == cli.EXIT_OK and "no ledger exists" in text
    assert not ledger_file.parent.exists(), "a read created the data directory"


def test_the_ordinary_ledger_read_DOES_create_state__which_is_why_the_cli_does_not_use_it(
        ledger_file):
    """The control for the test above, and the reason ``history_readonly``
    exists. If this ever stops creating a file, the premise has changed and the
    new method may be unnecessary -- delete it then, deliberately."""
    Ledger(ledger_file).history()
    assert ledger_file.is_file()


def test_history_json_distinguishes_no_ledger_from_an_empty_one(ledger_file):
    absent = json.loads(_run(["history", "--json"])[1])
    assert absent["ledger_exists"] is False and absent["operations"] == []

    Ledger(ledger_file).initialise()
    empty = json.loads(_run(["history", "--json"])[1])
    assert empty["ledger_exists"] is True and empty["operations"] == []
    assert "holds no operations" in _run(["history"])[1]


def test_history_lists_what_was_recorded_and_labels_a_rehearsal(ledger_file):
    _seed(ledger_file, started="2026-10-20T09:00:00")
    _seed(ledger_file, dry_run=True, started="2026-10-21T09:00:00")
    code, text = _run(["history"])
    assert code == cli.EXIT_OK
    newest, older = text.index("2026-10-21"), text.index("2026-10-20")
    assert newest < older, "newest first"
    assert "dry run" in text and "A rehearsal: nothing was changed." in text
    assert "5.0 MB" in text and "user-temp, pip-cache" in text


def test_history_json_carries_structured_fields(ledger_file):
    _seed(ledger_file)
    op = json.loads(_run(["history", "--json"])[1])["operations"][0]
    assert op["rule_ids"] == ["user-temp", "pip-cache"]
    assert op["dry_run"] is False and op["bytes_freed"] == 5 * 1024 ** 2
    assert op["elevation"] == {"requested": 0, "granted": 0,
                               "attempted": 0, "succeeded": 0}


def test_reading_history_does_not_touch_the_ledger_file(ledger_file):
    _seed(ledger_file)
    before = hashlib.sha256(ledger_file.read_bytes()).hexdigest()
    _run(["history"]); _run(["history", "--json"])
    assert hashlib.sha256(ledger_file.read_bytes()).hexdigest() == before
    assert sorted(p.name for p in ledger_file.parent.iterdir()) == [
        "ledger.sqlite"], "a journal, lock or backup appeared beside it"


def test_an_old_ledger_is_read_as_it_is_and_not_migrated(ledger_file):
    """``_conn()`` would add the elevation columns. A read must not. Absent
    columns are reported as absent, never as 'no elevation'."""
    ledger_file.parent.mkdir(parents=True)
    conn = sqlite3.connect(ledger_file)
    conn.execute(
        "CREATE TABLE operations (operation_id TEXT PRIMARY KEY, started_at TEXT,"
        " finished_at TEXT, outcome TEXT, dry_run INTEGER, bytes_freed INTEGER,"
        " items_completed INTEGER, rule_ids TEXT, summary TEXT)")
    conn.execute("INSERT INTO operations VALUES"
                 " ('o','2026-01-01T00:00:00','2026-01-01T00:00:00','success',"
                 "0,1,1,'[\"a\"]','old')")
    conn.commit(); conn.close()
    before = ledger_file.read_bytes()

    op = json.loads(_run(["history", "--json"])[1])["operations"][0]
    assert op["elevation"] is None
    assert ledger_file.read_bytes() == before


def test_an_unreadable_ledger_is_not_shown_as_empty(ledger_file, capsys):
    ledger_file.parent.mkdir(parents=True)
    ledger_file.write_bytes(b"this is not a database" * 50)
    code, text = _run(["history"])
    assert code == cli.EXIT_COULD_NOT_RUN
    assert "could not be read" in capsys.readouterr().err
    assert "no ledger" not in text and "no operations" not in text


def test_history_limit_must_be_positive(ledger_file, capsys):
    code, _ = _run(["history", "--limit", "0"])
    assert code == cli.EXIT_USAGE
    assert "at least 1" in capsys.readouterr().err


# ── arguments and dispatch ───────────────────────────────────────────────────

def test_an_abbreviated_option_is_not_accepted(scan_stub):
    """``--js`` is not ``--json``: entry.py's rule about near misses."""
    scan_stub(_result())
    assert _run(["scan", "--js"])[0] == cli.EXIT_USAGE


def test_an_unknown_option_or_verb_is_a_usage_error(scan_stub):
    scan_stub(_result())
    assert _run(["scan", "--delete"])[0] == cli.EXIT_USAGE
    assert _run(["clean"])[0] == cli.EXIT_USAGE
    assert _run([])[0] == cli.EXIT_USAGE


def test_the_flag_is_routed_and_a_bare_verb_is_still_an_unknown_argument(
        monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(cli, "main", lambda argv, out=None: seen.append(argv) or 0)
    assert entry.main([entry.CLI_FLAG, "scan", "--json"]) == 0
    assert seen == [["scan", "--json"]]
    assert entry.main(["scan"]) == 2
    assert "unknown argument: 'scan'" in capsys.readouterr().err


def test_without_a_console_it_declines_instead_of_crashing(monkeypatch):
    """A build with --windows-console-mode=disable has no stdout at all."""
    monkeypatch.setattr(sys, "stdout", None)
    assert cli.main(["history"]) == cli.EXIT_COULD_NOT_RUN


def test_a_path_a_legacy_console_cannot_encode_does_not_lose_the_report():
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    cli._never_fail_on_encoding(stream)
    print("C:\\Users\\x\\日本語.tmp", file=stream)
    stream.flush()
    assert b"\\u65e5" in raw.getvalue()


def test_interrupting_a_scan_says_nothing_had_changed(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_load_rules",
                        lambda: (_rules("cache-a"), [], set()))

    def boom(*a):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "_collect_scan", boom)
    assert _run(["scan"])[0] == cli.EXIT_INTERRUPTED
    assert "Nothing had been changed" in capsys.readouterr().err


# ── the real entry point, in a subprocess ────────────────────────────────────

def _run_entry(tmp_path, *argv):
    env = dict(os.environ, POLYSCOUR_DATA_DIR=str(tmp_path / "data"))
    probe = (
        "import sys\n"
        "from polyscour.entry import main\n"
        f"code = main(['--cli', *{list(argv)!r}])\n"
        "gui = {'customtkinter', 'tkinter', 'PIL', 'pystray'}\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in gui)\n"
        "sys.stderr.write(repr((code, loaded)))\n"
    )
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                          text=True, timeout=120, env=env)
    code, loaded = eval(done.stderr.strip().splitlines()[-1])
    return done, code, loaded


def test_history_through_the_real_entry_point_imports_no_gui_and_creates_nothing(
        tmp_path):
    done, code, loaded = _run_entry(tmp_path, "history")
    assert done.returncode == 0, done.stderr
    assert loaded == [], f"the CLI branch imported {loaded}"
    assert code == 0 and "no ledger exists" in done.stdout
    assert not (tmp_path / "data").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="asks the Windows Shell")
def test_a_real_scan_through_the_entry_point_is_json_and_creates_nothing(
        tmp_path):
    """The Recycle Bin is the one real scan fast enough for the suite; it still
    builds the real Guard, advisor, scanner and settings. The full file-rule
    scan takes about 40 s and was run by hand when this was written."""
    done, code, loaded = _run_entry(tmp_path, "scan", "--rule", "recycle-bin",
                                    "--json")
    assert done.returncode == 0, done.stderr
    assert loaded == []
    doc = json.loads(done.stdout)
    assert doc["read_only"] is True
    assert [r["rule_id"] for r in doc["rules"]] == ["recycle-bin"]
    assert not (tmp_path / "data").exists(), "a scan created state"
