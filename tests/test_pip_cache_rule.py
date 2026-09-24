r"""The pip-cache rule: the first cleaner for a *developer* tool, and what is specific to it.

The generic guard, rule and executor tests already run over every policy entry.
What needs its own tests is what is particular to pip, and each of these is a way
a plausible implementation deletes something it should not:

* **the location must not be redirectable.** pip lets a user move its cache with
  ``PIP_CACHE_DIR`` or a ``pip.ini``. Following either turns "delete pip's cache"
  into "delete whatever a config file names" -- configuration is not authority.
* **the real layout must be fully reachable** -- pip nests its cache six levels
  deep, and a depth ceiling that stops short leaves most of it behind silently.
* **a file a live pip has open must be skipped, not forced.**
* **a junction planted in the cache must not be followed out of it.**
"""
from __future__ import annotations

import os
import subprocess

import pytest

from polyscour import paths
from polyscour.cleaning.executor import Executor
from polyscour.cleaning.planner import plan
from polyscour.cleaning.rules import RuleError, load_file, parse
from polyscour.cleaning.scanner import Scanner
from polyscour.contracts import RiskLevel, SkipReason
from polyscour.ledger import Ledger
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import (POLICY, Operation, RootFamily, Scope,
                                     permitted_roots, resolve_family)
from polyscour.vault import Vault

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

RULE_ID = "pip-cache"


def make_junction(link, target) -> bool:
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    return r.returncode == 0


@pytest.fixture
def local(monkeypatch, tmp_path):
    """A %LOCALAPPDATA% of our own, with every pip redirect switched off."""
    base = tmp_path / "local"
    base.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(base))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    for var in ("PIP_CACHE_DIR", "PIP_CONFIG_FILE"):
        monkeypatch.delenv(var, raising=False)
    return base


@pytest.fixture
def cache(local):
    """pip's default cache, laid out the way pip lays it out (measured: depth 6)."""
    root = local / "pip" / "Cache"
    for sub in ("http-v2/a/b/c/d/e", "http-v2/f/0/1/2/3", "http/9/8/7/6/5",
                "wheels/ab/cd/ef/0123456789", "selfcheck"):
        (root / sub).mkdir(parents=True)
    (root / "http-v2/a/b/c/d/e/deadbeef").write_bytes(b"h" * 100)
    (root / "http-v2/a/b/c/d/e/deadbeef.body").write_bytes(b"b" * 4000)
    (root / "http-v2/f/0/1/2/3/cafe.body").write_bytes(b"c" * 900)
    (root / "http/9/8/7/6/5/old.body").write_bytes(b"o" * 50)
    (root / "wheels/ab/cd/ef/0123456789/pkg-1.0-py3-none-any.whl").write_bytes(b"w" * 2000)
    (root / "selfcheck/abc123").write_text("{}", encoding="utf-8")
    return root.resolve()


@pytest.fixture
def rule():
    return load_file(paths.rules_dir() / "pip-cache.json")


def scan(rule):
    return Scanner(guard=Guard()).scan([rule]).outcomes[0]


def execute(tmp_path, findings, *, dry_run):
    ex = Executor(vault=Vault(tmp_path / "vault"),
                  ledger=Ledger(tmp_path / "history.sqlite"), guard=Guard())
    return ex.execute(plan(findings, dry_run=dry_run))


def files_under(root):
    return sorted(p for p in root.rglob("*") if p.is_file())


# ══ What the policy grants ════════════════════════════════════════════════════

def test_the_policy_grants_exactly_one_family_and_only_delete():
    entry = POLICY[RULE_ID]
    assert entry.families == frozenset({RootFamily.PIP_CACHE})
    assert entry.operations == frozenset({Operation.DELETE})
    assert entry.scope is Scope.ONE_DIRECTORY
    # Ceilings are safety limits, so they are pinned to a band rather than left
    # free to drift: deep enough for pip's real layout (6), no deeper than a
    # planted structure should be walked.
    assert 6 <= entry.max_depth <= 12
    assert entry.max_bytes <= 64 * 1024**3
    # No age floor: this is not a working directory, and nothing elevated acts
    # on it, so there is no helper that needs a floor it can trust.
    assert entry.min_age_days == 0


def test_the_rule_is_offered_unticked(rule):
    """Regenerable, but the rebuild costs bandwidth and, offline, can be a
    failed install -- not something a pre-ticked box should decide for anyone
    (adr/0009 addendum)."""
    from datetime import datetime, timezone
    from pathlib import Path

    from polyscour.cleaning.planner import recommend
    from polyscour.contracts import Evidence, Finding, RuleOutcome, ScanResult

    def recommended(risk):
        now = datetime.now(timezone.utc)
        f = Finding(rule_id=rule.id, title="t", path=Path(r"C:\x\a"),
                    size_bytes=1, risk=risk, reversible=False,
                    evidence=Evidence("m", "o", "r"))
        (rec,) = recommend(ScanResult(started_at=now, finished_at=now, outcomes=[
            RuleOutcome(rule_id=rule.id, findings=[f])]))
        return rec.recommended

    assert recommended(RiskLevel.SAFE) is True      # the control
    assert recommended(rule.risk) is False


def test_the_rule_loads_reconciled_with_its_policy(rule):
    assert rule.id == RULE_ID
    assert rule.risk is RiskLevel.LOW
    assert rule.operation is Operation.DELETE and not rule.reversible
    assert rule.requires_elevation is False
    assert rule.families == (RootFamily.PIP_CACHE,)


def test_a_rule_cannot_claim_a_second_family_from_the_pip_policy():
    """Authority narrows outward. A pip rule that also asked for user_temp would
    be a cleaner that reaches somewhere its reviewed entry never granted."""
    raw = {"id": RULE_ID, "name": "x", "description": "x", "category": "Developer",
           "risk": "safe", "patterns": ["*"],
           "root_families": ["pip_cache", "user_temp"]}
    with pytest.raises(RuleError, match="does not grant"):
        parse(raw)


# ══ The location is not redirectable ══════════════════════════════════════════

def test_the_family_resolves_to_pips_default_cache_and_nothing_else(cache, local):
    assert resolve_family(RootFamily.PIP_CACHE) == [cache]
    assert permitted_roots(RULE_ID) == [cache]


def test_no_cache_at_all_is_nothing_to_scan_not_an_error(local, rule):
    assert resolve_family(RootFamily.PIP_CACHE) == []
    out = scan(rule)
    assert out.aborted and "nothing to scan" in out.abort_reason


@pytest.fixture
def precious(tmp_path):
    d = tmp_path / "Documents-ish"
    d.mkdir()
    (d / "thesis.txt").write_text("years of work", encoding="utf-8")
    return d


def redirect_everything_at(precious, monkeypatch, tmp_path):
    """Every way pip lets a user move its cache, all pointing at ``precious``."""
    monkeypatch.setenv("PIP_CACHE_DIR", str(precious))
    ini = tmp_path / "pip.ini"
    ini.write_text(f"[global]\ncache-dir = {precious}\n", encoding="utf-8")
    monkeypatch.setenv("PIP_CONFIG_FILE", str(ini))
    user_ini = tmp_path / "roaming" / "pip" / "pip.ini"
    user_ini.parent.mkdir(parents=True)
    user_ini.write_text(f"[global]\ncache-dir = {precious}\n", encoding="utf-8")


def test_a_redirect_in_the_environment_or_an_ini_is_not_followed(
        cache, precious, monkeypatch, tmp_path):
    """The reason this family reads no pip configuration.

    ``cache-dir = <a folder that matters>`` is data somebody else controls. If
    the resolver honoured it, deleting pip's cache would mean deleting that. The
    control is that the redirect really is in place -- so a resolver that DID
    follow it would fail here rather than pass by accident.
    """
    redirect_everything_at(precious, monkeypatch, tmp_path)
    assert os.environ["PIP_CACHE_DIR"] == str(precious)      # the trap is set

    assert resolve_family(RootFamily.PIP_CACHE) == [cache]
    assert precious.resolve() not in permitted_roots(RULE_ID)


def test_the_guard_refuses_a_target_in_a_redirected_directory(
        cache, precious, monkeypatch, tmp_path):
    redirect_everything_at(precious, monkeypatch, tmp_path)
    with pytest.raises(GuardRefusal, match="under none of its permitted roots"):
        Guard().authorize(RULE_ID, precious / "thesis.txt", Operation.DELETE)


def test_a_redirect_with_no_default_cache_scans_nothing_rather_than_the_redirect(
        local, precious, monkeypatch, tmp_path, rule):
    redirect_everything_at(precious, monkeypatch, tmp_path)
    out = scan(rule)
    assert out.aborted and out.findings == []
    assert (precious / "thesis.txt").read_text(encoding="utf-8") == "years of work"


# ══ The real layout is reachable ══════════════════════════════════════════════

def test_every_file_in_pips_real_layout_is_found(cache, rule):
    """Measured on a real cache: files at depth 1, 5 and 6. A ceiling that stops
    short would leave most of the cache behind, and say nothing."""
    out = scan(rule)
    assert not out.aborted
    assert sorted(f.path for f in out.findings) == files_under(cache)
    assert rule.max_depth >= 6


def test_a_tree_deeper_than_pip_ever_makes_is_left_alone(cache, rule):
    """The depth ceiling is a blast-radius limit; this pins where it bites."""
    deep = cache
    for i in range(rule.max_depth + 2):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    stray = deep / "unexpected.bin"
    stray.write_text("x", encoding="utf-8")

    found = {f.path for f in scan(rule).findings}
    assert stray.resolve() not in found


# ══ Cleaning it ═══════════════════════════════════════════════════════════════

def test_a_dry_run_changes_nothing(cache, rule, tmp_path):
    before = {p: p.stat().st_size for p in files_under(cache)}
    result = execute(tmp_path, scan(rule).findings, dry_run=True)
    assert {p: p.stat().st_size for p in files_under(cache)} == before
    assert result.dry_run and result.items_completed == len(before)


def test_a_real_run_removes_the_files_and_only_the_files(cache, local, rule, tmp_path):
    """The executor unlinks files. It has no directory removal at all, so the
    empty folders stay -- and nothing outside ``Cache`` is touched."""
    sibling = local / "pip" / "keep-me.txt"
    sibling.write_text("not the cache", encoding="utf-8")
    dirs_before = sorted(p for p in cache.rglob("*") if p.is_dir())

    result = execute(tmp_path, scan(rule).findings, dry_run=False)

    assert files_under(cache) == []
    assert sorted(p for p in cache.rglob("*") if p.is_dir()) == dirs_before
    assert cache.is_dir()
    assert sibling.read_text(encoding="utf-8") == "not the cache"
    assert result.bytes_freed == 100 + 4000 + 900 + 50 + 2000 + 2
    assert result.items_completed == 6


def test_a_file_pip_has_open_is_skipped_and_survives(cache, rule, tmp_path):
    """A running pip holds its files open, and Windows refuses to delete an open
    file. That is the guard against pip mid-install: nothing is forced, the file
    is reported as in use, and everything else is still cleaned."""
    held = cache / "http-v2/a/b/c/d/e/deadbeef.body"
    with open(held, "rb"):
        result = execute(tmp_path, scan(rule).findings, dry_run=False)

    assert held.exists() and held.read_bytes() == b"b" * 4000
    locked = [s for s in result.skips if s.reason is SkipReason.LOCKED]
    assert [s.path.name for s in locked] == ["deadbeef.body"]
    assert result.items_completed == 5
    assert files_under(cache) == [held]


def test_a_junction_planted_in_the_cache_is_not_followed_out_of_it(
        cache, precious, rule, tmp_path):
    if not make_junction(cache / "http-v2" / "link", precious):
        pytest.skip("could not create a junction here")

    out = scan(rule)
    assert not any("thesis" in str(f.path) for f in out.findings)
    execute(tmp_path, out.findings, dry_run=False)

    assert (precious / "thesis.txt").read_text(encoding="utf-8") == "years of work"
