r"""npm and Cargo cache rules -- and the two caches that were measured and refused.

The pip rule (tests/test_pip_cache_rule.py) established the contract; this file
applies it to npm's ``_cacache`` and Cargo's ``registry/cache`` and adds what is
particular to each. The important tests here are about what must SURVIVE:

* npm: ``_npx`` (installed package trees) and ``_logs`` sit beside ``_cacache``
* Cargo: ``registry/src`` and its ``.cargo-ok`` markers, ``bin``, ``git`` and
  ``config.toml`` sit around ``registry/cache``

Those are not incidental. A Cargo build whose ``.cargo-ok`` survives while its
sources were deleted fails and does not recover, and a Gradle cache half-deleted
was left unable to build in 2 of 6 trials at just 10% -- both measured
(docs/adr/0010). A file-by-file cleaner can be cancelled, or skip a locked file,
so it may only touch caches where *every partial state is safe*.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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


def make_junction(link, target) -> bool:
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    return r.returncode == 0


@dataclass(frozen=True)
class Tool:
    rule_id: str
    family: RootFamily
    #: the deepest a real cache's files sit below the root (measured)
    layout_depth: int
    #: (env-root -> cache root); env-root is the tmp dir standing in for the profile
    root: Callable[[Path, Path], Path]
    #: create the cache; return {file: content} that MUST be found and removed
    fill: Callable[[Path], dict]
    #: create things around the cache that must SURVIVE; return {path: content}
    neighbours: Callable[[Path, Path], dict]
    #: point every documented redirect at ``precious``; returns {where: value}
    redirect: Callable[[pytest.MonkeyPatch, Path, Path, Path], dict]
    #: a subdirectory of the cache in which a junction can be planted
    plant_in: str


def _write(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ── npm ──────────────────────────────────────────────────────────────────────

def _npm_root(local: Path, home: Path) -> Path:
    return local / "npm-cache" / "_cacache"


def _npm_fill(root: Path) -> dict:
    """Measured on a real cache: files at depth 3 (index) and 4 (content)."""
    files = {
        root / "content-v2/sha512/ab/cd/ef0123456789": b"tarball" * 100,
        root / "content-v2/sha1/12/34/5678abcdef": b"older" * 50,
        root / "index-v5/aa/bb/cc0011223344": b"index entry",
        root / "index-v5/dd/ee/ff5566778899": b"another entry",
        root / "tmp/partial-download": b"in flight",
    }
    for p, data in files.items():
        _write(p, data)
    return files


def _npm_neighbours(local: Path, home: Path) -> dict:
    base = local / "npm-cache"
    out = {
        base / "_npx/abc123/node_modules/left-pad/package.json": b"{}",
        base / "_npx/abc123/node_modules/left-pad/index.js": b"module.exports={}",
        base / "_npx/abc123/package.json": b"{}",
        base / "_logs/2026-09-01-debug-0.log": b"log",
        base / "_prebuilds/x.tar.gz": b"p",
        base / "_update-notifier-last-checked": b"",
        home / ".npmrc": b"registry=https://example.invalid/\n",
    }
    for p, data in out.items():
        _write(p, data)
    return out


def _npm_redirect(mp, precious: Path, tmp: Path, home: Path) -> dict:
    """Every documented way to move npm's cache. Returns where each was set, as
    the text the test can check actually names the folder that matters."""
    mp.setenv("NPM_CONFIG_CACHE", str(precious))
    mp.setenv("npm_config_cache", str(precious))
    (home / ".npmrc").write_text(f"cache={precious}\n", encoding="utf-8")
    (tmp / "global.npmrc").write_text(f"cache={precious}\n", encoding="utf-8")
    mp.setenv("NPM_CONFIG_GLOBALCONFIG", str(tmp / "global.npmrc"))
    return {"NPM_CONFIG_CACHE": os.environ["NPM_CONFIG_CACHE"],
            "npm_config_cache": os.environ["npm_config_cache"],
            "~/.npmrc": (home / ".npmrc").read_text(encoding="utf-8"),
            "global npmrc": (tmp / "global.npmrc").read_text(encoding="utf-8")}


# ── Cargo ────────────────────────────────────────────────────────────────────

_IDX = "index.crates.io-1949cf8c6b5b557f"


def _cargo_root(local: Path, home: Path) -> Path:
    return home / ".cargo" / "registry" / "cache"


def _cargo_fill(root: Path) -> dict:
    files = {
        root / _IDX / "serde-1.0.0.crate": b"s" * 900,
        root / _IDX / "tokio-1.2.3.crate": b"t" * 1500,
        root / _IDX / "adler2-2.0.1.crate": b"a" * 40,
    }
    for p, data in files.items():
        _write(p, data)
    return files


def _cargo_neighbours(local: Path, home: Path) -> dict:
    cargo = home / ".cargo"
    out = {
        # the extracted crate and its marker -- the state that breaks if half-removed
        cargo / f"registry/src/{_IDX}/serde-1.0.0/.cargo-ok": b'{"v":1}',
        cargo / f"registry/src/{_IDX}/serde-1.0.0/src/lib.rs": b"pub fn f() {}",
        cargo / f"registry/index/{_IDX}/.cache/se/rd/serde": b"idx",
        cargo / "bin/rustfmt.exe": b"MZ",
        cargo / "bin/cargo-installed-tool.exe": b"MZ",
        cargo / "git/db/repo/HEAD": b"ref",
        cargo / "config.toml": b"[net]\noffline = false\n",
        # something that is not a .crate, inside the cache directory itself
        cargo / f"registry/cache/{_IDX}/NOTES.txt": b"not a crate",
    }
    for p, data in out.items():
        _write(p, data)
    return out


def _cargo_redirect(mp, precious: Path, tmp: Path, home: Path) -> dict:
    mp.setenv("CARGO_HOME", str(precious))
    return {"CARGO_HOME": os.environ["CARGO_HOME"]}


TOOLS = [
    Tool("npm-cache", RootFamily.NPM_CACHE, 4, _npm_root, _npm_fill,
         _npm_neighbours, _npm_redirect, "content-v2"),
    Tool("cargo-registry-cache", RootFamily.CARGO_REGISTRY_CACHE, 1, _cargo_root,
         _cargo_fill, _cargo_neighbours, _cargo_redirect, _IDX),
]
IDS = [t.rule_id for t in TOOLS]


@pytest.fixture(params=TOOLS, ids=IDS)
def tool(request):
    return request.param


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A profile of our own, with every documented redirect switched off."""
    local, home = tmp_path / "local", tmp_path / "home"
    local.mkdir(); home.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    for var in ("NPM_CONFIG_CACHE", "npm_config_cache", "NPM_CONFIG_GLOBALCONFIG",
                "CARGO_HOME"):
        monkeypatch.delenv(var, raising=False)
    return local, home


@pytest.fixture
def cache(tool, env):
    """The tool's cache, laid out as measured, with its neighbours beside it."""
    local, home = env
    root = tool.root(local, home)
    files = tool.fill(root)
    neighbours = tool.neighbours(local, home)
    return root.resolve(), files, neighbours


@pytest.fixture
def precious(tmp_path):
    d = tmp_path / "Documents-ish"
    _write(d / "thesis.txt", b"years of work")
    return d


def rule_for(tool):
    return load_file(paths.rules_dir() / f"{tool.rule_id}.json")


def scan(rule):
    return Scanner(guard=Guard()).scan([rule]).outcomes[0]


def execute(tmp_path, findings, *, dry_run):
    ex = Executor(vault=Vault(tmp_path / "vault"),
                  ledger=Ledger(tmp_path / "history.sqlite"), guard=Guard())
    return ex.execute(plan(findings, dry_run=dry_run))


def snapshot(files):
    return {p: p.read_bytes() for p in files}


def all_files(root):
    return sorted(p for p in root.rglob("*") if p.is_file())


# ══ What the policy grants ════════════════════════════════════════════════════

def test_the_policy_grants_one_family_and_only_delete(tool):
    entry = POLICY[tool.rule_id]
    assert entry.families == frozenset({tool.family})
    assert entry.operations == frozenset({Operation.DELETE})
    assert entry.scope is Scope.ONE_DIRECTORY
    # Ceilings are safety limits, pinned to a band: deep enough for the measured
    # layout, no deeper than a planted structure should be walked.
    assert tool.layout_depth <= entry.max_depth <= 12
    assert entry.max_bytes <= 64 * 1024**3
    assert entry.min_age_days == 0


def test_the_rule_loads_reconciled_with_its_policy(tool):
    rule = rule_for(tool)
    assert rule.id == tool.rule_id
    assert rule.risk is RiskLevel.LOW
    assert rule.operation is Operation.DELETE and not rule.reversible
    assert rule.requires_elevation is False
    assert rule.families == (tool.family,)


def test_the_rule_is_offered_unticked(tool):
    """Regenerable, yes -- but the rebuild costs bandwidth and, offline, can be
    a failed build, which a pre-ticked box would not let anyone see coming. So
    the default action of a user who clicks straight through leaves it alone
    (adr/0009 addendum)."""
    from datetime import datetime, timezone
    from pathlib import Path

    from polyscour.cleaning.planner import recommend
    from polyscour.contracts import Evidence, Finding, RuleOutcome, ScanResult

    rule = rule_for(tool)

    def finding(risk):
        return Finding(rule_id=rule.id, title="t", path=Path(r"C:\x\a"),
                       size_bytes=1, risk=risk, reversible=False,
                       evidence=Evidence("m", "o", "r"))

    def recommended(risk):
        now = datetime.now(timezone.utc)
        result = ScanResult(started_at=now, finished_at=now, outcomes=[
            RuleOutcome(rule_id=rule.id, findings=[finding(risk)])])
        (rec,) = recommend(result)
        return rec.recommended

    assert recommended(RiskLevel.SAFE) is True      # the control: SAFE is ticked
    assert recommended(rule.risk) is False


def test_a_rule_cannot_claim_a_second_family(tool):
    raw = {"id": tool.rule_id, "name": "x", "description": "x",
           "category": "Developer", "risk": "safe", "patterns": ["*"],
           "root_families": [tool.family.value, "user_temp"]}
    with pytest.raises(RuleError, match="does not grant"):
        parse(raw)


# ══ The location is the default, and nothing else ═════════════════════════════

def test_the_family_resolves_to_the_default_cache_and_nothing_else(tool, cache):
    root, _, _ = cache
    assert resolve_family(tool.family) == [root]
    assert permitted_roots(tool.rule_id) == [root]


def test_no_cache_at_all_is_nothing_to_scan_not_an_error(tool, env):
    assert resolve_family(tool.family) == []
    out = scan(rule_for(tool))
    assert out.aborted and "nothing to scan" in out.abort_reason


def test_a_redirect_is_not_followed(tool, cache, precious, monkeypatch, tmp_path, env):
    """Every documented way to move the cache, all pointing at a folder that
    matters. The trap is confirmed set, so a resolver that followed any of them
    would fail here instead of passing by accident."""
    _, home = env
    set_at = tool.redirect(monkeypatch, precious, tmp_path, home)
    assert set_at, "the redirect helper set nothing"
    for where, value in set_at.items():                 # the trap really is set
        assert str(precious) in value, f"{where} does not point at the folder that matters"

    root, _, _ = cache
    assert resolve_family(tool.family) == [root]
    assert precious.resolve() not in permitted_roots(tool.rule_id)
    with pytest.raises(GuardRefusal, match="under none of its permitted roots"):
        Guard().authorize(tool.rule_id, precious / "thesis.txt", Operation.DELETE)


def test_a_redirect_with_no_default_cache_scans_nothing(
        tool, env, precious, monkeypatch, tmp_path):
    _, home = env
    tool.redirect(monkeypatch, precious, tmp_path, home)
    out = scan(rule_for(tool))
    assert out.aborted and out.findings == []
    assert (precious / "thesis.txt").read_bytes() == b"years of work"


# ══ The real layout is reachable ══════════════════════════════════════════════

def test_every_file_in_the_real_layout_is_found(tool, cache):
    root, files, _ = cache
    rule = rule_for(tool)
    out = scan(rule)
    assert not out.aborted
    assert sorted(f.path for f in out.findings) == sorted(p.resolve() for p in files)
    assert rule.max_depth >= tool.layout_depth


# ══ Cleaning it ═══════════════════════════════════════════════════════════════

def test_a_dry_run_changes_nothing(tool, cache, tmp_path):
    root, files, neighbours = cache
    # The cache and its neighbours -- not a parent directory, which would also
    # hold the vault and ledger the executor legitimately writes.
    watched = lambda: snapshot(all_files(root) + sorted(neighbours))   # noqa: E731
    before = watched()
    result = execute(tmp_path, scan(rule_for(tool)).findings, dry_run=True)
    assert watched() == before
    assert result.dry_run and result.items_completed == len(files)


def test_a_real_run_removes_the_cache_and_leaves_everything_around_it(
        tool, cache, tmp_path):
    """The heart of both rules. Files in the cache go; the neighbours -- the
    ``_npx`` trees, the extracted crate sources and their markers, installed
    tools, config -- survive byte for byte."""
    root, files, neighbours = cache
    kept_before = {p: p.read_bytes() for p in neighbours if p.exists()}
    dirs_before = sorted(p for p in root.rglob("*") if p.is_dir())

    result = execute(tmp_path, scan(rule_for(tool)).findings, dry_run=False)

    remaining = {p.resolve() for p in all_files(root)}
    removed = {p.resolve() for p in files}
    assert not (remaining & removed)                     # every cache file gone
    assert sorted(p for p in root.rglob("*") if p.is_dir()) == dirs_before
    for path, data in kept_before.items():               # nothing around it touched
        assert path.read_bytes() == data, f"{path} was modified"
    assert result.items_completed == len(files)
    assert result.bytes_freed == sum(len(d) for d in files.values())


def test_a_file_held_open_is_skipped_and_survives(tool, cache, tmp_path):
    """A live npm or cargo holds a file it is using; Windows refuses the delete."""
    root, files, _ = cache
    held = sorted(files)[0]
    with open(held, "rb"):
        result = execute(tmp_path, scan(rule_for(tool)).findings, dry_run=False)

    assert held.exists() and held.read_bytes() == files[held]
    locked = [s for s in result.skips if s.reason is SkipReason.LOCKED]
    assert [s.path.name for s in locked] == [held.name]
    assert result.items_completed == len(files) - 1


def test_a_junction_planted_in_the_cache_is_not_followed_out_of_it(
        tool, cache, precious, tmp_path):
    root, _, _ = cache
    if not make_junction(root / tool.plant_in / "link", precious):
        pytest.skip("could not create a junction here")
    out = scan(rule_for(tool))
    assert not any("thesis" in str(f.path) for f in out.findings)
    execute(tmp_path, out.findings, dry_run=False)
    assert (precious / "thesis.txt").read_bytes() == b"years of work"


# ══ Cargo: only .crate files, and the sources are left alone ══════════════════

def test_cargo_removes_crate_archives_and_leaves_a_crates_marker_and_sources(env, tmp_path):
    """The exact state that breaks a build if it is half-removed: a crate's
    ``.cargo-ok`` marker beside its sources. Cleaning ``registry/cache`` must
    leave both -- measured (adr/0010): marker kept + sources gone = broken build
    that does not recover; marker and sources both intact = fine."""
    local, home = env
    tool = TOOLS[1]
    root = tool.root(local, home)
    tool.fill(root)
    neighbours = tool.neighbours(local, home)

    execute(tmp_path, scan(rule_for(tool)).findings, dry_run=False)

    marker = home / ".cargo" / "registry" / "src" / _IDX / "serde-1.0.0" / ".cargo-ok"
    lib = marker.parent / "src" / "lib.rs"
    assert marker.read_bytes() == b'{"v":1}' and lib.read_bytes() == b"pub fn f() {}"
    assert (root / _IDX / "NOTES.txt").exists()          # not a .crate: not matched
    assert not list(root.rglob("*.crate"))
    assert all(p.exists() for p in neighbours)


def test_cargo_rule_matches_only_crate_archives():
    rule = load_file(paths.rules_dir() / "cargo-registry-cache.json")
    assert rule.patterns == ("*.crate",)


# ══ The caches that were measured and refused ═════════════════════════════════

def test_no_rule_reaches_a_cache_whose_partial_deletion_was_shown_unsafe(monkeypatch, tmp_path):
    """Cargo's ``registry/src``, Gradle's ``caches`` and npm's ``_npx``.

    Not an absence that happens to be true today: a file-by-file cleaner can be
    cancelled or skip a locked file, and each of these was left broken (Cargo,
    Gradle: measured) or was not shown safe (``_npx``). This fails if any rule's
    permitted root becomes one of them, or a parent of one -- so adding them
    means reading adr/0010 and changing this test on purpose.
    """
    local, home = tmp_path / "local", tmp_path / "home"
    #: caches shown unsafe (or not shown safe) to clean file by file: no root may
    #: BE one, be INSIDE one, or CONTAIN one.
    unsafe = [
        home / ".cargo" / "registry" / "src",
        home / ".gradle" / "caches",
        local / "npm-cache" / "_npx",
    ]
    #: parents that hold both a safe cache and things that are not caches (tools,
    #: config, extracted sources): no root may BE one or contain one -- a legitimate
    #: root sits *inside* them, which is exactly the point.
    parents = [
        home / ".cargo" / "registry",
        home / ".cargo",
        home / ".gradle",
        local / "npm-cache",
    ]
    for d in unsafe + parents:
        d.mkdir(parents=True, exist_ok=True)
    # a real cache under each tool too, so every family resolves to something
    (home / ".cargo/registry/cache" / _IDX).mkdir(parents=True, exist_ok=True)
    (local / "npm-cache/_cacache").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("USERPROFILE", str(home))
    # user-temp resolves %TEMP%, and pytest's own tmp_path lives inside the real
    # one -- which would make user-temp look like it "contains" the folders above.
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))
    (tmp_path / "temp").mkdir()

    def within(child: Path, parent: Path) -> bool:
        c, p = [x.lower() for x in child.parts], [x.lower() for x in parent.parts]
        return c[:len(p)] == p

    roots_seen = 0
    for rule_id in POLICY:
        for root in permitted_roots(rule_id):
            roots_seen += 1
            for bad in (d.resolve() for d in unsafe):
                assert not within(root, bad), f"{rule_id}: {root} is inside {bad}"
                assert not within(bad, root), f"{rule_id}: {root} contains {bad}"
            for parent in (d.resolve() for d in parents):
                assert not within(parent, root), (
                    f"{rule_id}: {root} is, or contains, {parent}")
    assert roots_seen >= 2       # the oracle is alive: both dev families resolved
