r"""The guard. These are the most important tests in the product.

A bug in a web app is annoying; a bug here deletes someone's files. Everything
below is written to fail loudly rather than to pass conveniently, and none of it
may be weakened for the convenience of a later feature.

Real directories under ``tmp_path`` throughout, not a filesystem abstraction.
The guard is the thing worth testing; a mock would only prove the mock behaves.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from polyscour.safety import reparse
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import (
    POLICY,
    Operation,
    PolicyViolation,
    RootFamily,
    entry_for,
    permitted_roots,
    resolve_family,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


def make_junction(link, target) -> bool:
    """Create a directory junction. Unlike a symlink this needs no elevation."""
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    return r.returncode == 0


@pytest.fixture
def temp_root(monkeypatch, tmp_path):
    """Point the USER_TEMP family at a directory we control."""
    root = tmp_path / "temp"
    root.mkdir()
    monkeypatch.setenv("TEMP", str(root))
    return root.resolve()


@pytest.fixture
def guard():
    return Guard()


# ══ A rule cannot authorise itself ════════════════════════════════════════════

def test_a_rule_with_no_policy_entry_cannot_load():
    """The whole design rests on this. A cleaning rule that arrives without a
    reviewed policy entry beside it must not be able to run at all."""
    with pytest.raises(PolicyViolation, match="no entry in the trust policy"):
        entry_for("rule-someone-just-invented")


def test_an_unknown_rule_is_refused_by_the_guard_too(guard, temp_root):
    """Not merely at load time -- the guard looks the policy up itself rather
    than trusting that something upstream already checked."""
    with pytest.raises(GuardRefusal, match="trust policy"):
        guard.authorize("rule-someone-just-invented",
                        temp_root / "x", Operation.DELETE)


def test_a_rule_cannot_perform_an_operation_its_policy_withholds(guard, temp_root):
    """user-temp may DELETE; it may not VAULT. Permissions narrow as authority
    flows outward -- they never widen."""
    victim = temp_root / "a.tmp"
    victim.write_text("x", encoding="utf-8")
    with pytest.raises(GuardRefusal, match="not permitted to vault"):
        guard.authorize("user-temp", victim, Operation.VAULT)


def test_rules_never_name_paths_at_all():
    """The property that eliminates the class rather than validating against it.

    A rule file that cannot contain a path cannot widen its own reach by
    editing one. Locations are named symbolically and resolved only by code.
    """
    for rule_id, entry in POLICY.items():
        assert entry.families, f"{rule_id} declares no root family"
        for family in entry.families:
            assert isinstance(family, RootFamily)


def test_every_policy_entry_has_a_working_resolver():
    """A family without a resolver would fail at the call site of whichever
    feature asked for it, which is the wrong place to find out."""
    for rule_id, entry in POLICY.items():
        for family in entry.families:
            resolve_family(family)      # must not raise


# ══ Containment ═══════════════════════════════════════════════════════════════

def test_a_target_outside_every_permitted_root_is_refused(guard, temp_root, tmp_path):
    outsider = tmp_path / "elsewhere" / "precious.txt"
    outsider.parent.mkdir()
    outsider.write_text("mine", encoding="utf-8")

    with pytest.raises(GuardRefusal, match="under none of its permitted roots"):
        guard.authorize("user-temp", outsider, Operation.DELETE)


def test_a_legitimate_target_is_authorised_and_returned_canonical(guard, temp_root):
    victim = temp_root / "sub" / "a.tmp"
    victim.parent.mkdir()
    victim.write_text("x", encoding="utf-8")

    approved = guard.authorize("user-temp", victim, Operation.DELETE)

    assert approved == victim.resolve()
    assert approved.is_absolute()


def test_dotdot_cannot_walk_out_of_a_permitted_root(guard, temp_root, tmp_path):
    """Canonicalisation happens inside the guard precisely so that a caller
    cannot smuggle a traversal past it."""
    escape = temp_root / ".." / "elsewhere.txt"
    (tmp_path / "elsewhere.txt").write_text("mine", encoding="utf-8")

    with pytest.raises(GuardRefusal):
        guard.authorize("user-temp", escape, Operation.DELETE)


# ══ Reparse points ════════════════════════════════════════════════════════════

def test_a_junction_out_of_the_root_is_refused(guard, temp_root, tmp_path):
    """The canonical attack: plant a junction inside a cache directory that
    points at something valuable, and let the cleaner walk into it."""
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "thesis.txt").write_text("years of work", encoding="utf-8")

    link = temp_root / "innocent_cache"
    if not make_junction(link, outside):
        pytest.skip("could not create a junction on this machine")

    with pytest.raises(GuardRefusal, match="reparse point"):
        guard.authorize("user-temp", link / "thesis.txt", Operation.DELETE)


def test_a_junction_is_refused_even_several_levels_down(guard, temp_root, tmp_path):
    """A junction five directories deep is exactly as effective as one at the
    top, so every component is inspected rather than just the first."""
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "thesis.txt").write_text("years of work", encoding="utf-8")

    deep = temp_root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    link = deep / "cache"
    if not make_junction(link, outside):
        pytest.skip("could not create a junction on this machine")

    with pytest.raises(GuardRefusal, match="reparse point"):
        guard.authorize("user-temp", link / "thesis.txt", Operation.DELETE)


def test_a_junction_inside_an_otherwise_valid_tree_does_not_taint_its_siblings(
        guard, temp_root, tmp_path):
    """The refusal must be precise. A planted junction is not a reason to stop
    cleaning the legitimate files beside it -- that would make one hostile
    directory a denial of service against the whole rule."""
    outside = tmp_path / "precious"
    outside.mkdir()

    link = temp_root / "trap"
    if not make_junction(link, outside):
        pytest.skip("could not create a junction on this machine")

    sibling = temp_root / "real.tmp"
    sibling.write_text("junk", encoding="utf-8")

    assert guard.authorize("user-temp", sibling, Operation.DELETE) == sibling.resolve()
    with pytest.raises(GuardRefusal):
        guard.authorize("user-temp", link, Operation.DELETE)


def test_the_junction_itself_is_refused_not_only_paths_through_it(
        guard, temp_root, tmp_path):
    """Deleting the junction would be safe; deleting *through* it would not.
    The guard refuses both rather than reasoning about which is which."""
    outside = tmp_path / "precious"
    outside.mkdir()
    link = temp_root / "trap"
    if not make_junction(link, outside):
        pytest.skip("could not create a junction on this machine")

    with pytest.raises(GuardRefusal, match="reparse point"):
        guard.authorize("user-temp", link, Operation.DELETE)


def test_reparse_detection_does_not_follow_the_link(temp_root, tmp_path):
    """lstat, not stat. Following it to ask what it is would already be the
    traversal we are trying to refuse."""
    outside = tmp_path / "precious"
    outside.mkdir()
    link = temp_root / "trap"
    if not make_junction(link, outside):
        pytest.skip("could not create a junction on this machine")

    assert reparse.is_reparse_point(link) is True
    assert reparse.is_reparse_point(temp_root) is False


def test_a_missing_path_is_not_reported_as_a_reparse_point(temp_root):
    """The caller finds out it is missing from the operation itself, where the
    error is specific -- not from a safety check giving a misleading reason."""
    assert reparse.is_reparse_point(temp_root / "nope") is False


# ══ The global denylist ═══════════════════════════════════════════════════════

def test_the_denylist_covers_the_obvious_places(guard):
    protected = [str(p).lower() for p in guard.protected_locations]
    assert any("system32" in p for p in protected)
    assert any("documents" in p for p in protected)
    assert any("downloads" in p for p in protected), \
        "Downloads is where a maintenance tool is most tempted to look for junk"


def test_a_target_inside_a_protected_location_is_refused(monkeypatch, tmp_path):
    """Even when a rule's own root would otherwise permit it -- the denylist is
    applied independently of any rule, and last."""
    profile = tmp_path / "profile"
    (profile / "Documents").mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("TEMP", str(profile))       # deliberately overlapping

    victim = profile / "Documents" / "thesis.txt"
    victim.write_text("years of work", encoding="utf-8")

    with pytest.raises(GuardRefusal, match="protected location"):
        Guard().authorize("user-temp", victim, Operation.DELETE)


def test_a_target_that_contains_a_protected_location_is_refused(
        monkeypatch, tmp_path):
    """The dangerous direction, and the one a containment-only check waves
    through: deleting a directory that *holds* Documents takes Documents with
    it."""
    profile = tmp_path / "profile"
    (profile / "Documents").mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("TEMP", str(tmp_path))

    with pytest.raises(GuardRefusal, match="contains the protected location"):
        Guard().authorize("user-temp", profile, Operation.DELETE)


# ══ User exclusions ═══════════════════════════════════════════════════════════

def test_an_excluded_path_is_refused(temp_root):
    keep = temp_root / "keep_me"
    keep.mkdir()
    (keep / "a.tmp").write_text("x", encoding="utf-8")

    guard = Guard(exclusions=[keep])

    with pytest.raises(GuardRefusal, match="excluded by the user"):
        guard.authorize("user-temp", keep / "a.tmp", Operation.DELETE)


def test_an_exclusion_does_not_protect_its_siblings(temp_root):
    keep = temp_root / "keep_me"
    keep.mkdir()
    other = temp_root / "other.tmp"
    other.write_text("x", encoding="utf-8")

    guard = Guard(exclusions=[keep])

    assert guard.authorize("user-temp", other, Operation.DELETE) == other.resolve()


# ══ No permitted root at all ══════════════════════════════════════════════════

def test_a_rule_whose_family_resolves_to_nothing_is_refused(monkeypatch, tmp_path):
    """A browser that is not installed resolves to no directories. That is a
    normal outcome, and it must mean 'do nothing' rather than 'no constraint'."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "empty"))

    with pytest.raises(GuardRefusal, match="no resolvable root"):
        Guard().authorize("firefox-cache", tmp_path / "x", Operation.DELETE)
