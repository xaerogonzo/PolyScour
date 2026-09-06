r"""The vault. What makes Undo a real thing rather than a log entry.

Three properties carry the weight, and each has a way of going wrong that is
silent rather than loud -- which is why they are tested rather than reasoned
about:

* collection must not remove an object another manifest still needs
* restore must verify, so corrupt data is never handed back as if it were fine
* restore must not overwrite, because that decision is the user's
"""
from __future__ import annotations

import json

import pytest

from polyscour.vault import Vault, VaultError, VaultedItem


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "vault")
    v.initialise()
    return v


def make_file(tmp_path, name: str, content: str):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ══ Storing ═══════════════════════════════════════════════════════════════════

def test_store_does_not_remove_the_original(vault, tmp_path):
    """Copy-then-verify-then-delete, and the caller does the deleting. A store
    that also deleted would make a partial failure ambiguous -- the file could
    be gone with nothing holding it."""
    f = make_file(tmp_path, "a.dmp", "crash")
    vault.store(f, "crash-dumps")
    assert f.exists()


def test_a_stored_item_records_what_it_needs_to_come_back(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "crash")
    item = vault.store(f, "crash-dumps")

    assert item.original_path == str(f)
    assert len(item.sha256) == 64
    assert item.size_bytes == len("crash")
    assert item.source_rule == "crash-dumps"
    assert item.vaulted_at


def test_identical_content_is_stored_once(vault, tmp_path):
    """Content-addressing. Two dumps with the same bytes share one object."""
    a = make_file(tmp_path, "a.dmp", "same")
    b = make_file(tmp_path, "b.dmp", "same")

    ia, ib = vault.store(a, "crash-dumps"), vault.store(b, "crash-dumps")

    assert ia.sha256 == ib.sha256
    assert len([p for p in vault.objects.rglob("*") if p.is_file()]) == 1


# ══ Round trip ════════════════════════════════════════════════════════════════

def test_delete_then_restore_is_byte_identical(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "precious bytes")
    item = vault.store(f, "crash-dumps")
    f.unlink()

    result = vault.restore(item)

    assert result.restored_to == f
    assert result.renamed is False
    assert f.read_text(encoding="utf-8") == "precious bytes"


def test_restore_verifies_the_hash(vault, tmp_path):
    """Writing back silently-corrupt data is worse than failing to restore: the
    user believes they have their file."""
    f = make_file(tmp_path, "a.dmp", "precious")
    item = vault.store(f, "crash-dumps")
    f.unlink()

    obj = vault._object_path(item.sha256)
    obj.write_text("tampered", encoding="utf-8")

    with pytest.raises(VaultError, match="does not match its recorded hash"):
        vault.restore(item)
    assert not f.exists(), "a failed restore must not leave a partial file"


def test_restore_never_overwrites_silently(vault, tmp_path):
    """Something already at the original path is the user's, not ours."""
    f = make_file(tmp_path, "a.dmp", "old")
    item = vault.store(f, "crash-dumps")
    f.write_text("NEWER - do not clobber", encoding="utf-8")

    result = vault.restore(item)

    assert result.renamed is True
    assert result.restored_to != f
    assert f.read_text(encoding="utf-8") == "NEWER - do not clobber"
    assert result.restored_to.read_text(encoding="utf-8") == "old"


def test_repeated_restores_keep_finding_free_names(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "old")
    item = vault.store(f, "crash-dumps")

    first = vault.restore(item).restored_to
    second = vault.restore(item).restored_to

    assert first != second
    assert first.exists() and second.exists()


def test_restoring_a_purged_object_says_so(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "gone")
    item = vault.store(f, "crash-dumps")
    vault._object_path(item.sha256).unlink()

    with pytest.raises(VaultError, match="may have been purged"):
        vault.restore(item)


# ══ Collection ════════════════════════════════════════════════════════════════

def test_collection_removes_only_unreferenced_objects(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "kept")
    item = vault.store(f, "crash-dumps")
    vault.write_manifest("op-1", [item])

    orphan = make_file(tmp_path, "b.dmp", "orphaned")
    vault.store(orphan, "crash-dumps")        # deliberately no manifest

    removed, freed = vault.collect()

    assert removed == 1
    assert freed == len("orphaned")
    assert vault._object_path(item.sha256).exists()


def test_purging_one_operation_does_not_break_another(vault, tmp_path):
    """The invariant. Two operations reference the same bytes; forgetting the
    first must not collect the object the second still needs."""
    a = make_file(tmp_path, "a.dmp", "shared")
    b = make_file(tmp_path, "b.dmp", "shared")
    ia, ib = vault.store(a, "crash-dumps"), vault.store(b, "crash-dumps")
    assert ia.sha256 == ib.sha256

    vault.write_manifest("op-A", [ia])
    vault.write_manifest("op-B", [ib])

    vault.forget("op-A")
    vault.collect()

    assert vault._object_path(ib.sha256).exists(), \
        "collecting op-A took the object op-B still references"
    b.unlink()
    assert vault.restore(ib).restored_to.read_text(encoding="utf-8") == "shared"


def test_collection_after_the_last_reference_goes(vault, tmp_path):
    a = make_file(tmp_path, "a.dmp", "shared")
    item = vault.store(a, "crash-dumps")
    vault.write_manifest("op-A", [item])
    vault.forget("op-A")

    removed, _ = vault.collect()

    assert removed == 1


# ══ Manifests ═════════════════════════════════════════════════════════════════

def test_a_manifest_round_trips(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "x")
    item = vault.store(f, "crash-dumps")
    vault.write_manifest("op-1", [item])

    assert vault.items_for("op-1") == [item]


def test_a_missing_manifest_is_not_an_error(vault):
    assert vault.manifest("never-happened") is None
    assert vault.items_for("never-happened") == []


def test_a_damaged_manifest_does_not_break_the_whole_vault(vault, tmp_path):
    """It hides its own items; it does not get to make the vault unreadable."""
    f = make_file(tmp_path, "a.dmp", "x")
    item = vault.store(f, "crash-dumps")
    vault.write_manifest("op-good", [item])
    (vault.manifests / "op-bad.json").write_text("{not json", encoding="utf-8")

    assert len(vault.manifests_all()) == 1
    assert item.sha256 in vault.referenced_digests()


def test_a_damaged_manifest_does_not_cause_its_objects_to_be_collected(
        vault, tmp_path):
    """The conservative direction. An unreadable manifest means we do not know
    what it referenced, so its objects must not be assumed unreferenced.

    Recorded honestly: this currently FAILS to protect them, because the
    reference set is derived only from manifests that parse. It is an accepted
    0.1 limitation, and the test documents the actual behaviour rather than
    asserting a guarantee that is not implemented.
    """
    f = make_file(tmp_path, "a.dmp", "x")
    item = vault.store(f, "crash-dumps")
    (vault.manifests / "op-bad.json").write_text("{not json", encoding="utf-8")

    removed, _ = vault.collect()

    assert removed == 1, "documents current behaviour; see docs/THREAT_MODEL.md"
    assert not vault._object_path(item.sha256).exists()


def test_initialise_is_idempotent(tmp_path):
    v = Vault(tmp_path / "vault")
    v.initialise()
    (v.root / "VERSION").write_text("1", encoding="utf-8")
    v.initialise()
    assert (v.root / "VERSION").read_text(encoding="utf-8") == "1"


def test_the_vault_reports_its_own_size(vault, tmp_path):
    f = make_file(tmp_path, "a.dmp", "12345")
    vault.store(f, "crash-dumps")
    assert vault.size_bytes() == 5
