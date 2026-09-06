r"""Staged deletion. What makes "Undo" a real thing rather than a log entry.

    vault/
    ├── VERSION
    ├── objects/     payload, content-addressed by SHA-256
    └── manifests/   one JSON record per operation

Content-addressing means two operations can reference the same bytes, which is
common -- the same crash dump vaulted twice, a duplicated log. That makes the
collection rule the important part of the design:

    **A vault object may only be collected when no retained manifest
    references it.**

Refcounted by scanning manifests rather than by keeping a count, because a
stored count can drift out of agreement with reality and a derived one cannot.
There are tens of manifests, not millions; the scan is cheap and it is right.

Two further rules, both learned from how restore actually goes wrong:

* **Restore verifies the hash.** Writing back silently-corrupt data is worse
  than failing to restore, because the user believes they have their file.
* **Restore never overwrites.** If something already occupies the original path,
  the restored copy is placed beside it under a suffixed name and the caller is
  told. Overwriting is a decision only the user can make.

Honest about what it is not
---------------------------

Vaulting does **not** free disk space -- the bytes move, they do not leave. Only
data a user might actually want back is vaulted; regenerable caches are deleted
outright and labelled "Not reversible", because pretending otherwise would be a
lie told by a product whose entire pitch is not lying.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

VAULT_VERSION = "1"

_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class VaultedItem:
    """One file's record inside an operation's manifest."""
    original_path: str
    sha256: str
    size_bytes: int
    source_rule: str
    vaulted_at: str


@dataclass(frozen=True)
class RestoreResult:
    original_path: Path
    restored_to: Path
    #: True when the original path was occupied and the file was placed beside
    #: it instead. Surfaced to the user rather than resolved silently.
    renamed: bool


class VaultError(Exception):
    """A vault operation could not be completed safely."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


class Vault:
    """The staged-deletion store. One instance per operation is fine."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.manifests = self.root / "manifests"

    # ── layout ───────────────────────────────────────────────────────────────

    def initialise(self) -> None:
        """Create the tree. Idempotent, and safe to call on every start."""
        self.objects.mkdir(parents=True, exist_ok=True)
        self.manifests.mkdir(parents=True, exist_ok=True)
        version = self.root / "VERSION"
        if not version.exists():
            version.write_text(VAULT_VERSION, encoding="utf-8")

    def _object_path(self, digest: str) -> Path:
        """Sharded two levels deep.

        A single directory holding every object is fine at a hundred files and
        unpleasant at a hundred thousand, and the sharding cannot be introduced
        later without migrating every existing vault.
        """
        return self.objects / digest[:2] / digest[2:4] / digest

    # ── writing ──────────────────────────────────────────────────────────────

    def store(self, path: Path, source_rule: str) -> VaultedItem:
        """Copy `path` into the vault and return its record.

        Copy-then-verify-then-delete, in that order, and the caller deletes.
        This method never removes the original: a store that also deleted would
        make a partial failure ambiguous -- the file could be gone with nothing
        holding it, which is the one outcome the vault exists to prevent.
        """
        self.initialise()
        digest = _sha256(path)
        size = path.stat().st_size
        dest = self._object_path(digest)

        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(".incoming")
            shutil.copy2(path, tmp)
            if _sha256(tmp) != digest:
                tmp.unlink(missing_ok=True)
                raise VaultError(
                    f"{path} changed while it was being vaulted; nothing was "
                    f"removed")
            os.replace(tmp, dest)

        return VaultedItem(
            original_path=str(path),
            sha256=digest,
            size_bytes=size,
            source_rule=source_rule,
            vaulted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    def write_manifest(self, operation_id: str,
                       items: list[VaultedItem]) -> Path:
        """Record an operation's vaulted items, atomically.

        Written once at the end rather than appended per item, so a cancellation
        or a crash mid-batch leaves either a complete manifest or none -- never
        a half-written one that a restore would read as authoritative.
        """
        self.initialise()
        target = self.manifests / f"{operation_id}.json"
        payload = {
            "operation_id": operation_id,
            "vault_version": VAULT_VERSION,
            "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "items": [asdict(i) for i in items],
        }
        tmp = target.with_suffix(f".{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, target)
        return target

    # ── reading ──────────────────────────────────────────────────────────────

    def manifest(self, operation_id: str) -> dict | None:
        target = self.manifests / f"{operation_id}.json"
        if not target.exists():
            return None
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def manifests_all(self) -> list[dict]:
        if not self.manifests.is_dir():
            return []
        out = []
        for f in sorted(self.manifests.glob("*.json")):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue      # a damaged manifest hides its items; it does not
                              # get to make the whole vault unreadable
        return out

    def items_for(self, operation_id: str) -> list[VaultedItem]:
        m = self.manifest(operation_id)
        if not m:
            return []
        return [VaultedItem(**i) for i in m.get("items", [])]

    # ── restoring ────────────────────────────────────────────────────────────

    def restore(self, item: VaultedItem) -> RestoreResult:
        """Put one file back, verified, without overwriting anything."""
        src = self._object_path(item.sha256)
        if not src.exists():
            raise VaultError(
                f"the vaulted copy of {item.original_path} is gone "
                f"(object {item.sha256[:12]}); it may have been purged")

        if _sha256(src) != item.sha256:
            raise VaultError(
                f"the vaulted copy of {item.original_path} does not match its "
                f"recorded hash and will not be restored")

        original = Path(item.original_path)
        target, renamed = original, False
        if original.exists():
            target = self._beside(original)
            renamed = True

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        return RestoreResult(original_path=original, restored_to=target,
                             renamed=renamed)

    @staticmethod
    def _beside(original: Path) -> Path:
        """A free name next to `original`. Never overwrites, never gives up."""
        for n in range(1, 1000):
            candidate = original.with_name(
                f"{original.stem} (restored {n}){original.suffix}")
            if not candidate.exists():
                return candidate
        return original.with_name(f"{original.stem} (restored {uuid.uuid4().hex[:8]})"
                                  f"{original.suffix}")

    # ── collecting ───────────────────────────────────────────────────────────

    def referenced_digests(self) -> set[str]:
        """Every object any retained manifest still points at."""
        return {i.get("sha256", "")
                for m in self.manifests_all()
                for i in m.get("items", [])} - {""}

    def forget(self, operation_id: str) -> None:
        """Drop one operation's manifest. Objects are left for collection."""
        (self.manifests / f"{operation_id}.json").unlink(missing_ok=True)

    def collect(self) -> tuple[int, int]:
        """Remove unreferenced objects. Returns (objects removed, bytes freed).

        The invariant this exists to hold: purging operation A must not remove
        an object operation B still needs. Since the reference set is derived
        from the manifests each time rather than counted as we go, that holds by
        construction rather than by bookkeeping.
        """
        if not self.objects.is_dir():
            return (0, 0)
        keep = self.referenced_digests()
        removed = freed = 0
        for obj in self.objects.rglob("*"):
            if not obj.is_file() or obj.name in keep:
                continue
            if obj.suffix == ".incoming":
                continue        # a store() in flight; not ours to judge
            try:
                size = obj.stat().st_size
                obj.unlink()
            except OSError:
                continue
            removed += 1
            freed += size
        return (removed, freed)

    def size_bytes(self) -> int:
        if not self.objects.is_dir():
            return 0
        return sum(p.stat().st_size for p in self.objects.rglob("*") if p.is_file())
