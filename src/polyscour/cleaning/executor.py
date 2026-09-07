r"""EXECUTE, VERIFY, LOG. The only code in PolyScour that removes anything.

Four rules govern everything here.

**Re-authorise immediately before acting.** The scan's verdict is not carried
forward. Another local process may have replaced a target with a junction
between the scan and now; re-checking is what makes that race lose. The cost is
one guard call per item, which is nothing next to the I/O.

**Never force.** No handle closing, no read-only bit clearing, no aggressive
deletion techniques. A sharing violation means an application is using the file,
which is a normal condition on a live machine, not an obstacle to overcome. The
item is skipped, reported, and the run continues. This is also why "is this file
open?" is not a preflight check: it is race-prone in both directions and would
be a safety guarantee that is not one.

**Vault before delete, verify before removing.** For reversible items the copy
is made and hash-checked *first*; only then is the original removed. The
opposite order has a failure mode where the file is gone and nothing holds it.

**Cancellation lands between items, never inside one.** A cancelled run leaves
completed items completed, and writes exactly one manifest describing them.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from polyscour.contracts import (
    ActionPlan,
    ActionResult,
    Reversal,
    Skip,
    SkipReason,
    classify,
)
from polyscour.ledger import Ledger, new_operation_id
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import Operation, entry_for
from polyscour.vault import Vault, VaultedItem, VaultError

#: Windows error codes worth telling apart. Anything else is unclassified and
#: therefore not benign -- an unknown failure must degrade the outcome.
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33


def _classify_os_error(exc: OSError) -> tuple[SkipReason, str]:
    if isinstance(exc, FileNotFoundError):
        return SkipReason.VANISHED, "already gone"
    winerror = getattr(exc, "winerror", None)
    if winerror in (_ERROR_SHARING_VIOLATION, _ERROR_LOCK_VIOLATION):
        return SkipReason.LOCKED, "in use by another program"
    if isinstance(exc, PermissionError):
        # Includes the read-only attribute. Clearing it to get past this would
        # be forcing, which this module does not do.
        return SkipReason.PERMISSION, "permission denied"
    return SkipReason.ERROR, str(exc)


class Executor:
    def __init__(self, vault: Vault, ledger: Ledger,
                 guard: Guard | None = None,
                 allow_elevation: bool = False) -> None:
        self.vault = vault
        self.ledger = ledger
        self.guard = guard or Guard()
        #: Off unless a caller explicitly turns it on, and a caller should only
        #: do that after a person has agreed to it. docs/THREAT_MODEL.md is
        #: explicit that elevation is never requested speculatively, so an
        #: Executor built the ordinary way can never raise a UAC prompt.
        self.allow_elevation = allow_elevation

    def execute(self, plan: ActionPlan,
                cancel: threading.Event | None = None) -> ActionResult:
        """Carry out a plan and record what happened.

        Holds the mutation lock for the whole run: a vault write and its ledger
        row are one logical change, and a second process interleaving between
        them would corrupt the relationship the Undo Center depends on.
        """
        cancel = cancel or threading.Event()
        self.guard.begin()      # roots re-resolve here, after the scan
        operation_id = new_operation_id()
        started = datetime.now(timezone.utc)

        if plan.dry_run:
            return self._rehearse(plan, operation_id, started, cancel)

        with self.ledger.lock.held():
            result = self._perform(plan, operation_id, started, cancel)

        self.ledger.record(result, [f.rule_id for f in plan.findings])
        return result

    # ── the rehearsal ────────────────────────────────────────────────────────

    def _rehearse(self, plan: ActionPlan, operation_id: str,
                  started: datetime, cancel: threading.Event) -> ActionResult:
        """A dry run. Touches nothing, and is asserted to touch nothing.

        Still runs the full guard chain, because the point of a rehearsal is to
        find out what would happen -- including which items the guard would
        refuse.
        """
        completed = bytes_ = 0
        skips: list[Skip] = []

        for finding in plan.findings:
            if cancel.is_set():
                break
            try:
                self._authorise(finding)
            except GuardRefusal as exc:
                skips.append(Skip(finding.path, SkipReason.REFUSED_BY_GUARD, str(exc)))
                continue
            if not finding.path.exists():
                skips.append(Skip(finding.path, SkipReason.VANISHED, "already gone"))
                continue
            completed += 1
            bytes_ += finding.size_bytes

        result = ActionResult(
            operation_id=operation_id,
            outcome=classify(len(plan.findings), completed, skips, cancel.is_set()),
            started_at=started, finished_at=datetime.now(timezone.utc),
            bytes_freed=bytes_, items_completed=completed,
            skips=skips, dry_run=True)
        self.ledger.record(result, [f.rule_id for f in plan.findings])
        return result

    # ── the real thing ───────────────────────────────────────────────────────

    def _perform(self, plan: ActionPlan, operation_id: str,
                 started: datetime, cancel: threading.Event) -> ActionResult:
        completed = bytes_ = 0
        skips: list[Skip] = []
        reversals: list[Reversal] = []
        vaulted: list[VaultedItem] = []

        for finding in plan.findings:
            if cancel.is_set():
                break

            try:
                approved = self._authorise(finding)
            except GuardRefusal as exc:
                skips.append(Skip(finding.path, SkipReason.REFUSED_BY_GUARD, str(exc)))
                continue

            operation = next(iter(entry_for(finding.rule_id).operations))

            try:
                if operation is Operation.VAULT:
                    item = self.vault.store(approved, finding.rule_id)
                    size = self._remove(approved)
                    vaulted.append(item)
                    reversals.append(Reversal(operation_id, item.sha256, approved))
                else:
                    size = self._remove(approved)
            except VaultError as exc:
                # The original is untouched by design; nothing was lost.
                skips.append(Skip(approved, SkipReason.ERROR, str(exc)))
                continue
            except OSError as exc:
                reason, detail = _classify_os_error(exc)
                if reason is SkipReason.PERMISSION and self.allow_elevation:
                    # Only this one class of failure, and only when a person
                    # has already agreed. Note what is NOT passed to the
                    # helper: no decision, no approval, no "the guard said yes"
                    # -- just the rule and the path, which it re-authorises for
                    # itself at privilege.
                    size = self._remove_elevated(finding.rule_id, approved)
                    if size is not None:
                        completed += 1
                        bytes_ += size
                        continue
                skips.append(Skip(approved, reason, detail))
                continue

            completed += 1
            bytes_ += size

        # Written once, at the end, so a cancellation or a crash leaves either a
        # complete manifest or none -- never a half-written one that a restore
        # would read as authoritative.
        if vaulted:
            self.vault.write_manifest(operation_id, vaulted)

        return ActionResult(
            operation_id=operation_id,
            outcome=classify(len(plan.findings), completed, skips, cancel.is_set()),
            started_at=started, finished_at=datetime.now(timezone.utc),
            bytes_freed=bytes_, items_completed=completed,
            skips=skips, reversals=reversals, dry_run=False)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _authorise(self, finding) -> Path:
        operation = next(iter(entry_for(finding.rule_id).operations))
        return self.guard.authorize(finding.rule_id, finding.path, operation)

    def _remove_elevated(self, rule_id: str, path: Path) -> "int | None":
        """Ask the elevated helper to delete one file. None if it did not.

        The size is read *before* asking, because after a successful delete
        there is nothing left to measure -- and reporting zero bytes freed for
        a file that was removed would understate the result.

        Every failure returns None so the caller records the original
        permission skip: a user who declined the UAC prompt should see "needs
        administrator rights", not a second, stranger error.
        """
        from polyscour.elevation.client import request
        from polyscour.elevation.protocol import Operation as ElevOp

        try:
            size = path.stat().st_size
        except OSError:
            return None

        response = request(ElevOp.DELETE_APPROVED_PATH,
                           rule_id=rule_id, path=str(path))
        return size if response.ok else None

    @staticmethod
    def _remove(path: Path) -> int:
        """Delete one directory entry and return the bytes it accounted for.

        ``os.unlink`` operates on the directory entry, which is the correct
        semantic for a file that may have hard links: another name for the same
        data is not this rule's to remove, and the space is only reclaimed when
        the last link goes. The size is read first so the figure reported is the
        one that existed at the moment of removal.
        """
        size = path.stat().st_size
        os.unlink(path)
        return size

    # ── undo ─────────────────────────────────────────────────────────────────

    def restore(self, operation_id: str) -> list[str]:
        """Put a vaulted operation's files back. Returns human-readable notes.

        Verified against the recorded hash, never overwriting anything already
        at the original path -- see ``polyscour.vault``.
        """
        notes: list[str] = []
        with self.ledger.lock.held():
            for item in self.vault.items_for(operation_id):
                try:
                    outcome = self.vault.restore(item)
                except VaultError as exc:
                    notes.append(f"{Path(item.original_path).name}: {exc}")
                    continue
                self.ledger.mark_restored(operation_id, item.original_path)
                if outcome.renamed:
                    notes.append(
                        f"{outcome.original_path.name}: something was already "
                        f"there, restored as {outcome.restored_to.name}")
                else:
                    notes.append(f"{outcome.original_path.name}: restored")
        return notes
