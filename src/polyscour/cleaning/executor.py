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
    ElevationRecord,
    Skip,
    SkipReason,
    classify,
    classify_os_error,
)
from polyscour.ledger import Ledger, new_operation_id
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import Operation, entry_for
from polyscour.vault import Vault, VaultedItem, VaultError

def _skips_from(data: dict) -> list[Skip]:
    """Turn the helper's report into skips, without losing the totals.

    The helper names at most a few hundred paths however many it skipped, so a
    rule that refused two hundred thousand files does not produce a two hundred
    thousand entry response. ``skip_counts`` stays exact, so the remainder is
    reconstructed as unnamed skips of the right reason -- which keeps both the
    displayed count and ``classify()``'s benign/not-benign judgement correct.
    """
    rule_id = str(data.get("rule_id", ""))
    named = data.get("skips") or []
    counts = dict(data.get("skip_counts") or {})
    out: list[Skip] = []

    for entry in named:
        try:
            reason = SkipReason(entry["reason"])
        except (KeyError, ValueError):
            reason = SkipReason.ERROR
        out.append(Skip(Path(entry.get("path", "")), reason,
                        str(entry.get("detail", "")), rule_id))
        counts[reason.value] = counts.get(reason.value, 0) - 1

    for value, remaining in counts.items():
        if remaining <= 0:
            continue
        try:
            reason = SkipReason(value)
        except ValueError:
            reason = SkipReason.ERROR
        out.extend(Skip(Path(""), reason, "not listed individually", rule_id)
                   for _ in range(remaining))
    return out


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
                skips.append(Skip(finding.path, SkipReason.REFUSED_BY_GUARD, str(exc),
                                  finding.rule_id))
                continue
            if not finding.path.exists():
                skips.append(Skip(finding.path, SkipReason.VANISHED, "already gone",
                                  finding.rule_id))
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
                skips.append(Skip(finding.path, SkipReason.REFUSED_BY_GUARD, str(exc),
                                  finding.rule_id))
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
                skips.append(Skip(approved, SkipReason.ERROR, str(exc),
                                  finding.rule_id))
                continue
            except OSError as exc:
                reason, detail = classify_os_error(exc)
                skips.append(Skip(approved, reason, detail, finding.rule_id))
                continue

            completed += 1
            bytes_ += size

        # Everything that needs administrator rights, in one pass, after the
        # ordinary one. Deliberately not inline above: escalating per file
        # means one UAC prompt per file, and windows-temp is several hundred
        # files. See docs/adr/0004.
        elevation = ElevationRecord()
        if self.allow_elevation and not cancel.is_set():
            completed, bytes_, skips, elevation = self._elevated_pass(
                skips, completed, bytes_, cancel)

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
            skips=skips, reversals=reversals, dry_run=False,
            elevation=elevation)

    def _elevated_pass(self, skips: list[Skip], completed: int, bytes_: int,
                       cancel: threading.Event
                       ) -> tuple[int, int, list[Skip], ElevationRecord]:
        r"""Retry the permission-denied items, one prompt per rule.

        Only ``SkipReason.PERMISSION`` reaches here. A locked file is not
        something administrator rights fix -- it is in use -- and offering to
        elevate for it would be selling a privilege that cannot help.

        What is *not* sent: no path, no decision, no "the guard already said
        yes". The helper is given a rule id and the user's exclusions, and
        resolves everything else for itself at privilege.
        """
        from polyscour.elevation.client import request as elevated_request
        from polyscour.elevation.protocol import Operation as ElevOp

        needs_admin = [s for s in skips if s.reason is SkipReason.PERMISSION]
        if not needs_admin:
            return completed, bytes_, skips, ElevationRecord()

        # Sorted so the prompts arrive in a stable order rather than whatever
        # order the filesystem produced. A user seeing two prompts should see
        # them in the same order twice.
        rule_ids = sorted({s.rule_id for s in needs_admin if s.rule_id})
        exclusions = [str(p) for p in self.guard.exclusions]

        record = ElevationRecord(requested=True)
        kept = [s for s in skips if s.reason is not SkipReason.PERMISSION]
        granted = False
        attempted = succeeded = 0
        details: list[str] = []

        for rule_id in rule_ids:
            if cancel.is_set():
                break
            response = elevated_request(ElevOp.DELETE_APPROVED_PATHS_FOR_RULE,
                                        cancel=cancel,
                                        rule_id=rule_id,
                                        exclusions=exclusions)
            if not response.ok:
                # Report the original permission skips, not a second stranger
                # error. Someone who declined the prompt should read "needs
                # administrator rights", which is what they already saw.
                kept.extend(s for s in needs_admin if s.rule_id == rule_id)
                details.append(response.detail)
                continue

            granted = True
            data = response.data
            deleted = int(data.get("deleted", 0))
            attempted += int(data.get("candidates", 0))
            succeeded += deleted
            completed += deleted
            bytes_ += int(data.get("bytes_freed", 0))
            kept.extend(_skips_from(data))

        record = ElevationRecord(requested=True, granted=granted,
                                 attempted=attempted, succeeded=succeeded,
                                 detail="; ".join(d for d in details if d))
        return completed, bytes_, kept, record

    # ── helpers ──────────────────────────────────────────────────────────────

    def _authorise(self, finding) -> Path:
        operation = next(iter(entry_for(finding.rule_id).operations))
        return self.guard.authorize(finding.rule_id, finding.path, operation)

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
