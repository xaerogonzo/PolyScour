r"""The shared vocabulary. Every subsystem speaks in these types.

The shape encodes the product's central rule: **a finding is not a
recommendation.** A ``Finding`` says what was found and why; deciding whether to
act on it is a separate step producing an ``ActionPlan``, and executing that plan
is a third. Nothing here lets a scanner delete anything.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


class RiskLevel(enum.IntEnum):
    """Drives how much confirmation the UI demands.

    Ordered, so a plan can be summarised by its worst member.
    """
    SAFE = 0        # regenerable cache; losing it costs a rebuild
    LOW = 1         # temporary data no application expects to survive
    MODERATE = 2    # data a user might miss
    HIGH = 3        # system state; reversible only through a recorded rollback
    CRITICAL = 4    # irreversible and destructive; not reachable in 0.1

    @property
    def label(self) -> str:
        return self.name.capitalize()


class OperationOutcome(enum.Enum):
    """How an execution ended.

    A locked file is a *normal condition*, not a failure -- an antivirus, a
    browser, or the user's own editor holding a handle is the expected case on a
    live machine. Collapsing that into FAILED would train users to ignore the
    result, which is the opposite of what this product is for.
    """
    SUCCESS = "success"                          # every planned item handled
    SUCCESS_WITH_SKIPS = "success_with_skips"    # all failures expected/benign
    PARTIALLY_COMPLETED = "partially_completed"  # some failed unexpectedly
    FAILED = "failed"                            # nothing done, or precondition failed
    CANCELLED = "cancelled"                      # user stopped it; completed items stand

    @property
    def is_clean(self) -> bool:
        return self in (OperationOutcome.SUCCESS,
                        OperationOutcome.SUCCESS_WITH_SKIPS)


class SkipReason(enum.Enum):
    """Why one item was not acted on.

    Benign reasons do not degrade the outcome. REFUSED_BY_GUARD deliberately is
    not benign: the guard refusing a target the planner produced means either a
    bug or an attack, and either way it should be loud.
    """
    LOCKED = "locked"                        # sharing violation -- expected
    PERMISSION = "permission"                # needs elevation -- expected
    VANISHED = "vanished"                    # gone before we got to it
    REFUSED_BY_GUARD = "refused_by_guard"    # NOT benign
    ERROR = "error"                          # unclassified -- not benign

    @property
    def is_benign(self) -> bool:
        return self in (SkipReason.LOCKED, SkipReason.PERMISSION,
                        SkipReason.VANISHED)


@dataclass(frozen=True)
class Evidence:
    """Why this was detected, in terms a user can check for themselves.

    Free text is deliberately not enough: ``mechanism`` names the concrete
    Windows thing being read or changed, because "some Windows startup thing" is
    how a maintenance tool starts being untrustworthy.
    """
    mechanism: str        # e.g. r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache"
    observation: str      # e.g. "412 files older than 7 days"
    rationale: str        # e.g. "Chrome rebuilds this cache on next launch."


@dataclass(frozen=True)
class Finding:
    """One thing that was found. Says nothing about whether to act on it."""
    rule_id: str
    title: str
    path: Path
    size_bytes: int
    risk: RiskLevel
    evidence: Evidence
    #: False means deletion is permanent. Stated per finding rather than per rule
    #: because the UI must never imply an undo that does not exist.
    reversible: bool
    requires_elevation: bool = False

    @property
    def rollback_label(self) -> str:
        return "Recoverable from the vault" if self.reversible else "Not reversible"


@dataclass
class RuleOutcome:
    """What happened to one rule during a scan -- including refusing to run.

    An aborted rule is reported rather than silently dropped: a rule that
    unexpectedly matched 842,000 files is a fault worth seeing, and hiding it
    would present someone's filesystem as cache.
    """
    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    skipped_paths: int = 0

    @property
    def total_bytes(self) -> int:
        return sum(f.size_bytes for f in self.findings)


@dataclass
class ScanResult:
    started_at: datetime
    finished_at: datetime
    outcomes: list[RuleOutcome] = field(default_factory=list)
    cancelled: bool = False

    @property
    def findings(self) -> list[Finding]:
        return [f for o in self.outcomes for f in o.findings]

    @property
    def total_bytes(self) -> int:
        return sum(f.size_bytes for f in self.findings)

    @property
    def aborted_rules(self) -> list[RuleOutcome]:
        return [o for o in self.outcomes if o.aborted]

    def bytes_by_risk(self) -> dict[RiskLevel, int]:
        out: dict[RiskLevel, int] = {}
        for f in self.findings:
            out[f.risk] = out.get(f.risk, 0) + f.size_bytes
        return out


@dataclass(frozen=True)
class ActionPlan:
    """The user's decision, frozen. The executor acts on this and nothing else.

    Separate from ScanResult because the set the user confirmed is not
    necessarily the set that was found -- and that difference is exactly what a
    confirmation step is for.
    """
    findings: tuple[Finding, ...]
    dry_run: bool

    @property
    def total_bytes(self) -> int:
        return sum(f.size_bytes for f in self.findings)

    @property
    def worst_risk(self) -> RiskLevel:
        return max((f.risk for f in self.findings), default=RiskLevel.SAFE)

    @property
    def reversible_count(self) -> int:
        return sum(1 for f in self.findings if f.reversible)


@dataclass(frozen=True)
class Skip:
    path: Path
    reason: SkipReason
    detail: str = ""
    #: Which rule was acting. Needed because a permission skip is retried by
    #: *rule* — the elevated helper is asked for a rule, never for a path —
    #: and because the retry offer has to name what it will act on.
    rule_id: str = ""


@dataclass(frozen=True)
class Reversal:
    """How to undo one executed item, or the recorded fact that it cannot be."""
    operation_id: str
    vault_object: str | None      # SHA-256 of the vaulted payload, or None
    original_path: Path

    @property
    def possible(self) -> bool:
        return self.vault_object is not None


@dataclass(frozen=True)
class ElevationRecord:
    """What happened when administrator rights were involved.

    Four facts rather than one flag, because "elevated: yes" is untrue in both
    of the common failure paths. A user who declines the prompt requested
    elevation and was not granted it; a helper that runs and partly fails was
    granted it and did not finish. Collapsing those into a boolean would make
    History assert something that did not happen, which is the one thing this
    product's records exist not to do.
    """
    requested: bool = False
    granted: bool = False
    attempted: int = 0
    succeeded: int = 0
    #: Why it did not happen, when it did not. The helper's own words.
    detail: str = ""

    @property
    def happened(self) -> bool:
        return self.granted and self.succeeded > 0

    def describe(self) -> str:
        """A sentence for History. Empty when elevation was never involved."""
        if not self.requested:
            return ""
        if not self.granted:
            return (f"Administrator retry requested — not granted"
                    f"{': ' + self.detail if self.detail else ''}")
        return (f"Administrator retry requested and granted — "
                f"{self.succeeded:,} of {self.attempted:,} items removed")


@dataclass
class ActionResult:
    operation_id: str
    outcome: OperationOutcome
    started_at: datetime
    finished_at: datetime
    bytes_freed: int = 0
    items_completed: int = 0
    skips: list[Skip] = field(default_factory=list)
    reversals: list[Reversal] = field(default_factory=list)
    dry_run: bool = False
    elevation: ElevationRecord = field(default_factory=lambda: ElevationRecord())

    @property
    def benign_skips(self) -> list[Skip]:
        return [s for s in self.skips if s.reason.is_benign]

    @property
    def hard_failures(self) -> list[Skip]:
        return [s for s in self.skips if not s.reason.is_benign]

    def summary(self) -> str:
        """One line, honest about what was and was not done."""
        if self.dry_run:
            return (f"Dry run: {self.items_completed} items "
                    f"({self.bytes_freed:,} bytes) would be removed.")
        parts = [f"{self.items_completed} items removed",
                 f"{self.bytes_freed:,} bytes freed"]
        if self.benign_skips:
            parts.append(f"{len(self.benign_skips)} skipped")
        if self.hard_failures:
            parts.append(f"{len(self.hard_failures)} failed")
        return ", ".join(parts) + "."


#: Windows error codes worth telling apart. Anything else is unclassified and
#: therefore not benign — an unknown failure must degrade the outcome.
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33


def classify_os_error(exc: OSError) -> tuple[SkipReason, str]:
    """Turn a failed filesystem call into a skip reason and a phrase.

    Lives here rather than in the executor because there are now two callers at
    two privilege levels — the executor and the elevated helper — and they must
    agree about what "locked" means. A helper that called a sharing violation
    an error would make an ordinary in-use file look like a failure that needs
    investigating.
    """
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


def classify(planned: int, completed: int, skips: list[Skip],
             cancelled: bool = False) -> OperationOutcome:
    """The single place an outcome is decided.

    Kept as one function so the taxonomy cannot drift between the executor, the
    history view and later scheduled runs.
    """
    if cancelled:
        return OperationOutcome.CANCELLED

    went_wrong = any(not s.reason.is_benign for s in skips)

    # FAILED means "something went wrong and nothing was achieved" -- not merely
    # "nothing happened". A plan of one file that turned out to be open in a
    # browser achieved nothing and yet nothing broke; reporting that as FAILED
    # would tell the user to go looking for a fault that does not exist, and
    # would train them to ignore the outcome. It is SUCCESS_WITH_SKIPS with a
    # count of zero, and the summary line says so plainly.
    if went_wrong:
        return (OperationOutcome.FAILED if completed == 0
                else OperationOutcome.PARTIALLY_COMPLETED)
    if skips:
        return OperationOutcome.SUCCESS_WITH_SKIPS
    return OperationOutcome.SUCCESS
