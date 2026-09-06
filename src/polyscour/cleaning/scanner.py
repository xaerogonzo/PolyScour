r"""DISCOVER and ANALYZE. Produces findings; deletes nothing, ever.

The scanner has no destructive capability at all -- not a guarded one, none. It
walks, measures, and describes. That separation is why "scan" can be the default
thing the product does and why it can run unelevated without asking for anything.

Three properties worth stating because they are easy to lose later:

* **Every candidate is authorised by the guard, during the scan.** Not because
  the scan could delete anything, but because a finding the guard would refuse
  must never reach the user as an offer. Offering it and then refusing at
  execution time would be a worse experience and a worse bug.
* **Ceilings abort a rule rather than truncating it.** Returning the first
  50,000 of 842,000 matches would present a wrong number confidently. Aborting
  and saying so is the honest failure.
* **Cancellation is checked between items**, so a scan over a large tree stops
  when asked instead of when finished.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from polyscour.cleaning.rules import Rule
from polyscour.contracts import Evidence, Finding, RuleOutcome, ScanResult
from polyscour.safety.guard import Guard, GuardRefusal
from polyscour.safety.policy import resolve_family


def _process_names() -> set[str]:
    """Lower-cased names of running processes, or an empty set if unknowable.

    An empty set is deliberately *not* treated as "nothing is running" by the
    caller -- see `condition_met`. Failing open here would let a cache be
    cleaned out from under a live browser.
    """
    try:
        import psutil
    except ImportError:
        return set()
    names = set()
    for proc in psutil.process_iter(["name"]):
        try:
            n = proc.info.get("name")
            if n:
                names.add(n.lower())
        except Exception:
            continue
    return names


#: condition name -> process names whose absence the condition requires
_BROWSER_PROCESSES = {
    "chrome_not_running": {"chrome.exe"},
    "edge_not_running": {"msedge.exe"},
    "firefox_not_running": {"firefox.exe"},
}


def condition_met(condition: str, running: set[str] | None) -> tuple[bool, str]:
    """Whether a precondition holds, and why.

    ``running is None`` means process enumeration failed. That is treated as
    **not met**: cleaning a browser cache while the browser holds it open can
    corrupt the profile, so an unknown answer must behave like the dangerous
    one. Failing open would be a silent correctness bug that only shows up on
    someone else's machine.
    """
    procs = _BROWSER_PROCESSES.get(condition)
    if procs is None:
        return False, f"unknown condition {condition!r}"
    if running is None:
        return False, (f"cannot tell whether {'/'.join(sorted(procs))} is "
                       f"running; skipping rather than risking an open profile")
    clash = procs & running
    if clash:
        return False, f"{', '.join(sorted(clash))} is running"
    return True, ""


class Scanner:
    def __init__(self, guard: Guard | None = None) -> None:
        self.guard = guard or Guard()

    def scan(self, rules: list[Rule],
             cancel: threading.Event | None = None,
             on_progress=None) -> ScanResult:
        """Walk every rule and describe what is there.

        ``on_progress(rule_id, files_seen)`` is called from this thread, at
        intervals rather than per file. A full scan of a real machine takes tens
        of seconds; without it the UI shows a motionless "Scanning..." and the
        honest interpretation of that is "hung".
        """
        started = datetime.now(timezone.utc)
        cancel = cancel or threading.Event()
        self.guard.begin()      # re-resolve root families once, not per file
        outcomes: list[RuleOutcome] = []

        running = _process_names() or None

        for rule in rules:
            if cancel.is_set():
                break
            outcomes.append(
                self._scan_rule(rule, running, cancel, on_progress))

        return ScanResult(started_at=started,
                          finished_at=datetime.now(timezone.utc),
                          outcomes=outcomes,
                          cancelled=cancel.is_set())

    # ── one rule ─────────────────────────────────────────────────────────────

    def _scan_rule(self, rule: Rule, running: set[str] | None,
                   cancel: threading.Event, on_progress=None) -> RuleOutcome:
        outcome = RuleOutcome(rule_id=rule.id)

        for condition in rule.conditions:
            ok, why = condition_met(condition, running)
            if not ok:
                outcome.aborted = True
                outcome.abort_reason = why
                return outcome

        roots: list[Path] = []
        for family in rule.families:
            roots.extend(resolve_family(family))
        if not roots:
            outcome.aborted = True
            outcome.abort_reason = "nothing to scan on this machine"
            return outcome

        cutoff = (datetime.now(timezone.utc)
                  - timedelta(days=rule.min_age_days)).timestamp()

        if on_progress:
            on_progress(rule.id, 0)

        seen = 0
        total = 0
        walked = 0
        for root in roots:
            for path, depth in self._walk(root, rule.max_depth, cancel):
                if cancel.is_set():
                    return outcome

                walked += 1
                if on_progress and walked % 2000 == 0:
                    on_progress(rule.id, walked)

                if not self._matches(path, rule.patterns):
                    continue

                try:
                    st = path.stat()
                except OSError:
                    outcome.skipped_paths += 1
                    continue

                if rule.min_age_days and st.st_mtime > cutoff:
                    continue

                try:
                    approved = self.guard.authorize(rule.id, path, rule.operation)
                except GuardRefusal:
                    # Not surfaced as a finding: an offer the guard would refuse
                    # must never reach the user. Counted, so a rule that refuses
                    # everything is visible rather than merely empty.
                    outcome.skipped_paths += 1
                    continue

                seen += 1
                total += st.st_size

                if seen > rule.max_candidates or total > rule.max_bytes:
                    outcome.aborted = True
                    outcome.findings.clear()
                    outcome.abort_reason = (
                        f"matched more than the {rule.max_candidates:,} files / "
                        f"{rule.max_bytes:,} bytes this rule is allowed to "
                        f"consider. Scan abandoned for this rule rather than "
                        f"reporting a partial figure as if it were complete.")
                    return outcome

                outcome.findings.append(self._finding(rule, approved, st.st_size))

        return outcome

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _walk(root: Path, max_depth: int, cancel: threading.Event):
        """Depth-limited walk that never follows a directory link.

        ``os.walk(followlinks=False)`` is the default and is relied on here: the
        guard would refuse anything reached through a junction anyway, but not
        descending into one in the first place means a planted link cannot make
        a scan take an hour.
        """
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if cancel.is_set():
                return
            here = Path(dirpath)
            depth = len(here.parts) - root_depth
            if depth >= max_depth:
                dirnames.clear()
            for name in filenames:
                yield here / name, depth

    @staticmethod
    def _matches(path: Path, patterns: tuple[str, ...]) -> bool:
        from fnmatch import fnmatch
        name = path.name.lower()
        return any(fnmatch(name, p.lower()) for p in patterns)

    @staticmethod
    def _finding(rule: Rule, path: Path, size: int) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.name,
            path=path,
            size_bytes=size,
            risk=rule.risk,
            reversible=rule.reversible,
            requires_elevation=rule.requires_elevation,
            evidence=Evidence(
                mechanism=", ".join(f.value for f in rule.families),
                observation=f"{path.name} ({size:,} bytes)",
                rationale=rule.description,
            ),
        )
