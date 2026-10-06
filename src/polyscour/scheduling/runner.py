r"""What runs when Task Scheduler invokes ``polyscour.exe --scheduled-clean
<schedule-id>``. No GUI, no confirmation dialog -- the whole point of a
schedule is that nobody is watching, which is exactly why every refusal here
is loud (a log file, and every real cleanup still reaches History through the
same ``ledger.record()`` a manual run does) rather than merely silent.

The order, every run
---------------------

    schedule exists and is enabled?
        -> the live Task Scheduler task still matches what PolyScour created?
            -> the safety policy has not moved past what was consented to?
                -> each rule's definition still matches its consented hash?
                    -> scan  ->  plan (dry_run=False)  ->  execute

Any refusal stops there and is logged; a per-rule refusal only drops that
rule, everything else in the schedule still runs (``scheduling/consent.py``).

Elevation is not a decision made here
---------------------------------------

``Executor`` is constructed with its default ``allow_elevation=False`` and
nothing in this module ever sets it otherwise -- not from
``Schedule.elevation_allowed``, not from anything else the schedule claims.
There is no code path here that could turn it on, which is a stronger
guarantee than "checked and refused": elevation for a scheduled run is not a
possibility this function contains, not a possibility this function checks
for.
"""
from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

log = logging.getLogger(__name__)


def _configure_logging() -> None:
    """A scheduled task has no console; without a file handler, every log
    line from an unattended run goes nowhere and a silent failure looks
    identical to nothing needing to happen."""
    from polyscour import paths

    logs_dir = paths.logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(logs_dir / "scheduled-clean.log",
                                  encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def run(schedule_id: str) -> int:
    # polyscour.settings, not polybedrock.settings directly -- importing the
    # substrate module bare would read an unconfigured singleton and raise.
    # polyscour.settings is what calls polybedrock.settings.configure() as an
    # import side effect (see polyscour/settings.py); app.py gets this for
    # free by importing it at module scope, but this entry point is reached
    # without ever importing app.py, so nothing else would trigger it.
    from polyscour import settings as cfg

    from polyscour import paths
    from polyscour.cleaning import rules as rules_module
    from polyscour.cleaning.executor import Executor
    from polyscour.cleaning.planner import plan
    from polyscour.cleaning.scanner import Scanner
    from polyscour.integrations.polyshield import PathAdvisor
    from polyscour.ledger import Ledger
    from polyscour.safety.guard import Guard
    from polyscour.scheduling import consent, store, task
    from polyscour.vault import Vault

    schedule = store.get(schedule_id)
    if schedule is None:
        log.error("no such schedule: %s", schedule_id)
        return 1

    if not schedule.enabled:
        log.info("%s: disabled; nothing to do", schedule_id)
        return 0

    task_ok, task_detail = task.verify(schedule_id)
    if not task_ok:
        log.error("%s: refusing -- %s", schedule_id, task_detail)
        return 1

    verified = consent.verify(schedule)
    if verified.schedule_refused:
        log.error("%s: refusing -- %s", schedule_id, verified.schedule_refused)
        return 1
    for rule_id, reason in verified.refused.items():
        log.warning("%s: skipping rule %s -- %s", schedule_id, rule_id, reason)
    if not verified.runnable_rule_ids:
        log.info("%s: no rule still matches its consented definition",
                 schedule_id)
        return 0

    exclusions = [Path(p) for p in (cfg.get("exclusions") or [])]
    # Unattended, so PolyShield's say matters more here than anywhere: nobody
    # is watching to notice a detection being cleaned away. Refuse-only, and
    # UNKNOWN (no PolyShield) changes nothing.
    guard = Guard(exclusions=exclusions, advisor=PathAdvisor())
    scanner = Scanner(guard=guard)
    vault = Vault(paths.vault_dir())
    ledger = Ledger(paths.ledger_path())
    ledger.initialise()
    vault.initialise()

    # allow_elevation is not passed -- see the module docstring. This is the
    # one line that matters most in this function.
    executor = Executor(vault=vault, ledger=ledger, guard=guard)

    loaded, load_failures = rules_module.load_all(paths.rules_dir())
    for path_, exc in load_failures:
        log.warning("%s: rule file %s did not load: %s", schedule_id, path_, exc)
    by_id = {r.id: r for r in loaded}
    runnable_rules = [by_id[r] for r in verified.runnable_rule_ids if r in by_id]
    if not runnable_rules:
        log.info("%s: none of the consented rules currently load", schedule_id)
        return 0

    scan_result = scanner.scan(runnable_rules, threading.Event())
    for outcome in scan_result.outcomes:
        if outcome.withheld_by_polyshield:
            log.info("%s: %s: left %d item(s) alone -- PolyShield has a "
                     "recorded detection there", schedule_id,
                     outcome.rule_id, outcome.withheld_by_polyshield)
    findings = scan_result.findings
    if not findings:
        log.info("%s: nothing found to clean", schedule_id)
        return 0

    action_plan = plan(findings, dry_run=False)
    action_result = executor.execute(action_plan, threading.Event())
    log.info("%s: %s", schedule_id, action_result.summary())
    return 0


def main(args: list[str]) -> int:
    _configure_logging()
    if not args:
        log.error("--scheduled-clean requires a schedule id")
        return 2
    try:
        return run(args[0])
    except Exception:                                       # noqa: BLE001
        # This process has no one watching it. An unhandled exception must
        # still leave a trace, not just a nonzero exit code Task Scheduler
        # quietly records in a history nobody checks.
        log.exception("%s: scheduled clean failed", args[0])
        return 1


if __name__ == "__main__":                                  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
