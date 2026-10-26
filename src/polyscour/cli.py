r"""The command line: ``PolyScour.exe --cli <verb>``. Read-only, and only two verbs.

``scan``     what the Clean screen would find, per rule, with the same guard.
``history``  what the ledger recorded PolyScour doing.

Nothing here changes the machine: no executor is constructed, no vault, no
elevation, no ledger write. There is deliberately no ``plan`` verb. A plan is
the executor's input, and with no execute verb a printed "plan" would be a
recommendation with no decision behind it -- ``scan`` already shows each
finding's risk and whether it could be undone, which is what a plan adds.
adr/0017 records this, and why a mutating verb is a separate decision.

Why ``--cli`` is a flag and not a bare ``scan``
-----------------------------------------------

``entry.py`` dispatches on exact strings and refuses what it does not
recognise, because this is the command line of a program that can be launched
with administrator rights. A bare ``PolyScour.exe scna`` must stay an unknown
argument rather than becoming a near miss that something helpfully accepts.
The same reasoning is why ``allow_abbrev`` is off below: ``--js`` is not
``--json``.

No GUI toolkit is imported anywhere on this path, for the reason ``entry.py``
gives, and a test asserts it.

Exit codes
----------

0  ran to the end and read everything it was asked to
1  ran, but part of it could not be read: a rule aborted, a rule file did not
   load, or the scan was cancelled. The output says which. An unread rule is
   never reported as one with nothing found.
2  usage error
3  could not run at all (no output stream, or the ledger could not be read)
130 interrupted. Nothing had been changed.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import threading
from pathlib import Path

#: Bumped when a key is renamed or removed, never when one is added.
SCHEMA = 1

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_USAGE = 2
EXIT_COULD_NOT_RUN = 3
EXIT_INTERRUPTED = 130

#: Imported lazily elsewhere so ``--help`` does not pay for the scanner; this
#: is the one constant that is cheap and needed to validate ``--rule``.
_RECYCLE_BIN_ID = "recycle-bin"


class _Usage(Exception):
    """The arguments were well formed but name something that is not there."""


# ── argument parsing ─────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="PolyScour.exe --cli", allow_abbrev=False,
        description="Read-only. Nothing this command does changes your machine.")
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="<verb>")

    scan = verbs.add_parser(
        "scan", allow_abbrev=False,
        help="find what the Clean screen would find; delete nothing",
        description="Scan with the same safety guard the Clean screen uses and "
                    "report what was found. Nothing is deleted, moved or "
                    "planned.")
    scan.add_argument("--rule", action="append", default=[], metavar="ID",
                      help="scan only this rule (repeatable); default is every "
                           "rule not disabled in Settings, plus the Recycle Bin")
    scan.add_argument("--list", action="store_true", dest="list_paths",
                      help="list every finding's path in the text output "
                           "(JSON always includes them)")
    scan.add_argument("--json", action="store_true",
                      help="machine-readable output, schema %d" % SCHEMA)

    history = verbs.add_parser(
        "history", allow_abbrev=False,
        help="what PolyScour recorded doing, newest first",
        description="Read the operation ledger without creating or changing "
                    "it.")
    history.add_argument("--limit", type=int, default=20, metavar="N",
                         help="most recent N operations (default 20)")
    history.add_argument("--json", action="store_true",
                         help="machine-readable output, schema %d" % SCHEMA)
    return parser


# ── scan ─────────────────────────────────────────────────────────────────────

def _load_rules():
    """(rules, load failures, disabled ids). The only place the CLI reads the
    rule files or the setting that disables some of them."""
    from polyscour import paths, settings as cfg
    from polyscour.cleaning.rules import load_all

    rules, failures = load_all(paths.rules_dir())
    return rules, failures, set(cfg.get("disabled_rules") or [])


def _choose(rules, disabled: set[str], wanted: list[str]):
    """Which rules to scan, and whether to include the Recycle Bin."""
    by_id = {r.id: r for r in rules}
    if not wanted:
        return [r for r in rules if r.id not in disabled], True

    unknown = [w for w in wanted if w not in by_id and w != _RECYCLE_BIN_ID]
    if unknown:
        known = ", ".join(sorted([*by_id, _RECYCLE_BIN_ID]))
        raise _Usage(f"unknown rule: {', '.join(unknown)}. Known rules: {known}")
    off = [w for w in wanted if w in disabled]
    if off:
        # A rule turned off in Settings is the person's decision, and a
        # command line is not a way around it.
        raise _Usage(f"disabled in Settings, so not scanned: {', '.join(off)}")
    chosen = [by_id[w] for w in dict.fromkeys(wanted) if w in by_id]
    return chosen, _RECYCLE_BIN_ID in wanted


def _collect_scan(rules, include_recycle_bin: bool):
    """The scan itself: the Clean screen's own construction, minus the GUI.

    ``Services`` in ``app.py`` is not reused because importing it imports
    CustomTkinter. It is also not constructed because it creates the vault,
    initialises the ledger and runs Game Mode recovery -- all of which change
    the machine, none of which a scan needs.
    """
    from polyscour import settings as cfg
    from polyscour.cleaning import recyclebin
    from polyscour.cleaning.scanner import Scanner
    from polyscour.integrations.polyshield import PathAdvisor
    from polyscour.safety.guard import Guard

    exclusions = [Path(p) for p in (cfg.get("exclusions") or [])]
    guard = Guard(exclusions=exclusions, advisor=PathAdvisor(
        enabled=lambda: bool(cfg.get("polyshield_path_checks"))))
    result = Scanner(guard=guard).scan(rules, threading.Event())
    if include_recycle_bin and not result.cancelled:
        result.outcomes.append(recyclebin.scan())
    return result


def _finding_doc(f) -> dict:
    return {
        "path": str(f.path),
        "title": f.title,
        "size_bytes": f.size_bytes,
        "risk": f.risk.name.lower(),
        "reversible": f.reversible,
        "requires_elevation": f.requires_elevation,
        "evidence": {"mechanism": f.evidence.mechanism,
                     "observation": f.evidence.observation,
                     "rationale": f.evidence.rationale},
    }


def _scan_doc(result, failures) -> dict:
    return {
        "schema": SCHEMA,
        "command": "scan",
        "read_only": True,
        "started_at": result.started_at.isoformat(timespec="seconds"),
        "finished_at": result.finished_at.isoformat(timespec="seconds"),
        "cancelled": result.cancelled,
        "total_findings": len(result.findings),
        "total_bytes": result.total_bytes,
        "rules": [{
            "rule_id": o.rule_id,
            "aborted": o.aborted,
            "abort_reason": o.abort_reason,
            "skipped_paths": o.skipped_paths,
            "withheld_by_polyshield": o.withheld_by_polyshield,
            "finding_count": len(o.findings),
            "total_bytes": o.total_bytes,
            "findings": [_finding_doc(f) for f in o.findings],
        } for o in result.outcomes],
        "rule_files_failed": [{"path": str(p), "error": str(e)}
                              for p, e in failures],
    }


def _rollback_summary(findings) -> str:
    recoverable = sum(1 for f in findings if f.reversible)
    if recoverable == len(findings):
        return "Recoverable from the vault"
    if recoverable == 0:
        return "Not reversible"
    return f"{recoverable} of {len(findings)} recoverable from the vault"


def _print_scan(result, failures, names: dict[str, str], list_paths: bool,
                out) -> None:
    from polyscour.formatting import human

    print("PolyScour scan. Read-only: nothing was changed.\n", file=out)
    for o in result.outcomes:
        title = names.get(o.rule_id, o.rule_id)
        print(f"{title} ({o.rule_id})", file=out)
        if o.aborted:
            print(f"    NOT READ: the rule stopped. {o.abort_reason}", file=out)
        elif not o.findings:
            print("    Nothing found.", file=out)
        else:
            risk = max(f.risk for f in o.findings)
            print(f"    {len(o.findings):,} item(s), {human(o.total_bytes)}"
                  f"  |  {risk.label} risk  |  {_rollback_summary(o.findings)}",
                  file=out)
            mechanisms = sorted({f.evidence.mechanism for f in o.findings})
            shown = "; ".join(mechanisms[:3])
            more = f" (+{len(mechanisms) - 3} more)" if len(mechanisms) > 3 else ""
            print(f"    Reads: {shown}{more}", file=out)
            needs_admin = sum(1 for f in o.findings if f.requires_elevation)
            if needs_admin:
                print(f"    {needs_admin:,} need administrator rights. This "
                      f"command never asks for them.", file=out)
        if o.skipped_paths:
            print(f"    {o.skipped_paths:,} path(s) skipped (in use or "
                  f"unreadable).", file=out)
        if o.withheld_by_polyshield:
            print(f"    {o.withheld_by_polyshield:,} left out: PolyShield has "
                  f"a recorded detection there.", file=out)
        if list_paths:
            for f in o.findings:
                print(f"      {human(f.size_bytes):>10}  {f.path}", file=out)
        print(file=out)

    for path_, error in failures:
        print(f"NOT READ: rule file {path_} did not load: {error}", file=out)
    if result.cancelled:
        print("NOT FINISHED: the scan was cancelled, so what is above is "
              "partial.", file=out)
    print(f"Found {human(result.total_bytes)} in {len(result.findings):,} "
          f"item(s) across {len(result.outcomes)} rule(s).", file=out)


def _cmd_scan(ns, out) -> int:
    rules, failures, disabled = _load_rules()
    chosen, include_bin = _choose(rules, disabled, ns.rule)
    result = _collect_scan(chosen, include_bin)

    if ns.json:
        json.dump(_scan_doc(result, failures), out, indent=2)
        print(file=out)
    else:
        names = {r.id: r.name for r in rules}
        names[_RECYCLE_BIN_ID] = "Recycle Bin"
        _print_scan(result, failures, names, ns.list_paths, out)

    unread = (any(o.aborted for o in result.outcomes) or bool(failures)
              or result.cancelled)
    return EXIT_PARTIAL if unread else EXIT_OK


# ── history ──────────────────────────────────────────────────────────────────

def _operation_doc(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        rule_ids = json.loads(d["rule_ids"])
    except (ValueError, TypeError):
        rule_ids = d["rule_ids"]
    doc = {
        "operation_id": d["operation_id"],
        "started_at": d["started_at"],
        "finished_at": d["finished_at"],
        "outcome": d["outcome"],
        "dry_run": bool(d["dry_run"]),
        "bytes_freed": d["bytes_freed"],
        "items_completed": d["items_completed"],
        "rule_ids": rule_ids,
        "summary": d["summary"],
    }
    # Columns a ledger written by an older PolyScour does not have. Absent is
    # absent, not "no elevation".
    keys = ("elevation_requested", "elevation_granted",
            "elevation_attempted", "elevation_succeeded")
    doc["elevation"] = ({k.split("_", 1)[1]: d[k] for k in keys}
                        if all(k in d for k in keys) else None)
    return doc


def _cmd_history(ns, out) -> int:
    from polyscour import paths
    from polyscour.formatting import human
    from polyscour.ledger import Ledger

    if ns.limit < 1:
        raise _Usage("--limit must be at least 1")
    try:
        rows = Ledger(paths.ledger_path()).history_readonly(ns.limit)
    except sqlite3.Error as exc:
        # Unreadable is not empty.
        print(f"The ledger could not be read: {exc}", file=sys.stderr)
        return EXIT_COULD_NOT_RUN

    ops = [_operation_doc(r) for r in (rows or [])]
    if ns.json:
        json.dump({"schema": SCHEMA, "command": "history", "read_only": True,
                   "ledger_exists": rows is not None, "operations": ops},
                  out, indent=2)
        print(file=out)
        return EXIT_OK

    if rows is None:
        print("Nothing has been recorded yet: no ledger exists.", file=out)
        return EXIT_OK
    if not ops:
        print("The ledger exists and holds no operations.", file=out)
        return EXIT_OK
    for op in ops:
        if op["dry_run"]:
            freed = "dry run"
        else:
            freed = human(op["bytes_freed"])
        rules = (", ".join(op["rule_ids"]) if isinstance(op["rule_ids"], list)
                 else str(op["rule_ids"]))
        print(f"{op['started_at']}  {op['outcome']:<24} {freed:>10}  "
              f"{op['items_completed']:,} item(s)  {rules}", file=out)
        print(f"    {op['summary']}", file=out)
        if op["dry_run"]:
            print("    A rehearsal: nothing was changed.", file=out)
    return EXIT_OK


# ── entry ────────────────────────────────────────────────────────────────────

def _never_fail_on_encoding(stream) -> None:
    """A legacy console code page cannot encode every character a Windows path
    may contain, and an exception here would lose the whole report over one
    file name. Escape instead."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass


def main(argv: list[str], out=None) -> int:
    if out is None:
        out = sys.stdout
        if out is None:
            # A build with no console (build.ps1 uses
            # --windows-console-mode=disable) has no stream to write to, and a
            # GUI-subsystem program is not waited for by cmd or PowerShell
            # either. adr/0017: the installed executable is not a supported
            # place to run this.
            return EXIT_COULD_NOT_RUN
        _never_fail_on_encoding(out)
        _never_fail_on_encoding(sys.stderr)

    try:
        ns = _build_parser().parse_args(argv)
    except SystemExit as exc:                       # argparse's own exit
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    try:
        if ns.verb == "scan":
            return _cmd_scan(ns, out)
        return _cmd_history(ns, out)
    except _Usage as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("Interrupted. Nothing had been changed.", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":                          # pragma: no cover
    sys.exit(main(sys.argv[1:]))
