r"""Print how a real build resolves its paths — the part no unit test can reach.

``tests/test_entry.py`` drives frozen behaviour by overriding
``polybedrock.paths._FROZEN_OVERRIDE``. That covers the **policy** — what the
code does when it believes it is frozen — and cannot cover the **detection**,
because the suite never runs inside a compiled build. Two claims go unchecked
there, and both are silent when wrong:

1. ``is_frozen()`` rests on ``"__compiled__" in globals()``, which is a claim
   about Nuitka rather than about this code. A build that believes it is a
   source checkout resolves ``resource_root()`` two levels too high and finds
   no rules at all — a Clean screen with nothing on it and no error.

2. ``resource_root()``'s level adjustment exists because a build has no ``src/``
   level. That discrepancy lives in a ``__file__`` layout which only exists
   inside a real build. PolyShield's equivalent off-by-one was found by a probe
   exactly like this one, after no test could.

So this is compiled with the same flags as the real entry point and run from
the build, where its answers are facts rather than fixtures:

    venv\Scripts\python.exe -m nuitka --onefile ^
        --include-package=polyscour --include-package=polybedrock ^
        --include-data-dir=rules=rules ^
        --output-dir=dist tools\build_probe.py
    dist\build_probe.exe

Emits JSON so ``build.ps1`` can gate on it. Exits non-zero when the build has
resolved something **durable** underneath the extraction directory, which is
the one outcome that must never ship: a onefile extraction directory is deleted
when the process exits, so a vault resolved into it loses every file a user
believed was recoverable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Run from a checkout too, so the probe can be sanity-checked before a build.
_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parent / "src",):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from polyscour import paths  # noqa: E402  (after bootstrap)


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def collect(expect_frozen: bool) -> dict:
    """``expect_frozen`` is passed by build.ps1 and not inferred.

    The probe cannot tell "running from a checkout, as intended" from "running
    inside a build whose detection failed" — both report ``frozen=False``, and
    they are opposite outcomes. So the caller says which run this is, and the
    gate only exists when it was compiled.
    """
    frozen = paths.is_frozen()
    resource = paths.resource_root()
    rules = paths.rules_dir()
    data = paths.app_root()

    try:
        rule_files = sorted(p.name for p in rules.glob("*.json"))
    except OSError:
        rule_files = []

    findings: list[str] = []

    # 1. The detection itself. Only a compiled run can answer this, and it is
    #    the assumption every other answer here rests on.
    if expect_frozen and not frozen:
        findings.append(
            "is_frozen() returned False inside a build. Every path below is "
            "resolved as if this were a source checkout, which means the "
            "predicate rather than the paths is what is broken.")
    if frozen and not expect_frozen:
        findings.append(
            "is_frozen() returned True outside a build. Harmless here, but it "
            "means the predicate is answering something other than the "
            "question, and every frozen-only path is now unverifiable.")

    # 2. Durable data must never live under a directory that is deleted on
    #    exit. This is the failure that silently destroys a user's vault.
    if _is_within(data, resource):
        findings.append(
            f"the data root {data} is underneath the resource root {resource}. "
            f"A onefile extraction directory is removed when the process ends, "
            f"so the vault and ledger would not survive a restart.")

    # 3. Resources have to actually be in the bundle. A build that resolves the
    #    right directory and finds nothing in it presents as a working
    #    application with no cleaning rules -- which reads as a scan that found
    #    nothing, rather than as a broken build. Checked in both runs, because
    #    a checkout that cannot find its own rules is equally broken.
    if not rules.is_dir():
        findings.append(f"the rules directory {rules} does not exist. "
                        f"Is --include-data-dir=rules=rules set?")
    elif not rule_files:
        findings.append(f"the rules directory {rules} is empty.")

    # 4. adr/0005: the vault stays user-scoped. A build must not relocate it.
    if "ProgramData" in str(data):
        findings.append(
            f"the data root {data} is machine-scoped. docs/adr/0005 keeps it "
            f"in %LOCALAPPDATA%; PolyScour has no privileged writer.")

    return {
        "frozen": frozen,
        "executable": sys.executable,
        "resource_root": str(resource),
        "rules_dir": str(rules),
        "rule_files": rule_files,
        "data_root": str(data),
        "vault_dir": str(paths.vault_dir()),
        "ledger_path": str(paths.ledger_path()),
        "config_dir": str(paths.config_dir()),
        "findings": findings,
        "ok": not findings,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    unknown = [a for a in args if a != "--expect-frozen"]
    if unknown:
        print(f"usage: build_probe [--expect-frozen]  (got {unknown})",
              file=sys.stderr)
        return 2

    report = collect(expect_frozen="--expect-frozen" in args)
    print(json.dumps(report, indent=2))
    for finding in report["findings"]:
        print(f"FAIL: {finding}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
