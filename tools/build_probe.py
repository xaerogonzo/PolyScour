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

    venv\Scripts\python.exe -m nuitka --standalone ^
        --include-package=polyscour --include-package=polybedrock ^
        --include-data-dir=rules=rules ^
        --output-dir=dist tools\build_probe.py
    dist\probe\build_probe.exe

**Same packaging as the product**, which is not a detail. A probe built
``--onefile`` would report on a layout nobody ships, and the layout is exactly
where these bugs live. THREAT_MODEL T24 records why the packaging is
``--standalone``.

Emits JSON so ``build.ps1`` can gate on it. Exits non-zero when the build has
put durable data under the resource root, when the cleaning rules are missing
from the payload, or when anything frozen is running out of a temporary
directory.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Run from a checkout too, so the probe can be sanity-checked before a build.
_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parent / "src",):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from polyscour import paths  # noqa: E402  (after bootstrap)


def _is_writable(directory: Path) -> bool:
    """Whether this process can create a file here.

    Probed rather than read from the DACL: ``os.access(..., W_OK)`` on Windows
    reports the read-only attribute and knows nothing about permissions, so it
    answers the wrong question in both directions.
    """
    import os as _os

    probe = directory / f".polyscour-probe-{_os.getpid()}"
    try:
        probe.touch(exist_ok=False)
    except OSError:
        return False
    try:
        probe.unlink()
    except OSError:
        pass
    return True



def _describe_dacl(directory: Path) -> list[str]:
    """The directory's ACEs as ``icacls`` prints them, or why they are unknown.

    Descriptive only. The *proof* is ``_is_writable`` above -- an ACL can be
    read and misread, whereas a file that appears is a file that appeared. This
    is here so a report that says "user-writable" also says *which* entry made
    it so, without the reader having to go and look.
    """
    import subprocess

    try:
        out = subprocess.run(["icacls", str(directory)], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"icacls unavailable: {exc}"]
    if out.returncode != 0:
        return [f"icacls exited {out.returncode}: {out.stderr.strip()}"]
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    return [ln for ln in lines if "Successfully processed" not in ln]

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
    #: True but not fatal. Kept apart from findings so `ok` keeps
    #: meaning "this build is shippable" rather than "nothing to say".
    notes: list[str] = []

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

    # 2. Durable data must never live under the resource root.
    #
    #    The check is unchanged; the reason it matters is not. Under onefile
    #    the resource root was a temporary directory deleted on exit, so a
    #    vault resolved into it was destroyed silently. Under --standalone the
    #    resource root is the INSTALLED directory, which fails differently and
    #    just as badly: it is administrator-only by design (T15), so an
    #    unelevated PolyScour could not write its vault there at all -- and an
    #    uninstall, which the installer promises leaves the vault alone, would
    #    take it with the program.
    #
    #    Spelled out because a check whose stated reason has quietly become
    #    false is one somebody eventually deletes as obsolete.
    if _is_within(data, resource):
        findings.append(
            f"the data root {data} is underneath the resource root {resource}. "
            f"The resource root is the installed program directory: "
            f"administrator-only by design, and removed by uninstall -- so the "
            f"vault would be unwritable, then lost. See adr/0005.")

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

    # 4. WHAT WOULD BE ELEVATED, and WHAT IT LOADS ONCE IT IS. Two questions,
    #    and the second was only asked after the first had been answered.
    #
    #    T23: under onefile, sys.executable named a python.exe inside a
    #    temporary extraction directory the user could write, and that was what
    #    ShellExecute("runas") was handed.
    #
    #    T24: fixing which binary is elevated did not fix what that binary
    #    loads. Onefile unpacked the runtime and every .pyd into
    #    %TEMP%\onefile_* and executed from there, so the code running as
    #    administrator lived outside the directory T15 protects. Measured here
    #    (user held Full Control, inherited from %LOCALAPPDATA%\Temp), and
    #    fixed by building --standalone: the DLLs now ship beside the
    #    executable, inside the installed directory.
    #
    #    So the invariant this gate enforces is the one that survives both:
    #    **nothing frozen may run out of a temporary directory.**
    #
    #    Note what it deliberately does NOT check any more. The old form asked
    #    whether the launcher was inside `resource_root()`, which under onefile
    #    meant "inside the extraction directory" and was the right question by
    #    accident. Under --standalone the resource root IS the installed
    #    directory, so the launcher being inside it is not merely permitted --
    #    it is the entire point, and that gate would fail every build.
    launcher = paths.running_executable()
    runtime_dir = Path(sys.executable).resolve().parent

    temp_root = Path(tempfile.gettempdir()).resolve()
    runtime_in_temp = _is_within(runtime_dir, temp_root)
    launcher_in_temp = _is_within(launcher, temp_root)

    if frozen and launcher_in_temp:
        findings.append(
            f"the launch target {launcher} is inside the temporary directory "
            f"{temp_root}. ShellExecute(\"runas\") on it would elevate a binary "
            f"an ordinary user can replace first -- THREAT_MODEL T23.")

    if frozen and runtime_in_temp:
        findings.append(
            f"the running image {sys.executable} is inside the temporary "
            f"directory {temp_root}, so the Python runtime and the native "
            f"extension modules this process loads -- including when it runs "
            f"as the ELEVATED helper -- are in a location an ordinary user can "
            f"write. That is THREAT_MODEL T24, and it is what --standalone "
            f"exists to prevent. Has --onefile come back?")

    # Writability of the launch directory is deliberately a NOTE, not a
    # finding. A freshly built exe sits in dist\, which is always writable --
    # gating on it would fail every build that ever runs, which is a gate
    # nobody can keep. Whether the SHIPPED location is administrator-only is
    # the installer's question, and installer\set_program_acls.ps1 -Verify
    # answers it where the answer means something.
    if frozen and _is_writable(launcher.parent):
        notes.append(
            f"{launcher.parent} is writable by this user, as an uninstalled "
            f"build's directory always is. T15 is satisfied by installing, "
            f"not by building -- check it with set_program_acls.ps1 -Verify.")

    # Reported whether or not it is a problem, because T24 was found by reading
    # these three values on a run where nothing was failing.
    runtime_dacl = _describe_dacl(runtime_dir) if frozen else []

    # 5. adr/0005: the vault stays user-scoped. A build must not relocate it.
    if "ProgramData" in str(data):
        findings.append(
            f"the data root {data} is machine-scoped. docs/adr/0005 keeps it "
            f"in %LOCALAPPDATA%; PolyScour has no privileged writer.")

    return {
        "frozen": frozen,
        "executable": sys.executable,
        "resource_root": str(resource),
        "launch_target": str(launcher),
        "runtime_dir": str(runtime_dir) if frozen else None,
        "runtime_dir_in_temp": runtime_in_temp if frozen else None,
        "runtime_dir_writable": _is_writable(runtime_dir) if frozen else None,
        "runtime_dir_dacl": runtime_dacl,
        "sys_executable": sys.executable,
        "rules_dir": str(rules),
        "rule_files": rule_files,
        "data_root": str(data),
        "vault_dir": str(paths.vault_dir()),
        "ledger_path": str(paths.ledger_path()),
        "config_dir": str(paths.config_dir()),
        "findings": findings,
        "notes": notes,
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
    for note in report.get("notes", []):
        print(f"note: {note}", file=sys.stderr)
    for finding in report["findings"]:
        print(f"FAIL: {finding}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
