r"""``installer/set_program_acls.ps1``, and the one door its mask did not cover.

T15 is the claim every other guarantee in ``THREAT_MODEL.md`` rests on: the
installed program directory is one an ordinary user cannot write. That claim is
enforced by a bitmask in a PowerShell script, and a bitmask with a missing bit
fails silently and in the passing direction.

``DeleteSubdirectoriesAndFiles`` (``FILE_DELETE_CHILD``, 0x40) was missing. It
is a right on the *directory* that permits removing a child **without** holding
``Delete`` (0x10000) on that child -- two independent bits, so the presence of
one says nothing about the other. An ACE granting Users only ``FILE_DELETE_CHILD``
therefore satisfied every check the script made, while leaving an ordinary user
able to remove ``PolyScour.exe`` and put their own there.

The second test below is the point of this module. It grants exactly that ACE
and requires the script to **fail**. A verifier that has never been watched
failing is not yet a verifier -- and this one shipped for two releases
answering "OK" to a directory it should have refused.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "installer" / "set_program_acls.ps1"

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="Windows ACLs")


def _powershell() -> str:
    for exe in ("pwsh", "powershell"):
        try:
            subprocess.run([exe, "-NoProfile", "-Command", "$null"],
                           capture_output=True, timeout=30, check=True)
            return exe
        except (OSError, subprocess.SubprocessError):
            continue
    pytest.skip("no PowerShell on PATH")


def _is_elevated() -> bool:
    out = subprocess.run(
        [_powershell(), "-NoProfile", "-Command",
         "[bool](New-Object Security.Principal.WindowsPrincipal("
         "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("
         "[Security.Principal.WindowsBuiltInRole]::Administrator)"],
        capture_output=True, text=True, timeout=60)
    return out.stdout.strip().lower() == "true"


def _verify(directory: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(_SCRIPT), "-Root", str(directory), "-Verify"],
        capture_output=True, text=True, timeout=120)


def _grant(directory: Path, rights: str) -> None:
    """Add an explicit ACE for Users, after breaking inheritance."""
    ps = _powershell()
    script = f'''
$p = "{directory}"
$acl = Get-Acl -LiteralPath $p
$acl.SetAccessRuleProtection($true, $false)          # break inheritance
$acl.Access | ForEach-Object {{ $null = $acl.RemoveAccessRule($_) }}
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $me, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    (New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")),
    "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    (New-Object Security.Principal.SecurityIdentifier("S-1-5-32-545")),
    "{rights}", "ContainerInherit,ObjectInherit", "None", "Allow")))
Set-Acl -LiteralPath $p -AclObject $acl
'''
    out = subprocess.run([ps, "-NoProfile", "-Command", script],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        pytest.skip(f"could not set a test ACL here: {out.stderr.strip()}")


def test_the_mask_names_file_delete_child():
    """The regression guard, read straight out of the script.

    Cheap and worth having on its own: the bug was one absent line, and it
    would come back the same way.
    """
    text = _SCRIPT.read_text(encoding="utf-8")
    assert "DeleteSubdirectoriesAndFiles" in text, (
        "WRITE_MASK must include DeleteSubdirectoriesAndFiles "
        "(FILE_DELETE_CHILD). Without it, an ACE granting Users only that "
        "right passes verification while permitting PolyScour.exe to be "
        "replaced -- which is T15, defeated.")


def test_verify_refuses_a_directory_where_users_hold_only_delete_child(tmp_path):
    """**The negative control.** The ACE the old mask let through.

    ``FILE_DELETE_CHILD`` alone: no ``WriteData``, no ``AppendData``, no
    ``Delete``. Every bit the mask used to test is absent, and the directory is
    still one where an ordinary user can remove the executable.
    """
    target = tmp_path / "program"
    target.mkdir()
    (target / "PolyScour.exe").write_bytes(b"MZ")

    _grant(target, "DeleteSubdirectoriesAndFiles")

    result = _verify(target)

    # THE ASSERTION THAT MATTERS is the second one, and the order here is
    # misleading enough to be worth stating.
    #
    # This test creates its own directory, so the current user owns it and can
    # write into it whatever the DACL says -- which means the script's write
    # probe fires on this fixture no matter what the mask contains. A check on
    # the exit code alone would therefore pass even with FILE_DELETE_CHILD
    # missing, for a reason that has nothing to do with the bug.
    #
    # Confirmed by removing the flag and re-running: the exit code stayed
    # non-zero and only the DACL assertion below caught the regression.
    assert result.returncode != 0, (
        "set_program_acls.ps1 -Verify PASSED a directory where the BUILTIN "
        "Users group hold FILE_DELETE_CHILD:\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    assert "may write" in result.stdout, (
        "-Verify failed, but NOT for the DACL reason -- so the mask did not "
        "notice FILE_DELETE_CHILD and this test would go on passing on the "
        f"strength of the write probe alone. stdout:\n{result.stdout}")


def test_verify_passes_a_real_administrator_only_directory():
    r"""The positive control, so the negative one is not merely always-fails.

    Without this, a script that refused *everything* would satisfy the test
    above perfectly and be worthless.

    It uses a real Windows directory rather than a fixture, and that is not
    laziness -- it is the only way to get one. A temp directory cannot serve:
    the current user *owns* it, an owner implicitly holds ``READ_CONTROL`` and
    ``WRITE_DAC``, and the script's write probe correctly notices. Trying it
    that way is what produced this test's first failure, and the script was
    right both times.

    ``C:\Program Files\Windows Defender`` is administrator-only on every
    supported Windows, and is the directory ``docs/adr/0006`` records being
    used for exactly this by hand.
    """
    if _is_elevated():
        pytest.skip("elevated: an administrator can write anywhere, so the "
                    "write probe would prove the opposite of what it looks "
                    "like it proves")

    import os
    target = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender"
    if not target.is_dir():
        pytest.skip(f"{target} is not present on this machine")

    result = _verify(target)
    assert result.returncode == 0, (
        f"{target} is administrator-only, so -Verify should pass it. A failure "
        f"here means the checks reject something they should accept, which "
        f"would make the negative control above meaningless:\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
