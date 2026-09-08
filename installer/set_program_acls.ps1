# =============================================================================
# set_program_acls.ps1 - make the program directory administrator-only
# =============================================================================
#
#   powershell -ExecutionPolicy Bypass -File set_program_acls.ps1 -Root "C:\Program Files\PolyScour"
#   powershell -ExecutionPolicy Bypass -File set_program_acls.ps1 -Root "..." -WhatIf
#   powershell -ExecutionPolicy Bypass -File set_program_acls.ps1 -Root "..." -Verify
#
# Run ELEVATED, by the installer, before the application is first started.
#
# Why this exists at all
# ----------------------
#
# PolyScour.exe is two programs: the GUI, and the elevated helper it launches
# through Windows' consent prompt. Every rule inside that helper -- the closed
# operation set, the guard chain re-run at privilege, the refusal to delete a
# directory -- is worth exactly as much as the answer to "who can rewrite this
# file?". THREAT_MODEL.md T15 says so plainly:
#
#     an attacker who can modify PolyScour's installed files can modify the
#     helper too, and then no rule inside it means anything
#
# {autopf} is already administrator-only on a default Windows installation. But
# "already, by default, probably" is not a boundary: an installation into a
# non-default directory inherits whatever ACL that parent had, and nothing
# would report it. Set it explicitly, then check it.
#
# What this does NOT touch
# ------------------------
#
# The data root. PolyScour has no privileged writer -- the vault, ledger and
# settings are written by the unelevated GUI on every run -- so they live in
# %LOCALAPPDATA%, where the user's own profile ACL is already correct and free.
# docs/adr/0005 is why a %ProgramData% tree here would be a boundary in the
# documentation and nowhere else.
#
# Identities are SIDs, not names
# ------------------------------
#
# "BUILTIN\Users" is localised: it is "Benutzer" on a German Windows and
# "Utilisateurs" on a French one. A script matching on the English string would
# silently fail to find the entry it meant to remove, and report success. The
# well-known SIDs are the same everywhere.
# =============================================================================

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    # Check rather than apply. Elevated, this inspects the DACL. Unelevated, it
    # additionally PROVES the boundary by trying to cross it -- which is the
    # only run that proves anything, because an administrator can write
    # anywhere and would see a boundary that is not there.
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Identities -------------------------------------------------------------

$SID_ADMINISTRATORS = "S-1-5-32-544"
$SID_SYSTEM         = "S-1-5-18"
$SID_USERS          = "S-1-5-32-545"
$SID_AUTHENTICATED  = "S-1-5-11"
$SID_EVERYONE       = "S-1-1-0"

# Anything in here holding a write right on the program directory is the
# failure this script exists to prevent.
$UNPRIVILEGED = @($SID_USERS, $SID_AUTHENTICATED, $SID_EVERYONE)

# Write-ish rights. Checked as a mask rather than by name because
# FileSystemRights is a flags enum and "Modify" is a combination: an entry
# granting only AppendData would not match a name comparison.
$WRITE_MASK = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
              [System.Security.AccessControl.FileSystemRights]::AppendData -bor
              [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
              [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
              [System.Security.AccessControl.FileSystemRights]::Delete -bor
              [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
              [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
              # FILE_DELETE_CHILD, and it is not implied by Delete above.
              #
              # Delete is a right on the FILE. DeleteSubdirectoriesAndFiles is
              # a right on the DIRECTORY, and it permits removing a child
              # WITHOUT holding Delete on that child. So an ACE granting Users
              # only this one would leave every check above satisfied while an
              # ordinary user could still remove PolyScour.exe and put their
              # own there -- which is precisely T15, reached by the one door
              # the mask did not cover.
              [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

function Test-IsElevated {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SidString {
    param($IdentityReference)
    try {
        return $IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function New-Rule {
    param([string]$Sid, [string]$Rights)
    New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($Sid)),
        [System.Security.AccessControl.FileSystemRights]$Rights,
        # Inherited by everything underneath, so a file added later is covered
        # without anyone having to remember to re-run this.
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}

# ---- Verify -----------------------------------------------------------------

function Invoke-Verify {
    param([string]$Path)

    $problems = New-Object System.Collections.Generic.List[string]
    $elevated = Test-IsElevated

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "FAIL: $Path does not exist." -ForegroundColor Red
        return 1
    }

    $acl = Get-Acl -LiteralPath $Path

    # 1. Inheritance must be off. An inherited ACL is one somebody else can
    #    change from a parent directory this script knows nothing about.
    if (-not $acl.AreAccessRulesProtected) {
        $problems.Add("the directory still inherits permissions from its parent")
    }

    # 2. No unprivileged identity may hold a write right.
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne
            [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = Get-SidString $rule.IdentityReference
        if ($null -eq $sid) { continue }
        if ($UNPRIVILEGED -notcontains $sid) { continue }
        if (($rule.FileSystemRights -band $WRITE_MASK) -ne 0) {
            $problems.Add(
                "$($rule.IdentityReference) ($sid) may write: $($rule.FileSystemRights)")
        }
    }

    # 3. Administrators must retain full control, or the next upgrade cannot
    #    replace the executable and the boundary becomes a lockout.
    $adminFull = $acl.Access | Where-Object {
        (Get-SidString $_.IdentityReference) -eq $SID_ADMINISTRATORS -and
        ($_.FileSystemRights -band
         [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0
    }
    if (-not $adminFull) {
        $problems.Add("Administrators do not have full control")
    }

    # 3b. THE PAYLOAD, not just the directory.
    #
    #     A --standalone build installs 978 files: PolyScour.exe, the Python
    #     runtime, and every .pyd it loads. The same binary runs as the elevated
    #     helper, so an ordinary user who can replace ANY of them has replaced
    #     code that executes as administrator. "The ACLs on PolyScour.exe are
    #     right" was never the claim worth making, and with a directory build
    #     it is visibly not. THREAT_MODEL T15, T24.
    #
    #     Only non-inheriting children are examined. A child that inherits is
    #     covered by the checks above on the parent, by definition -- and
    #     re-deriving that for a thousand files would turn a verification step
    #     into something slow enough that people stop running it. What a
    #     protected child ACL means is that somebody set permissions on that
    #     file specifically, which is exactly the case the parent cannot speak
    #     for.
    $childProblems = 0
    $childExamined = 0
    foreach ($item in (Get-ChildItem -LiteralPath $Path -Recurse -Force `
                       -ErrorAction SilentlyContinue)) {
        $childAcl = $null
        try { $childAcl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop }
        catch { continue }
        if (-not $childAcl.AreAccessRulesProtected) { continue }

        $childExamined++
        foreach ($rule in $childAcl.Access) {
            if ($rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = Get-SidString $rule.IdentityReference
            if ($null -eq $sid) { continue }
            if ($UNPRIVILEGED -notcontains $sid) { continue }
            if (($rule.FileSystemRights -band $WRITE_MASK) -ne 0) {
                $childProblems++
                # Capped. A thousand identical lines is not a report.
                if ($childProblems -le 10) {
                    $problems.Add(
                        "$($item.FullName): $($rule.IdentityReference) may write " +
                        "($($rule.FileSystemRights)) via an ACL of its own")
                }
            }
        }
    }
    if ($childProblems -gt 10) {
        $problems.Add("...and $($childProblems - 10) more files with their own writable ACLs")
    }

    # 4. The half that only an UNELEVATED run can answer. An administrator can
    #    write anywhere, so doing this elevated would prove the opposite of
    #    what it looks like it proves.
    if ($elevated) {
        Write-Host "note: running elevated, so the write probe is skipped." `
            -ForegroundColor Yellow
        Write-Host "      Re-run this with -Verify as an ordinary user to" `
            -ForegroundColor Yellow
        Write-Host "      prove the boundary rather than describe it." `
            -ForegroundColor Yellow
    } else {
        # 4a. An ordinary user must NOT be able to write here.
        $probe = Join-Path $Path ".polyscour-acl-probe"
        $wrote = $false
        try {
            [System.IO.File]::WriteAllText($probe, "probe")
            $wrote = $true
        } catch {
            # Expected. This is the pass.
        }
        if ($wrote) {
            try { Remove-Item -LiteralPath $probe -Force } catch { }
            $problems.Add(
                "an ordinary user CAN write into $Path -- T15 is unmet, and " +
                "the elevated helper can be replaced by anything")
        }

        # 4b. ...and must still be able to read and execute it, or the product
        #     does not run. A boundary the application cannot operate under is
        #     worse than none, because it will be found by a user.
        $exe = Join-Path $Path "PolyScour.exe"
        if (Test-Path -LiteralPath $exe) {
            try {
                $stream = [System.IO.File]::OpenRead($exe)
                $stream.Close()
            } catch {
                $problems.Add("an ordinary user cannot READ $exe")
            }
        }
    }

    if ($problems.Count -eq 0) {
        $scope = if ($elevated) { "DACL" } else { "DACL and write probe" }
        Write-Host "OK: $Path is administrator-only ($scope)." -ForegroundColor Green
        return 0
    }

    Write-Host "FAIL: $Path" -ForegroundColor Red
    foreach ($p in $problems) { Write-Host "  - $p" -ForegroundColor Red }
    return 1
}

# ---- Apply ------------------------------------------------------------------

function Invoke-Apply {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Path does not exist. Install the program before securing it."
    }
    if (-not (Test-IsElevated)) {
        throw "This must run elevated. Changing a program directory's ACL is " +
              "exactly the thing an unprivileged process may not do."
    }

    if (-not $PSCmdlet.ShouldProcess($Path, "set administrator-only ACL")) {
        return 0
    }

    $acl = Get-Acl -LiteralPath $Path

    # Stop inheriting, and do not copy the inherited entries down: copying them
    # would preserve whatever the parent granted, which is the thing being
    # removed.
    $acl.SetAccessRuleProtection($true, $false)

    # Owner matters as much as the DACL: an owner can rewrite the DACL whatever
    # it says, so leaving an installing user as owner would leave them able to
    # grant themselves write access afterwards.
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($SID_ADMINISTRATORS)))

    $acl.AddAccessRule((New-Rule $SID_ADMINISTRATORS "FullControl"))
    $acl.AddAccessRule((New-Rule $SID_SYSTEM         "FullControl"))
    # Read and execute, and nothing more. This is what lets an ordinary user
    # actually run the program they installed.
    $acl.AddAccessRule((New-Rule $SID_USERS          "ReadAndExecute"))

    Set-Acl -LiteralPath $Path -AclObject $acl

    Write-Host "Secured $Path" -ForegroundColor Green
    Write-Host "  Administrators : FullControl"
    Write-Host "  SYSTEM         : FullControl"
    Write-Host "  Users          : ReadAndExecute"
    return 0
}

# ---- Main -------------------------------------------------------------------

if ($Verify) {
    exit (Invoke-Verify -Path $Root)
}
exit (Invoke-Apply -Path $Root)
