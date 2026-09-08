<#
.SYNOPSIS
    Measure what a real PolyScour installation became. Emits JSON; exits
    non-zero on a finding.

.DESCRIPTION
    docs/adr/0006 ends by naming what it could not do:

        Nobody has installed it. [...] That is a good argument and it is not a
        measurement.

    T15 -- the installed program directory is one an ordinary user cannot write
    -- is the claim every other guarantee in THREAT_MODEL.md rests on. An
    attacker who can rewrite what the elevated helper executes has defeated the
    closed operation set, the re-run guard chain and the narrow-never-widen
    rule together, all at once. Until this script has been run, that claim is
    supported by an installer script and by tests against OTHER directories.

    This is the counterpart to tools/build_probe.py and deliberately copies its
    contract: emit JSON, keep `findings` (fatal) apart from `notes` (true but
    not blocking), exit non-zero when there is a finding. build_probe answers
    "what does this build resolve"; this answers "what did this installation
    become".

.PARAMETER Stage
    PreInstall   Snapshot the machine BEFORE running setup. Required, because
                 "the installer created no data directory" is a DELTA and a
                 delta needs a before -- %LOCALAPPDATA%\PolyScour already
                 exists on any machine PolyScour has ever been run from, so an
                 absolute "must be absent" check reports a false failure on the
                 second installation ever performed.
    Installed    Run after setup completes.
    Uninstalled  Run after uninstalling.

.PARAMETER SnapshotPath
    Where PreInstall writes and Installed reads. Defaults to
    artifacts/verify_install.snapshot.json beside the repository.

.NOTES
    MUST NOT BE RUN ELEVATED, and refuses to be. An administrator can write
    anywhere, so an elevated run would probe a boundary that is not there,
    find no obstacle, and report success. That is the single most dangerous way
    this script could fail: a green result that measured nothing.

    installer/set_program_acls.ps1 only warns in that case and skips its write
    probe. Here it is a refusal, because that script has other legitimate uses
    (it APPLIES the ACLs, which does need elevation) and this one does not.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("PreInstall", "Installed", "Uninstalled")]
    [string]$Stage,

    [string]$SnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO       = Split-Path -Parent $PSScriptRoot
$ACL_SCRIPT = Join-Path $REPO "installer\set_program_acls.ps1"
if (-not $SnapshotPath) {
    $SnapshotPath = Join-Path $REPO "artifacts\verify_install.snapshot.json"
}

# Inno Setup appends "_is1" to the AppId from installer/polyscour.iss.
$APP_ID   = "{4E9A7C31-6D82-4F15-9C0B-3A7E5D1F8B24}_is1"
$UNINST   = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$APP_ID",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$APP_ID",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$APP_ID"
)
$DATA_ROOT = Join-Path $env:LOCALAPPDATA "PolyScour"

$findings = New-Object System.Collections.Generic.List[string]
$notes    = New-Object System.Collections.Generic.List[string]
$facts    = [ordered]@{}

function Add-Finding($text) { $findings.Add($text) }
function Add-Note($text)    { $notes.Add($text) }

function Test-IsElevated {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UninstallKey {
    foreach ($path in $UNINST) {
        if (Test-Path $path) { return Get-ItemProperty -Path $path }
    }
    return $null
}

function Test-CanWrite($directory) {
    # Probed, not read from the DACL. os.access-style answers and
    # Get-Acl interpretation both answer a different question than "could this
    # process actually create a file here"; a file that appears is a file that
    # appeared. Same reasoning as tools/build_probe.py::_is_writable.
    $probe = Join-Path $directory ".polyscour-verify-probe-$PID"
    try {
        [System.IO.File]::WriteAllText($probe, "probe")
    } catch {
        return $false
    }
    try { Remove-Item -LiteralPath $probe -Force } catch { }
    return $true
}

function Measure-Tree($directory) {
    if (-not (Test-Path -LiteralPath $directory)) {
        return [ordered]@{ exists = $false; files = 0; bytes = 0 }
    }
    $items = @(Get-ChildItem -LiteralPath $directory -Recurse -File -Force `
               -ErrorAction SilentlyContinue)
    $sum = ($items | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { $sum = 0 }
    return [ordered]@{
        exists = $true
        files  = $items.Count
        bytes  = [long]$sum
    }
}

function Get-AutorunLeftovers {
    # Everything the installer claims not to create. Checked rather than
    # trusted: README.md makes these promises to a reader, and a promise with
    # no reader is the shape of bug this project keeps finding.
    $found = @()
    foreach ($hive in @("HKCU:", "HKLM:")) {
        foreach ($key in @("Run", "RunOnce")) {
            $path = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\$key"
            if (-not (Test-Path $path)) { continue }
            # GetValueNames() rather than Get-ItemProperty's PSObject shape.
            # Under Set-StrictMode the latter throws on a key with no values --
            # RunOnce is normally empty, so the strict path was reached on the
            # first ordinary machine this ran on.
            $regKey = Get-Item -LiteralPath $path
            foreach ($name in $regKey.GetValueNames()) {
                $value = [string]$regKey.GetValue($name)
                if ($name -match "PolyScour" -or $value -match "PolyScour") {
                    $found += "$path -> $name = $value"
                }
            }
        }
    }
    $svc = Get-Service -Name "*PolyScour*" -ErrorAction SilentlyContinue
    foreach ($s in $svc) { $found += "service: $($s.Name)" }

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
             Where-Object { $_.TaskName -match "PolyScour" }
    foreach ($t in $tasks) { $found += "scheduled task: $($t.TaskName)" }

    return $found
}

# ---- The refusal ------------------------------------------------------------

if (Test-IsElevated) {
    Write-Host "REFUSING to run elevated." -ForegroundColor Red
    Write-Host ""
    Write-Host "An administrator can write anywhere, so every check below would" -ForegroundColor Red
    Write-Host "find no obstacle and report success -- measuring nothing while" -ForegroundColor Red
    Write-Host "looking exactly like a pass. Run this as an ordinary user."      -ForegroundColor Red
    exit 2
}

# ---- Stages -----------------------------------------------------------------

switch ($Stage) {

  "PreInstall" {
    $programRoot = Join-Path $env:ProgramFiles "PolyScour"
    $snapshot = [ordered]@{
        taken_at        = (Get-Date).ToString("o")
        data_root       = $DATA_ROOT
        data_root_state = Measure-Tree $DATA_ROOT
        program_root    = $programRoot
        program_state   = Measure-Tree $programRoot
        uninstall_key   = [bool](Get-UninstallKey)
        autoruns        = @(Get-AutorunLeftovers)
    }
    $dir = Split-Path -Parent $SnapshotPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SnapshotPath -Encoding UTF8

    $facts["snapshot_path"] = $SnapshotPath
    $facts["snapshot"]      = $snapshot
    if ($snapshot.data_root_state.exists) {
        Add-Note ("$DATA_ROOT already exists with $($snapshot.data_root_state.files) " +
                  "files. That is expected on a development machine and is exactly " +
                  "why this stage exists -- the Installed stage compares against " +
                  "this, rather than requiring absence.")
    }
    if ($snapshot.uninstall_key) {
        Add-Note "PolyScour is already registered as installed. Uninstall first for a clean measurement."
    }
  }

  "Installed" {
    # 1. Resolve the install root from what the installer REGISTERED, not from
    #    an assumption about Program Files. Otherwise this measures the path it
    #    guessed while the installer used another, and reports on a directory
    #    nobody installed to.
    $key = Get-UninstallKey
    if ($null -eq $key) {
        Add-Finding ("no uninstall registry entry for $APP_ID. Either setup did " +
                     "not run, or it registered under an AppId this script does " +
                     "not know -- and every check below would be measuring a " +
                     "directory chosen by assumption.")
        $root = $null
    } else {
        $root = if ($key.PSObject.Properties.Name -contains "InstallLocation") {
                    ([string]$key.InstallLocation).TrimEnd('\')
                } else { $null }
        $facts["display_version"] = if ($key.PSObject.Properties.Name -contains "DisplayVersion") {
                                        [string]$key.DisplayVersion } else { $null }
        if ([string]::IsNullOrWhiteSpace($root)) {
            Add-Finding "the uninstall entry has no InstallLocation, so the installed root cannot be established."
            $root = $null
        }
    }
    $facts["install_root"] = $root

    if ($root -and (Test-Path -LiteralPath $root)) {
        # 2. The registered directory is the one holding the executable.
        $exe = Join-Path $root "PolyScour.exe"
        $facts["executable"] = $exe
        if (-not (Test-Path -LiteralPath $exe)) {
            Add-Finding "$exe does not exist, so the registered install root holds no PolyScour."
        }

        $tree = Measure-Tree $root
        $facts["payload"] = $tree
        if ($tree.files -lt 100) {
            Add-Finding ("the install root holds only $($tree.files) files. A " +
                         "--standalone build is around a thousand: this looks " +
                         "like a onefile installation, which is THREAT_MODEL T24 " +
                         "back again, or a partial install.")
        }

        # 3. THE CHECK THIS SCRIPT EXISTS FOR. Delegated, never reimplemented --
        #    the mask that decides what "writable" means lives in one file, and
        #    a second copy of it is a second place for FILE_DELETE_CHILD to go
        #    missing. set_program_acls.ps1 -Verify now walks the payload too.
        $installedAclScript = Join-Path $root "set_program_acls.ps1"
        $aclScript = if (Test-Path -LiteralPath $installedAclScript) {
                         $installedAclScript } else { $ACL_SCRIPT }
        $facts["acl_script"] = $aclScript

        & powershell -NoProfile -ExecutionPolicy Bypass -File $aclScript -Root $root -Verify
        $aclExit = $LASTEXITCODE
        $facts["acl_verify_exit"] = $aclExit
        if ($aclExit -ne 0) {
            Add-Finding ("set_program_acls.ps1 -Verify failed against $root (exit " +
                         "$aclExit, output above). T15 is UNMET on this real " +
                         "installation: an ordinary user can modify code that " +
                         "runs as administrator.")
        }
    } elseif ($root) {
        Add-Finding "the registered install root $root does not exist."
    }

    # 3c. The last link in the version chain.
    #
    #     pyproject.toml -> __version__ -> build.ps1 -> .iss -> DisplayVersion.
    #     tests/test_version.py checks every earlier link by opening both files;
    #     this is the only one that can only be checked on an installed machine,
    #     and it is the one a user actually sees, in Apps & features.
    $pyproject = Join-Path $REPO "pyproject.toml"
    if ((Test-Path -LiteralPath $pyproject) -and
        $facts.Contains("display_version") -and $facts["display_version"]) {
        $m = [regex]::Match((Get-Content -LiteralPath $pyproject -Raw),
                            '(?m)^version\s*=\s*"([^"]+)"')
        if ($m.Success) {
            $facts["pyproject_version"] = $m.Groups[1].Value
            if ($m.Groups[1].Value -ne $facts["display_version"]) {
                Add-Finding ("the installed DisplayVersion is " +
                             "$($facts['display_version']) while pyproject.toml " +
                             "declares $($m.Groups[1].Value). The installed " +
                             "artifact is not the version the source says it is.")
            }
        }
    } else {
        Add-Note ("version chain not checked -- run this from the repository, " +
                  "against an installation built from it.")
    }

    # 4. The installer creates no data directory. A DELTA against PreInstall.
    if (Test-Path -LiteralPath $SnapshotPath) {
        $before = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
        $now = Measure-Tree $DATA_ROOT
        $facts["data_root_before"] = $before.data_root_state
        $facts["data_root_now"]    = $now
        if ((-not $before.data_root_state.exists) -and $now.exists) {
            Add-Finding ("$DATA_ROOT did not exist before setup and does now. " +
                         "The installer claims to create no data directory; the " +
                         "application creates it on first run.")
        }
    } else {
        Add-Note ("no PreInstall snapshot at $SnapshotPath, so the " +
                  "installer-created-no-data-directory check was skipped. It " +
                  "cannot be inferred: this machine may have had $DATA_ROOT for " +
                  "months.")
    }

    # 5. The data root must be usable and separate. Not merely present: the
    #    point of adr/0005 is that an unelevated application can still write its
    #    vault while the program directory is closed to it.
    if (Test-Path -LiteralPath $DATA_ROOT) {
        $writable = Test-CanWrite $DATA_ROOT
        $facts["data_root_writable"] = $writable
        if (-not $writable) {
            Add-Finding ("$DATA_ROOT is not writable by this user. The vault, " +
                         "ledger and settings all live there and PolyScour runs " +
                         "unelevated -- see adr/0005.")
        }
        if ($root -and $DATA_ROOT.ToLower().StartsWith($root.ToLower())) {
            Add-Finding ("$DATA_ROOT is inside the program directory $root, which " +
                         "is administrator-only and is removed by uninstall.")
        }
    } else {
        Add-Note "$DATA_ROOT does not exist yet. Launch PolyScour once, then re-run this stage."
    }

    # 6. No autorun, no service, no scheduled task.
    $leftovers = @(Get-AutorunLeftovers)
    $facts["autoruns"] = $leftovers
    if ($leftovers.Count -gt 0) {
        Add-Finding ("the installation registered something that starts by " +
                     "itself: $($leftovers -join '; '). README.md promises none " +
                     "of these, and a maintenance tool that installs its own " +
                     "autorun while declining to recommend disabling anyone " +
                     "else's is saying two different things.")
    }
  }

  "Uninstalled" {
    $key = Get-UninstallKey
    if ($null -ne $key) {
        Add-Finding "the uninstall registry entry still exists; uninstall did not complete."
    }

    if (Test-Path -LiteralPath $SnapshotPath) {
        $before = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
        $root = ([string]$before.program_root).TrimEnd('\')
        $facts["program_root"] = $root
        $tree = Measure-Tree $root
        $facts["program_state"] = $tree
        if ($tree.exists -and $tree.files -gt 0) {
            $exes = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force `
                      -ErrorAction SilentlyContinue |
                      Where-Object { $_.Extension -in ".exe", ".dll", ".pyd" })
            if ($exes.Count -gt 0) {
                Add-Finding ("$($exes.Count) executable files remain under $root " +
                             "after uninstall. Leftover code in a directory that " +
                             "no longer has an owner is worse than leftover data.")
            } else {
                Add-Note "$root still exists with $($tree.files) non-executable files."
            }
        }
    }

    # THE ONE THAT MUST SURVIVE. The vault may hold the only remaining copy of
    # a file the user deleted through PolyScour, which is why uninstall is told
    # to leave it alone and why this is checked rather than assumed.
    $data = Measure-Tree $DATA_ROOT
    $facts["data_root_after_uninstall"] = $data
    if (-not $data.exists) {
        Add-Finding ("$DATA_ROOT was removed by uninstall. It may hold the only " +
                     "remaining copy of a file the user deleted through " +
                     "PolyScour, and README.md promises it is left alone.")
    } else {
        $vault = Join-Path $DATA_ROOT "vault"
        if (Test-Path -LiteralPath $vault) {
            $facts["vault"] = Measure-Tree $vault
        }
    }

    $leftovers = @(Get-AutorunLeftovers)
    $facts["autoruns"] = $leftovers
    if ($leftovers.Count -gt 0) {
        Add-Finding ("privileged leftovers after uninstall: $($leftovers -join '; ')")
    }
  }
}

# ---- Report -----------------------------------------------------------------

$report = [ordered]@{
    stage    = $Stage
    elevated = $false
    facts    = $facts
    findings = @($findings)
    notes    = @($notes)
    ok       = ($findings.Count -eq 0)
}

Write-Host ""
$report | ConvertTo-Json -Depth 8

foreach ($n in $notes)    { Write-Host "note: $n" -ForegroundColor Yellow }
foreach ($f in $findings) { Write-Host "FAIL: $f" -ForegroundColor Red }

if ($findings.Count -eq 0) {
    Write-Host ""
    Write-Host "OK: stage '$Stage' found nothing wrong." -ForegroundColor Green
    exit 0
}
exit 1
