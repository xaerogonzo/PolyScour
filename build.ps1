# =============================================================================
# nuitka-build.ps1 - PolyScour build pipeline
# Generated from nuitka-build.ps1.template
# =============================================================================
#
# Produces standalone .exe files in dist\ with no Python install required.
#
# STATUS: NOT YET RUN on this machine (Nuitka is not installed in venv/), but
# no longer knowingly wrong. This note used to say packaging lands in 0.9,
# which stopped being true the moment the elevated helper shipped: T15 requires
# an installed location only administrators can write, and the helper's frozen
# launch path cannot be honest without a frozen build to launch. Packaging is
# 0.2. See docs/adr/0006.
#
# Fixed here since that note was written:
#   - the entry point is entry.py, not app.py. app.py imports CustomTkinter at
#     module scope, and this same executable also runs the ELEVATED helper --
#     so entering through app.py would load a GUI toolkit as administrator.
#   - polybedrock is staged into the payload. It is installed editable from a
#     sibling checkout, which Nuitka does not follow on its own.
#   - PIL and pystray are gone. Nothing in PolyScour imports either; pillow
#     arrives only through polybedrock-ui's uishot, which is a development
#     tool with no business in a shipped build.
#
# Prerequisites (run once):
#   pip install nuitka ordered-set zstandard
#   + any runtime deps your project uses (pillow, pystray, etc.)
#
# Optional:
#   icon.ico - place a 256x256 icon file next to this script.
#   If absent, the --windows-icon-from-ico flag is skipped automatically.
#
# See NUITKA_GOTCHAS.md (in the same templates folder) for known issues.
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ROOT = $PSScriptRoot
$DIST = "$ROOT\dist"
$ICON = "$ROOT\icon.ico"

# ---------- Pre-flight checks ------------------------------------------------

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "python is not on PATH. Activate your venv or install Python first."
}

# Check Nuitka is installed (cheap version probe)
& python -m nuitka --version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Nuitka is not installed. Run: pip install nuitka ordered-set zstandard"
}

# ---------- Orphan cleanup ---------------------------------------------------
# Nuitka leaves *.onefile-build, *.build, *.dist dirs if --remove-output was
# blocked (AV file lock, interrupted compile). Clear them before building so
# we start clean and never accumulate stale state.

function Clear-NuitkaOrphans($dir) {
    if (-not (Test-Path $dir)) { return }
    $patterns = @("*.onefile-build", "*.build", "*.dist")
    foreach ($pat in $patterns) {
        Get-ChildItem -Path $dir -Directory -Filter $pat -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  [clean] removing $($_.Name)" -ForegroundColor DarkGray
            try {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Host "  [warn]  could not remove $($_.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

# ---------- Build helper -----------------------------------------------------

function Build-Exe($script, $outName, $nuArgs) {
    $isGuiBuild = $nuArgs -contains "--enable-plugin=tk-inter"

    if ((Test-Path $ICON) -and ($isGuiBuild)) {
        $nuArgs += "--windows-icon-from-ico=$ICON"
    }

    Clear-NuitkaOrphans $DIST

    Write-Host "  Building $outName ..." -ForegroundColor Cyan

    # Capture output so we can parse the uncompressed payload size for the sanity check.
    # Temporarily suspend Stop mode: with $ErrorActionPreference = "Stop", PowerShell
    # treats each native command stderr line as a NativeCommandError and aborts.
    # Nuitka writes progress to stderr, so we must use Continue while capturing.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $buildOutput = & python @nuArgs $script 2>&1
    $nuitkaExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP

    $buildOutput | ForEach-Object { Write-Host $_ }
    if ($nuitkaExit -ne 0) {
        throw "Nuitka failed (exit $nuitkaExit) building $outName"
    }
    Write-Host "  OK: $DIST\$outName" -ForegroundColor Green

    Clear-NuitkaOrphans $DIST

    # ---- Sanity check: uncompressed payload size ---------------------------
    # Nuitka compresses onefile payloads ~27%, so a healthy tkinter+PIL+pystray
    # app lands at ~14 MB on disk even though the uncompressed payload is ~55 MB.
    # Checking the compressed exe size would always fire a false WARN, so we
    # parse the uncompressed size from Nuitka's own "Onefile payload..." log line.
    # Only enforce for GUI builds (--enable-plugin=tk-inter present).
    # CLI tools can legitimately be a few MB uncompressed - skip the check.
    if ($isGuiBuild) {
        $payloadLine = ($buildOutput | Select-String "Onefile payload compression ratio") | Select-Object -Last 1
        if ($payloadLine -match "size (\d+) to") {
            $uncompressedMB = [math]::Round([long]$Matches[1] / 1MB, 1)
            if ($uncompressedMB -lt 30) {
                Write-Host ""
                Write-Host "  [WARN] $outName uncompressed payload is only $uncompressedMB MB - suspicious for a GUI build." -ForegroundColor Yellow
                Write-Host "         Likely a missing --enable-plugin or --include-package flag." -ForegroundColor Yellow
                Write-Host "         Run the exe from cmd with --windows-console-mode=attach to debug." -ForegroundColor Yellow
                Write-Host ""
            } else {
                Write-Host "  Payload OK: $uncompressedMB MB uncompressed" -ForegroundColor DarkGray
            }
        } else {
            $sizeMB = [math]::Round((Get-Item "$DIST\$outName").Length / 1MB, 1)
            Write-Host "  Compressed size: $sizeMB MB (could not parse uncompressed payload)" -ForegroundColor DarkGray
        }
    }
}

# ---------- Main -------------------------------------------------------------

Write-Host ""
Write-Host "=== PolyScour - Nuitka build ===" -ForegroundColor Cyan
Write-Host ""

New-Item -ItemType Directory -Force -Path $DIST | Out-Null

# ---- GUI build (tkinter app) ------------------------------------------------
# Remove PIL/pystray below if this app does not use them.
$guiArgs = @(
    "-m", "nuitka",
    "--onefile",
    "--windows-console-mode=disable",
    "--enable-plugin=tk-inter",
    # Installed editable from ..\PolyBedrock, so it is not an ordinary package
    # in site-packages and Nuitka will not find it by tracing imports alone.
    # Without this the build succeeds and the exe dies on its first import.
    "--include-package=polybedrock",
    # Both halves matter: the GUI needs polybedrock.ui, and the ELEVATED helper
    # needs polybedrock.paths. A build missing either is one whose helper
    # cannot run -- and that failure would only appear at a UAC prompt.
    "--include-package=polyscour",
    # Cleaning rules ship INSIDE the binary, not beside it. paths.rules_dir()
    # resolves them relative to the module tree, which is where Nuitka puts
    # this -- and which survives onefile, where the modules and their data land
    # in the same temporary extraction directory. Installing them next to the
    # exe instead would offer an editable rules folder with no authority behind
    # it: adding a rule already requires a reviewed PolicyEntry in code.
    "--include-data-dir=$ROOT\rules=rules",
    # ---- Anaconda bloat exclusions (safe to remove if not using Anaconda) ----
    # If building from an Anaconda or conda env, Nuitka traces into numpy,
    # scipy, pandas etc. even if your app never imports them, bundling ~450 MB
    # of Intel MKL DLLs and scientific libraries. These flags block that.
    # Remove any package your app actually uses.
    "--nofollow-import-to=numpy",
    "--nofollow-import-to=scipy",
    "--nofollow-import-to=pandas",
    "--nofollow-import-to=matplotlib",
    "--nofollow-import-to=sklearn",
    "--nofollow-import-to=IPython",
    "--nofollow-import-to=notebook",
    # --------------------------------------------------------------------------
    "--remove-output",
    "--assume-yes-for-downloads",
    "--output-dir=$DIST",
    "--output-filename=PolyScour.exe"
)

# ---- CLI build (no GUI plugins) ---------------------------------------------
# Uncomment and use this instead of the GUI block above for CLI-only tools.
# $cliArgs = @(
#     "-m", "nuitka",
#     "--onefile",
#     "--windows-console-mode=force",
#     "--nofollow-import-to=numpy",
#     "--nofollow-import-to=scipy",
#     "--nofollow-import-to=pandas",
#     "--nofollow-import-to=matplotlib",
#     "--nofollow-import-to=sklearn",
#     "--nofollow-import-to=IPython",
#     "--nofollow-import-to=notebook",
#     "--remove-output",
#     "--assume-yes-for-downloads",
#     "--output-dir=$DIST",
#     "--output-filename=PolyScour.exe"
# )

# entry.py, NOT app.py. One executable is two programs -- the GUI and the
# elevated helper -- and which one runs is decided by an argument before
# anything is imported. Entering through app.py would pull CustomTkinter, Tk
# and Tcl into the elevated process. See src/polyscour/entry.py.
Build-Exe "$ROOT\src\polyscour\entry.py" "PolyScour.exe" $guiArgs

# There is deliberately no second binary. A separate helper.exe would be a
# second file to protect with ACLs and a second to verify, for no gain: the
# helper has to be the same trusted binary in the same protected directory.

# ---------- Probe the build's own idea of where things are -------------------
#
# The suite cannot check this. tests/test_entry.py drives frozen behaviour by
# overriding a flag, which covers the POLICY and not the DETECTION -- nothing
# in pytest ever runs inside a compiled build. Two things go unchecked there
# and both are silent when wrong: whether is_frozen() actually returns True
# here, and whether resource_root()'s level adjustment lands on the directory
# the rules were bundled into.
#
# So the probe is compiled with the same flags and run, where its answers are
# facts. It exits non-zero if the build resolved anything durable underneath
# the extraction directory -- the outcome that silently destroys a vault.

$probeArgs = @(
    "-m", "nuitka",
    "--onefile",
    "--windows-console-mode=force",
    "--include-package=polyscour",
    "--include-package=polybedrock",
    "--include-data-dir=$ROOT\rules=rules",
    "--nofollow-import-to=customtkinter",
    "--nofollow-import-to=tkinter",
    "--remove-output",
    "--assume-yes-for-downloads",
    "--output-dir=$DIST",
    "--output-filename=build_probe.exe"
)

Build-Exe "$ROOT\tools\build_probe.py" "build_probe.exe" $probeArgs

Write-Host ""
Write-Host "--- how the build resolves its paths ---" -ForegroundColor Cyan
& "$DIST\build_probe.exe" --expect-frozen
if ($LASTEXITCODE -ne 0) {
    throw "build_probe reported a path the build resolves wrongly (above). " +
          "Shipping this would produce an application that either cannot find " +
          "its rules or cannot keep a vault."
}

# ---------- Installer --------------------------------------------------------
#
# The ACLs are the whole reason installing beats unzipping: PolyScour.exe is
# also the ELEVATED helper, and every rule inside it is worth exactly as much
# as the answer to "who can rewrite this file?" (THREAT_MODEL.md T15).

$iscc = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
if (-not $iscc) {
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $candidate) { $iscc = $candidate; break }
    }
}

if (-not $iscc) {
    Write-Host ""
    Write-Host "Inno Setup (ISCC.exe) not found - skipping the installer." `
        -ForegroundColor Yellow
    Write-Host "  The exe in $DIST is complete, but running it from there" `
        -ForegroundColor Yellow
    Write-Host "  leaves the program directory writable by an ordinary user," `
        -ForegroundColor Yellow
    Write-Host "  which is exactly what T15 says must not be true of a" `
        -ForegroundColor Yellow
    Write-Host "  release. Install Inno Setup 6 before shipping." `
        -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "--- installer ---" -ForegroundColor Cyan
    & $iscc "$ROOT\installer\polyscour.iss"
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)" }
}

# ---------- Stage data files (edit per project) ------------------------------
# If your app ships with config files, templates, docs, etc., copy them
# into $DIST here. Example:
#
# Copy-Item "$ROOT\README.md" "$DIST\README.md" -Force
#
# For JSON config files, use [System.IO.File]::WriteAllText so PowerShell
# doesn't add a UTF-8 BOM (which crashes Python's json.load):
#
# $config = @{ key = "value" }
# [System.IO.File]::WriteAllText("$DIST\config.json", ($config | ConvertTo-Json -Depth 5))

Write-Host ""
Write-Host "Build complete -> $DIST" -ForegroundColor Green
Write-Host ""

exit 0
