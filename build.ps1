# =============================================================================
# nuitka-build.ps1 - PolyScour build pipeline
# Generated from nuitka-build.ps1.template
# =============================================================================
#
# Produces dist\PolyScour\ -- a standalone directory holding PolyScour.exe
# and every DLL it loads, with no Python install required. NOT a single
# file: see THREAT_MODEL.md T24.
#
# STATUS: RUN, on 2026-09-08, with Nuitka 4.2.1 / zig 0.16.0 on Python 3.13.
# Produces PolyScour.exe at ~15.5 MB (58.9 MB uncompressed payload). The GUI
# starts and shows its window; the elevated helper answers a request and writes
# its response; an unknown argument exits 2. See docs/adr/0006 for what the
# build measured and what it found.
#
# The first run found a privilege escalation that four rounds of reasoning had
# missed -- sys.executable under onefile names a python.exe in a user-writable
# temp directory, and that is what was being elevated. THREAT_MODEL.md T23.
#
# Fixed here since this note first claimed packaging was a 0.9 concern:
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

# Prefer the project's own venv over whatever `python` happens to mean.
#
# This is not politeness. Nuitka compiles the environment it is RUN from, so a
# bare `python` that resolves to a system or Anaconda install produces either a
# "No module named polyscour" failure or -- worse, if that interpreter happens
# to have some of the dependencies -- a build made from the wrong ones. The
# original script only said "activate your venv" in an error message that never
# fires, because `python` is almost always on PATH and almost never the venv.
$PYTHON = "$ROOT\venv\Scripts\python.exe"
if (-not (Test-Path $PYTHON)) {
    $fallback = Get-Command python -ErrorAction SilentlyContinue
    if (-not $fallback) {
        throw "No venv at $PYTHON and no python on PATH. Create the venv first: " +
              "python -m venv venv"
    }
    $PYTHON = $fallback.Source
    Write-Host "WARNING: no venv found; building with $PYTHON" -ForegroundColor Yellow
}

Write-Host "Interpreter: $PYTHON" -ForegroundColor Cyan

# It has to be able to import what it is about to compile. Checked here rather
# than discovered fifteen minutes into a Nuitka run.
& $PYTHON -c "import polyscour, polybedrock" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "$PYTHON cannot import polyscour and polybedrock. Install them: " +
          "pip install -e ..\PolyBedrock\core -e ..\PolyBedrock\ui -e ."
}

# Check Nuitka is installed (cheap version probe)
& $PYTHON -m nuitka --version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Nuitka is not installed. Run: pip install nuitka ordered-set zstandard"
}

# ---------- Orphan cleanup ---------------------------------------------------
# Nuitka leaves *.onefile-build, *.build, *.dist dirs if --remove-output was
# blocked (AV file lock, interrupted compile). Clear them before building so
# we start clean and never accumulate stale state.

function Clear-NuitkaOrphans($dir) {
    if (-not (Test-Path $dir)) { return }
    # NOT "*.dist". Under --standalone that directory IS the build output --
    # the executable plus every DLL and .pyd it loads. This list removes
    # Nuitka's scratch directories, and deleting the product along with
    # them would be a build that reports success and ships nothing.
    $patterns = @("*.onefile-build", "*.build")
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

function Build-Exe($script, $outName, $nuArgs, $distName) {
    # Checked rather than defaulted. A missing $distName used to surface four
    # minutes into a compile as "Cannot bind argument to parameter 'NewName'",
    # after the expensive part had already succeeded.
    if ([string]::IsNullOrWhiteSpace($distName)) {
        throw "Build-Exe requires a `$distName (the directory to rename " +
              "<script>.dist to). Building $outName without one."
    }

    $isGuiBuild = $nuArgs -contains "--enable-plugin=tk-inter"

    if ((Test-Path $ICON) -and ($isGuiBuild)) {
        $nuArgs += "--windows-icon-from-ico=$ICON"
    }

    Clear-NuitkaOrphans $DIST

    Write-Host "  Building $outName ..." -ForegroundColor Cyan

    # Capture output so the size sanity check below can read it. Temporarily
    # suspend Stop mode: with $ErrorActionPreference = "Stop", PowerShell treats
    # each native command stderr line as a NativeCommandError and aborts, and
    # Nuitka writes its progress to stderr.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $buildOutput = & $PYTHON @nuArgs $script 2>&1
    $nuitkaExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP

    $buildOutput | ForEach-Object { Write-Host $_ }
    if ($nuitkaExit -ne 0) {
        throw "Nuitka failed (exit $nuitkaExit) building $outName"
    }

    # ---- Name the output directory -----------------------------------------
    # --standalone emits "<script basename>.dist", so entry.py would install as
    # "entry.dist" -- a directory name that says nothing about what is in it,
    # in C:\Program Files. Renamed here so the installer, the ACL script and
    # verify_install.ps1 all name the same thing.
    $stem     = [System.IO.Path]::GetFileNameWithoutExtension($script)
    $produced = Join-Path $DIST "$stem.dist"
    $target   = Join-Path $DIST $distName

    if (-not (Test-Path $produced)) {
        throw "Nuitka reported success but $produced does not exist. " +
              "Did --standalone get dropped from the argument list?"
    }
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    Rename-Item -LiteralPath $produced -NewName $distName

    $exe = Join-Path $target $outName
    if (-not (Test-Path $exe)) {
        throw "$exe is missing from the standalone output. " +
              "Check --output-filename=$outName."
    }
    Write-Host "  OK: $exe" -ForegroundColor Green

    Clear-NuitkaOrphans $DIST

    # ---- Sanity check: payload size ----------------------------------------
    # A GUI build that lost --enable-plugin or an --include-package still
    # compiles; it dies on its first import instead, at a user's machine. The
    # cheap tell is that it is far too small.
    #
    # Measured over the DIRECTORY now. The old check parsed Nuitka's "Onefile
    # payload compression ratio" line, which --standalone never prints -- so
    # left alone it would have silently stopped checking anything. A check that
    # quietly matches nothing is worse than no check, because it still reports.
    if ($isGuiBuild) {
        $bytes = (Get-ChildItem $target -Recurse -File |
                  Measure-Object -Property Length -Sum).Sum
        $sizeMB = [math]::Round($bytes / 1MB, 1)
        if ($sizeMB -lt 30) {
            Write-Host ""
            Write-Host "  [WARN] $distName is only $sizeMB MB - suspicious for a GUI build." -ForegroundColor Yellow
            Write-Host "         Likely a missing --enable-plugin or --include-package flag." -ForegroundColor Yellow
            Write-Host ""
        } else {
            Write-Host "  Payload OK: $sizeMB MB across $((Get-ChildItem $target -Recurse -File).Count) files" -ForegroundColor DarkGray
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
    # --standalone, NOT --onefile. Onefile unpacks the runtime and every
    # .pyd into %TEMP%\onefile_* and executes from there -- a directory the
    # user holds Full Control over, inherited from %LOCALAPPDATA%\Temp.
    # This same binary runs as the ELEVATED helper, so that put the code
    # executing at privilege OUTSIDE the directory T15's ACLs protect.
    # Measured, then fixed: THREAT_MODEL.md T24.
    "--standalone",
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
Build-Exe "$ROOT\src\polyscour\entry.py" "PolyScour.exe" $guiArgs "PolyScour"

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
    # --standalone for the same reason the GUI is (T24). The probe must be
    # built with the same packaging as the thing it probes, or it reports
    # on a build nobody ships.
    "--standalone",
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

Build-Exe "$ROOT\tools\build_probe.py" "build_probe.exe" $probeArgs "probe"

Write-Host ""
Write-Host "--- how the build resolves its paths ---" -ForegroundColor Cyan
& "$DIST\probe\build_probe.exe" --expect-frozen
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
if ($iscc) { $iscc = $iscc.Source }
if (-not $iscc) {
    # Inno Setup 6 offers a per-user install, and it does not go under
    # Program Files. The first version of this list assumed it did and
    # reported "not found" on a machine that had it -- the same shape of
    # mistake as every other path assumption in this project, just cheaper.
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
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
