@echo off
REM Launcher for the PolyScour GUI, run from source (the venv checkout).
REM
REM   run.bat            start the GUI with no console window
REM   run.bat --console  same, but in this console, so a startup traceback shows
REM
REM Enters through polyscour.entry, the entry point an installed build uses, not
REM app.py. Nothing else is forwarded: entry.py refuses arguments it does not
REM know, and the helper flags are not something to launch by hand.
setlocal

set "PY=%~dp0venv\Scripts\pythonw.exe"
if /i "%~1"=="--console" set "PY=%~dp0venv\Scripts\python.exe"
if not "%~1"=="" if /i not "%~1"=="--console" (
    echo usage: run.bat [--console]
    exit /b 2
)

if not exist "%PY%" (
    echo No virtual environment at "%~dp0venv". Create it first:
    echo.
    echo     python -m venv venv
    echo     .\venv\Scripts\pip install -e "..\PolyBedrock\core" -e "..\PolyBedrock\ui" -e .
    echo.
    pause
    exit /b 1
)

if /i "%~1"=="--console" (
    "%PY%" -m polyscour.entry
    exit /b
)

REM pythonw has no console, so start returns at once and this window closes.
start "" "%PY%" -m polyscour.entry
