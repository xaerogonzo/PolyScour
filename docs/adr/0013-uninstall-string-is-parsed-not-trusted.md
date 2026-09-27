# 0013 — `UninstallString` is tokenised with `CommandLineToArgvW`, never joined into a shell command

**Status:** Accepted · **Date:** 2026-09-27

## Context

The Uninstaller lists what Windows' registry `...\Uninstall\*` keys recorded
and offers to start each program's own registered uninstaller — the same
command Control Panel's Programs and Features would run. That command,
`UninstallString`, is a single string a program's installer wrote, and it can
take any of several shapes:

```
"C:\Program Files\Foo\uninstall.exe" /S
C:\Program Files\Foo\uninstall.exe /S
MsiExec.exe /X{90140000-0011-0000-0000-0000000FF1CE}
"C:\Vendor\launcher.exe" "argument with spaces" /quiet
```

The obvious implementation calls `subprocess.Popen(uninstall_string,
shell=True)` and lets `cmd.exe` sort out the quoting. That is the wrong
implementation, for the same reason a cleaning rule cannot declare a path: a
string PolyScour did not write, handed to a shell, is a string PolyScour does
not actually control the meaning of.

## Decision — `CommandLineToArgvW`, then launch the argv list directly

`uninstall/command.py` splits `UninstallString` with
`ctypes.windll.shell32.CommandLineToArgvW` — the same tokenizer
`CreateProcess` itself uses internally — into an `executable` and a tuple of
`arguments`. `uninstall/launcher.py` then calls
`subprocess.Popen([executable, *arguments], shell=False)`.

This is a narrower, more mechanical version of the same principle
`safety/policy.py`'s module docstring states for paths: *"configuration is
not authority."* `UninstallString` is data a vendor's installer wrote, not
something PolyScour can trust to already mean what it appears to mean. The
defence is not to validate the string's *content* (there is no reliable way
to tell a legitimate uninstaller string from a malicious one by inspection)
but to remove the one thing that would let it do more than launch a single
program: a shell. `shell=True` would let a string containing `&`, `|`, or
`&&` run more than one command; `CommandLineToArgvW` plus `shell=False`
tokenises the string exactly the way Windows' own process creation would and
launches exactly one process with exactly the arguments recorded, nothing
compounded.

`QuietUninstallString`, when present, is recorded on `InstalledProgram` but
never parsed or launched by the visible "Run Uninstaller" action. A quiet
string is designed for unattended removal, which is a different promise than
the one that button makes.

## Consequences

- An `UninstallString` that is itself malformed in a way `CommandLineToArgvW`
  cannot tokenise at all yields `command.parse() -> None`, and
  `uninstall/policy.veto()` refuses it with "the registered uninstall command
  could not be parsed as a command PolyScour can launch safely." The row is
  still listed — Windows recorded that this program exists — only its launch
  button is disabled, with the reason shown, the same pattern
  `startup/policy.py` uses for an entry it will not change.
- A syntactically valid but semantically wrong string (an unquoted path
  containing a space, which tokenises into a nonexistent "executable" plus a
  stray argument) is *not* rejected at parse time — `CommandLineToArgvW`
  succeeds on it, the same way `CreateProcess` would. `uninstall/launcher.py`
  catches this at launch time instead, by checking that an *absolute* parsed
  executable path still exists before calling `Popen`. A bare name (e.g.
  `MsiExec.exe`) is not checked for existence, because Windows resolves it
  through its own search path when launched, and PolyScour has no way to
  replicate that resolution more reliably than letting Windows do it.
- Launching still happens **twice-checked**: once when the inventory renders
  a row (`policy.evaluate()`, so the button can be disabled up front) and
  again immediately before `Popen` (`launcher.launch()` re-parses and
  re-checks), the same "authorise twice" discipline `safety/guard.py` and
  `gamemode/policy.py` both use — between listing and clicking, the registry
  value or the file on disk can change.
