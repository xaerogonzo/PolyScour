r"""Turning a registry ``UninstallString`` into a command PolyScour can launch.

``UninstallString`` is an arbitrary command line, not a path: a bare
executable, a quoted path with a flag (``"C:\Program Files\Foo\uninstall.exe"
/S``), an MSI invocation (``MsiExec.exe /X{GUID}``), or a vendor launcher with
a quoted argument containing spaces. Splitting it with a naive ``.split()``,
or handing the raw string to a shell (``subprocess.Popen(s, shell=True)``),
would either break on the quoting or hand an untrusted-looking string to
``cmd.exe`` — neither is acceptable for a maintenance tool launching things on
someone's behalf.

``CommandLineToArgvW`` is the same tokenizer ``CreateProcess`` itself uses, so
splitting with it is splitting the way Windows would — not PolyScour's own
guess at Windows quoting rules.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

_CommandLineToArgvW = ctypes.windll.shell32.CommandLineToArgvW
_CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
_CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)

_LocalFree = ctypes.windll.kernel32.LocalFree
_LocalFree.argtypes = [ctypes.c_void_p]
_LocalFree.restype = ctypes.c_void_p


@dataclass(frozen=True)
class UninstallCommand:
    """A registered uninstall command, already split into launchable parts."""
    executable: str
    arguments: tuple[str, ...]
    #: Where this was read from, e.g. r"HKLM\...\Uninstall\{GUID}" — carried
    #: through so a launch failure can name its source, not just the command.
    source_registry_key: str

    @property
    def argv(self) -> list[str]:
        """What to hand ``subprocess.Popen`` — never a single joined string."""
        return [self.executable, *self.arguments]


def _split(command_line: str) -> list[str] | None:
    """Tokenise exactly as ``CreateProcess`` would. ``None`` if it cannot be."""
    if not command_line.strip():
        return None
    argc = ctypes.c_int(0)
    argv_ptr = _CommandLineToArgvW(command_line, ctypes.byref(argc))
    if not argv_ptr:
        return None
    try:
        return [argv_ptr[i] for i in range(argc.value)]
    finally:
        _LocalFree(ctypes.cast(argv_ptr, ctypes.c_void_p))


def parse(command_line: str, source_registry_key: str) -> UninstallCommand | None:
    """Split a registry ``UninstallString`` into an executable and its argv.

    ``None`` for anything that does not yield at least one token — an empty
    string, or a command line the Shell itself could not tokenise. A caller
    must treat ``None`` as "cannot be launched", never as "launch nothing and
    call it done".
    """
    tokens = _split(command_line)
    if not tokens:
        return None
    return UninstallCommand(executable=tokens[0], arguments=tuple(tokens[1:]),
                            source_registry_key=source_registry_key)
