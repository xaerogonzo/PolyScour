r"""The process entry point: which of the two programs in this binary to run.

An installed PolyScour is one executable that is two things — the GUI, and the
elevated helper the GUI launches. They are one file because the helper must be
the *same* trusted binary, in the same administrator-protected directory: a
separate helper.exe would be a second thing to protect and a second thing to
verify, for no gain.

Splitting them at the argument, before anything else happens, is what keeps
that from being a compromise.

Why the dispatch is here and not in ``app.py``
----------------------------------------------

``app.py`` imports CustomTkinter at module scope, and importing it imports Tk,
Tcl, and everything the theme layer touches. Dispatching from there would mean
**a GUI toolkit loaded into an elevated process** — tens of thousands of lines
of code running as administrator to delete a file, in a program whose threat
model says the elevated part is deliberately small.

Nothing in this module imports the GUI. The helper branch returns before any
such import can happen, and a test asserts ``customtkinter`` is absent from
``sys.modules`` in a real elevated run.

Unknown arguments are refused, not ignored
------------------------------------------

This is the command line of a program that can be launched with administrator
rights. Ignoring an argument it does not understand means proceeding on the
overlap between what the caller meant and what this understood, which is the
same mistake ``protocol.Request.from_json`` refuses to make about parameters.

A bare launch — no arguments, which is what a shortcut and a double-click
produce — is the GUI. That is the only implicit case.
"""
from __future__ import annotations

import sys

#: The flags. Not prefix matches, not ``argparse``: exact strings, so
#: ``--elevated-helper-x`` is an unknown argument rather than a near miss that
#: something helpfully accepts.
HELPER_FLAG = "--elevated-helper"
SUPERVISOR_FLAG = "--supervise-game-mode"

#: Backwards-compatible alias. The name was private when there was one flag.
_HELPER_FLAG = HELPER_FLAG


def child_argv(flag: str, *args: str) -> list[str]:
    """The argv that re-invokes *this program* with ``flag``.

    One place, because the frozen/source distinction has now been got wrong
    once already: ``_helper_command`` tested ``sys.frozen``, which Nuitka does
    not set, so a compiled build would have asked the executable to run a
    module it has no interpreter for. Every caller that needs to launch
    PolyScour as a child asks here instead of deciding again.

    ``polyscour.paths`` is imported inside the function rather than at module
    scope, so this module keeps its property of importing neither branch until
    something actually asks for one.
    """
    from polyscour import paths

    if paths.is_frozen():
        # running_executable(), NOT sys.executable. Under onefile the latter
        # names a python.exe inside the user-writable extraction directory,
        # and one of the callers here elevates what it is given. See T23.
        return [str(paths.running_executable()), flag, *args]
    return [sys.executable, "-m", "polyscour.entry", flag, *args]

_USAGE = f"""PolyScour — a transparent, evidence-based Windows maintenance suite.

  PolyScour.exe                                    start the application
  PolyScour.exe {HELPER_FLAG} <request>            run one elevated operation
  PolyScour.exe {SUPERVISOR_FLAG} <pid> <started>  watch a Game Mode session

Neither of the latter two is a supported way to run anything by hand.

The second is launched by PolyScour through Windows' own administrator prompt:
the request file names an operation from a closed set, and the elevated process
re-checks every part of it regardless of who wrote it.

The third is an ordinary, unprivileged child that waits for the process it was
given and then resumes whatever the ledger says that process left frozen. It
holds no privilege, and its arguments can only ever make it do less."""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if args and args[0] == HELPER_FLAG:
        # Imported here rather than at module scope so the GUI branch does not
        # pay for it, and -- far more importantly -- so this branch cannot
        # reach anything the other one imports.
        from polyscour.elevation.helper import main as helper_main
        return helper_main(args[1:])

    if args and args[0] == SUPERVISOR_FLAG:
        # Also GUI-free, for a different reason: this one may outlive the
        # window by seconds and there is no sense keeping Tk loaded to do it.
        from polyscour.gamemode.supervisor import main as supervisor_main
        return supervisor_main(args[1:])

    if args:
        print(f"unknown argument: {args[0]!r}\n", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2

    from polyscour.app import main as app_main
    return app_main()


if __name__ == "__main__":
    sys.exit(main())
