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

#: The one flag. Not a prefix match, not ``argparse``: an exact string, so
#: ``--elevated-helper-x`` is an unknown argument rather than a near miss that
#: something helpfully accepts.
_HELPER_FLAG = "--elevated-helper"

_USAGE = f"""PolyScour — a transparent, evidence-based Windows maintenance suite.

  PolyScour.exe                            start the application
  PolyScour.exe {_HELPER_FLAG} <request>   run one elevated operation

The second form is launched by PolyScour itself, through Windows' own
administrator prompt. It is not a supported way to run anything by hand: the
request file names an operation from a closed set, and the elevated process
re-checks every part of it regardless of who wrote it."""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if args and args[0] == _HELPER_FLAG:
        # Imported here rather than at module scope so the GUI branch does not
        # pay for it, and -- far more importantly -- so this branch cannot
        # reach anything the other one imports.
        from polyscour.elevation.helper import main as helper_main
        return helper_main(args[1:])

    if args:
        print(f"unknown argument: {args[0]!r}\n", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2

    from polyscour.app import main as app_main
    return app_main()


if __name__ == "__main__":
    sys.exit(main())
