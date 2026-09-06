r"""
CLI:  python tools\uishot\__main__.py [--only NAME] [--check | --update-golden]

    ... --list                   list the scenes
    ... --only clean             capture one
    ... --update-golden          record the current look as expected
    ... --check                  fail if anything drifted from golden
    ... --probe                  exit 0 if capture works here, 2 if not

Nothing appears on screen, nothing takes focus, and the mouse is never touched.

Argument parsing, the capture loop and the golden comparison live in
``polybedrock.ui.uishot.cli``. This file supplies PolyScour's scene registry and
a session wired to its entry point.

Kept as a runnable file rather than a console script because the hidden desktop
must be bound before the calling thread owns any window — so this has to be able
to run in a process of its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]
for _p in (_HERE.parents[1], _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from polybedrock.ui.uishot import cli               # noqa: E402
from uishot.scenes import REGISTRY                  # noqa: E402
from uishot.session import TkSession                # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return cli.run(
        argv,
        registry=REGISTRY,
        project_root=_PROJECT_ROOT,
        session_factory=lambda out_dir, root: TkSession(out_dir=out_dir,
                                                        project_root=root),
    )


if __name__ == "__main__":
    raise SystemExit(main())
