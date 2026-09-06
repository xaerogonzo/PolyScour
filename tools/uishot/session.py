"""PolyScour's capture session.

The generic machinery lives in ``polybedrock.ui.uishot.session``. What is here
is the part that is not generic: which entry point to import, and what that
entry point's startup does to the root.

``polyscour/app.py`` sets the CustomTkinter appearance mode at *module* level.
Importing only the view modules would leave it at CustomTkinter's default, and
every label without an explicit ``text_color`` would render against the wrong
defaults — a screenshot that looks plausible and is wrong. Import the entry
point rather than guessing at what it configures.
"""
from __future__ import annotations

from pathlib import Path

from polybedrock.ui.uishot.session import Shot, is_supported  # noqa: F401
from polybedrock.ui.uishot.session import TkSession as _TkSession

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _prepare_root(root) -> None:
    """Everything PolyScour's startup does beyond creating the window."""
    from polybedrock import settings as cfg
    from polybedrock.ui import theme

    from polyscour.app import APP_TITLE

    cfg.load()
    theme.configure(APP_TITLE)
    theme.init(cfg)
    theme.init_colors(cfg)
    theme.apply_ctk_palette()


class TkSession(_TkSession):
    """The shared session, wired to PolyScour's entry point."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("project_root", _PROJECT_ROOT)
        kwargs.setdefault("entry_module", "polyscour.app")
        kwargs.setdefault("on_root", _prepare_root)
        super().__init__(*args, **kwargs)
