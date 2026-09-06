"""uishot — photograph PolyScour without it ever being on screen.

The machinery lives in ``polybedrock.ui.uishot``; this package supplies the
scenes and the entry-point wiring. See that package for the measurements behind
the hidden-desktop design.
"""
from polybedrock.ui.uishot import (CaptureError, DesktopUnavailable, Shot,
                                   capture_window, compare, hidden_desktop,
                                   is_supported, write_diff)

from .session import TkSession

__all__ = ["capture_window", "compare", "write_diff", "CaptureError",
           "hidden_desktop", "DesktopUnavailable", "TkSession", "Shot",
           "is_supported"]
