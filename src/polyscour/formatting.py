"""How sizes are written, in one place.

Was a function inside ``views/dashboard_view.py`` that three other views
imported from there. It moved when the Storage export needed it too, because
a module under ``storage/`` importing a GUI view module for a string helper is
the dependency pointing the wrong way.
"""
from __future__ import annotations


def human(n: int) -> str:
    """``1536`` -> ``"1.5 KB"``. Non-negative; see :func:`signed` for change."""
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def signed(n: int) -> str:
    """A change, with its direction: ``+12.4 GB``, ``-3.0 GB``, ``0 bytes``.

    ``human`` alone would print a negative as raw bytes, because ``-5e9 < 1024``.
    ASCII signs, so the text survives being pasted anywhere.
    """
    if n > 0:
        return f"+{human(n)}"
    if n < 0:
        return f"-{human(-n)}"
    return human(0)
