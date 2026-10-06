r"""Informational PolyShield labels for Storage and Startup. Decoration only.

What this is, and the lines it will not cross
---------------------------------------------

Where PolyShield is installed and running, a row can say two plain facts about
its own path -- that PolyShield monitors the location, or holds a recorded
detection at or beneath it. That is *annotation*. The step from there to
*recommendation* is a short one -- "flagged, so remove it" -- and it is the step
this product exists not to take, so the boundary is stated in code, not just
here:

* **Never a sort key.** Storage's folders stay ordered by size and Startup's
  rows keep their order. This module receives rows that are already laid out
  and only ever *adds a label to one*; it has no handle on order.
* **Never a state.** It cannot touch a switch, a checkbox or a button. The
  only widget it makes is a ``CTkLabel`` in the dim "mechanism" colour.
* **Never preselects anything**, and creates nothing at all when there is
  nothing to say -- a row with no label is laid out exactly as it was before
  this existed, so a machine without PolyShield sees no change whatsoever.
* **Lazy.** Only the rows actually on screen are asked about (Storage shows 12
  per list), in one background pass after the screen is drawn. Walking a whole
  scan through PolyShield to put badges on it would layer an IPC walk under a
  filesystem walk whose value is that it is fast.

``flagged: False`` and UNKNOWN both produce no label (``describe_path``): the
absence of a note is not a statement that anything is fine.
"""
from __future__ import annotations

import tkinter
from pathlib import Path

from polyscour.integrations.polyshield import describe_path


def annotate(app, targets, is_current=lambda: True) -> None:
    """Ask PolyShield about each target off the UI thread, then label the rows.

    ``targets`` is a list of ``(path, is_folder, place)``, where ``place(text)``
    adds a label to that row. It is called only for a non-empty text, and only
    on the UI thread, and only if ``is_current()`` still holds -- an answer that
    arrives after the screen was rebuilt would label rows that no longer exist.
    """
    # Absolute paths only. PolyShield refuses anything else (and an empty
    # ``Path("")`` is ``.``), so asking would cost a round trip for a certain
    # UNKNOWN -- and a Startup ``Run`` value that never resolved to a file is
    # common.
    targets = [t for t in targets
               if t[0] is not None and Path(t[0]).is_absolute()]
    if not targets:
        return
    advisor = app.services.annotator

    def work():
        advisor.begin()
        return [advisor.status(Path(path)) for path, _, _ in targets]

    def done(statuses, error) -> None:
        if error is not None or not is_current():
            return
        for (_, folder, place), status in zip(targets, statuses):
            text = describe_path(status, folder=folder)
            if text:
                try:
                    place(text)
                except tkinter.TclError:
                    pass       # the row was destroyed under us; nothing to label

    app.run_off_thread(work, done)
