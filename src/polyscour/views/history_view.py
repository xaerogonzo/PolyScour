r"""What PolyScour has done, and what can be taken back.

Every meaningful change is here, including dry runs -- labelled as rehearsals,
because presenting one as a change would be a lie in the one place the product
is supposed to be checkable.

Undo appears only where it is real. A row whose findings were regenerable caches
gets no button, because offering one that would fail is worse than not offering
one at all.
"""
from __future__ import annotations

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.contracts import OperationOutcome
from polyscour.views.dashboard_view import human

_OUTCOME_TEXT = {
    OperationOutcome.SUCCESS.value: ("Completed", "#7ec699"),
    OperationOutcome.SUCCESS_WITH_SKIPS.value: ("Completed, some skipped", "#9ccfd8"),
    OperationOutcome.PARTIALLY_COMPLETED.value: ("Partly completed", "#e0af68"),
    OperationOutcome.FAILED.value: ("Failed", "#f7768e"),
    OperationOutcome.CANCELLED.value: ("Cancelled", "#888899"),
}


def _elevation_sentence(row) -> str:
    """What administrator rights did for this operation, if anything.

    Reads the four recorded facts rather than one flag, and says nothing at all
    when elevation was never requested. Tolerant of a row from a database
    written before those columns existed: an upgraded history is still history.
    """
    from polyscour.contracts import ElevationRecord

    try:
        requested = bool(row["elevation_requested"])
    except (IndexError, KeyError):
        return ""
    if not requested:
        return ""
    return ElevationRecord(
        requested=True,
        granted=bool(row["elevation_granted"]),
        attempted=int(row["elevation_attempted"] or 0),
        succeeded=int(row["elevation_succeeded"] or 0),
    ).describe()

class HistoryView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(self, text="History", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w").grid(row=0, column=0, sticky="ew",
                                      padx=20, pady=(20, 4))

        self.totals = ctk.CTkLabel(self, text="", font=theme.get("small"),
                                   anchor="w",
                                   text_color=theme.color("subtext"))
        self.totals.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 8))

        self.list = ctk.CTkScrollableFrame(self, fg_color=theme.color("card2"))
        self.list.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.list.grid_columnconfigure(0, weight=1)

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()

        ledger = self.app.services.ledger
        totals = ledger.totals()
        self.totals.configure(
            text=f"{totals['runs']} completed run"
                 f"{'s' if totals['runs'] != 1 else ''}, "
                 f"{human(totals['bytes_freed'])} reclaimed in total.")

        undoable = {r["operation_id"] for r in ledger.undoable()}
        rows = ledger.history()

        if not rows:
            ctk.CTkLabel(self.list, text="Nothing yet.", font=theme.get("small"),
                         text_color=theme.color("subtext")).grid(
                row=0, column=0, sticky="w", padx=12, pady=12)
            return

        for i, row in enumerate(rows):
            self._add_row(i, row, row["operation_id"] in undoable)

    def _add_row(self, index: int, row, can_undo: bool) -> None:
        frame = ctk.CTkFrame(self.list, fg_color="transparent")
        frame.grid(row=index, column=0, sticky="ew", pady=2)
        frame.grid_columnconfigure(1, weight=1)

        label, colour = _OUTCOME_TEXT.get(row["outcome"], (row["outcome"], None))
        if row["dry_run"]:
            label = "Rehearsal (nothing changed)"
            colour = theme.color("subtext")

        ctk.CTkLabel(frame, text=row["started_at"].replace("T", "  "),
                     font=theme.get("small"), anchor="w", width=150,
                     text_color=theme.color("subtext")).grid(
            row=0, column=0, rowspan=2, sticky="w", padx=(12, 8))

        ctk.CTkLabel(frame, text=label, font=theme.get("item_title"),
                     anchor="w", text_color=colour).grid(row=0, column=1,
                                                         sticky="ew")
        # The elevation sentence goes on its own line rather than into the
        # summary, because "PolyScour changed this with administrator rights"
        # is a different class of fact from how many bytes it freed -- and it
        # is the one a user scanning this list is most likely to be looking
        # for. Absent entirely when elevation was never involved: a permanent
        # "administrator: no" would be noise on every row.
        detail = row["summary"]
        elevation = _elevation_sentence(row)
        if elevation:
            detail = f"{detail}\n{elevation}"
        ctk.CTkLabel(frame, text=detail, font=theme.get("small"),
                     anchor="w", justify="left", wraplength=560,
                     text_color=theme.color("subtext")).grid(
            row=1, column=1, sticky="ew", pady=(0, 6))

        if can_undo:
            ctk.CTkButton(
                frame, text="Undo", width=80,
                command=lambda op=row["operation_id"]: self._undo(op)).grid(
                row=0, column=2, rowspan=2, padx=12)
        else:
            # Says why there is no button, rather than leaving a gap the user
            # has to interpret.
            ctk.CTkLabel(frame, text="Not reversible", font=theme.get("small"),
                         width=90, text_color=theme.color("dim")).grid(
                row=0, column=2, rowspan=2, padx=12)

    def _undo(self, operation_id: str) -> None:
        self.app.set_status("Restoring")
        self.app.run_off_thread(
            lambda: self.app.services.executor.restore(operation_id),
            self._restored)

    def _restored(self, notes, error) -> None:
        if error is not None:
            self.app.set_status(f"Restore failed: {error}")
            return
        self.app.set_status("; ".join(notes) if notes else "Nothing to restore")
        self.refresh()
