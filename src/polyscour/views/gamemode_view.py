r"""Game Mode — freeze background processes while you play, and let them go after.

What this screen deliberately does not do
-----------------------------------------

**Nothing is ticked when you arrive.** The list is sorted by memory because
that is a fact worth showing, but sorting is not selecting: PolyScour has no
opinion about which of your programs you want frozen, and pre-ticking the top
of a list is a recommendation dressed as a convenience. "Using 2 GB" is not
evidence that suspending something is a good idea.

**Refused processes are shown, greyed, with the reason.** Hiding them would
make the policy invisible and leave a user hunting for a program that is not in
the list. Saying *why* `explorer.exe` cannot be frozen is more useful than
pretending it does not exist.

Suspension is a state, not an action
------------------------------------

The button says **Resume all** for as long as anything is frozen, because that
is the only thing the user needs from this screen while a session is live. If
PolyScour dies instead, the next launch resumes them and says so in the banner
at the top -- see ``polyscour.gamemode.session``.
"""
from __future__ import annotations

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.gamemode import session as gm
from polyscour.gamemode.policy import veto
from polyscour.views.dashboard_view import human


class GameModeView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._session: gm.GameSession | None = None
        self._rows: list[tuple[ctk.CTkCheckBox, object]] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self, text="Game Mode", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 4))

        self.subtitle = ctk.CTkLabel(
            self, anchor="w", justify="left", font=theme.get("small"),
            text_color=theme.color("subtext"),
            text="Suspend background programs while you play. They keep their "
                 "memory and carry on where they left off when resumed.")
        self.subtitle.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 8))

        #: Only rendered when a previous run left something frozen. An empty
        #: banner on every launch would train people to ignore the one that
        #: matters.
        self.recovery = ctk.CTkLabel(
            self, anchor="w", justify="left", font=theme.get("small"),
            text_color=theme.color("warning") if _has(theme, "warning")
            else theme.color("subtext"), text="")
        self.recovery.grid(row=2, column=0, sticky="ew", padx=20)
        self.recovery.grid_remove()

        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew", padx=20, pady=(6, 6))
        self.action = ctk.CTkButton(bar, text="Suspend selected",
                                    command=self.on_action)
        self.action.pack(side="left")
        self.status = ctk.CTkLabel(bar, text="", font=theme.get("small"),
                                   text_color=theme.color("subtext"))
        self.status.pack(side="left", padx=12)

        self.list = ctk.CTkScrollableFrame(self, fg_color=theme.color("card2"))
        self.list.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.list.grid_columnconfigure(0, weight=1)

    # ── lifecycle ──────────────────────────────────────────────────────────

    def on_show(self) -> None:
        self._show_recovery()
        self.refresh()

    def _show_recovery(self) -> None:
        report = getattr(self.app.services, "game_recovery", None)
        if report is not None and report.anything_found:
            self.recovery.configure(text=report.summary())
            self.recovery.grid()
        else:
            self.recovery.grid_remove()

    # ── the list ───────────────────────────────────────────────────────────

    def refresh(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()
        self._rows = []

        if self._session is not None and self._session.held_count:
            self._render_held()
            return

        candidates = gm.enumerate_candidates()
        if candidates is None:
            # Not an empty list. "Nothing is running" is never true, and an
            # empty screen would look like a harmless answer to a broken probe.
            self.status.configure(
                text="Could not read the process list, so nothing is offered.")
            self.action.configure(state="disabled")
            return

        self.action.configure(state="normal", text="Suspend selected")
        # Sorted by memory: a fact, shown so a person can judge. Not a ranking
        # of what should be suspended, and nothing arrives ticked.
        for cand in sorted(candidates, key=lambda c: -c.memory_bytes):
            self._render_row(cand)
        self.status.configure(text=f"{len(candidates)} processes")

    def _render_row(self, cand) -> None:
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=1)
        row.grid_columnconfigure(1, weight=1)

        refusal = veto(cand)
        box = ctk.CTkCheckBox(row, text="", width=24,
                              state="disabled" if refusal else "normal")
        box.grid(row=0, column=0)

        colour = theme.color("subtext") if refusal else theme.color("text")
        ctk.CTkLabel(row, text=cand.display_name, anchor="w",
                     text_color=colour, font=theme.get("body")
                     ).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkLabel(row, text=human(cand.memory_bytes), anchor="e",
                     text_color=theme.color("subtext"), font=theme.get("small")
                     ).grid(row=0, column=2, padx=6)

        if refusal:
            # Shown rather than hidden: an absent row sends the user hunting.
            ctk.CTkLabel(row, text=refusal, anchor="w",
                         text_color=theme.color("subtext"),
                         font=theme.get("small")
                         ).grid(row=1, column=1, columnspan=2, sticky="ew",
                                padx=6, pady=(0, 2))
        else:
            self._rows.append((box, cand))

    def _render_held(self) -> None:
        self.action.configure(state="normal", text="Resume all")
        held = self._session.held_count
        self.status.configure(
            text=f"{held} process{'es' if held != 1 else ''} suspended")
        ctk.CTkLabel(self.list, anchor="w", justify="left",
                     text_color=theme.color("subtext"), font=theme.get("small"),
                     text="Suspended programs are frozen, not closed. If "
                          "PolyScour is closed without resuming them, the next "
                          "launch will resume them for you."
                     ).grid(sticky="ew", padx=10, pady=10)

    # ── the one button ─────────────────────────────────────────────────────

    def on_action(self) -> None:
        if self._session is not None and self._session.held_count:
            self._resume()
        else:
            self._suspend()

    def _suspend(self) -> None:
        chosen = [cand for box, cand in self._rows if box.get()]
        if not chosen:
            self.status.configure(text="Nothing selected.")
            return

        self._session = gm.GameSession(self.app.services.ledger)
        results = self._session.suspend(chosen)

        frozen = [r for r in results if r.suspended]
        refused = [r for r in results if not r.suspended]
        self.refresh()
        if refused:
            # Named, not counted. "3 were refused" is not something a user can
            # act on or check.
            self.status.configure(
                text=f"{len(frozen)} suspended. Refused: "
                     + ", ".join(f"{r.candidate.display_name} ({r.reason})"
                                 for r in refused[:3]))

    def _resume(self) -> None:
        stubborn = self._session.resume_all()
        self.refresh()
        if stubborn:
            # The one outcome that must never pass quietly.
            self.status.configure(
                text="Could not resume: " + ", ".join(stubborn)
                     + ". They are still frozen.")


def _has(theme_mod, name: str) -> bool:
    """Whether the shared palette defines *name*.

    PolyBedrock owns the palette and PolyScour must not assume a key exists --
    a missing colour would raise here at import of a view rather than showing
    up as a wrong colour.
    """
    try:
        theme_mod.color(name)
        return True
    except Exception:
        return False
