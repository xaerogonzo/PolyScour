r"""Game Mode — freeze background processes while you play, and let them go after.

What this screen deliberately does not do
-----------------------------------------

**Nothing is ticked when you arrive.** The list is sorted by memory because
that is a fact worth showing, but sorting is not selecting: PolyScour has no
opinion about which of your programs you want frozen, and pre-ticking the top
of a list is a recommendation dressed as a convenience. "Using 2 GB" is not
evidence that suspending something is a good idea.

**Refused processes are shown, with the reason.** Hiding them would make the
policy invisible and leave a user hunting for a program that is not in the
list. Saying *why* `explorer.exe` cannot be frozen is more useful than
pretending it does not exist. They are not a row each: they are one summary
line (how many, and per reason) over a single read-only text box listing every
one of them with its reason, so nothing is dropped and nothing is a widget.

**The screen's cost in Windows USER objects does not depend on how many
processes are running.** Every CustomTkinter widget is several USER objects
and a process may hold at most 10,000; one row per process took the app from
~200 to ~7,700 on a 529-process machine, and the failure surfaced screens
later as ``No more menus can be allocated``. So at most ``MAX_ROWS`` selectable
rows are built, largest memory first, and the rest are *counted aloud* on the
screen -- a hidden number is stated, never implied to be zero. The cap is a
rendering limit, not a policy: ``veto()`` still decides what may be frozen, and
runs again inside ``session.suspend``.

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
from polyscour.formatting import human


#: Selectable rows built at once. ~14 USER objects each, so this is ~850.
MAX_ROWS = 60


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
        ordered = sorted(candidates, key=lambda c: -c.memory_bytes)
        offered: list = []
        refused: list[tuple[object, str]] = []
        for cand in ordered:
            reason = veto(cand)
            if reason:
                refused.append((cand, reason))
            else:
                offered.append(cand)

        for cand in offered[:MAX_ROWS]:
            self._render_row(cand)
        unshown = offered[MAX_ROWS:]
        if unshown:
            self._render_unshown(unshown)
        if refused:
            self._render_refused(refused)
        self.status.configure(text=f"{len(candidates)} processes")

    def _render_row(self, cand) -> None:
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=1)
        row.grid_columnconfigure(1, weight=1)

        box = ctk.CTkCheckBox(row, text="", width=24)
        box.grid(row=0, column=0)
        ctk.CTkLabel(row, text=cand.display_name, anchor="w",
                     text_color=theme.color("text"), font=theme.get("body")
                     ).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkLabel(row, text=human(cand.memory_bytes), anchor="e",
                     text_color=theme.color("subtext"), font=theme.get("small")
                     ).grid(row=0, column=2, padx=6)
        self._rows.append((box, cand))

    def _render_unshown(self, unshown) -> None:
        """Say how many selectable processes have no row, and why.

        The count is the point: a list that silently stops is read as complete.
        """
        total = sum(c.memory_bytes for c in unshown)
        ctk.CTkLabel(
            self.list, anchor="w", justify="left", wraplength=560,
            text_color=theme.color("subtext"), font=theme.get("small"),
            text=f"{len(unshown)} more suspendable processes are not listed "
                 f"(the smallest by memory, {human(total)} between them). "
                 f"Showing the {MAX_ROWS} largest."
        ).grid(sticky="ew", padx=10, pady=(6, 2))

    def _render_refused(self, refused) -> None:
        """One summary and one text box for every process the policy refuses."""
        by_reason: dict[str, int] = {}
        for _cand, reason in refused:
            by_reason[reason] = by_reason.get(reason, 0) + 1
        breakdown = "; ".join(f"{n} x {r}" for r, n in
                              sorted(by_reason.items(), key=lambda kv: -kv[1]))
        ctk.CTkLabel(
            self.list, anchor="w", justify="left", wraplength=560,
            text_color=theme.color("subtext"), font=theme.get("small"),
            text=f"{len(refused)} processes PolyScour will not suspend: "
                 f"{breakdown}."
        ).grid(sticky="ew", padx=10, pady=(10, 2))

        lines = [f"{c.display_name}  {human(c.memory_bytes)}  {reason}"
                 for c, reason in refused]
        box = ctk.CTkTextbox(self.list, height=max(48, min(140, 20 + 17 * len(lines))), font=theme.get("small"),
                             text_color=theme.color("subtext"), wrap="none")
        box.insert("1.0", chr(10).join(lines))
        box.configure(state="disabled")
        box.grid(sticky="ew", padx=6, pady=(0, 6))

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

        parts = [f"{len(frozen)} suspended."]
        if refused:
            # Named, not counted. "3 were refused" is not something a user can
            # act on or check.
            parts.append("Refused: " + ", ".join(
                f"{r.candidate.display_name} ({r.reason})"
                for r in refused[:3]))
        if frozen:
            parts.append(_recovery_note(self._session.supervised))
        self.status.configure(text=" ".join(parts))

    def _resume(self) -> None:
        stubborn = self._session.resume_all()
        self.refresh()
        if stubborn:
            # The one outcome that must never pass quietly.
            self.status.configure(
                text="Could not resume: " + ", ".join(stubborn)
                     + ". They are still frozen.")


def _recovery_note(supervised: bool) -> str:
    """What happens to these processes if PolyScour dies, in one sentence.

    Two sentences rather than one, because the two states are genuinely
    different and the difference is what a user would want to know. Neither
    promises restoration: a supervisor narrows the window and does not close
    it (THREAT_MODEL.md T20), and a maintenance tool that overstates its own
    recovery is doing the thing this product exists not to do.
    """
    if supervised:
        return ("If PolyScour stops, a recovery helper resumes them; if both "
                "stop, the next launch does.")
    return "If PolyScour stops, the next launch resumes them."


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
