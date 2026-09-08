r"""Startup Manager — what runs when Windows starts, and a switch for it.

The temptation this screen is built to resist
---------------------------------------------

The obvious feature is a "recommended" list: sort by how long each entry adds
to boot, pre-tick the slow ones, offer *Disable all*. It would look decisive
and it would be wrong. Startup impact is usually negligible, and "you have not
used this in a while" is not evidence that switching it off helps anybody.

So this screen states facts and provides a switch. It does not score, rank,
pre-select, or use the word "recommended". An entry whose target is missing is
described as exactly that — not as "safe to remove", because a missing target is
very often an installer that will put the file back.

The exact mechanism, named
--------------------------

Toggling writes ``HKCU\...\Explorer\StartupApproved\Run``, the same approval
byte Task Manager writes. The ``Run`` value itself is never touched, so nothing
is deleted and every other tool on the machine sees the same truth. Machine-wide
(``HKLM``) entries have a working switch and a stated cost: changing one affects
every account, so it goes through the elevated helper and raises a UAC prompt.
Nothing is pre-selected and nothing is recommended, at either privilege.
"""
from __future__ import annotations

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.startup import service
from polyscour.startup.manager import list_items
from polyscour.startup.policy import (describe_target,
                                      requires_elevation, veto)



class StartupView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self, text="Startup", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 4))

        ctk.CTkLabel(
            self, anchor="w", justify="left", font=theme.get("small"),
            text_color=theme.color("subtext"),
            text="Programs Windows starts for you. Turning one off uses the "
                 "same switch as Task Manager — nothing is deleted, and you "
                 "can turn it back on here or there."
        ).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 4))

        # Said once, plainly, instead of implied by a number nobody can check.
        ctk.CTkLabel(
            self, anchor="w", justify="left", font=theme.get("small"),
            text_color=theme.color("subtext"),
            text="PolyScour does not suggest what to turn off. Startup impact "
                 "is usually small, and an entry you rarely use is not "
                 "evidence that disabling it helps."
        ).grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))

        self.status = ctk.CTkLabel(self, text="", anchor="w",
                                   font=theme.get("small"),
                                   text_color=theme.color("subtext"))
        self.status.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 10))

        self.list = ctk.CTkScrollableFrame(self, fg_color=theme.color("card2"))
        self.list.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 4))
        self.list.grid_columnconfigure(0, weight=1)

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()

        try:
            items = list_items()
        except OSError as exc:
            # Not an empty list: "nothing starts up" is a claim, and a failed
            # read is not evidence for it.
            self.status.configure(text=f"Could not read the startup entries: {exc}")
            return

        for it in items:
            self._render_row(it)

        on = sum(1 for i in items if i.enabled)
        self.status.configure(
            text=f"{len(items)} entries, {on} enabled. "
                 f"Machine-wide entries affect every account and ask for "
                 f"administrator rights when you change one.")

    def _render_row(self, it) -> None:
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=2)
        row.grid_columnconfigure(1, weight=1)

        refusal = veto(it)
        cost = requires_elevation(it)
        var = ctk.BooleanVar(value=it.enabled)
        switch = ctk.CTkSwitch(
            row, text="", width=40, variable=var,
            state="disabled" if refusal else "normal",
            command=lambda i=it, v=var: self._toggle(i, v))
        switch.grid(row=0, column=0, rowspan=2, padx=(0, 8))

        ctk.CTkLabel(row, text=it.name, anchor="w", font=theme.get("body"),
                     text_color=theme.color("subtext") if refusal
                     else theme.color("text")
                     ).grid(row=0, column=1, sticky="ew")

        # describe_target already explains a missing or unresolvable target;
        # appending a second phrase for the same fact read as two problems.
        #
        # The elevation cost is shown next to a *working* switch rather than
        # in place of one. "Affects every account on this machine" is a thing
        # to read before flipping it, not an explanation for why it is greyed.
        detail = describe_target(it)
        if refusal:
            detail = f"{detail}  ·  {refusal}"
        elif cost:
            detail = f"{detail}  ·  {cost}"
        ctk.CTkLabel(row, text=detail, anchor="w", font=theme.get("small"),
                     text_color=theme.color("subtext")
                     ).grid(row=1, column=1, sticky="ew")

        scope = f"{it.scope}  ·  admin" if cost and not refusal else it.scope
        ctk.CTkLabel(row, text=scope, anchor="e", font=theme.get("small"),
                     text_color=theme.color("subtext")
                     ).grid(row=0, column=2, rowspan=2, padx=6)

    def _toggle(self, it, var) -> None:
        wanted = bool(var.get())
        ledger = self.app.services.ledger

        if requires_elevation(it) is None:
            self._toggled(it, var, wanted,
                          service.apply_change(it, wanted, ledger), None)
            return

        # A machine-wide change raises a UAC prompt, and the prompt is modal to
        # the desktop rather than to us: doing it inline freezes the window
        # behind the dialog and Windows paints it as "not responding". The
        # switch is left where the user put it and disabled until the answer
        # arrives, so the screen never shows a state nobody has agreed to yet.
        self.status.configure(
            text=f"{it.name}: waiting for administrator rights…")
        self.app.run_off_thread(
            lambda: service.apply_change(it, wanted, ledger),
            lambda result, error: self._toggled(it, var, wanted, result, error))

    def _toggled(self, it, var, wanted, result, error) -> None:
        if error is not None:
            var.set(it.enabled)
            self.status.configure(text=f"{it.name}: {error}")
            return
        if not result.changed:
            # Put the switch back where it was: leaving it showing a state the
            # registry does not have would be the screen lying about the machine.
            var.set(it.enabled)
            self.status.configure(text=f"{it.name}: {result.reason}")
            return
        self.refresh()
        # Says which mechanism was used, because "PolyScour changed something
        # for every account on this machine" is a different sentence from
        # "PolyScour changed something for you", and the user should read the
        # one that happened.
        where = ("for every account on this machine" if result.elevated
                 else "for your account")
        self.status.configure(
            text=f"{it.name} is now {'enabled' if wanted else 'disabled'} "
                 f"{where}. Undo it here or in Task Manager.")
