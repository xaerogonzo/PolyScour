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

import threading

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.startup import service
from polyscour.startup.inventory import Source, describe, read_inventory
from polyscour.startup.manager import list_items
from polyscour.startup.policy import (describe_target,
                                      requires_elevation, veto)

#: Section titles, and the exact mechanism each one reads. Naming the mechanism
#: is a project rule; "some Windows startup thing" is not an acceptable label.
_SECTIONS = [
    (Source.STARTUP_FOLDER, "Startup folders"),
    (Source.RUN_ONCE, "RunOnce keys"),
    (Source.SCHEDULED_TASK, "Scheduled tasks that start at logon or boot"),
    (Source.SERVICE, "Services set to start automatically"),
]


#: One line, deliberately: a wrapped label in this row is squashed, not grown.
_WAITING_ROW = ("Waiting for the Windows administrator prompt "
                "(check behind other windows and the taskbar)")
_WAITING_STATUS = "waiting for administrator rights…"
_CANCELLING_STATUS = ("Cancelling. If the Windows prompt is answered later, "
                      "nothing will be changed.")


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
        self._generation = 0
        #: Identities whose administrator request is still in flight, and the
        #: switch drawn for each row, so a row can be locked and unlocked.
        self._pending: set[str] = set()
        self._switches: dict = {}
        #: One cancel Event per pending request, and the row parts that show
        #: the wait: (detail label, its normal text, cancel button).
        self._cancels: dict = {}
        self._waiting_parts: dict = {}

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()
        self._switches = {}
        self._waiting_parts = {}

        try:
            items = list_items()
        except OSError as exc:
            # Not an empty list: "nothing starts up" is a claim, and a failed
            # read is not evidence for it.
            self.status.configure(text=f"Could not read the startup entries: {exc}")
            items = None

        if items is not None:
            for it in items:
                self._render_row(it)

            on = sum(1 for i in items if i.enabled)
            self.status.configure(
                text=f"{len(items)} entries, {on} enabled. "
                     f"Machine-wide entries affect every account and ask for "
                     f"administrator rights when you change one.")
        self._load_inventory()

    # ── the view-only inventory ──────────────────────────────────────────────

    def _load_inventory(self) -> None:
        """Read tasks and services off the UI thread; render when they arrive.

        ``schtasks`` is a subprocess, and a screen that freezes while one runs
        is the wrong trade for a section that changes nothing. The generation
        counter drops an answer that arrives after the list was rebuilt --
        painting it would duplicate the section.
        """
        self._generation += 1
        generation = self._generation
        self._section_label("Also starts with Windows — view only")
        self._placeholder = self._note("Reading scheduled tasks and services…")
        self.app.run_off_thread(
            read_inventory,
            lambda inv, err: self._inventory_done(generation, inv, err))

    def _inventory_done(self, generation, inventory, error) -> None:
        if generation != self._generation:
            return
        self._placeholder.destroy()      # keep the section heading
        if error is not None:
            self._note(f"Could not read these: {error}")
            return
        self._note("These are other places Windows starts things from. They "
                   "have no switch here on purpose: changing a task or a "
                   "service is a different mechanism from the Run keys above, "
                   "and PolyScour does not do it. Nothing below is a "
                   "recommendation.")
        for source, title in _SECTIONS:
            self._render_source(inventory, source, title)

    def _section_label(self, text: str) -> None:
        ctk.CTkLabel(self.list, text=text, anchor="w",
                     font=theme.get("section_title"),
                     text_color=theme.color("text")
                     ).grid(sticky="ew", padx=6, pady=(18, 2))

    def _note(self, text: str):
        label = ctk.CTkLabel(self.list, text=text, anchor="w", justify="left",
                             wraplength=700, font=theme.get("small"),
                             text_color=theme.color("subtext"))
        label.grid(sticky="ew", padx=6, pady=(0, 4))
        return label

    def _render_source(self, inventory, source, title: str) -> None:
        status = inventory.status(source)
        entries = inventory.of(source)
        counted = (f"; {status.in_windows_folder} others, whose programs are "
                   f"all inside the Windows folder, are not listed"
                   if status.in_windows_folder else "")
        ctk.CTkLabel(self.list, text=f"{title} — {len(entries)} listed{counted}",
                     anchor="w", font=theme.get("body"),
                     text_color=theme.color("text")
                     ).grid(sticky="ew", padx=6, pady=(10, 0))
        if status.error:
            # Unread is not empty. Said in the source's own section so it
            # cannot be mistaken for "nothing found".
            self._note(f"Could not read all of this: {status.error}")
        elif not entries:
            self._note("None found.")
        for entry in entries:
            self._render_entry(entry)

    def _render_entry(self, entry) -> None:
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=2)
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(row, text=entry.name, anchor="w", font=theme.get("body"),
                     text_color=theme.color("text")
                     ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(row, text=describe(entry), anchor="w", justify="left",
                     wraplength=620, font=theme.get("small"),
                     text_color=theme.color("subtext")
                     ).grid(row=1, column=0, sticky="ew")
        where = f"{entry.mechanism}" + (
            f"  ·  runs as {entry.runs_as}" if entry.runs_as else "")
        ctk.CTkLabel(row, text=where, anchor="w", justify="left",
                     wraplength=620, font=theme.get("small"),
                     text_color=theme.color("dim")
                     ).grid(row=2, column=0, sticky="ew")
        if entry.state:
            ctk.CTkLabel(row, text=entry.state, anchor="e",
                         font=theme.get("small"),
                         text_color=theme.color("subtext")
                         ).grid(row=0, column=1, rowspan=2, padx=6)

    def _render_row(self, it) -> None:
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=2)
        row.grid_columnconfigure(1, weight=1)

        refusal = veto(it)
        cost = requires_elevation(it)
        var = ctk.BooleanVar(value=it.enabled)
        switch = ctk.CTkSwitch(
            row, text="", width=40, variable=var,
            state="disabled" if refusal or it.identity in self._pending
            else "normal",
            command=lambda i=it, v=var: self._toggle(i, v))
        switch.grid(row=0, column=0, rowspan=2, padx=(0, 8))
        self._switches[it.identity] = switch

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
        detail_label = ctk.CTkLabel(
            row, text=detail, anchor="w", font=theme.get("small"),
            text_color=theme.color("subtext"))
        detail_label.grid(row=1, column=1, sticky="ew")

        scope = f"{it.scope}  ·  admin" if cost and not refusal else it.scope
        ctk.CTkLabel(row, text=scope, anchor="e", font=theme.get("small"),
                     text_color=theme.color("subtext")
                     ).grid(row=0, column=2, rowspan=2, padx=6)

        # Only a row that waits on a Windows prompt can be cancelled. Built for
        # every such row and shown only while a request is pending, so a rebuilt
        # list still shows the wait and its way out.
        cancel_button = None
        if cost and not refusal:
            cancel_button = ctk.CTkButton(
                row, text="Cancel", width=80, height=24,
                command=lambda ident=it.identity: self._cancel(ident))
            cancel_button.grid(row=0, column=3, rowspan=2, padx=(0, 6))
            cancel_button.grid_remove()
        self._waiting_parts[it.identity] = (detail_label, detail, cancel_button)
        self._show_waiting(it.identity, it.identity in self._pending)

    def _toggle(self, it, var) -> None:
        if it.identity in self._pending:
            # A second click on a row whose request is still in flight. Judged
            # against the row's *old* state it would read as "already in that
            # state" and snap the switch back to a position the registry does
            # not have -- which is what happened on a real machine. Ignored,
            # and the switch put back where the pending request left it.
            var.set(it.enabled)
            return

        wanted = bool(var.get())
        ledger = self.app.services.ledger

        if requires_elevation(it) is None:
            self._toggled(it, wanted,
                          service.apply_change(it, wanted, ledger), None)
            return

        # A machine-wide change raises a UAC prompt, and the prompt is modal to
        # the desktop rather than to us: doing it inline freezes the window
        # behind the dialog and Windows paints it as "not responding". The
        # switch is left where the user put it and *locked* until the answer
        # arrives, so the screen never shows a state nobody has agreed to yet
        # and a second click cannot race the first.
        #
        # The prompt can be hidden behind other windows or only blink in the
        # taskbar, and Windows lets it sit for minutes. So the row says what it
        # is waiting for and offers a Cancel; see ``_cancel`` for what that
        # does and does not promise.
        cancel = threading.Event()
        self._cancels[it.identity] = cancel
        self._pending.add(it.identity)
        self._lock(it.identity, True)
        self._show_waiting(it.identity, True)
        self.status.configure(text=f"{it.name}: {_WAITING_STATUS}")
        self.app.run_off_thread(
            lambda: service.apply_change(it, wanted, ledger, cancel),
            lambda result, error: self._toggled(it, wanted, result, error))

    def _show_waiting(self, identity: str, waiting: bool) -> None:
        parts = self._waiting_parts.get(identity)
        if parts is None:
            return
        label, normal, button = parts
        label.configure(text=_WAITING_ROW if waiting else normal)
        if button is None:
            return
        if waiting:
            cancelled = self._cancels.get(identity)
            button.configure(
                text="Cancelling…" if cancelled is not None and cancelled.is_set()
                else "Cancel",
                state="disabled" if cancelled is not None and cancelled.is_set()
                else "normal")
            button.grid()
        else:
            button.grid_remove()

    def _cancel(self, identity: str) -> None:
        """Ask for the pending change not to happen.

        What this promises, exactly: if Windows' prompt is answered *after* this,
        the helper finds the cancel sentinel and changes nothing, and the row's
        History entry is closed as not done. What it cannot do is dismiss the
        prompt itself -- that belongs to Windows -- so an unanswered prompt stays
        on screen and the row stays locked until it is answered or Windows drops
        it. A change the helper had already made is reported as made.
        """
        cancel = self._cancels.get(identity)
        if cancel is None:
            return
        cancel.set()
        self._show_waiting(identity, True)
        self.status.configure(text=_CANCELLING_STATUS)

    def _lock(self, identity: str, locked: bool) -> None:
        switch = self._switches.get(identity)
        if switch is not None:
            switch.configure(state="disabled" if locked else "normal")

    def _toggled(self, it, wanted, result, error) -> None:
        self._pending.discard(it.identity)
        self._cancels.pop(it.identity, None)
        # Whatever happened, the list is re-read from the registry rather than
        # patched from what this row remembered. A refusal does not mean the
        # switch is where it started (an earlier request may have landed), and
        # leaving a row showing a state the registry does not have would be the
        # screen lying about the machine.
        self.refresh()
        if error is not None:
            self.status.configure(text=f"{it.name}: {error}")
            return
        if not result.changed:
            self.status.configure(text=f"{it.name}: {result.reason}")
            return
        # Says which mechanism was used, because "PolyScour changed something
        # for every account on this machine" is a different sentence from
        # "PolyScour changed something for you", and the user should read the
        # one that happened.
        where = ("for every account on this machine" if result.elevated
                 else "for your account")
        self.status.configure(
            text=f"{it.name} is now {'enabled' if wanted else 'disabled'} "
                 f"{where}. Undo it here or in Task Manager.")
