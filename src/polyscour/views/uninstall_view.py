r"""Uninstall — what Windows recorded as installed, and a way to start its own
uninstaller. PolyScour removes nothing itself.

The boundary this screen exists to keep
----------------------------------------

The obvious feature is a "clean removal" tool: delete the program's folder,
its registry keys, its leftovers. That is exactly the authority this project
refuses to invent (docs/adr/0007 declines a duplicate finder for the same
reason) — deciding what a program's "leftovers" are is a judgement call
PolyScour cannot make safely, and a path handed to it that way could be
anything.

So this screen does one thing: it lists what Windows' own Programs and
Features would list, and starts the program's own registered uninstaller —
the same command Control Panel would run. PolyScour decides nothing about
what counts as clean. Nothing here is sorted to imply which program to
remove; it is sorted by size because size is a fact, the same argument the
Storage screen already makes for folders.
"""
from __future__ import annotations

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.formatting import human
from polyscour.uninstall import launcher, policy
from polyscour.uninstall.inventory import describe_install_date, read_inventory


def _describe(program) -> str:
    bits = []
    if program.publisher:
        bits.append(program.publisher)
    if program.version:
        bits.append(f"v{program.version}")
    if program.estimated_size_bytes:
        bits.append(human(program.estimated_size_bytes))
    installed = describe_install_date(program.install_date)
    if installed:
        bits.append(f"installed {installed}")
    return "  ·  ".join(bits) if bits else "No further detail recorded."


class UninstallView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._loaded = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self, text="Uninstall", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 4))

        ctk.CTkLabel(
            self, anchor="w", justify="left", wraplength=1000,
            font=theme.get("small"), text_color=theme.color("subtext"),
            text="Programs Windows recorded as installed. “Run Uninstaller” "
                 "starts the program's own registered uninstaller — the same "
                 "command Control Panel would run. PolyScour does not delete "
                 "files, registry keys, or anything else on the program's "
                 "behalf, and does not track what its uninstaller does "
                 "afterwards."
        ).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 4))

        ctk.CTkLabel(
            self, anchor="w", justify="left", wraplength=1000,
            font=theme.get("small"), text_color=theme.color("subtext"),
            text="PolyScour does not suggest what to remove. Sorted by size, "
                 "because size is a fact — not because a large program is "
                 "more worth removing than a small one."
        ).grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))

        self.status = ctk.CTkLabel(self, text="", anchor="w",
                                   font=theme.get("small"),
                                   text_color=theme.color("subtext"))
        self.status.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 10))

        self.list = ctk.CTkScrollableFrame(self, fg_color=theme.color("card2"))
        self.list.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 4))
        self.list.grid_columnconfigure(0, weight=1)

        self._generation = 0
        self._buttons: dict[str, ctk.CTkButton] = {}

    def on_show(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self.refresh()

    def refresh(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()
        self._buttons = {}

        self._generation += 1
        generation = self._generation
        self.status.configure(text="Reading installed programs…")
        self.app.run_off_thread(
            read_inventory, lambda inv, err: self._inventory_done(
                generation, inv, err))

    def _inventory_done(self, generation, inventory, error) -> None:
        if generation != self._generation:
            return
        if error is not None:
            self.status.configure(
                text=f"Could not read installed programs: {error}")
            return

        for program in inventory.programs:
            self._render_row(program)

        unread = [s for s in inventory.statuses if s.error]
        hidden = sum(s.hidden_system_component for s in inventory.statuses)
        parts = [f"{len(inventory.programs)} programs listed"]
        if hidden:
            parts.append(f"{hidden} system components not shown")
        if unread:
            parts.append(f"{len(unread)} location(s) could not be read")
        self.status.configure(text="  ·  ".join(parts) + ".")

        if not inventory.programs and not unread:
            ctk.CTkLabel(self.list, text="No installed programs found.",
                        anchor="w", font=theme.get("small"),
                        text_color=theme.color("subtext")
                        ).grid(sticky="ew", padx=6, pady=6)

    def _render_row(self, program) -> None:
        _, refusal = policy.evaluate(program)

        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.grid(sticky="ew", padx=6, pady=2)
        row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(row, text=program.name, anchor="w", font=theme.get("body"),
                     text_color=theme.color("subtext") if refusal
                     else theme.color("text")
                     ).grid(row=0, column=0, sticky="ew")

        detail = _describe(program)
        if refusal:
            detail = f"{detail}  ·  {refusal}"
        ctk.CTkLabel(row, text=detail, anchor="w", justify="left",
                     wraplength=620, font=theme.get("small"),
                     text_color=theme.color("subtext")
                     ).grid(row=1, column=0, sticky="ew")

        ctk.CTkLabel(row, text=program.source_registry_key, anchor="w",
                     justify="left", wraplength=620, font=theme.get("small"),
                     text_color=theme.color("dim")
                     ).grid(row=2, column=0, sticky="ew")

        button = ctk.CTkButton(
            row, text="Run Uninstaller", width=150, height=28,
            state="disabled" if refusal else "normal",
            command=lambda p=program: self._run(p))
        button.grid(row=0, column=1, rowspan=3, padx=(8, 0))
        self._buttons[program.identity] = button

    # ── launching ────────────────────────────────────────────────────────────

    def _run(self, program) -> None:
        if not self._confirm(program):
            return

        button = self._buttons.get(program.identity)
        if button is not None:
            button.configure(state="disabled", text="Launching…")

        self.app.run_off_thread(
            lambda: launcher.launch(program),
            lambda result, err: self._launched(program, result, err))

    def _confirm(self, program) -> bool:
        """The last stop, naming exactly what will run and where it came from."""
        lines = [
            f"This starts {program.name}'s own registered uninstaller:",
            f"  {program.source_registry_key}",
            "",
            "PolyScour does not delete anything itself and will not track "
            "what happens next.",
        ]
        dialog = ctk.CTkInputDialog(
            title="Run uninstaller",
            text="\n".join(lines) + "\n\nType UNINSTALL to confirm:")
        return (dialog.get_input() or "").strip().upper() == "UNINSTALL"

    def _launched(self, program, result, error) -> None:
        button = self._buttons.get(program.identity)
        if error is not None:
            if button is not None:
                button.configure(state="normal", text="Run Uninstaller")
            self.status.configure(text=f"Could not launch: {error}")
            return

        if button is not None:
            button.configure(
                state="normal" if result.ok else "disabled",
                text="Run Uninstaller" if result.ok else "Could not launch")
        self.status.configure(text=result.detail)
