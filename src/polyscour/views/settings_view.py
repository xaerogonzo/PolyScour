r"""Settings, and the things a user is entitled to be able to check.

The protected-locations list is shown rather than merely promised. A user who
cannot see what is protected has to take it on trust, which is exactly what this
product is trying not to ask for.

Note what is *not* editable: the built-in denylist. An exclusion can only add
protection. There is no control here that makes PolyScour able to touch more
than it could before.
"""
from __future__ import annotations

from pathlib import Path

import customtkinter as ctk
from polybedrock import settings as cfg
from polybedrock.ui import theme

from polyscour.formatting import human
from polyscour.safety.policy import POLICY
from polyscour.scheduling import consent, service, store
from polyscour.storage.history import DEFAULT_KEEP_PER_VOLUME


def _valid_time(text: str) -> bool:
    if len(text) != 5 or text[2] != ":":
        return False
    hh, mm = text[:2], text[3:]
    return (hh.isdigit() and mm.isdigit()
           and 0 <= int(hh) <= 23 and 0 <= int(mm) <= 59)


class SettingsView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self, text="Settings", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w").grid(row=0, column=0, sticky="ew",
                                      padx=20, pady=(20, 8))

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        body.grid_columnconfigure(0, weight=1)

        row = 0
        row = self._behaviour(body, row)
        row = self._rules(body, row)
        row = self._exclusions(body, row)
        row = self._protected(body, row)
        row = self._scheduled_cleaning(body, row)
        row = self._storage_history(body, row)
        self._privacy(body, row)

    def on_show(self) -> None:
        # Built once, shown many times, and a Storage scan adds rows meanwhile.
        self._refresh_history()
        self._render_schedules()

    # ── sections ─────────────────────────────────────────────────────────────

    def _section(self, parent, row: int, title: str, blurb: str = ""):
        card = ctk.CTkFrame(parent, fg_color=theme.color("card"),
                            corner_radius=8)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=theme.get("section_title"),
                     text_color=theme.color("text"), anchor="w").grid(row=0, column=0, sticky="ew",
                                      padx=16, pady=(12, 2))
        if blurb:
            ctk.CTkLabel(card, text=blurb, font=theme.get("small"), anchor="w",
                         justify="left", wraplength=720,
                         text_color=theme.color("subtext")).grid(
                row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        return card

    def _behaviour(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Cleaning",
            "A dry run shows exactly what would be removed without touching "
            "anything. It is the default on purpose.")
        var = ctk.BooleanVar(value=bool(cfg.get("default_to_dry_run")))
        ctk.CTkCheckBox(
            card, text="Start every cleanup as a dry run", variable=var,
            font=theme.get("small"),
            command=lambda: cfg.set_value("default_to_dry_run", var.get())).grid(
            row=2, column=0, sticky="w", padx=16, pady=(0, 14))
        return row + 1

    def _rules(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Cleaning rules",
            "Every rule, what it removes, and whether it can be undone. What "
            "each rule is permitted to touch is fixed in code, not here.")
        disabled = set(cfg.get("disabled_rules") or [])

        for i, rule in enumerate(sorted(self.app.services.rules,
                                        key=lambda r: r.id), start=2):
            var = ctk.BooleanVar(value=rule.id not in disabled)
            reversible = "recoverable from the vault" if rule.reversible \
                else "permanent"
            ctk.CTkCheckBox(
                card, variable=var, font=theme.get("small"),
                text=f"{rule.name} — {rule.risk.label.lower()}, {reversible}",
                command=lambda r=rule.id, v=var: self._toggle_rule(r, v)).grid(
                row=i, column=0, sticky="w", padx=16, pady=2)
            ctk.CTkLabel(card, text=f"      {rule.description}",
                         font=theme.get("small"), anchor="w", justify="left",
                         wraplength=680,
                         text_color=theme.color("dim")).grid(
                row=i + 100, column=0, sticky="ew", padx=16, pady=(0, 6))
        return row + 1

    def _toggle_rule(self, rule_id: str, var) -> None:
        disabled = set(cfg.get("disabled_rules") or [])
        disabled.discard(rule_id) if var.get() else disabled.add(rule_id)
        cfg.set_value("disabled_rules", sorted(disabled))

    def _exclusions(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Exclusions",
            "Folders PolyScour must never touch, in addition to the protected "
            "locations below. Takes effect on restart.")

        current = list(cfg.get("exclusions") or [])
        self._exclusion_box = ctk.CTkTextbox(card, height=90,
                                             font=theme.get("code"))
        self._exclusion_box.grid(row=2, column=0, sticky="ew", padx=16, pady=4)
        self._exclusion_box.insert("1.0", "\n".join(current))

        ctk.CTkButton(card, text="Save exclusions", width=140,
                      command=self._save_exclusions).grid(
            row=3, column=0, sticky="w", padx=16, pady=(4, 14))
        return row + 1

    def _save_exclusions(self) -> None:
        raw = self._exclusion_box.get("1.0", "end").splitlines()
        paths = [str(Path(line.strip())) for line in raw if line.strip()]
        cfg.set_value("exclusions", paths)
        self.app.set_status(
            f"{len(paths)} exclusion{'s' if len(paths) != 1 else ''} saved; "
            f"restart PolyScour to apply.")

    def _protected(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Protected locations",
            "Built in, and not editable. PolyScour refuses to touch anything "
            "inside these, or anything that contains one — regardless of what "
            "any cleaning rule asks for.")
        text = "\n".join(str(p) for p in self.app.services.guard.protected_locations)
        box = ctk.CTkTextbox(card, height=140, font=theme.get("code"))
        box.grid(row=2, column=0, sticky="ew", padx=16, pady=(4, 14))
        box.insert("1.0", text)
        box.configure(state="disabled")
        return row + 1

    def _scheduled_cleaning(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Scheduled cleaning",
            "Runs a fixed, reviewed set of rules on its own — unelevated, "
            "and only while you are logged on. Consent happens once, here, "
            "when you create a schedule; there is no confirmation dialog at "
            "run time, and a rule whose definition changes afterward is "
            "skipped until you review the schedule again.")

        self._schedule_list = ctk.CTkFrame(card, fg_color="transparent")
        self._schedule_list.grid(row=2, column=0, sticky="ew",
                                 padx=16, pady=(0, 8))
        self._schedule_list.grid_columnconfigure(0, weight=1)

        add = ctk.CTkFrame(card, fg_color=theme.color("card2"),
                           corner_radius=6)
        add.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 14))
        add.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(add, text="Add a schedule", font=theme.get("body"),
                     text_color=theme.color("text"), anchor="w").grid(
            row=0, column=0, sticky="ew", padx=12, pady=(10, 4))

        eligible = consent.eligible_rule_ids()
        by_id = {r.id: r for r in self.app.services.rules}
        self._schedule_rule_vars: dict[str, ctk.BooleanVar] = {}
        if not eligible:
            ctk.CTkLabel(
                add, text="No rules are eligible — a rule that needs "
                         "administrator rights is never offered here.",
                font=theme.get("small"), anchor="w",
                text_color=theme.color("subtext")).grid(
                row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        for i, rule_id in enumerate(eligible, start=1):
            rule = by_id.get(rule_id)
            var = ctk.BooleanVar(value=False)
            self._schedule_rule_vars[rule_id] = var
            ctk.CTkCheckBox(add, text=rule.name if rule else rule_id,
                            variable=var, font=theme.get("small")).grid(
                row=i, column=0, sticky="w", padx=12, pady=1)

        controls_row = len(eligible) + 1
        controls = ctk.CTkFrame(add, fg_color="transparent")
        controls.grid(row=controls_row, column=0, sticky="ew",
                      padx=12, pady=(8, 4))

        self._schedule_frequency = ctk.StringVar(value="Daily")
        ctk.CTkOptionMenu(
            controls, values=["Daily", "Weekly"], width=100,
            variable=self._schedule_frequency,
            command=self._update_schedule_day_visibility).grid(
            row=0, column=0, padx=(0, 8))

        self._schedule_day = ctk.StringVar(value=consent.WEEKDAYS[0])
        self._schedule_day_menu = ctk.CTkOptionMenu(
            controls, values=list(consent.WEEKDAYS),
            variable=self._schedule_day, width=90)
        self._schedule_day_menu.grid(row=0, column=1, padx=(0, 8))
        self._schedule_day_menu.grid_remove()

        self._schedule_time = ctk.StringVar(value="03:00")
        ctk.CTkEntry(controls, textvariable=self._schedule_time, width=70,
                    placeholder_text="HH:MM").grid(row=0, column=2, padx=(0, 8))

        ctk.CTkButton(add, text="Create schedule", width=150,
                      command=self._create_schedule).grid(
            row=controls_row + 1, column=0, sticky="w", padx=12, pady=(4, 12))

        self._render_schedules()
        return row + 1

    def _update_schedule_day_visibility(self, _value: str = "") -> None:
        if self._schedule_frequency.get() == "Weekly":
            self._schedule_day_menu.grid()
        else:
            self._schedule_day_menu.grid_remove()

    def _render_schedules(self) -> None:
        if not hasattr(self, "_schedule_list"):
            return         # called from on_show before the section is built
        for child in self._schedule_list.winfo_children():
            child.destroy()

        schedules = sorted(store.load_all(), key=lambda s: s.created_at)
        if not schedules:
            ctk.CTkLabel(self._schedule_list, text="No schedules yet.",
                        font=theme.get("small"), anchor="w",
                        text_color=theme.color("subtext")).grid(
                row=0, column=0, sticky="w")
            return

        by_id = {r.id: r for r in self.app.services.rules}
        for i, sched in enumerate(schedules):
            row = ctk.CTkFrame(self._schedule_list, fg_color="transparent")
            row.grid(row=i, column=0, sticky="ew", pady=3)
            row.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(row, text=sched.describe(), font=theme.get("small"),
                        anchor="w", text_color=theme.color("text")).grid(
                row=0, column=0, sticky="ew")
            names = ", ".join(by_id[r].name if r in by_id else r
                              for r in sched.rule_ids)
            ctk.CTkLabel(row, text=names, font=theme.get("small"),
                        anchor="w", text_color=theme.color("dim")).grid(
                row=1, column=0, sticky="ew")

            var = ctk.BooleanVar(value=sched.enabled)
            ctk.CTkSwitch(
                row, text="", width=40, variable=var,
                command=lambda s=sched.id, v=var: self._toggle_schedule(s, v)
                ).grid(row=0, column=1, rowspan=2, padx=8)
            ctk.CTkButton(
                row, text="Remove", width=80, height=24,
                fg_color=theme.color("card2"),
                command=lambda s=sched.id: self._remove_schedule(s)
                ).grid(row=0, column=2, rowspan=2, padx=(0, 4))

    def _create_schedule(self) -> None:
        chosen = [rule_id for rule_id, var in self._schedule_rule_vars.items()
                 if var.get()]
        if not chosen:
            self.app.set_status("Choose at least one rule to schedule.")
            return

        time_text = self._schedule_time.get().strip()
        if not _valid_time(time_text):
            self.app.set_status("Enter a time as HH:MM, 24-hour.")
            return

        weekly = self._schedule_frequency.get() == "Weekly"
        trigger = consent.Trigger(
            frequency=consent.Frequency.WEEKLY if weekly
            else consent.Frequency.DAILY,
            time=time_text, day_of_week=self._schedule_day.get() if weekly else None)

        if not self._confirm_create_schedule(chosen, trigger):
            return

        try:
            service.create_schedule(chosen, trigger)
        except service.ScheduleRefused as exc:
            self.app.set_status(f"Could not create the schedule: {exc}")
            return

        for var in self._schedule_rule_vars.values():
            var.set(False)
        self._render_schedules()
        self.app.set_status("Schedule created.")

    def _confirm_create_schedule(self, rule_ids: list[str], trigger) -> bool:
        """The consent envelope, spelled out, before anything is created."""
        by_id = {r.id: r for r in self.app.services.rules}
        names = [by_id[r].name if r in by_id else r for r in rule_ids]
        n = len(rule_ids)
        lines = [
            f"This schedule is permitted to perform these {n} cleaning "
            f"operation{'s' if n != 1 else ''} and nothing else, "
            f"{trigger.describe().lower()}, unelevated, only while you are "
            f"logged on:",
        ]
        lines += [f"  • {name}" for name in names]
        lines.append("\nA rule whose definition changes afterward is "
                     "skipped until this schedule is reviewed again.")
        dialog = ctk.CTkInputDialog(
            title="Create schedule",
            text="\n".join(lines) + "\n\nType CREATE to confirm:")
        return (dialog.get_input() or "").strip().upper() == "CREATE"

    def _toggle_schedule(self, schedule_id: str, var) -> None:
        try:
            service.set_enabled(schedule_id, var.get())
        except service.ScheduleRefused as exc:
            self.app.set_status(str(exc))
        self._render_schedules()

    def _remove_schedule(self, schedule_id: str) -> None:
        result = service.remove_schedule(schedule_id)
        if not result.ok:
            self.app.set_status(f"Could not remove the schedule: {result.detail}")
        self._render_schedules()

    def _storage_history(self, parent, row: int) -> int:
        card = self._section(
            parent, row, "Saved Storage scans",
            f"The Storage screen keeps its last {DEFAULT_KEEP_PER_VOLUME} completed "
            f"scans of each volume so it can say what changed since the last one. "
            f"They hold the paths and sizes of your largest folders and files, on "
            f"this machine only. Clearing them changes nothing else: the next scan "
            f"simply has no earlier one to compare with, and says so.")
        self._history_label = ctk.CTkLabel(
            card, text="", font=theme.get("small"), anchor="w",
            text_color=theme.color("subtext"))
        self._history_label.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 6))
        self._clear_history_button = ctk.CTkButton(
            card, text="Clear saved scans", width=160,
            command=self._clear_history)
        self._clear_history_button.grid(row=3, column=0, sticky="w",
                                        padx=16, pady=(0, 14))
        self._refresh_history()
        return row + 1

    def _refresh_history(self) -> None:
        try:
            s = self.app.services.storage_history.summary()
        except Exception as exc:                       # noqa: BLE001
            # Unreadable is not empty, and must not read as "nothing saved".
            self._history_label.configure(
                text=f"Saved scans could not be read: {exc}")
            self._clear_history_button.configure(state="normal")
            return
        if s.scans == 0:
            self._history_label.configure(text="No saved scans.")
            self._clear_history_button.configure(state="disabled")
            return
        self._history_label.configure(
            text=(f"{s.scans:,} saved scan{'s' if s.scans != 1 else ''} of "
                  f"{s.volumes:,} volume{'s' if s.volumes != 1 else ''}  ·  "
                  f"{human(s.file_bytes)} on disk"))
        self._clear_history_button.configure(state="normal")

    def _confirm_clear_history(self) -> bool:
        """The dialog, behind a seam so tests never open a real one."""
        from tkinter import messagebox
        return messagebox.askyesno(
            "Clear saved scans",
            "Delete every saved Storage scan?\n\nThey cannot be recovered. "
            "Nothing else is affected: the next scan will just have no earlier "
            "one to compare with.", icon="warning")

    def _clear_history(self) -> None:
        if not self._confirm_clear_history():
            return
        try:
            removed = self.app.services.storage_history.clear()
        except Exception as exc:                       # noqa: BLE001
            self.app.set_status(f"Could not clear saved scans: {exc}")
        else:
            self.app.set_status(f"{removed:,} saved scan{'s' if removed != 1 else ''} cleared.")
        self._refresh_history()

    def _privacy(self, parent, row: int) -> int:
        self._section(
            parent, row, "Privacy",
            "PolyScour has no telemetry, sends nothing anywhere, and needs no "
            "account. It reads your machine to do its job and keeps what it "
            f"learns on your machine. {len(POLICY)} cleaning rules are defined, "
            "and each one's permitted locations are fixed in the source.")
        return row + 1
