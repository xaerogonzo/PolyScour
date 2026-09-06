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

from polyscour.safety.policy import POLICY


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
        self._privacy(body, row)

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

    def _privacy(self, parent, row: int) -> int:
        self._section(
            parent, row, "Privacy",
            "PolyScour has no telemetry, sends nothing anywhere, and needs no "
            "account. It reads your machine to do its job and keeps what it "
            f"learns on your machine. {len(POLICY)} cleaning rules are defined, "
            "and each one's permitted locations are fixed in the source.")
        return row + 1
