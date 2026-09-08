r"""Scan, review, confirm, clean, verify.

The whole point of the product is in this order. The user sees what was found
and why *before* anything is offered, and what will happen before it happens.

Findings are presented **grouped by rule**, not one row per file. A real machine
produced 36,194 findings on the first live run; one row each is unusable for a
person, and it is not the decision they are actually making -- nobody chooses
whether to delete ``f_00a3c1``, they choose whether to clear the Chrome cache.
(It also crashed Tk outright with "row out of bounds", which is how the design
error announced itself.)

Nothing above SAFE is pre-ticked. A user who clicks straight through gets the
conservative action, which is the correct default for software that deletes
things.
"""
from __future__ import annotations

import threading
from collections import OrderedDict

import customtkinter as ctk
from polybedrock import settings as cfg
from polybedrock.ui import theme

from polyscour.cleaning import planner
from polyscour.cleaning.executor import Executor
from polyscour.contracts import RiskLevel, SkipReason
from polyscour.views.dashboard_view import human

_RISK_COLOUR = {
    RiskLevel.SAFE: "#7ec699",
    RiskLevel.LOW: "#9ccfd8",
    RiskLevel.MODERATE: "#e0af68",
    RiskLevel.HIGH: "#f7768e",
    RiskLevel.CRITICAL: "#ff5555",
}


def _by_reason(result, reason) -> list:
    if result is None:
        return []
    return [s for s in result.skips if s.reason is reason]


def _describe(result) -> list[str]:
    """The result, with each kind of skip named separately.

    "in use or need administrator rights" was one sentence covering two facts,
    only one of which a user can do anything about. Merging them made the
    actionable half invisible.
    """
    lines = [result.summary()]

    if result.hard_failures:
        names = sorted({s.path.name for s in result.hard_failures if s.path.name})
        lines.append(f"{len(result.hard_failures)} failed unexpectedly"
                     + (": " + ", ".join(names[:5]) if names else "."))

    locked = _by_reason(result, SkipReason.LOCKED)
    if locked:
        lines.append(f"{len(locked):,} were in use by another program and were "
                     f"left alone.")

    blocked = _by_reason(result, SkipReason.PERMISSION)
    if blocked:
        lines.append(f"{len(blocked):,} need administrator rights.")

    vanished = _by_reason(result, SkipReason.VANISHED)
    if vanished:
        lines.append(f"{len(vanished):,} were already gone.")

    if result.elevation.requested:
        lines.append(result.elevation.describe())

    return lines


class CleanView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._cancel = threading.Event()
        self._result = None
        self._groups: list[tuple] = []      # (checkbox var, rule_id, findings)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 8))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="Clean", font=theme.get("heading"),
                     text_color=theme.color("text")).grid(row=0, column=0,
                                                          sticky="w")

        self.scan_btn = ctk.CTkButton(header, text="Scan", width=110,
                                      command=self._scan)
        self.scan_btn.grid(row=0, column=2, padx=4)
        self.cancel_btn = ctk.CTkButton(header, text="Cancel", width=90,
                                        fg_color="transparent", border_width=1,
                                        text_color=theme.color("text"),
                                        state="disabled", command=self._cancel_now)
        self.cancel_btn.grid(row=0, column=3, padx=4)

        self.summary = ctk.CTkLabel(
            self, text="Nothing scanned yet.", font=theme.get("small"),
            anchor="w", justify="left", wraplength=800,
            text_color=theme.color("subtext"))
        self.summary.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 8))

        self.list = ctk.CTkScrollableFrame(self, fg_color=theme.color("card2"))
        self.list.grid(row=2, column=0, sticky="nsew", padx=20, pady=4)
        self.list.grid_columnconfigure(0, weight=1)

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", padx=20, pady=(8, 20))
        footer.grid_columnconfigure(0, weight=1)

        self.selection = ctk.CTkLabel(footer, text="", font=theme.get("small"),
                                      anchor="w",
                                      text_color=theme.color("subtext"))
        self.selection.grid(row=0, column=0, sticky="w")

        self.dry_run = ctk.BooleanVar(value=bool(cfg.get("default_to_dry_run")))
        ctk.CTkCheckBox(footer, text="Dry run (change nothing)",
                        variable=self.dry_run, font=theme.get("small"),
                        text_color=theme.color("text"),
                        command=self._update_selection).grid(row=0, column=1,
                                                             padx=12)

        self.clean_btn = ctk.CTkButton(footer, text="Preview", width=150,
                                       state="disabled", command=self._clean)
        self.clean_btn.grid(row=0, column=2)

        # Hidden until a run actually produces something administrator rights
        # would fix. Never a standing offer: a button that is always there is
        # an invitation to elevate speculatively.
        self.retry_btn = ctk.CTkButton(footer, text="", width=220,
                                       fg_color=theme.color("card2"),
                                       command=self._retry_elevated)
        self.retry_btn.grid(row=0, column=3, padx=(8, 0))
        self.retry_btn.grid_remove()
        self._retry_rules: list[str] = []
        self._last_result = None
        self._plan = None

    # ── scanning ─────────────────────────────────────────────────────────────

    def _scan(self) -> None:
        self._cancel = threading.Event()
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.clean_btn.configure(state="disabled")
        self._clear()
        self.summary.configure(text="Scanning…")
        self.app.set_status("Scanning")

        rules = self.app.services.enabled_rules()
        self.app.run_off_thread(
            lambda: self.app.services.scanner.scan(
                rules, self._cancel, on_progress=self._progress),
            self._scanned)

    def _progress(self, rule_id: str, walked: int) -> None:
        """Called from the scanning thread; Tk is touched only on its own."""
        text = (f"Scanning {rule_id}…" if not walked
                else f"Scanning {rule_id} — {walked:,} files examined")
        self.app.after(0, lambda t=text: self.app.set_status(t))

    def _scanned(self, result, error) -> None:
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        if error is not None:
            self.summary.configure(text=f"The scan could not finish: {error}")
            self.app.set_status("Scan failed")
            return

        self._result = result
        self._render(result)
        self.app.set_status("Ready")

    def _cancel_now(self) -> None:
        self._cancel.set()
        self.app.set_status("Cancelling")

    # ── rendering ────────────────────────────────────────────────────────────

    def _clear(self) -> None:
        for child in self.list.winfo_children():
            child.destroy()
        self._groups.clear()

    def _render(self, result) -> None:
        self._clear()

        bits = [f"{human(result.total_bytes)} across "
                f"{len(result.findings):,} items"]
        by_risk = result.bytes_by_risk()
        for risk in sorted(by_risk, reverse=True):
            bits.append(f"{risk.label.lower()} {human(by_risk[risk])}")
        text = " · ".join(bits) if result.findings else "Nothing found to clean."
        if result.cancelled:
            text += "\nScan cancelled; results are partial."
        self.summary.configure(text=text)

        # Group by rule. Recommendations are per finding, but every finding from
        # one rule shares its risk and reversibility, so the first speaks for all.
        groups: OrderedDict[str, list] = OrderedDict()
        for rec in planner.recommend(result):
            groups.setdefault(rec.finding.rule_id, []).append(rec)

        row = 0
        for rule_id, recs in groups.items():
            self._add_group(row, rule_id, recs)
            row += 1

        # A rule that refused to run is reported, never quietly dropped.
        for outcome in result.aborted_rules:
            self._add_note(row, outcome.rule_id, outcome.abort_reason)
            row += 1

        self._update_selection()

    def _add_group(self, row: int, rule_id: str, recs: list) -> None:
        first = recs[0].finding
        findings = [r.finding for r in recs]
        total = sum(f.size_bytes for f in findings)

        frame = ctk.CTkFrame(self.list, fg_color="transparent")
        frame.grid(row=row, column=0, sticky="ew", pady=2)
        frame.grid_columnconfigure(1, weight=1)

        var = ctk.BooleanVar(value=recs[0].recommended)
        ctk.CTkCheckBox(frame, text="", width=24, variable=var,
                        command=self._update_selection).grid(
            row=0, column=0, rowspan=2, padx=(8, 6))

        ctk.CTkLabel(frame, text=first.title, font=theme.get("item_title"),
                     text_color=theme.color("text"), anchor="w").grid(
            row=0, column=1, sticky="ew")
        ctk.CTkLabel(frame, text=f"{len(findings):,} items · {human(total)}",
                     font=theme.get("small"), anchor="e", width=170,
                     text_color=theme.color("subtext")).grid(row=0, column=2,
                                                             padx=8)
        ctk.CTkLabel(frame, text=first.risk.label, font=theme.get("small"),
                     text_color=_RISK_COLOUR[first.risk], anchor="e",
                     width=70).grid(row=0, column=3, padx=(0, 8))

        # Why it was found, whether it comes back, and whether we suggest it --
        # all three answered on the row, without a click.
        why = (f"{first.evidence.rationale}  ·  {first.rollback_label}  ·  "
               f"{recs[0].reason}")
        ctk.CTkLabel(frame, text=why, font=theme.get("small"), anchor="w",
                     justify="left", wraplength=700,
                     text_color=theme.color("subtext")).grid(
            row=1, column=1, columnspan=3, sticky="ew", pady=(0, 6))

        self._groups.append((var, rule_id, findings))

    def _add_note(self, row: int, rule_id: str, reason: str) -> None:
        frame = ctk.CTkFrame(self.list, fg_color="transparent")
        frame.grid(row=row, column=0, sticky="ew", pady=2)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=f"{rule_id} — not scanned: {reason}",
                     font=theme.get("small"), anchor="w", justify="left",
                     wraplength=760, text_color=theme.color("dim")).grid(
            row=0, column=0, sticky="ew", padx=(38, 8), pady=4)

    # ── selection and execution ──────────────────────────────────────────────

    def _selected(self):
        return [f for var, _, findings in self._groups if var.get()
                for f in findings]

    def _update_selection(self) -> None:
        selected = self._selected()
        self.clean_btn.configure(state="normal" if selected else "disabled",
                                 text="Preview" if self.dry_run.get()
                                 else "Clean selected")
        self.selection.configure(
            text=planner.summarise(planner.plan(selected, self.dry_run.get())))

    def _clean(self) -> None:
        selected = self._selected()
        if not selected:
            return
        plan = planner.plan(selected, dry_run=self.dry_run.get())

        if not plan.dry_run and not self._confirm(plan):
            return

        # Kept so an administrator retry re-runs the plan the user approved,
        # rather than re-deriving one from a selection that may have changed.
        self._plan = plan

        self.clean_btn.configure(state="disabled")
        self.retry_btn.grid_remove()
        self.app.set_status("Previewing" if plan.dry_run else "Cleaning")
        self.app.run_off_thread(
            lambda: self.app.services.executor.execute(plan), self._cleaned)

    def _confirm(self, plan) -> bool:
        """The last stop. Says what will happen, including what cannot be undone."""
        permanent = len(plan.findings) - plan.reversible_count
        lines = [planner.summarise(plan)]
        if permanent:
            lines.append(f"\n{permanent:,} of these cannot be recovered "
                         f"afterwards.")
        if plan.reversible_count:
            lines.append(f"{plan.reversible_count:,} will be moved to the vault "
                         f"and can be restored from History.")

        dialog = ctk.CTkInputDialog(
            title="Confirm cleanup",
            text="\n".join(lines) + "\n\nType CLEAN to confirm:")
        return (dialog.get_input() or "").strip().upper() == "CLEAN"

    def _cleaned(self, result, error) -> None:
        self.clean_btn.configure(state="normal")
        if error is not None:
            self.summary.configure(text=f"The cleanup could not finish: {error}")
            self.app.set_status("Cleanup failed")
            return

        self._last_result = result
        self.summary.configure(text="\n".join(_describe(result)))
        self.app.set_status(result.outcome.value.replace("_", " ").capitalize())
        self._offer_elevation(result)

        if not result.dry_run:
            self._scan()          # verify by re-scanning rather than by assuming

    # ── the administrator offer ──────────────────────────────────────────────

    def _offer_elevation(self, result) -> None:
        """Offer a retry for the items administrator rights would actually fix.

        Deliberately *after* a run and never before one. There is no pre-flight
        checkbox, no Settings key, and no way to arrive at a UAC prompt without
        having first seen what it is for — docs/THREAT_MODEL.md T18, where the
        specific consent lives in this screen because the prompt itself only
        names PolyScour.

        Only permission failures are offered. A locked file is in use, and
        administrator rights do not open it; offering to elevate for one would
        spend a prompt to achieve nothing.
        """
        self.retry_btn.grid_remove()
        if result.dry_run:
            return

        blocked = _by_reason(result, SkipReason.PERMISSION)
        if not blocked:
            return

        rules = sorted({s.rule_id for s in blocked if s.rule_id})
        self._retry_rules = rules
        self.retry_btn.configure(
            text=f"Retry {len(blocked):,} as administrator")
        self.retry_btn.grid()

    def _retry_elevated(self) -> None:
        plan = self._plan
        if plan is None:
            return
        if not self._confirm_elevation():
            return

        self.retry_btn.grid_remove()
        self.clean_btn.configure(state="disabled")
        self.app.set_status("Waiting for administrator rights")

        # A fresh Executor rather than the shared one: allow_elevation is
        # run-scoped and consented, so it must not outlive this click. An
        # Executor that kept the flag would be able to raise a prompt on some
        # later run the user never agreed to.
        executor = Executor(vault=self.app.services.vault,
                            ledger=self.app.services.ledger,
                            guard=self.app.services.guard,
                            allow_elevation=True)
        self.app.run_off_thread(lambda: executor.execute(plan), self._cleaned)

    def _confirm_elevation(self) -> bool:
        """Say what will be retried, what will not, and which mechanism."""
        blocked = _by_reason(self._last_result, SkipReason.PERMISSION)
        others = [s for s in self._last_result.skips
                  if s.reason is not SkipReason.PERMISSION]

        lines = [f"{len(blocked):,} items need administrator rights and will "
                 f"be retried:"]
        for rule_id in self._retry_rules:
            count = sum(1 for s in blocked if s.rule_id == rule_id)
            lines.append(f"  • {rule_id} — {count:,} items")
        if others:
            # Naming what will NOT be retried is the same discipline as
            # refusing invented numbers: the honest figure is the one the
            # action actually covers, not the total that was skipped.
            lines.append(f"\n{len(others):,} other items were skipped for "
                         f"reasons administrator rights do not fix (in use, "
                         f"or already gone) and will not be retried.")
        lines.append("\nWindows will ask you to confirm, once per rule.")

        dialog = ctk.CTkInputDialog(
            title="Retry as administrator",
            text="\n".join(lines) + "\n\nType ADMIN to confirm:")
        return (dialog.get_input() or "").strip().upper() == "ADMIN"
