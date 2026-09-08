r"""Where the disk actually went — and, just as prominently, where we could not look.

This screen has **no action controls at all**. No Delete, no Clean, no Remove,
no Optimise, and no per-row button of any kind. That is the point rather than an
omission: sorting directories by size is a fact worth showing, and a button
beside it would turn that fact into a recommendation. `CLAUDE.md`'s first
invariant, applied to the one feature most tempting to violate it — every
competitor's storage screen ends in a delete button.

The residual gets the same visual weight as the total, because *"your 500 GB
drive holds 380 GB of files"* with 120 GB unexplained is the
"63 devices not reporting OK" failure wearing a different hat.
"""
from __future__ import annotations

import threading

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.storage import volumes
from polyscour.storage.analyser import (StopReason, StorageScanRequest, analyse)
from polyscour.views.dashboard_view import human

_STOP_TEXT = {
    StopReason.COMPLETED: ("Complete", "#7ec699"),
    StopReason.BUDGET_EXHAUSTED: ("Stopped at the size budget", "#e0af68"),
    StopReason.TIME_EXHAUSTED: ("Stopped at the time budget", "#e0af68"),
    StopReason.CANCELLED: ("Cancelled", "#888899"),
    StopReason.ERROR: ("Stopped by an error", "#f7768e"),
}


class StorageView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._cancel: threading.Event | None = None
        self._report = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self, text="Storage", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w").grid(
            row=0, column=0, sticky="ew", padx=20, pady=(20, 2))
        ctk.CTkLabel(
            self,
            text=("What is using the disk. This screen only measures — it "
                  "cannot change anything, and offers nothing to click that "
                  "would."),
            font=theme.get("small"), text_color=theme.color("subtext"),
            anchor="w", justify="left", wraplength=760).grid(
            row=1, column=0, sticky="ew", padx=20, pady=(0, 12))

        self._controls = ctk.CTkFrame(self, fg_color="transparent")
        self._controls.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))

        self._body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._body.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self._body.grid_columnconfigure(0, weight=1)

        self._build_controls()

    # ── chrome ───────────────────────────────────────────────────────────────

    def _build_controls(self) -> None:
        found = volumes.fixed_volumes()
        self._volumes = {v.label: v for v in found}

        if not found:
            ctk.CTkLabel(self._controls,
                         text="No fixed volumes could be enumerated.",
                         font=theme.get("body"),
                         text_color=theme.color("subtext")).grid(row=0, column=0)
            return

        ctk.CTkLabel(self._controls, text="Volume", font=theme.get("small"),
                     text_color=theme.color("subtext")).grid(row=0, column=0,
                                                             padx=(0, 8))
        self._choice = ctk.CTkOptionMenu(
            self._controls, values=[v.label for v in found], width=90)
        self._choice.grid(row=0, column=1, padx=(0, 12))

        self._scan_button = ctk.CTkButton(self._controls, text="Scan",
                                          width=110, command=self._start)
        self._scan_button.grid(row=0, column=2)

        self._status = ctk.CTkLabel(self._controls, text="", anchor="w",
                                    font=theme.get("small"),
                                    text_color=theme.color("subtext"))
        self._status.grid(row=0, column=3, sticky="ew", padx=12)
        self._controls.grid_columnconfigure(3, weight=1)

        self._render_idle()

    def on_show(self) -> None:
        if self._report is None and getattr(self, "_volumes", None):
            self._render_idle()

    # ── scanning ─────────────────────────────────────────────────────────────

    def _start(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            return

        volume = self._volumes[self._choice.get()]
        self._cancel = threading.Event()
        self._scan_button.configure(text="Cancel")
        self._status.configure(text=f"Scanning {volume.label} …")
        self._clear()

        request = StorageScanRequest(volume=volume)
        cancel = self._cancel
        self.app.run_off_thread(lambda: analyse(request, cancel), self._done)

    def _done(self, report, error) -> None:
        self._cancel = None
        self._scan_button.configure(text="Scan")
        if error is not None:
            self._status.configure(text=f"Scan failed: {error}")
            return
        self._report = report
        self._status.configure(text="")
        self._render(report)

    # ── rendering ────────────────────────────────────────────────────────────

    def _clear(self) -> None:
        for child in self._body.winfo_children():
            child.destroy()

    def _render_idle(self) -> None:
        self._clear()
        for i, volume in enumerate(self._volumes.values()):
            row = ctk.CTkFrame(self._body, fg_color=theme.color("card"),
                               corner_radius=8)
            row.grid(row=i, column=0, sticky="ew", pady=4, padx=4)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=volume.label, font=theme.get("section_title"),
                         text_color=theme.color("text"), width=46,
                         anchor="w").grid(row=0, column=0, padx=(16, 8), pady=12)
            ctk.CTkLabel(
                row,
                text=(f"{human(volume.used_bytes)} used of "
                      f"{human(volume.total_bytes)}  ·  "
                      f"{human(volume.free_bytes)} free  ·  {volume.fstype}"),
                font=theme.get("body"), text_color=theme.color("subtext"),
                anchor="w").grid(row=0, column=1, sticky="ew", pady=12)

    def _section(self, parent, row: int, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=theme.color("card"),
                             corner_radius=8)
        frame.grid(row=row, column=0, sticky="ew", pady=6, padx=4)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=title, font=theme.get("section_title"),
                     text_color=theme.color("subtext"), anchor="w").grid(
            row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        return frame

    def _bars(self, frame, rows, total: int, start_row: int) -> None:
        """Name, size, and a proportional bar. No button on any row."""
        for i, (label, size) in enumerate(rows, start=start_row):
            line = ctk.CTkFrame(frame, fg_color="transparent")
            line.grid(row=i, column=0, sticky="ew", padx=16, pady=1)
            line.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(line, text=label, font=theme.get("body"), width=250,
                         anchor="w", text_color=theme.color("text")).grid(
                row=0, column=0, sticky="w")
            bar = ctk.CTkProgressBar(line, height=8)
            bar.set((size / total) if total else 0)
            bar.grid(row=0, column=1, sticky="ew", padx=10)
            ctk.CTkLabel(line, text=human(size), font=theme.get("small"),
                         width=90, anchor="e",
                         text_color=theme.color("subtext")).grid(row=0, column=2)

    def _render(self, report) -> None:
        self._clear()
        row = 0

        # ── the summary, with the residual beside the total rather than under it
        summary = self._section(self._body, row, f"{report.volume.label} — measured")
        row += 1
        text, colour = _STOP_TEXT[report.stop_reason]
        ctk.CTkLabel(
            summary,
            text=(f"{human(report.measured_bytes)} accounted for  ·  "
                  f"{human(report.residual_bytes)} not"),
            font=theme.get("heading"), text_color=theme.color("text"),
            anchor="w").grid(row=1, column=0, sticky="ew", padx=16)
        ctk.CTkLabel(
            summary,
            text=(f"{text} — {report.entries_examined:,} items in "
                  f"{report.elapsed_seconds:.0f}s"),
            font=theme.get("small"), text_color=colour, anchor="w").grid(
            row=2, column=0, sticky="ew", padx=16, pady=(2, 12))

        # ── what we could not see. Deliberately above the tree.
        residual = self._section(self._body, row,
                                 "What this scan could not account for")
        row += 1
        breakdown = report.residual_breakdown()
        if breakdown:
            self._bars(residual, [(r.label, b) for r, b in breakdown],
                       report.residual_bytes, 1)
        notes = []
        if report.permission_denied_directories:
            notes.append(f"{report.permission_denied_directories:,} directories "
                         f"could not be opened, so their size is unknown rather "
                         f"than zero")
        if report.reparse_points_skipped:
            notes.append(f"{report.reparse_points_skipped:,} junctions were not "
                         f"followed — their contents are counted where they "
                         f"really live, not missing")
        if report.hardlinks_deduplicated:
            notes.append(f"{report.hardlinks_deduplicated:,} files share storage "
                         f"with another name and were counted once "
                         f"({human(report.hardlink_bytes_saved)} not "
                         f"double-counted)")
        if abs(report.volume_drift_bytes) > 64 * 1024 * 1024:
            notes.append(f"the volume's usage moved by "
                         f"{human(abs(report.volume_drift_bytes))} while this "
                         f"ran, so the two figures will not reconcile exactly")
        notes.append("This is a limit of the scan, not a fault on the machine. "
                     "Windows manages some of a disk in ways no ordinary "
                     "program can see.")
        ctk.CTkLabel(residual, text="\n".join(f"·  {n}" for n in notes),
                     font=theme.get("small"), text_color=theme.color("subtext"),
                     anchor="w", justify="left", wraplength=720).grid(
            row=90, column=0, sticky="ew", padx=16, pady=(8, 12))

        # ── the three read-only views
        largest = self._section(self._body, row, "Largest folders")
        row += 1
        children = report.root.largest_children(12)
        self._bars(largest, [(c.name, c.allocated_bytes) for c in children],
                   report.measured_bytes, 1)
        ctk.CTkLabel(largest, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                    pady=(0, 8))

        files = self._section(self._body, row, "Largest files")
        row += 1
        self._bars(files, [(f.path.name, f.allocated_bytes)
                           for f in report.largest_files[:12]],
                   report.measured_bytes, 1)
        ctk.CTkLabel(files, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                  pady=(0, 8))

        by_ext = sorted(report.by_extension.items(), key=lambda kv: kv[1],
                        reverse=True)[:12]
        if by_ext:
            ext = self._section(self._body, row, "By file type")
            row += 1
            self._bars(ext, by_ext, report.measured_bytes, 1)
            ctk.CTkLabel(ext, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                     pady=(0, 8))
