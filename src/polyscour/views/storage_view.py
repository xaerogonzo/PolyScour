r"""Where the disk actually went — and, just as prominently, where we could not look.

This screen has **no control that acts on a finding**. No Delete, no Clean, no
Remove, no Optimise, and no per-row button of any kind. That is the point rather
than an omission: sorting directories by size is a fact worth showing, and a
button beside it would turn that fact into a recommendation. `CLAUDE.md`'s first
invariant, applied to the one feature most tempting to violate it — every
competitor's storage screen ends in a delete button.

There are two controls beside the scan, and they act on the *report*, not on any
folder in it: copy it, or save it to a file the person chooses. That is what
"changes nothing" always meant; it was worded more broadly than the rule, and
`docs/adr/0008` records the narrowing. The screen also keeps a local history of
its own scans, so it can say what changed since the last one.

The residual gets the same visual weight as the total, because *"your 500 GB
drive holds 380 GB of files"* with 120 GB unexplained is the
"63 devices not reporting OK" failure wearing a different hat.
"""
from __future__ import annotations

import threading
from pathlib import Path

import customtkinter as ctk
from polybedrock.ui import theme

from polyscour.formatting import human
from polyscour.storage import report as storage_report
from polyscour.storage import volumes
from polyscour.storage.analyser import (StopReason, StorageScanRequest, analyse)
from polyscour.storage.review import review_scan

#: Colour only. The wording is ``storage.report.STOP_LABEL``, shared with the
#: export so the two cannot describe a scan differently.
_STOP_COLOUR = {
    StopReason.COMPLETED: "#7ec699",
    StopReason.BUDGET_EXHAUSTED: "#e0af68",
    StopReason.TIME_EXHAUSTED: "#e0af68",
    StopReason.CANCELLED: "#888899",
    StopReason.ERROR: "#f7768e",
}

#: Width of the path column in the change rows, in characters.
_PATH_CHARS = 36


def _shorten(path: str, limit: int = _PATH_CHARS) -> str:
    """``C:\\…\\tail`` -- the drive and the end, which is what identifies a folder."""
    if len(path) <= limit:
        return path
    return f"{path[:3]}…{path[-(limit - 4):]}"


class StorageView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._cancel: threading.Event | None = None
        self._report = None
        self._review = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self, text="Storage", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w").grid(
            row=0, column=0, sticky="ew", padx=20, pady=(20, 2))
        ctk.CTkLabel(
            self,
            text=("What is using the disk. This screen measures. It never "
                  "deletes, moves or modifies anything on your disk or in "
                  "Windows. It keeps a local history of its own scans, and "
                  "Copy or Save writes the report only where you choose."),
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

        # These act on the report -- copy it, or save it where the person
        # chooses -- and on no folder in it. Disabled until a scan exists.
        self._copy_button = ctk.CTkButton(
            self._controls, text="Copy report", width=110, state="disabled",
            fg_color=theme.color("input_hover"), command=self._copy)
        self._copy_button.grid(row=0, column=4, padx=(0, 6))
        self._save_button = ctk.CTkButton(
            self._controls, text="Save report…", width=120, state="disabled",
            fg_color=theme.color("input_hover"), command=self._save)
        self._save_button.grid(row=0, column=5)

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
        store = self.app.services.storage_history
        self._set_export_enabled(False)

        def work():
            # All of it off the UI thread: building a snapshot walks the whole
            # tree, and the store is a disk read and write.
            report = analyse(request, cancel)
            return report, review_scan(report, store)

        self.app.run_off_thread(work, self._done)

    def _done(self, outcome, error) -> None:
        self._cancel = None
        self._scan_button.configure(text="Scan")
        if error is not None:
            self._status.configure(text=f"Scan failed: {error}")
            return
        report, review = outcome
        self._report, self._review = report, review
        self._status.configure(text="")
        self._set_export_enabled(True)
        self._render(report, review)

    # ── export ───────────────────────────────────────────────────────────────

    def _set_export_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self._copy_button.configure(state=state)
        self._save_button.configure(state=state)

    def _text(self) -> str | None:
        if self._report is None:
            return None
        return storage_report.render_text(self._report, self._review)

    def _copy(self) -> None:
        text = self._text()
        if text is None:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status.configure(text="Report copied. It contains folder and file "
                                    "names from this computer.")

    def _choose_path(self, default_name: str) -> str | None:
        """The save dialog, behind a seam so tests never open a real one."""
        from tkinter import filedialog
        return filedialog.asksaveasfilename(
            title="Save storage report", defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")]) or None

    def _save(self) -> None:
        text = self._text()
        if text is None:
            return
        stamp = (self._report.finished_at or self._report.started_at)
        name = (f"polyscour-storage-{self._report.volume.label.rstrip(':')}-"
                f"{stamp.astimezone():%Y%m%d}.txt")
        chosen = self._choose_path(name)
        if not chosen:
            return
        try:
            Path(chosen).write_text(text, encoding="utf-8")
        except OSError as exc:
            self._status.configure(text=f"Could not save the report: {exc}")
            return
        self._status.configure(text=f"Saved to {chosen}")

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

    def _change_rows(self, frame, rows, start_row: int) -> int:
        """Movement rows: path, a bar for its size, and the signed figure.

        ``at least`` rides in the figure's own text, so a bound cannot be read
        as a measurement. The bar is magnitude only: growth is a fact, not an
        alarm, so it is not coloured as one. No button on any row.
        """
        biggest = max((abs(r.delta) for r in rows), default=0)
        for i, r in enumerate(rows, start=start_row):
            line = ctk.CTkFrame(frame, fg_color="transparent")
            line.grid(row=i, column=0, sticky="ew", padx=16, pady=1)
            line.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(line, text=_shorten(r.label), font=theme.get("body"),
                         width=280, anchor="w",
                         text_color=theme.color("text")).grid(
                row=0, column=0, sticky="w")
            bar = ctk.CTkProgressBar(line, height=8)
            bar.set(abs(r.delta) / biggest if biggest else 0)
            bar.grid(row=0, column=1, sticky="ew", padx=10)
            ctk.CTkLabel(line, text=r.size_text, font=theme.get("small"),
                         width=150, anchor="e",
                         text_color=theme.color("subtext")).grid(row=0, column=2)
        return start_row + len(rows)

    def _history_section(self, row: int, review) -> None:
        """What changed since the last scan -- or, plainly, that there is no last scan."""
        s = storage_report.summarise(review)
        card = self._section(self._body, row, s.title)
        r = 1
        if s.headline:
            ctk.CTkLabel(card, text=s.headline, font=theme.get("heading"),
                         text_color=theme.color("text"), anchor="w").grid(
                row=r, column=0, sticky="ew", padx=16)
            r += 1
        for text in (s.detail, s.attribution):
            if text:
                ctk.CTkLabel(card, text=text, font=theme.get("small"),
                             text_color=theme.color("subtext"), anchor="w",
                             justify="left", wraplength=720).grid(
                    row=r, column=0, sticky="ew", padx=16, pady=(2, 0))
                r += 1
        for heading, rows in (("Folders", s.folders), ("Files", s.files),
                              ("File types", s.extensions)):
            if rows:
                ctk.CTkLabel(card, text=heading, font=theme.get("small"),
                             text_color=theme.color("subtext"), anchor="w").grid(
                    row=r, column=0, sticky="ew", padx=16, pady=(10, 2))
                r = self._change_rows(card, rows, r + 1)
        if s.notes:
            ctk.CTkLabel(card, text="\n".join(f"·  {n}" for n in s.notes),
                         font=theme.get("small"), text_color=theme.color("subtext"),
                         anchor="w", justify="left", wraplength=720).grid(
                row=r, column=0, sticky="ew", padx=16, pady=(8, 0))
            r += 1
        ctk.CTkLabel(card, text="", font=theme.get("small")).grid(
            row=r, column=0, pady=(0, 6))

    def _render(self, report, review=None) -> None:
        self._clear()
        row = 0

        # ── the summary, with the residual beside the total rather than under it
        summary = self._section(self._body, row, f"{report.volume.label} — measured")
        row += 1
        text = storage_report.STOP_LABEL[report.stop_reason]
        colour = _STOP_COLOUR[report.stop_reason]
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

        # ── what changed since the last scan. Windows' own figure leads it.
        if review is not None:
            self._history_section(row, review)
            row += 1

        # ── what we could not see. Deliberately above the tree.
        residual = self._section(self._body, row,
                                 "What this scan could not account for")
        row += 1
        breakdown = report.residual_breakdown()
        if breakdown:
            self._bars(residual, [(r.label, b) for r, b in breakdown],
                       report.residual_bytes, 1)
        notes = storage_report.scan_notes(report)
        ctk.CTkLabel(residual, text="\n".join(f"·  {n}" for n in notes),
                     font=theme.get("small"), text_color=theme.color("subtext"),
                     anchor="w", justify="left", wraplength=720).grid(
            row=90, column=0, sticky="ew", padx=16, pady=(8, 12))

        # ── the three read-only views
        largest = self._section(self._body, row, "Largest folders")
        row += 1
        children = report.root.largest_children(storage_report.LIST_ROWS)
        self._bars(largest, [(c.name, c.allocated_bytes) for c in children],
                   report.measured_bytes, 1)
        ctk.CTkLabel(largest, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                    pady=(0, 8))

        files = self._section(self._body, row, "Largest files")
        row += 1
        self._bars(files, [(f.path.name, f.allocated_bytes)
                           for f in report.largest_files[:storage_report.LIST_ROWS]],
                   report.measured_bytes, 1)
        ctk.CTkLabel(files, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                  pady=(0, 8))

        by_ext = sorted(report.by_extension.items(), key=lambda kv: kv[1],
                        reverse=True)[:storage_report.LIST_ROWS]
        if by_ext:
            ext = self._section(self._body, row, "By file type")
            row += 1
            self._bars(ext, by_ext, report.measured_bytes, 1)
            ctk.CTkLabel(ext, text="", font=theme.get("small")).grid(row=90, column=0,
                                                                     pady=(0, 8))
