r"""The PolyScour shell.

Deliberately thin. The GUI contains no business logic: it builds a plan out of
what the user ticked and hands it to the executor, and every safety decision
happens well below this layer. If a rule about what may be deleted ever appears
in this file, something has gone wrong.

Views are built on first show rather than at startup -- the pattern PolyShield
arrived at, for the same reason: a dashboard that has to construct four pages
before it can draw one is slow for no benefit.
"""
from __future__ import annotations

import sys
import threading
import tkinter
from pathlib import Path

import customtkinter as ctk
from polybedrock import settings as cfg
from polybedrock.ui import theme

from polyscour import paths, settings as _settings  # noqa: F401  (configures cfg)
from polyscour.cleaning.executor import Executor
from polyscour.cleaning.rules import load_all
from polyscour.cleaning.scanner import Scanner
from polyscour.gamemode import session as gamemode
from polyscour.ledger import Ledger
from polyscour.safety.guard import Guard
from polyscour.vault import Vault

APP_TITLE = "PolyScour"

# Module level, deliberately, and before any widget exists. Every palette in
# polybedrock.ui.theme is dark; left at CustomTkinter's default "System" mode, a
# machine with Windows in light mode renders light widget defaults against those
# dark colours -- which looks like a contrast bug in the application and is not.
# It also has to happen at import time so a harness that imports this module for
# its global setup (see tools/uishot) gets the same appearance the real entry
# point does.
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_NAV = [
    ("dashboard", "Dashboard"),
    ("clean", "Clean"),
    ("storage", "Storage"),
    ("game", "Game Mode"),
    ("startup", "Startup"),
    ("history", "History"),
    ("settings", "Settings"),
]


class Services:
    """Everything the views share, built once.

    Passed in rather than reached for, so a view cannot quietly construct its
    own Executor with a Guard that has no exclusions.
    """

    def __init__(self) -> None:
        exclusions = [Path(p) for p in (cfg.get("exclusions") or [])]
        self.guard = Guard(exclusions=exclusions)
        self.vault = Vault(paths.vault_dir())
        self.ledger = Ledger(paths.ledger_path())
        self.scanner = Scanner(guard=self.guard)
        self.executor = Executor(vault=self.vault, ledger=self.ledger,
                                 guard=self.guard)
        self.rules, self.rule_failures = load_all(paths.rules_dir())

        self.ledger.initialise()
        self.vault.initialise()

        # Before anything else can run: a previous PolyScour that died
        # mid-session may have left processes frozen, and a frozen process
        # presents as an application that has hung for no reason. Nothing
        # else in the system will ever release them. Cheap on the common
        # path -- one indexed query returning no rows -- and never fatal:
        # failing to recover must not stop the app that performs recovery
        # from starting.
        try:
            self.game_recovery = gamemode.recover(self.ledger)
        except Exception:
            self.game_recovery = gamemode.RecoveryReport()

    def enabled_rules(self):
        disabled = set(cfg.get("disabled_rules") or [])
        return [r for r in self.rules if r.id not in disabled]


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        cfg.load()
        theme.configure(APP_TITLE)
        theme.init(cfg)
        theme.init_colors(cfg)
        # Without this, any widget not given an explicit colour falls back to
        # CustomTkinter's stock blue theme, and the window renders as a
        # patchwork of two palettes -- most visibly as dim, low-contrast label
        # text on the preset's dark cards.
        theme.apply_ctk_palette()

        self.title(APP_TITLE)
        self.geometry("1060x680")
        self.minsize(900, 560)

        self.services = Services()
        self._views: dict[str, ctk.CTkFrame] = {}
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._active: str | None = None

        self._build()
        self._navigate("dashboard")

    # ── chrome ───────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=190, corner_radius=0,
                               fg_color=theme.color("sidebar"))
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text=APP_TITLE, font=theme.get("heading"),
                     text_color=theme.color("text")).grid(
            row=0, column=0, sticky="ew", padx=20, pady=(24, 4))
        ctk.CTkLabel(sidebar, text="Windows maintenance",
                     font=theme.get("small"),
                     text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="ew", padx=20, pady=(0, 20))

        for i, (key, label) in enumerate(_NAV, start=2):
            btn = ctk.CTkButton(
                sidebar, text=label, anchor="w", height=36, corner_radius=6,
                fg_color="transparent", font=theme.get("nav"),
                text_color=theme.color("text"),
                hover_color=theme.color("input_hover"),
                command=lambda k=key: self._navigate(k))
            btn.grid(row=i, column=0, sticky="ew", padx=10, pady=2)
            self._nav_buttons[key] = btn

        self.content = ctk.CTkFrame(self, fg_color=theme.color("content_bg"))
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.status = ctk.CTkLabel(self, text="Ready", anchor="w",
                                   font=theme.get("small"),
                                   text_color=theme.color("subtext"))
        self.status.grid(row=1, column=1, sticky="ew", padx=16, pady=(0, 8))

    # ── navigation ───────────────────────────────────────────────────────────

    def _factory(self, key: str):
        from polyscour.views import (clean_view, dashboard_view,
                                      gamemode_view, history_view,
                                      settings_view, startup_view,
                                      storage_view)
        return {
            "dashboard": lambda: dashboard_view.DashboardView(self.content, self),
            "clean": lambda: clean_view.CleanView(self.content, self),
            "storage": lambda: storage_view.StorageView(self.content, self),
            "game": lambda: gamemode_view.GameModeView(self.content, self),
            "startup": lambda: startup_view.StartupView(self.content, self),
            "history": lambda: history_view.HistoryView(self.content, self),
            "settings": lambda: settings_view.SettingsView(self.content, self),
        }[key]

    def get_view(self, key: str):
        view = self._views.get(key)
        if view is None:
            view = self._factory(key)()
            view.grid(row=0, column=0, sticky="nsew")
            self._views[key] = view
        return view

    def _navigate(self, key: str) -> None:
        if self._active:
            self._views[self._active].grid_remove()
            self._nav_buttons[self._active].configure(fg_color="transparent")

        view = self.get_view(key)
        view.grid()
        self._active = key
        self._nav_buttons[key].configure(fg_color=theme.color("nav_active"))
        if hasattr(view, "on_show"):
            view.on_show()

    def navigate(self, key: str) -> None:
        """Public: a view asking the shell to move somewhere else."""
        self._navigate(key)

    # ── shared helpers ───────────────────────────────────────────────────────

    def set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def run_off_thread(self, work, done) -> threading.Thread:
        """Run `work` off the UI thread and deliver its result on it.

        Tk is not thread-safe, so the result comes back through ``after(0, ...)``
        rather than the worker touching a widget. A scan over a large temp tree
        takes seconds; doing it inline would freeze the window and make Cancel
        unclickable, which would defeat the point of having cancellation.
        """
        def _deliver(fn):
            """Hand a result back to the UI thread, if there still is one.

            ``after()`` raises once the root is destroyed, and it is called from
            the worker thread — outside any try the work itself is wrapped in.
            Closing the window mid-scan therefore killed the thread with an
            unhandled traceback. There is genuinely nobody to deliver to at that
            point, so dropping the result is the correct outcome; what was wrong
            was doing it noisily.
            """
            try:
                self.after(0, fn)
            except (RuntimeError, tkinter.TclError):
                pass

        def _run():
            try:
                result = work()
            except Exception as exc:                # noqa: BLE001
                _deliver(lambda e=exc: done(None, e))
                return
            _deliver(lambda r=result: done(r, None))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t


def main() -> int:
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
