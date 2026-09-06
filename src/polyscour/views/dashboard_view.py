r"""The dashboard. Deliberately small.

Four things, and no more: what can be reclaimed, what the machine's health
actually says, what is sitting in the vault, and -- only if PolyShield happens to
be installed -- its security posture.

No score. A number between 0 and 100 with no defensible methodology behind it is
the single most recognisable feature of the software this product exists to
replace. Where PolyShield is present its score is shown as *PolyShield's*, with
its name on it, because that one is computed from something.
"""
from __future__ import annotations

import customtkinter as ctk
from polybedrock import win_security
from polybedrock.ui import theme

from polyscour.integrations import polyshield


def human(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


class Card(ctk.CTkFrame):
    """One tile. Title, a big number, and a line saying what it means."""

    def __init__(self, parent, title: str):
        super().__init__(parent, fg_color=theme.color("card"), corner_radius=8)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=title, font=theme.get("section_title"),
                     text_color=theme.color("subtext"),
                     anchor="w").grid(row=0, column=0, sticky="ew",
                                      padx=16, pady=(14, 2))
        self.value = ctk.CTkLabel(self, text="—", font=theme.get("heading"),
                                  text_color=theme.color("text"), anchor="w",
                                  justify="left", wraplength=260)
        self.value.grid(row=1, column=0, sticky="ew", padx=16)
        self.detail = ctk.CTkLabel(self, text="", font=theme.get("small"),
                                   anchor="w", justify="left", wraplength=260,
                                   text_color=theme.color("subtext"))
        self.detail.grid(row=2, column=0, sticky="ew", padx=16, pady=(2, 14))

    def set(self, value: str, detail: str = "") -> None:
        self.value.configure(text=value)
        self.detail.configure(text=detail)


class DashboardView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._loaded = False

        self.grid_columnconfigure((0, 1, 2), weight=1, uniform="cards")

        ctk.CTkLabel(self, text="PC health", font=theme.get("heading"),
                     text_color=theme.color("text"), anchor="w").grid(row=0, column=0, columnspan=3,
                                      sticky="ew", padx=20, pady=(20, 12))

        self.cleanup = Card(self, "Cleanup")
        self.cleanup.grid(row=1, column=0, sticky="nsew", padx=(20, 8), pady=8)

        self.health = Card(self, "System health")
        self.health.grid(row=1, column=1, sticky="nsew", padx=8, pady=8)

        self.vault = Card(self, "Vault")
        self.vault.grid(row=1, column=2, sticky="nsew", padx=(8, 20), pady=8)

        # Rendered only when PolyShield answers. Absent means absent -- no
        # greyed-out teaser, no advertisement for another product.
        self.polyshield = Card(self, "PolyShield")

        self.notice = ctk.CTkLabel(
            self, text="", font=theme.get("small"), anchor="w", justify="left",
            wraplength=760, text_color=theme.color("subtext"))
        self.notice.grid(row=3, column=0, columnspan=3, sticky="ew",
                         padx=20, pady=(4, 8))

        ctk.CTkButton(self, text="Scan for things to clean",
                      command=lambda: app.navigate("clean")).grid(
            row=4, column=0, sticky="w", padx=20, pady=(8, 20))

        self.grid_rowconfigure(5, weight=1)

    def on_show(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._show_rule_failures()
        self._refresh_vault()
        self.cleanup.set("—", "Run a scan to find out.")
        self.health.set("…", "Reading Windows health.")
        self.app.run_off_thread(self._gather, self._render)

    # ── off the UI thread ────────────────────────────────────────────────────

    @staticmethod
    def _gather() -> dict:
        """Everything slow, in one place.

        ``get_system_health()`` shells out to PowerShell several times; doing it
        inline would freeze the window for seconds on first paint.
        """
        return {
            "health": win_security.get_system_health(),
            "polyshield": polyshield.security_posture(),
        }

    def _render(self, data, error) -> None:
        if error is not None:
            self.health.set("Unavailable", f"Could not read system health: {error}")
            return

        self._render_health(data["health"])
        self._render_polyshield(data["polyshield"])

    def _render_health(self, health: dict) -> None:
        """Facts, with the mechanism named. No invented severity.

        Only findings we can actually stand behind are allowed to set the
        headline. Everything else is a neutral note.
        """
        problems, notes = [], []

        if health.get("pending_reboot"):
            problems.append("restart pending")
            notes.append("Windows Update is waiting for a restart.")

        # Deliberately NOT a headline problem. The underlying probe is
        # `Get-PnpDevice | Where Status -ne 'OK'`, which counts every device
        # that is not currently present -- every USB device ever plugged in
        # keeps an entry. On a normal machine that is routinely dozens, and
        # announcing "63 devices not reporting OK" would be precisely the
        # alarming-but-meaningless number this product exists to not produce.
        # Until PolyScour can tell "genuinely faulty" from "not plugged in
        # right now", it reports the count as a fact and says what it means.
        drivers = health.get("driver_errors")
        if drivers:
            notes.append(
                f"{drivers} device{'s' if drivers != 1 else ''} in Device "
                f"Manager are not reporting OK; most are usually hardware that "
                f"is simply not connected right now.")

        uptime = health.get("uptime_days")
        if uptime is not None:
            notes.append(f"Up {uptime} day{'s' if uptime != 1 else ''}.")

        patches = health.get("recent_patches") or []
        if patches:
            notes.append(f"Latest update {patches[0].get('kb', '?')} "
                         f"on {patches[0].get('installed_on', 'an unknown date')}.")

        headline = ", ".join(problems).capitalize() if problems else "No action needed"
        self.health.set(headline, " ".join(notes) or "Nothing to report.")

    def _render_polyshield(self, posture) -> None:
        if not posture.available:
            self.polyshield.grid_remove()
            return
        self.polyshield.grid(row=2, column=0, sticky="nsew",
                             padx=(20, 8), pady=8)
        age = posture.intel_age_days
        detail = "Real-time protection is running." if posture.watcher_running \
            else "Installed; real-time protection is off."
        if age is not None:
            detail += f" Threat intelligence is {age} day{'s' if age != 1 else ''} old."
        self.polyshield.set("Protected" if posture.watcher_running else "Installed",
                            detail)

    # ── on the UI thread ─────────────────────────────────────────────────────

    def _refresh_vault(self) -> None:
        size = self.app.services.vault.size_bytes()
        undoable = len(self.app.services.ledger.undoable())
        self.vault.set(
            human(size),
            f"{undoable} operation{'s' if undoable != 1 else ''} can be undone."
            if undoable else "Nothing staged for undo.")

    def _show_rule_failures(self) -> None:
        """A rule that failed to load is shown, not swallowed.

        Silently running eight of nine cleaners is how a maintenance tool starts
        quietly doing less than the user thinks it is.
        """
        failures = self.app.services.rule_failures
        if not failures:
            self.notice.configure(text="")
            return
        lines = [f"{path.name}: {exc}" for path, exc in failures]
        self.notice.configure(
            text="Some cleaning rules did not load and will not run:\n  "
                 + "\n  ".join(lines))

    def refresh(self) -> None:
        self._refresh_vault()
