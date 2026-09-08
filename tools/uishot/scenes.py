"""
PolyScour's shot list — one function per scene, registered by name.

States are **constructed directly** rather than reached naturally. That is the
point: a scan of a real machine takes ~39 seconds, returns different numbers
every run, and cannot produce the states most worth photographing on demand — a
rule that aborted because a browser is open, a plan that is entirely permanent,
an empty history. Injecting the state makes the shot both fast and comparable.

Note the data-root redirection at the bottom of this docstring's module: a
capture must never touch the user's real vault or ledger. Photographing the UI
is a read-only act and the harness is arranged so that stays true.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# BEFORE importing anything from polyscour: point the data root at a throwaway
# directory. polyscour.paths reads POLYSCOUR_DATA_DIR at call time, so this
# keeps every scene away from the user's real vault, ledger and settings.
# A screenshot tool that mutates the thing it is photographing would be a poor
# joke, and this is one line.
_SANDBOX = Path(tempfile.mkdtemp(prefix="polyscour-uishot-"))
os.environ["POLYSCOUR_DATA_DIR"] = str(_SANDBOX)

from polybedrock.ui.uishot import SceneRegistry            # noqa: E402

REGISTRY = SceneRegistry()
scene = REGISTRY.scene
all_scenes = REGISTRY.all_scenes
golden_scenes = REGISTRY.golden_scenes


# ── A stand-in for the App shell ──────────────────────────────────────────────

class _FakeApp:
    """What the views actually use from `App`, and nothing more.

    ``run_off_thread`` and ``after`` run **synchronously**. A background thread
    would race the capture, and a scene that sometimes photographs a half-filled
    view is worse than no scene.
    """

    def __init__(self, services):
        self.services = services
        self.status = ""

    def set_status(self, text: str) -> None:
        self.status = text

    def navigate(self, key: str) -> None:
        pass

    def after(self, _ms, func=None, *args):
        if func is not None:
            func(*args)
        return "after#0"

    def run_off_thread(self, work, done):
        try:
            done(work(), None)
        except Exception as exc:                    # noqa: BLE001
            done(None, exc)
        return None


def _app():
    from polyscour.app import Services
    return _FakeApp(Services())


# ── Synthetic findings ────────────────────────────────────────────────────────

def _scan_result(*, cancelled: bool = False, aborted: bool = True):
    """A scan that looks like a real machine, with fixed numbers.

    Modelled on an actual run: 36,194 findings, 39 GB, Firefox open.
    """
    from polyscour.contracts import (Evidence, Finding, RiskLevel, RuleOutcome,
                                     ScanResult)

    def group(rule_id, title, count, each, risk, reversible, rationale):
        return RuleOutcome(rule_id=rule_id, findings=[
            Finding(rule_id=rule_id, title=title,
                    path=Path(rf"C:\Users\me\AppData\Local\{rule_id}\f_{i:06d}"),
                    size_bytes=each, risk=risk, reversible=reversible,
                    evidence=Evidence(rule_id, f"f_{i:06d}", rationale))
            for i in range(count)])

    outcomes = [
        group("chrome-cache", "Google Chrome cache", 240, 2_700_000,
              RiskLevel.SAFE, False,
              "Chrome's on-disk page cache, for every profile. Rebuilt as you "
              "browse. Cookies, history and saved passwords are NOT touched."),
        group("crash-dumps", "Application crash dumps", 9, 22_000_000,
              RiskLevel.MODERATE, True,
              "Memory dumps written when an application crashed. Not "
              "regenerable, and occasionally still wanted, so these are moved "
              "to the vault rather than deleted."),
        group("directx-shader-cache", "DirectX shader cache", 120, 97_000_000,
              RiskLevel.SAFE, False,
              "Compiled GPU shaders cached by DirectX and by NVIDIA/AMD "
              "drivers. Regenerated on demand."),
        group("user-temp", "User temporary files", 400, 71_000_000,
              RiskLevel.LOW, False,
              "Files applications wrote to your TEMP folder and did not clean "
              "up. Nothing is expected to survive here across a reboot."),
    ]
    if aborted:
        outcomes.append(RuleOutcome(
            rule_id="firefox-cache", aborted=True,
            abort_reason="firefox.exe is running"))

    now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    return ScanResult(started_at=now, finished_at=now, outcomes=outcomes,
                      cancelled=cancelled)


# ── Scenes ────────────────────────────────────────────────────────────────────

@scene("dashboard")
def dashboard(session):
    """The three tiles, with health and PolyShield injected.

    Not read live: `get_system_health()` shells out to PowerShell and returns
    this machine's uptime and patch level, which is neither fast nor comparable.
    """
    from polyscour.views.dashboard_view import DashboardView

    view = session.mount(DashboardView, app=_app())
    view._show_rule_failures()
    view._refresh_vault()
    view.cleanup.set("—", "Run a scan to find out.")
    view._render_health({
        "pending_reboot": False,
        "driver_errors": 63,
        "uptime_days": 2,
        "recent_patches": [{"kb": "KB5121003", "installed_on": "2026-08-13"}],
    })
    view._render_polyshield(type("P", (), {
        "available": False, "watcher_running": None, "intel_age_days": None})())
    session.shot("dashboard_no_polyshield")

    view._render_polyshield(type("P", (), {
        "available": True, "watcher_running": True, "intel_age_days": 2})())
    session.shot("dashboard_with_polyshield")


@scene("dashboard-reboot")
def dashboard_reboot(session):
    """The one condition that is allowed to set the headline."""
    from polyscour.views.dashboard_view import DashboardView

    view = session.mount(DashboardView, app=_app())
    view._refresh_vault()
    view.cleanup.set("8.7 GB", "Across 4 categories. Review before cleaning.")
    view._render_health({
        "pending_reboot": True, "driver_errors": 0, "uptime_days": 31,
        "recent_patches": [],
    })
    session.shot("dashboard_reboot_pending")


@scene("clean")
def clean(session):
    """The findings list — grouped by rule, with an aborted rule reported."""
    from polyscour.views.clean_view import CleanView

    view = session.mount(CleanView, app=_app())
    session.shot("clean_before_scan")

    view._render(_scan_result())
    session.shot("clean_findings")


@scene("clean-cancelled")
def clean_cancelled(session):
    """A partial result must say so rather than looking like a complete one."""
    from polyscour.views.clean_view import CleanView

    view = session.mount(CleanView, app=_app())
    view._render(_scan_result(cancelled=True, aborted=False))
    session.shot("clean_cancelled")


@scene("history")
def history(session):
    """Empty, then with one reversible and one permanent operation."""
    from polyscour.contracts import (ActionResult, OperationOutcome, Reversal,
                                     Skip, SkipReason)
    from polyscour.views.history_view import HistoryView

    app = _app()
    view = session.mount(HistoryView, app=app)
    view.refresh()
    session.shot("history_empty")

    now = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
    ledger = app.services.ledger
    ledger.record(ActionResult(
        operation_id="20260905T101500-aaaaaaaa",
        outcome=OperationOutcome.SUCCESS_WITH_SKIPS,
        started_at=now - timedelta(hours=2), finished_at=now - timedelta(hours=2),
        bytes_freed=4_812_000_000, items_completed=14_159,
        skips=[Skip(Path(r"C:\x\locked.tmp"), SkipReason.LOCKED, "in use")],
    ), ["chrome-cache", "user-temp"])
    ledger.record(ActionResult(
        operation_id="20260905T113000-bbbbbbbb",
        outcome=OperationOutcome.SUCCESS,
        started_at=now - timedelta(minutes=30),
        finished_at=now - timedelta(minutes=30),
        bytes_freed=189_000_000, items_completed=9,
        reversals=[Reversal("20260905T113000-bbbbbbbb", "a" * 64,
                            Path(r"C:\x\crash.dmp"))],
    ), ["crash-dumps"])

    view.refresh()
    session.shot("history_populated")


@scene("settings", golden=False)
def settings(session):
    """Live: the protected-locations list is this machine's own environment."""
    from polyscour.views.settings_view import SettingsView

    session.mount(SettingsView, app=_app())
    session.shot("settings_top")


@scene("game-mode")
def game_mode(session):
    """The list, and the refusals.

    The candidate list is constructed rather than enumerated: a real one is
    this machine's processes, which differ every run and would make the golden
    a photograph of whatever happened to be open. The constructed list is
    chosen to include the cases the screen exists to show -- an ordinary
    program, one refused by the reviewed list, and one refused structurally for
    belonging to somebody else.
    """
    from polyscour.gamemode import session as gm
    from polyscour.gamemode.policy import Candidate
    from polyscour.views import gamemode_view

    me = r"DESK\alex"
    fixed = [
        Candidate(pid=5100, name="chrome.exe", username=me,
                  memory_bytes=1_850_000_000, create_time=1000.0),
        Candidate(pid=5200, name="Discord.exe", username=me,
                  memory_bytes=420_000_000, create_time=1000.0),
        Candidate(pid=1400, name="explorer.exe", username=me,
                  memory_bytes=310_000_000, create_time=1000.0),
        Candidate(pid=900, name="MsMpEng.exe", username=r"NT AUTHORITY\SYSTEM",
                  memory_bytes=280_000_000, create_time=1000.0),
        Candidate(pid=5300, name="Spotify.exe", username=me,
                  memory_bytes=190_000_000, create_time=1000.0),
    ]

    real_enumerate = gm.enumerate_candidates
    real_veto = gamemode_view.veto
    gm.enumerate_candidates = lambda: list(fixed)
    # Pin the identity the veto compares against, so "belongs to someone else"
    # is a property of the scene rather than of whoever runs the capture.
    gamemode_view.veto = lambda c, **kw: real_veto(
        c, current_user=me, protected_pids=frozenset())
    try:
        view = session.mount(gamemode_view.GameModeView, app=_app())
        view.refresh()
        session.shot("game_mode_candidates")
    finally:
        gm.enumerate_candidates = real_enumerate
        gamemode_view.veto = real_veto


@scene("startup")
def startup(session):
    """The list, the switches, and the entries whose switch is refused.

    Constructed rather than read: a real list is this machine's startup
    entries, which differ per machine and would make the golden a photograph
    of whatever happens to be installed. The fixed set covers what the screen
    exists to show -- an enabled user entry, a disabled one, one whose target
    is gone, one that cannot be resolved at all, and a machine-wide entry
    whose switch is refused with a reason.
    """
    from polybedrock.startup import RunEntry

    from polyscour.startup.manager import StartupItem, TargetState
    from polyscour.views import startup_view

    RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

    def mk(name, value, target, hive, scope, enabled, state):
        return StartupItem(
            entry=RunEntry(hive_name=hive, key_path=RUN, value_name=name,
                           raw_value=value, target_path=target, scope=scope),
            enabled=enabled, has_approval_record=True, target=state)

    fixed = [
        mk("OneDrive", r'"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background',
           r"C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
           "HKCU", "user", True, TargetState.PRESENT),
        mk("Steam", r'"C:\Program Files (x86)\Steam\steam.exe" -silent',
           r"C:\Program Files (x86)\Steam\steam.exe",
           "HKCU", "user", False, TargetState.PRESENT),
        mk("OldUpdater", r"C:\Vendor\gone\updater.exe",
           r"C:\Vendor\gone\updater.exe",
           "HKCU", "user", True, TargetState.MISSING),
        mk("Odd Entry", "rundll32 something,Entry", "",
           "HKCU", "user", True, TargetState.UNRESOLVED),
        mk("SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe",
           r"C:\Windows\system32\SecurityHealthSystray.exe",
           "HKLM", "machine", True, TargetState.PRESENT),
    ]

    real = startup_view.list_items
    startup_view.list_items = lambda: list(fixed)
    try:
        view = session.mount(startup_view.StartupView, app=_app())
        view.refresh()
        session.shot("startup_entries")
    finally:
        startup_view.list_items = real


@scene("storage")
def storage(session):
    """The measured tree, the residual, and the three read-only lists.

    Constructed, and it has to be: a real scan of C: takes minutes, returns
    different numbers every run, and its largest folders are whatever this
    machine happens to have installed. The golden would be a photograph of one
    developer's disk.

    The fixed report covers what the screen exists to show -- a scan that
    stopped at its time budget, a residual larger than a rounding error, every
    kind of diagnostic note, and enough folders and files to fill the lists.
    """
    from pathlib import Path

    from polyscour.storage.analyser import (DirectoryNode, FileEntry,
                                            ResidualReason, StopReason,
                                            VolumeReport)
    from polyscour.storage.volumes import Volume
    from polyscour.views import storage_view

    GB = 1024 ** 3
    volume = Volume(root=Path("C:\\"), fstype="NTFS",
                    total_bytes=953 * GB, used_bytes=807 * GB,
                    free_bytes=146 * GB)

    root = DirectoryNode(path=Path("C:\\"))
    for name, size in (("Games", 214 * GB), ("Windows", 71 * GB),
                       ("Users", 58 * GB), ("Program Files", 17 * GB),
                       ("ProgramData", 9 * GB), ("Program Files (x86)", 6 * GB)):
        child = DirectoryNode(path=Path("C:\\") / name)
        child.logical_bytes = child.allocated_bytes = size
        child.file_count = 1
        root.children.append(child)
    root.allocated_bytes = root.logical_bytes = sum(
        c.allocated_bytes for c in root.children)
    root.file_count = len(root.children)

    report = VolumeReport(
        volume=volume, root=root,
        stop_reason=StopReason.TIME_EXHAUSTED,
        elapsed_seconds=120.0, entries_examined=846_301,
        directories_examined=94_722, max_entries=2_000_000, max_seconds=120.0,
        used_at_start=807 * GB, used_at_end=807 * GB,
    )
    report.residual[ResidualReason.TIME_EXHAUSTED] = 340 * GB
    report.residual[ResidualReason.SYSTEM_MANAGED] = 51 * GB
    report.permission_denied_directories = 412
    report.reparse_points_skipped = 96
    report.hardlinks_deduplicated = 41_207
    report.hardlink_bytes_saved = 19 * GB
    report.largest_files = [
        FileEntry(Path(r"C:\Games\Mercs\Content.pak"), 75 * GB, 75 * GB),
        FileEntry(Path(r"C:\pagefile.sys"), 38 * GB, 38 * GB),
        FileEntry(Path(r"C:\Models\weights.safetensors"), 22 * GB, 22 * GB),
        FileEntry(Path(r"C:\hiberfil.sys"), 13 * GB, 13 * GB),
        FileEntry(Path(r"C:\Games\Mercs\textures.pak"), 9 * GB, 9 * GB),
    ]
    report.by_extension = {
        ".pak": 84 * GB, ".sys": 51 * GB, ".safetensors": 22 * GB,
        ".dll": 11 * GB, ".exe": 6 * GB, "(no extension)": 3 * GB,
    }

    # The idle screen lists real volumes, and this machine's used-bytes move
    # between runs -- the first attempt at this golden drifted by 77 px on the
    # capacity line alone. Patched the same way the startup scene patches
    # `list_items`, so the shot is comparable rather than a photograph of
    # whatever the disk happened to hold that minute.
    others = [
        Volume(root=Path("D:\\"), fstype="NTFS", total_bytes=1863 * GB,
               used_bytes=1484 * GB, free_bytes=379 * GB),
        Volume(root=Path("F:\\"), fstype="NTFS", total_bytes=931 * GB,
               used_bytes=631 * GB, free_bytes=300 * GB),
    ]
    real = storage_view.volumes.fixed_volumes
    storage_view.volumes.fixed_volumes = lambda: [volume, *others]
    try:
        view = session.mount(storage_view.StorageView, app=_app())
        session.shot("storage_before_scan")

        view._render(report)
        session.shot("storage_measured")
    finally:
        storage_view.volumes.fixed_volumes = real
