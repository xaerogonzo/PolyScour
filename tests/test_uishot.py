"""
Tests for the uishot capture harness.

The capture path is exercised through a **subprocess**, deliberately.
`SetThreadDesktop` fails once the calling thread owns a window, and
`test_ui_smoke.py` holds a module-scoped Tk root — so binding a hidden desktop
in-process would fail depending on test order. Running the real CLI also tests
the thing that actually gets invoked.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI = PROJECT_ROOT / "tools" / "uishot" / "__main__.py"

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="hidden-desktop capture is Windows-only")


def _run(*args, cwd=PROJECT_ROOT):
    return subprocess.run([sys.executable, str(CLI), *args],
                          cwd=str(cwd), capture_output=True, text=True,
                          timeout=600)


@pytest.fixture(scope="session")
def capture_supported():
    """Skip where the runner cannot host a hidden desktop.

    A CI box without an interactive window station is an environment limit, not
    a defect — it should read as 'skipped', not as a red build. The probe runs
    out-of-process so it never conflicts with a Tk root this session may hold.
    """
    probe = _run("--probe")
    if probe.returncode != 0:
        pytest.skip(f"capture unsupported here: {probe.stdout.strip()}")
    return True


# ── Pure helpers (no Tk, no desktop) ──────────────────────────────────────────

def test_compare_detects_identical_images():
    from PIL import Image

    from polybedrock.ui.uishot import compare

    img = Image.new("RGB", (40, 30), (12, 34, 56))
    result = compare(img, img.copy())
    assert result["match"] is True
    assert result["differing"] == 0


def test_compare_flags_a_changed_block():
    from PIL import Image

    from polybedrock.ui.uishot import compare

    a = Image.new("RGB", (40, 30), (12, 34, 56))
    b = a.copy()
    for x in range(5, 15):
        for y in range(5, 15):
            b.putpixel((x, y), (200, 10, 10))

    result = compare(a, b)
    assert result["match"] is False
    assert result["differing"] == 100


def test_a_registry_keeps_live_scenes_out_of_the_goldens():
    """The distinction the whole golden mechanism rests on."""
    from polybedrock.ui.uishot import SceneRegistry

    reg = SceneRegistry()
    reg.scene("stable")(lambda s: None)
    reg.scene("live", golden=False)(lambda s: None)

    assert set(reg.all_scenes()) == {"stable", "live"}
    assert reg.golden_scenes() == {"stable"}


def test_two_registries_do_not_share_scenes():
    """PolyScour and PolyShield each own one; module globals would collide."""
    from polybedrock.ui.uishot import SceneRegistry

    a, b = SceneRegistry(), SceneRegistry()
    a.scene("only-in-a")(lambda s: None)
    assert "only-in-a" not in b.all_scenes()


# ── The CLI ───────────────────────────────────────────────────────────────────

def test_list_reports_every_scene():
    result = _run("--list")
    assert result.returncode == 0, result.stderr
    names = set(result.stdout.split())
    assert {"clean", "dashboard", "history", "settings"} <= names


def test_an_unknown_scene_is_refused():
    result = _run("--only", "no-such-scene")
    assert result.returncode == 2
    assert "unknown scene" in result.stderr


def test_capture_produces_a_readable_png(capture_supported, tmp_path):
    """The end-to-end path: hidden desktop, real view, real PNG."""
    from PIL import Image

    result = _run("--only", "history", "--out", str(tmp_path))
    assert result.returncode == 0, result.stderr + result.stdout

    shots = sorted(tmp_path.glob("*.png"))
    assert shots, f"no PNG written; stdout was:\n{result.stdout}"
    for shot in shots:
        with Image.open(shot) as img:
            assert img.size[0] > 200 and img.size[1] > 200


def test_a_capture_is_not_blank(capture_supported, tmp_path):
    """The failure mode a size check misses.

    An off-screen window captures as mostly-white; the whole reason for the
    hidden desktop is that it does not. If this ever goes uniform, the harness
    is lying rather than failing.
    """
    from PIL import Image

    result = _run("--only", "clean", "--out", str(tmp_path))
    assert result.returncode == 0, result.stderr + result.stdout

    shot = tmp_path / "clean_findings.png"
    assert shot.exists(), f"expected shot missing; stdout:\n{result.stdout}"
    with Image.open(shot) as img:
        colours = img.convert("RGB").getcolors(maxcolors=1 << 20)
    assert colours is not None and len(colours) > 50, \
        "capture is nearly uniform — the window probably did not paint"


def test_check_passes_against_the_recorded_goldens(capture_supported):
    """Drift detection, run for real. Failing here means the UI changed."""
    result = _run("--check")
    assert result.returncode == 0, (
        "UI drifted from tests/golden/ui — inspect the side-by-side diffs in "
        f"artifacts/ui/diff, then --update-golden if intended.\n{result.stdout}")
