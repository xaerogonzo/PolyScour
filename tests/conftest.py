r"""Shared fixtures — and one thing the suite is not allowed to do.

The guard below exists because it was needed. Routing machine-wide startup
entries through the elevated helper turned three existing tests into calls that
reached ``ShellExecute("runas")`` for real: a UAC prompt raised by ``pytest``,
on a developer's machine, for a registry write nobody asked for.

``docs/THREAT_MODEL.md`` says elevation is never requested speculatively. A
test suite that can raise a consent dialog is precisely that, and it is worse
than the ordinary kind: a prompt that appears while someone is doing something
else is a prompt they will click to make go away.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def no_real_uac_prompts(monkeypatch, request):
    """Fail loudly rather than raising a consent dialog.

    Opt out with ``@pytest.mark.allows_elevation`` for a test that genuinely
    drives the launcher — there is currently none, and adding one should be a
    deliberate act rather than a side effect of a refactor.
    """
    if request.node.get_closest_marker("allows_elevation"):
        return

    import polyscour.elevation.client as client

    def refuse(request_path):
        raise AssertionError(
            "a test tried to launch the elevated helper for real. Stub "
            "polyscour.elevation.client.request (or _launch) in the test: the "
            "suite must never raise a UAC prompt.")

    monkeypatch.setattr(client, "_launch", refuse)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "allows_elevation: this test may drive the real helper launcher")
