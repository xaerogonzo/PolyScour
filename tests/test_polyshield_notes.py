r"""Storage and Startup labels: decoration that cannot become advice.

``views/polyshield_notes.annotate`` only ever *adds a label to a row that was
already drawn*. These tests pin the boundary the plan was most worried about --
that "PolyShield flagged it" must never quietly turn into "so rank it, tick it,
or recommend removing it" -- and the efficiency promise that a screen asks
about the rows it shows and nothing else.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from polyscour.integrations.polyshield import PathAdvisor, PathStatus, UNKNOWN_PATH
from polyscour.views import polyshield_notes
from polyscour.views.polyshield_notes import annotate

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")


class FakeServices:
    def __init__(self, advisor):
        self.annotator = advisor


class FakeApp:
    """Synchronous ``run_off_thread``, same contract as the real one."""

    def __init__(self, advisor):
        self.services = FakeServices(advisor)
        self.ran_work = 0

    def run_off_thread(self, work, done):
        self.ran_work += 1
        try:
            result = work()
        except Exception as exc:                              # noqa: BLE001
            done(None, exc)
        else:
            done(result, None)


def target(path, folder=False, sink=None):
    placed = [] if sink is None else sink
    return (Path(path), folder, lambda text, p=path: placed.append((p, text)))


def test_a_label_is_placed_only_where_there_is_something_to_say():
    advisor = PathAdvisor(lambda p: {
        r"C:\a": PathStatus(True, True),
        r"C:\b": PathStatus(False, False),
        r"C:\c": UNKNOWN_PATH,
        r"C:\d": PathStatus(True, False),
    }[p])
    placed = []
    targets = [target(p, sink=placed) for p in (r"C:\a", r"C:\b", r"C:\c", r"C:\d")]

    annotate(FakeApp(advisor), targets)

    assert [p for p, _ in placed] == [r"C:\a", r"C:\d"]


def test_nothing_known_creates_nothing_at_all():
    """A machine without PolyShield sees no change whatsoever: not an empty
    label, not a blank line -- no widget is made."""
    advisor = PathAdvisor(lambda p: None)                     # no reply
    placed = []

    annotate(FakeApp(advisor), [target(r"C:\a", sink=placed)])

    assert placed == []


def test_the_text_is_the_one_describe_path_produces():
    from polyscour.integrations.polyshield import describe_path
    advisor = PathAdvisor(lambda p: PathStatus(True, True))
    placed = []

    annotate(FakeApp(advisor), [target(r"C:\a", folder=True, sink=placed)])
    annotate(FakeApp(advisor), [target(r"C:\b", folder=False, sink=placed)])

    assert placed[0][1] == describe_path(PathStatus(True, True), folder=True)
    assert placed[1][1] == describe_path(PathStatus(True, True), folder=False)


def test_an_answer_for_a_screen_that_was_rebuilt_labels_nothing():
    advisor = PathAdvisor(lambda p: PathStatus(True, True))
    placed = []

    annotate(FakeApp(advisor), [target(r"C:\a", sink=placed)],
             is_current=lambda: False)

    assert placed == []


def test_no_targets_means_no_background_work_at_all():
    app = FakeApp(PathAdvisor(lambda p: pytest.fail("asked about nothing")))
    annotate(app, [])
    annotate(app, [(None, False, lambda t: None), (Path(""), False, lambda t: None)])
    assert app.ran_work == 0


def test_only_the_rows_handed_over_are_asked_about():
    asked = []
    advisor = PathAdvisor(lambda p: asked.append(p) or PathStatus(False, False))

    annotate(FakeApp(advisor), [target(rf"C:\row{i}") for i in range(12)])

    assert sorted(asked) == sorted(rf"C:\row{i}" for i in range(12))


def test_every_pass_is_a_fresh_operation():
    """``begin()`` first, so an answer from an earlier render never stands in
    for a question that should be asked again."""
    calls = []
    advisor = PathAdvisor(lambda p: calls.append(p) or PathStatus(False, False))

    annotate(FakeApp(advisor), [target(r"C:\a")])
    annotate(FakeApp(advisor), [target(r"C:\a")])

    assert calls == [r"C:\a", r"C:\a"]


def test_a_failure_in_the_background_pass_labels_nothing_and_does_not_raise():
    def boom(path):
        raise RuntimeError("socket exploded")

    placed = []
    annotate(FakeApp(PathAdvisor(boom)), [target(r"C:\a", sink=placed)])
    assert placed == []


def test_a_row_destroyed_before_the_answer_arrives_is_not_an_error():
    import tkinter

    def place(text):
        raise tkinter.TclError("bad window path name")

    advisor = PathAdvisor(lambda p: PathStatus(True, True))
    annotate(FakeApp(advisor), [(Path(r"C:\a"), False, place)])   # must not raise


# ── the boundary, stated in code ─────────────────────────────────────────────

#: Anything that could reorder rows, change a control's state, or press one.
FORBIDDEN = ("sort", "reverse", ".select", ".invoke", ".set(", "BooleanVar",
             "CTkButton", "CTkSwitch", "CTkCheckBox", "state=")


def handles_in(code: str) -> list[str]:
    return [word for word in FORBIDDEN if word in code]


def code_of(module) -> str:
    """The module's code, without comments or its (rule-naming) docstring."""
    source = Path(module.__file__).read_text(encoding="utf-8")
    lines = [ln for ln in source.splitlines() if not ln.strip().startswith("#")]
    return "\n".join(lines).split('"""', 2)[-1]


def test_the_module_has_no_handle_on_order_selection_or_state():
    """Checked statically as well as by behaviour: the module that adds PolyShield
    labels must not be able to sort, tick, switch or press anything."""
    assert handles_in(code_of(polyshield_notes)) == []


@pytest.mark.parametrize("planted", [
    "rows.sort(key=flagged)", "var.set(True)", "ctk.CTkSwitch(row)",
    "switch.invoke()", "ctk.CTkButton(row, text='Remove')",
    "ctk.CTkCheckBox(row)", "row.configure(state='disabled')",
])
def test_the_static_check_can_fail(planted):
    """Negative control: the same detector, run over planted code, must see it."""
    assert handles_in(planted)
