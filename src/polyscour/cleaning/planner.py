r"""Turning findings into a plan the user actually agreed to.

This is the step the product's central rule exists for: **a finding is not a
recommendation.** The scanner says what is there. The planner sorts that into
what is worth suggesting and what merely *could* be done, and the user decides.
Nothing is pre-selected above SAFE.

Deliberately thin. A recommendation engine that weighs benefit, confidence and
reversibility belongs here eventually; inventing it now, before there is any
evidence to weigh, would produce exactly the invented-authority numbers this
product exists to replace.
"""
from __future__ import annotations

from dataclasses import dataclass

from polyscour.contracts import ActionPlan, Finding, RiskLevel, ScanResult


@dataclass(frozen=True)
class Recommendation:
    """One offer, with the reason attached rather than implied."""
    finding: Finding
    #: Pre-ticked in the UI. True only for regenerable data at SAFE risk.
    recommended: bool
    reason: str


def recommend(result: ScanResult) -> list[Recommendation]:
    """Sort findings into recommended and optional.

    The bar for `recommended` is deliberately high: the data must be
    regenerable, unelevated, and SAFE. Everything else is offered unticked, so
    that the default action of a user who clicks straight through is the
    conservative one.
    """
    out: list[Recommendation] = []
    for f in result.findings:
        if f.requires_elevation:
            out.append(Recommendation(
                f, False,
                "Needs administrator rights; PolyScour runs unelevated."))
        elif f.risk <= RiskLevel.SAFE:
            out.append(Recommendation(
                f, True, "Regenerable cache; the application rebuilds it."))
        elif f.reversible:
            # Deliberately does not repeat `rollback_label`, which the row
            # already shows beside this. Say why it is *not* pre-selected.
            out.append(Recommendation(
                f, False, "Not regenerable, so not selected for you."))
        else:
            out.append(Recommendation(
                f, False, "Permanent. Review before selecting."))
    return out


def plan(findings: list[Finding], dry_run: bool = True) -> ActionPlan:
    """Freeze a selection into the only thing the executor will act on.

    ``dry_run`` defaults to True. A caller that wants to change the machine has
    to say so, which makes the destructive path the explicit one at every level
    of the stack rather than only in the UI.
    """
    return ActionPlan(findings=tuple(findings), dry_run=dry_run)


def summarise(plan_: ActionPlan) -> str:
    """One honest line for the confirmation dialog."""
    if not plan_.findings:
        return "Nothing selected."
    n = len(plan_.findings)
    reversible = plan_.reversible_count
    bits = [f"{n} item{'s' if n != 1 else ''}",
            f"{plan_.total_bytes:,} bytes",
            f"worst risk {plan_.worst_risk.label}"]
    if reversible:
        bits.append(f"{reversible} recoverable from the vault")
    if reversible < n:
        bits.append(f"{n - reversible} permanent")
    return ", ".join(bits) + "."
