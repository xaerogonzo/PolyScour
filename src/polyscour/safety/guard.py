r"""The independent authority. Nothing destructive happens without passing here.

The chain, in order, and every link is mandatory::

    rule identity
      -> policy lookup            (an unknown rule is refused, not defaulted)
      -> permitted root families  (resolved by code, never named by data)
      -> concrete target
      -> reparse inspection       (unresolved, component by component)
      -> canonicalise + contain   (re-verified against the canonical form)
      -> volume check
      -> global denylist          (independent of any rule)
      -> user exclusions
      -> operation permitted?
      -> authorised

The guard is deliberately *not* told what the rule claims. It is told the rule's
**identity** and looks the permissions up itself. A rule that lied about its
roots would therefore be lying to nobody: the value it forged is never read.

Called twice on purpose -- once while scanning, and again immediately before
each destructive operation. Re-checking is not redundancy. Another local process
may replace a target with a junction, or a path may change, between the two; the
second check is what makes that race lose rather than win.
"""
from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from polyscour.safety import reparse
from polyscour.safety.policy import (
    Operation,
    PolicyViolation,
    entry_for,
    permitted_roots,
)


class GuardRefusal(Exception):
    """The guard refused a target.

    Never benign. Reaching this means either a bug in a rule or scanner, or
    something on the machine actively interfering -- so it is surfaced as a hard
    failure rather than folded in with locked files and missing paths.
    """


def _denied_roots() -> list[Path]:
    r"""Directories nothing may ever touch, independent of any rule.

    Resolved from the environment rather than hard-coded to ``C:\``: a machine
    booting from another volume would otherwise be protected at the wrong paths,
    which is worse than not being protected, because it looks like it is.

    ``Downloads`` is deliberately included. It is where a maintenance tool is
    most tempted to look for "junk", and it is where users keep things they have
    not filed yet.
    """
    out: list[Path] = []

    system_root = os.environ.get("SystemRoot", "").strip()
    if system_root:
        out += [Path(system_root) / "System32", Path(system_root) / "SysWOW64"]

    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(var, "").strip()
        if val:
            out.append(Path(val))

    profile = os.environ.get("USERPROFILE", "").strip()
    if profile:
        p = Path(profile)
        out += [p / n for n in ("Documents", "Desktop", "Pictures", "Videos",
                                "Music", "Downloads", "Favorites")]
    return out


def _is_within(child: Path, parent: Path) -> bool:
    """Case-insensitive containment, on canonical paths."""
    c = [p.lower() for p in child.parts]
    p = [q.lower() for q in parent.parts]
    return c[:len(p)] == p


class Guard:
    """Authorises individual targets. One instance per scan or execution."""

    def __init__(self, exclusions: Iterable[Path] = ()) -> None:
        self._exclusions = [Path(e).resolve(strict=False) for e in exclusions]
        self._denied = [d.resolve(strict=False) for d in _denied_roots()]
        self._roots: dict[str, list[Path]] = {}

    def begin(self) -> None:
        """Start a fresh operation, re-resolving every root family.

        Call at the top of each scan and each execution. Resolving a family is
        not cheap -- ``BROWSER_CACHE_CHROME`` globs the profile tree, measured at
        7.2 ms -- and ``authorize()`` runs once per candidate file, so without a
        per-operation cache a scan of a 36,000-file ``%TEMP%`` spent about four
        minutes doing nothing but re-globbing the same directories.

        Caching the *root set* for one operation does not weaken anything. What
        protects an individual path is the per-file reparse inspection of every
        component below the root, plus containment, the denylist and exclusions
        -- all of which still run on every single file, every time. The roots
        themselves are directories that ``resolve_family()`` already
        canonicalised.
        """
        self._roots.clear()

    def _roots_for(self, rule_id: str) -> list[Path]:
        if rule_id not in self._roots:
            self._roots[rule_id] = permitted_roots(rule_id)
        return self._roots[rule_id]

    # ── the one entry point ──────────────────────────────────────────────────

    def authorize(self, rule_id: str, target: Path,
                  operation: Operation) -> Path:
        """Return the canonical target, or raise ``GuardRefusal``.

        The return value is the *canonical* path, and callers must act on that
        rather than on what they passed in -- acting on the unresolved path
        would reintroduce exactly the ambiguity this resolved.
        """
        try:
            entry = entry_for(rule_id)
        except PolicyViolation as exc:
            raise GuardRefusal(str(exc)) from exc

        if operation not in entry.operations:
            raise GuardRefusal(
                f"rule {rule_id!r} is not permitted to {operation.value}; "
                f"its policy allows {sorted(o.value for o in entry.operations)}")

        roots = self._roots_for(rule_id)
        if not roots:
            raise GuardRefusal(
                f"rule {rule_id!r} has no resolvable root on this machine")

        canonical = self._contained_in_a_permitted_root(rule_id, target, roots)
        self._refuse_denied(canonical)
        self._refuse_excluded(canonical)
        return canonical

    # ── the links in the chain ───────────────────────────────────────────────

    def _contained_in_a_permitted_root(self, rule_id: str, target: Path,
                                       roots: list[Path]) -> Path:
        """Find the one permitted root this target legitimately sits under.

        Every root is tried because a family can resolve to several directories
        (Chrome has one cache per profile). The *first* refusal is kept for the
        error message rather than the last: it is the one from the root the
        target most plausibly belonged to.
        """
        first_error: Exception | None = None
        for root in roots:
            try:
                # Roots come from resolve_family(), already canonical.
                return reparse.assert_within(root, target,
                                             root_is_canonical=True)
            except reparse.ReparseRefusal as exc:
                # A reparse refusal is decisive, not a near-miss to keep trying
                # past: the target IS under this root and something redirected
                # it. Trying the next root could only find a way to say yes.
                raise GuardRefusal(str(exc)) from exc
            except reparse.ContainmentRefusal as exc:
                first_error = first_error or exc
        raise GuardRefusal(
            f"rule {rule_id!r} may not touch {target}: it is under none of its "
            f"permitted roots ({first_error})")

    def _refuse_denied(self, canonical: Path) -> None:
        """The denylist, applied last and independently of any rule.

        Checked in both directions. Being *inside* a denied root is the obvious
        case; *containing* one is the dangerous one -- deleting a directory that
        holds ``Documents`` takes ``Documents`` with it, and a containment-only
        check would wave it through.
        """
        for denied in self._denied:
            if _is_within(canonical, denied):
                raise GuardRefusal(
                    f"refusing {canonical}: inside the protected location {denied}")
            if _is_within(denied, canonical):
                raise GuardRefusal(
                    f"refusing {canonical}: it contains the protected "
                    f"location {denied}")

    def _refuse_excluded(self, canonical: Path) -> None:
        for excluded in self._exclusions:
            if _is_within(canonical, excluded):
                raise GuardRefusal(
                    f"refusing {canonical}: excluded by the user ({excluded})")

    # ── introspection, for the UI and for diagnostics ────────────────────────

    @property
    def exclusions(self) -> list[Path]:
        """The user's own additions, canonical.

        Public because they have to cross a process boundary: the elevated
        helper cannot read the invoking user's settings, so the executor sends
        them with the request. Safe to send, because an exclusion can only ever
        narrow what is deleted — see docs/adr/0004.
        """
        return list(self._exclusions)

    @property
    def protected_locations(self) -> list[Path]:
        """What the denylist currently covers, so Settings can show it.

        A user who cannot see what is protected has to take it on trust, which
        is the thing this product is trying not to ask for.
        """
        return list(self._denied)
