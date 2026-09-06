r"""Reparse-point inspection, done *before* canonicalisation.

Order of operations is the entire point of this module.

``Path.resolve()`` **follows** junctions and symlinks. Canonicalising first and
then checking containment therefore asks the wrong question: it asks "where did
we end up", after the traversal that needed permission has already conceptually
happened. A junction planted inside a cache directory and pointing at
``C:\Users\me\Documents`` resolves to a path under ``Documents`` -- and a
containment check against the cache root then correctly *rejects* it, so the
naive order is not catastrophic. But it is fragile in a way worth removing:

  * it cannot distinguish "this rule legitimately spans two resolved trees"
    from "something redirected us", so it has to be conservative everywhere; and
  * the moment a rule legitimately needs a resolved root that differs from its
    literal one, the check has to be relaxed, and the relaxation is invisible.

So the traversal is inspected component by component, and a disallowed reparse
point is refused **as a reparse point**, by name, before anything is resolved.
Canonicalisation still happens afterwards, and containment is still re-verified
against the canonical form -- belt and braces, in that order.

The threat this closes is a live one: another local process may replace a target
directory with a junction *between* the scan and the execution. Re-inspecting at
execution time, rather than trusting the scan's verdict, is what makes that race
lose.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

#: Set on any file or directory carrying a reparse point -- junctions, symlinks,
#: mount points, and the OneDrive/AppX placeholder tags alike.
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ReparseRefusal(Exception):
    """A path component carries a reparse point that is not permitted here."""


class ContainmentRefusal(Exception):
    """A target escaped its permitted root, or changed volume."""


def is_reparse_point(path: Path) -> bool:
    """True if this exact path is a reparse point, without following it.

    Uses ``lstat`` so the link itself is examined rather than its destination.
    A path that cannot be stat'd is reported as not-a-reparse-point; the caller
    finds out it is missing from the operation itself, where the error is
    specific.
    """
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        return bool(attrs & _REPARSE)
    return stat.S_ISLNK(st.st_mode)      # non-Windows fallback, for test rigs


def _relative_parts(root: Path, target: Path) -> list[str]:
    """The components of `target` below `root`, or raise if it is not below it.

    Compared case-insensitively because Windows paths are, and a check that
    treats ``C:\\Users`` and ``C:\\users`` as different roots is not a check.
    """
    try:
        return list(target.relative_to(root).parts)
    except ValueError:
        pass
    r = [p.lower() for p in root.parts]
    t = [p.lower() for p in target.parts]
    if t[:len(r)] != r:
        raise ContainmentRefusal(f"{target} is not under {root}")
    return list(target.parts[len(r):])


def inspect_chain(root: Path, target: Path) -> None:
    """Refuse if any component from `root` down to `target` is a reparse point.

    `root` itself is not inspected: it arrives already resolved from
    ``policy.resolve_family()``, and a machine whose ``%TEMP%`` is legitimately
    a junction is a configuration this product should tolerate rather than
    refuse. Everything *below* it is the attack surface, and every level of it
    is checked -- a junction five directories down is as effective as one at the
    top.
    """
    walked = root
    for part in _relative_parts(root, target):
        walked = walked / part
        if is_reparse_point(walked):
            raise ReparseRefusal(
                f"refusing to traverse a reparse point at {walked} "
                f"(while walking to {target})")


def same_volume(a: Path, b: Path) -> bool:
    """Whether two canonical paths live on the same volume.

    Compared by drive rather than by ``st_dev``: a mount point can put another
    volume inside a directory tree while both sides still stat as reachable, and
    the drive letter is what the user reasons about.
    """
    return a.drive.lower() == b.drive.lower()


def assert_within(root: Path, target: Path,
                  root_is_canonical: bool = False) -> Path:
    """The full check, in the order that matters. Returns the canonical target.

    1. inspect every component below `root` for reparse points, unresolved
    2. canonicalise
    3. re-verify containment against the canonical form
    4. verify the volume did not change

    Steps 3 and 4 are not redundant with step 1. Step 1 refuses a redirection we
    can see; steps 3 and 4 catch one we could not -- a component replaced
    between the ``lstat`` and the ``resolve``, which is precisely the race this
    is written to lose gracefully.

    ``root_is_canonical`` skips re-resolving the root. Callers that got it from
    ``policy.resolve_family()`` already have a canonical path, and this runs once
    per candidate file -- a redundant ``resolve()`` on the same directory
    thirty thousand times is measurable and buys nothing.
    """
    inspect_chain(root, target)

    try:
        canonical = target.resolve(strict=False)
    except OSError as exc:
        raise ContainmentRefusal(f"cannot canonicalise {target}: {exc}") from exc

    canonical_root = root if root_is_canonical else root.resolve(strict=False)
    _relative_parts(canonical_root, canonical)      # raises if it escaped

    if not same_volume(canonical_root, canonical):
        raise ContainmentRefusal(
            f"{canonical} is on a different volume from {canonical_root}")

    return canonical
