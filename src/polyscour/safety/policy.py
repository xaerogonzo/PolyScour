r"""What each cleaning rule is *permitted* to touch. This file is the authority.

Configuration is not authority
------------------------------

A rule file is data, and data is untrusted. Checking ``target in
rule.declared_roots`` is not a safety property: a corrupted or hostile rule
simply declares::

    {"roots": ["C:\\Users\\me\\Documents"]}

and passes its own check.

So rules do not name paths at all. A rule names a **symbolic root family**, and
only this module -- code, reviewed, in the repository -- knows what a family
resolves to. A rule with no entry in ``POLICY`` fails to load. The consequence
is that a rule file which never contains a path cannot widen its own reach by
editing one, and adding a cleaner requires a code change that goes through
review rather than a JSON edit that does not.

``POLICY`` also owns the ceilings. A rule may be *stricter* than its policy
entry; it can never be looser. Authority only ever narrows as it flows outward.
"""
from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from pathlib import Path


class RootFamily(enum.Enum):
    """The only vocabulary a rule has for saying where it operates.

    Members are added alongside the code that resolves them, which is the point:
    there is no way to express a new location in a rule file alone.
    """
    USER_TEMP = "user_temp"
    WINDOWS_TEMP = "windows_temp"
    THUMBNAIL_CACHE = "thumbnail_cache"
    SHADER_CACHE = "shader_cache"
    BROWSER_CACHE_CHROME = "browser_cache_chrome"
    BROWSER_CACHE_EDGE = "browser_cache_edge"
    BROWSER_CACHE_FIREFOX = "browser_cache_firefox"
    CRASH_DUMPS = "crash_dumps"


class Operation(enum.Enum):
    """What may be done to a matched item."""
    DELETE = "delete"   # permanent; only for regenerable data
    VAULT = "vault"     # staged into the vault, restorable


class Scope(enum.Enum):
    """The blast radius a rule is expected to have.

    Checked against what a scan actually produced. A rule declaring
    ONE_DIRECTORY while returning findings across three volumes is a fault,
    and one worth failing a test over before hundreds of rules exist.
    """
    FILES_ONLY = "files_only"            # a handful of named files
    ONE_DIRECTORY = "one_directory"      # a single tree
    ENTIRE_USER_CACHE = "entire_user_cache"   # several trees under the profile
    SYSTEM_CACHE = "system_cache"        # machine-wide, needs elevation


def _env_dir(var: str, *parts: str) -> list[Path]:
    """One directory from an environment variable, or nothing if it is unset.

    Never falls back to a literal ``C:\\``: a machine booting from another
    volume would then be handed a path on the wrong disk.
    """
    base = os.environ.get(var, "").strip()
    if not base:
        return []
    return [Path(base).joinpath(*parts)]


def _globbed(var: str, pattern: str) -> list[Path]:
    """Profile-style expansion, e.g. ``User Data/*/Cache``.

    Expanded here rather than in a rule so that the wildcard cannot be widened
    by editing data. Only directories that exist are returned.
    """
    base = os.environ.get(var, "").strip()
    if not base:
        return []
    root = Path(base)
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob(pattern) if p.is_dir())


def _resolve(family: RootFamily) -> list[Path]:
    """The concrete directories a family stands for, on this machine, now."""
    if family is RootFamily.USER_TEMP:
        return _env_dir("TEMP") or _env_dir("LOCALAPPDATA", "Temp")

    if family is RootFamily.WINDOWS_TEMP:
        return _env_dir("SystemRoot", "Temp")

    if family is RootFamily.THUMBNAIL_CACHE:
        return _env_dir("LOCALAPPDATA", "Microsoft", "Windows", "Explorer")

    if family is RootFamily.SHADER_CACHE:
        out: list[Path] = []
        out += _env_dir("LOCALAPPDATA", "D3DSCache")
        out += _env_dir("LOCALAPPDATA", "NVIDIA", "DXCache")
        out += _env_dir("LOCALAPPDATA", "NVIDIA", "GLCache")
        out += _env_dir("LOCALAPPDATA", "AMD", "DxCache")
        return out

    if family is RootFamily.BROWSER_CACHE_CHROME:
        return (_globbed("LOCALAPPDATA", "Google/Chrome/User Data/*/Cache")
                + _globbed("LOCALAPPDATA", "Google/Chrome/User Data/*/Code Cache"))

    if family is RootFamily.BROWSER_CACHE_EDGE:
        return (_globbed("LOCALAPPDATA", "Microsoft/Edge/User Data/*/Cache")
                + _globbed("LOCALAPPDATA", "Microsoft/Edge/User Data/*/Code Cache"))

    if family is RootFamily.BROWSER_CACHE_FIREFOX:
        return (_globbed("LOCALAPPDATA", "Mozilla/Firefox/Profiles/*/cache2")
                + _globbed("APPDATA", "Mozilla/Firefox/Profiles/*/cache2"))

    if family is RootFamily.CRASH_DUMPS:
        return _env_dir("LOCALAPPDATA", "CrashDumps")

    raise ValueError(f"no resolver for {family!r}")


def resolve_family(family: RootFamily) -> list[Path]:
    """Existing, canonical directories for a family.

    Canonicalised here so that everything downstream compares like with like.
    A family that resolves to nothing (browser not installed) yields an empty
    list, which is a normal outcome rather than an error.
    """
    out: list[Path] = []
    for p in _resolve(family):
        try:
            if p.is_dir():
                out.append(p.resolve(strict=True))
        except OSError:
            continue      # unreadable or transient -- treat as absent
    return out


@dataclass(frozen=True)
class PolicyEntry:
    """The permissions and ceilings for exactly one rule id."""
    families: frozenset[RootFamily]
    operations: frozenset[Operation]
    scope: Scope
    #: Ceilings. A scan exceeding any of these aborts the rule and reports,
    #: rather than presenting 700 GB of somebody's filesystem as cache.
    max_candidates: int
    max_bytes: int
    max_depth: int


_C = RootFamily
_O = Operation

#: The built-in trust policy. A rule id absent from this mapping cannot load.
#:
#: Every entry is deliberately narrow: one family unless there is a reason for
#: more, DELETE only where the data provably regenerates, and VAULT wherever a
#: user might want it back.
POLICY: dict[str, PolicyEntry] = {
    "user-temp": PolicyEntry(
        families=frozenset({_C.USER_TEMP}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.ONE_DIRECTORY,
        max_candidates=200_000, max_bytes=64 * 1024**3, max_depth=12),

    "windows-temp": PolicyEntry(
        families=frozenset({_C.WINDOWS_TEMP}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.SYSTEM_CACHE,
        max_candidates=200_000, max_bytes=64 * 1024**3, max_depth=12),

    "thumbnail-cache": PolicyEntry(
        families=frozenset({_C.THUMBNAIL_CACHE}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.FILES_ONLY,
        max_candidates=2_000, max_bytes=8 * 1024**3, max_depth=1),

    "directx-shader-cache": PolicyEntry(
        families=frozenset({_C.SHADER_CACHE}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.ENTIRE_USER_CACHE,
        max_candidates=100_000, max_bytes=32 * 1024**3, max_depth=8),

    "chrome-cache": PolicyEntry(
        families=frozenset({_C.BROWSER_CACHE_CHROME}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.ENTIRE_USER_CACHE,
        max_candidates=200_000, max_bytes=32 * 1024**3, max_depth=8),

    "edge-cache": PolicyEntry(
        families=frozenset({_C.BROWSER_CACHE_EDGE}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.ENTIRE_USER_CACHE,
        max_candidates=200_000, max_bytes=32 * 1024**3, max_depth=8),

    "firefox-cache": PolicyEntry(
        families=frozenset({_C.BROWSER_CACHE_FIREFOX}),
        operations=frozenset({_O.DELETE}),
        scope=Scope.ENTIRE_USER_CACHE,
        max_candidates=200_000, max_bytes=32 * 1024**3, max_depth=8),

    # The one reversible rule in 0.1. A crash dump is not regenerable and
    # someone may still want it, so it is staged into the vault rather than
    # deleted -- and it is what proves the reversible path end to end.
    "crash-dumps": PolicyEntry(
        families=frozenset({_C.CRASH_DUMPS}),
        operations=frozenset({_O.VAULT}),
        scope=Scope.ONE_DIRECTORY,
        max_candidates=5_000, max_bytes=16 * 1024**3, max_depth=2),
}


class PolicyViolation(Exception):
    """A rule asked for something its policy entry does not grant.

    Raised at load time wherever possible, so a bad rule never reaches a scan.
    """


def entry_for(rule_id: str) -> PolicyEntry:
    """The policy for a rule, or a refusal.

    An unknown rule id is a hard failure rather than a permissive default: the
    whole design rests on a rule being unable to arrive without a reviewed
    policy entry beside it.
    """
    try:
        return POLICY[rule_id]
    except KeyError:
        raise PolicyViolation(
            f"rule {rule_id!r} has no entry in the trust policy. A cleaning "
            f"rule cannot grant itself permissions; add a reviewed PolicyEntry "
            f"in polyscour.safety.policy before shipping the rule file."
        ) from None


def permitted_roots(rule_id: str) -> list[Path]:
    """Every directory this rule may operate under, on this machine."""
    entry = entry_for(rule_id)
    roots: list[Path] = []
    for family in sorted(entry.families, key=lambda f: f.value):
        roots.extend(resolve_family(family))
    return roots
