r"""The closed set of things the elevated helper will do, and their shapes.

Specified in ``docs/THREAT_MODEL.md`` under "The elevated helper", written
before any of this existed. This module is the machine-readable half of that
section, shared by both sides so the client cannot construct a request the
helper does not understand and the helper cannot be surprised by one.

Why a closed set is the whole design
------------------------------------

There is no ``ExecuteCommand(string)``, no ``RunPowerShell(script)``, and no
``DeletePath(path)`` that takes a path and obeys. Every operation is named, its
parameters are typed, and adding one is a reviewed code change to a signed
binary — the same friction adding a cleaning rule already has.

The point is what it bounds: **the worst thing a compromised GUI can ask for is
the worst thing on this list.** A single generic operation would make that
sentence meaningless, which is why "just add a passthrough for now" is the one
change this file exists to refuse.

Shape validation is not authorisation
-------------------------------------

Everything here checks that a request is *well-formed*: known operation, right
parameters, right types. That is a convenience, not a security property. A
well-formed request to delete ``C:\Windows`` parses perfectly.

The authorisation happens in the helper, at full privilege, by re-running the
guard chain — see :mod:`polyscour.elevation.helper`. Nothing in this module
should ever be mistaken for a permission check.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum


class Operation(Enum):
    """Everything the helper will do. Additions are reviewed code changes."""

    #: Delete one path on behalf of a rule that needs administrator rights.
    #: Exists because `windows-temp` ships and is always skipped without it.
    DELETE_APPROVED_PATH = "delete_approved_path"

    #: Delete everything one rule is permitted to delete, under a single
    #: prompt. Exists because per-file elevation makes `windows-temp` several
    #: hundred UAC dialogs, and a prompt nobody reads is not consent.
    #:
    #: Note what it does NOT take: a path. This operation is *narrower* than
    #: DELETE_APPROVED_PATH -- the caller cannot name a target at all, so its
    #: best move is to ask for what an honest caller would have asked for. See
    #: docs/adr/0004 and THREAT_MODEL T19.
    DELETE_APPROVED_PATHS_FOR_RULE = "delete_approved_paths_for_rule"

    #: Flip the StartupApproved byte in HKLM. Exists because machine-wide
    #: startup entries are listed and refused without it.
    SET_MACHINE_STARTUP_APPROVAL = "set_machine_startup_approval"


#: parameter name -> type, per operation. The helper refuses anything that does
#: not match exactly: no extra keys, no missing ones, no coercion. Coercion is
#: how "1" becomes True and a refusal becomes an approval.
_PARAMS: dict[Operation, dict[str, type]] = {
    Operation.DELETE_APPROVED_PATH: {"rule_id": str, "path": str},
    Operation.DELETE_APPROVED_PATHS_FOR_RULE: {"rule_id": str,
                                               "exclusions": list},
    Operation.SET_MACHINE_STARTUP_APPROVAL: {"value_name": str,
                                             "enabled": bool,
                                             "expected_raw_value": str},
}

#: The one place a string parameter may legitimately be empty. Named as a pair
#: rather than granted per-name, so adding a second one is a visible decision.
#:
#: A Run value can genuinely hold empty data, and refusing the request would
#: make such an entry untoggleable for a reason the user could not act on. The
#: emptiness check exists to catch a caller's typo becoming a path -- there is
#: no path here to become.
_MAY_BE_EMPTY: frozenset[tuple[Operation, str]] = frozenset({
    (Operation.SET_MACHINE_STARTUP_APPROVAL, "expected_raw_value"),
})


class MalformedRequest(ValueError):
    """The request is not a shape this protocol defines."""


@dataclass(frozen=True)
class Request:
    operation: Operation
    params: dict

    def to_json(self) -> str:
        return json.dumps({"operation": self.operation.value,
                           "params": self.params}, ensure_ascii=False)

    @staticmethod
    def from_json(text: str) -> "Request":
        """Parse and shape-check. Raises :class:`MalformedRequest`.

        Deliberately strict about *extra* parameters as well as missing ones.
        An unexpected key means the sender and this helper disagree about what
        the operation is, and proceeding on the overlap is how a request gets
        interpreted as something it was not.
        """
        try:
            raw = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise MalformedRequest(f"not JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise MalformedRequest("request must be a JSON object")

        try:
            operation = Operation(raw.get("operation"))
        except ValueError:
            raise MalformedRequest(
                f"unknown operation {raw.get('operation')!r}") from None

        params = raw.get("params")
        if not isinstance(params, dict):
            raise MalformedRequest("params must be an object")

        expected = _PARAMS[operation]
        missing = sorted(set(expected) - set(params))
        extra = sorted(set(params) - set(expected))
        if missing:
            raise MalformedRequest(f"missing parameter(s): {', '.join(missing)}")
        if extra:
            raise MalformedRequest(f"unexpected parameter(s): {', '.join(extra)}")

        for name, kind in expected.items():
            value = params[name]
            # bool is a subclass of int; check it first or True passes as an int
            # and a caller's typo becomes a silently accepted value.
            if kind is bool and not isinstance(value, bool):
                raise MalformedRequest(f"{name} must be a boolean")
            if kind is not bool and not isinstance(value, kind):
                raise MalformedRequest(f"{name} must be {kind.__name__}")
            if kind is str and not value.strip():
                if (operation, name) not in _MAY_BE_EMPTY:
                    raise MalformedRequest(f"{name} must not be empty")
            if kind is list:
                # isinstance(value, list) says nothing about what is in it, and
                # the elements here become guard input. An empty list is valid
                # -- it means the user configured no exclusions.
                for element in value:
                    if not isinstance(element, str):
                        raise MalformedRequest(
                            f"{name} must contain only strings")
                    if not element.strip():
                        raise MalformedRequest(
                            f"{name} must not contain empty strings")

        return Request(operation=operation, params=dict(params))


@dataclass(frozen=True)
class Response:
    """What the helper reports back. Advisory only.

    Nothing security-relevant depends on the GUI believing this: it exists so
    the change can be recorded and shown, and a lying response can only produce
    a wrong History entry, never a wrong privileged action.
    """
    ok: bool
    detail: str = ""
    refused_by: str = ""          # which link in the chain said no
    data: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"ok": self.ok, "detail": self.detail,
                           "refused_by": self.refused_by, "data": self.data},
                          ensure_ascii=False)

    @staticmethod
    def from_json(text: str) -> "Response":
        """Never raises. An unreadable response is a failed operation.

        The client cannot distinguish "the helper refused" from "the helper
        crashed before writing", and must not try: both mean the privileged
        work did not verifiably happen, which is the only thing the caller can
        act on.
        """
        try:
            raw = json.loads(text)
            if not isinstance(raw, dict):
                raise ValueError("not an object")
            return Response(ok=bool(raw.get("ok")),
                            detail=str(raw.get("detail", "")),
                            refused_by=str(raw.get("refused_by", "")),
                            data=raw.get("data") if isinstance(raw.get("data"), dict) else {})
        except (ValueError, TypeError):
            return Response(False, "the helper did not return a readable result")
