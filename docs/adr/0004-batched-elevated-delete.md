# 0004 — The batched elevated delete takes a rule, not a list of paths

**Status:** Accepted · **Date:** 2026-09-07

## Context

The elevated helper shipped with `DeleteApprovedPath(rule_id, path)`, and the
executor called it once per file. Each call is a `ShellExecute("runas")`, so
each call is a UAC prompt.

`C:\Windows\Temp` holds several hundred files on an ordinary machine. The
`windows-temp` rule is therefore, as wired, several hundred consecutive consent
dialogs — which nobody will read, and which nobody would finish.

`THREAT_MODEL.md` had already named this as the decision it was deferring:

> Batching a whole cleaning run behind one prompt is a legitimate future
> request and would need its own entry here, because "one prompt, many deletes"
> is a materially different bargain from "one prompt, one delete".

So the question is not whether to batch. It is what a batched operation is
allowed to be told.

## Decision

A new operation, `DeleteApprovedPathsForRule`, taking `rule_id` and
`exclusions` — **and no path of any kind.**

The helper resolves the rule's permitted root families through its own copy of
`safety/policy.py`, enumerates them itself, and runs the full guard chain
against every candidate it finds.

`DeleteApprovedPath` stays. A single-file elevated delete is still a coherent
operation, and it is the shape the existing tests exercise.

## Why this is narrower than what it replaces

The instinct is that a batch operation is a bigger hole than a single
operation. Here it is the reverse, and the reason is worth stating because it
is the whole justification:

| | Caller supplies | Worst request a compromised GUI can make |
|---|---|---|
| `DeleteApprovedPath` | a rule **and a path** | a path of its choosing, which the guard must then refuse |
| `DeleteApprovedPathsForRule` | a rule | a rule id that was already in the reviewed policy table |

The batched form **removes a parameter**. The caller loses the ability to name
a target at all, so its best move is to ask for exactly what an honest caller
would have asked for: everything that rule is permitted to delete. The guard
still refuses each candidate individually; it simply never sees an
attacker-chosen path to refuse.

This is the same move `0002` made for rules. A rule that cannot name a path
cannot lie about which path it wants, and neither can a request.

## What one consent covers

Bounded by reviewed code rather than by the request: *everything this rule is
permitted to delete, that exists at that moment, and that the guard approves
one at a time.* The user is shown the rule and the count before the prompt, per
T18 — a consent surface that says "412 files from `C:\Windows\Temp`" is a
different thing from one that says "grant administrator rights".

## The batch is not a transaction

`authorize()` runs immediately before **that item's** `unlink()`. Never once
for the group.

This is the invariant most likely to be optimised away by someone reading the
loop later, so it is recorded here as well as in the code: authorising four
hundred paths and then deleting four hundred paths would collapse the TOCTOU
protection of T3 into one check with a long window behind it. The cost of doing
it per item is a few hundred cheap syscalls. The saving from hoisting it is
nothing anyone would notice, and the loss is the property the whole design is
for.

A sharing violation is a skip and the loop continues. **Never force** — no
handle closing, no read-only bit clearing, in the helper least of all, where it
would run at full privilege.

## Known residual: the path-resolution window

`os.unlink()` takes a path and resolves it again. So even per item, a window
remains between the guard approving a canonical path and the deletion resolving
it — on the order of one syscall.

Closing it properly means never re-resolving: open the object with
`CreateFileW` using `FILE_FLAG_OPEN_REPARSE_POINT`, verify it, and delete
through that handle with `FileDispositionInfo`, so the object deleted is
provably the object inspected.

**Not built, deliberately.** It is a meaningful amount of `ctypes` around a
window that the component-wise reparse check of T2 already makes hard to drive
rather than merely brief — an attacker needs to win a race whose result must
also survive a reparse inspection performed a syscall earlier. Recorded as a
residual with its mitigation named, because the alternative is a half-built
handle path that looks like protection and is not.

## Exclusions cross the privilege boundary

The helper cannot read the invoking user's settings: launched through `runas`,
its `%LOCALAPPDATA%` need not resolve to the same profile. Before this, the
helper constructed `Guard()` with no exclusions at all — so a path the user had
explicitly protected was honoured unelevated and deleted elevated. The setting
meant two different things depending on which privilege level reached the file.

Exclusions therefore travel in the request. This is the only place untrusted
input shapes what the helper does, and it is safe for one reason:

> An exclusion can only ever **narrow** what is deleted. A caller that lies
> about them makes the helper delete less, never more.

That is the test any future parameter must pass. `expected_raw_value` on the
startup operation passes it too: it can only cause a refusal. Anything that
could *add* to the permitted set never passes it, whatever it is called.

## Consequences

- One UAC prompt per rule that needs one, not one per file.
- A batch can outlive the client's 120-second timeout, so the protocol gains a
  progress heartbeat and a cancel sentinel. Without the heartbeat the GUI would
  report failure and re-scan while an elevated process was still deleting.
- The helper now enumerates, which it did not before. Enumeration is inside the
  privilege boundary, so a directory it cannot read is a skip, not a failure.
- `Response.data` carries per-item skip reasons; the **executor** classifies
  them through the existing `contracts.classify()`. The protocol does not get a
  second outcome vocabulary.
