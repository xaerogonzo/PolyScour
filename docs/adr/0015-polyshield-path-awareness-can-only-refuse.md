# 0015 — PolyShield's answer about a path can only ever make PolyScour do less

**Status:** Accepted · **Date:** 2026-10-06

## Context

PolyShield records detections. PolyScour deletes temporary files, browser
caches and crash dumps from the places malware most often drops things. The
collision is easy to picture: PolyShield detects `evil.exe` in `%TEMP%`, a
person (or, now, an unattended schedule — ADR 0014) runs Clean, and the evidence
and the quarantine target are gone before anyone looked at them.

PolyScour's side of the relationship had been three read-only questions —
`PING`, `STATUS`, `GET_INTEL_STATUS` — feeding one dashboard tile, and its own
docstring said a path-level query would be added "only when a concrete,
committed feature needs one". This is that feature. The query was added on
PolyShield's side **first** (its PR #35, `PATH_STATUS`), shaped by what this
side needed rather than discovered afterwards: a request of one absolute path,
a reply of `{ok, watched, flagged}`, string-only on PolyShield's side (so it
cannot follow a junction), and a refusal (`ok: false`) rather than a guess for
any path it cannot sensibly answer about.

Three things about that reply decide the design.

* `watched` and `flagged` are different facts. "PolyShield monitors this
  location" and "PolyShield has a recorded detection here" are not the same
  sentence, and only the second is any business of the cleaner.
* `flagged` means *a recorded detection at this path or beneath it*, read from
  PolyShield's **capped** event log. `flagged: false` is therefore "no recorded
  detection", never "safe".
* It is monotonic: a flagged file makes every directory above it flagged.

## Decision 1 — Three outcomes, kept apart; UNKNOWN blocks and clears nothing

Earlier drafts said "fail closed", which in security prose means *failure →
deny*, and which here would have made PolyShield a hard dependency of the
cleaner. The behaviour is three separate things, and each is tested:

| What happened | Treated as |
|---|---|
| A reply of the wrong shape (not booleans, no `ok`) | rejected → UNKNOWN. Something else on the port is not a degraded PolyShield. |
| No reply at all (not installed, not running, no token, timed out) | UNKNOWN |
| PolyShield refused the path (`ok: false`, which is also what a service older than PR #35 says to an unknown command) | UNKNOWN |
| **UNKNOWN** | **PolyScour carries on under its own guard chain exactly as before.** It grants no clearance and blocks nothing. |

Only `flagged: true` changes anything, and only by doing less. An optional
integration that could stop the cleaner would no longer be optional, and the
suite asserts the scan is identical across absent, too-old, nonsense, gone and
present-but-clean (`tests/test_polyshield_paths.py`).

## Decision 2 — A link at the end of the guard chain that can only refuse

`Guard._refuse_flagged` runs last, after policy, roots, reparse inspection,
containment, the denylist and exclusions have all said yes, and may only take
that back. No answer — true, false, forged, absent — can add a path to what is
permitted, because every earlier link has already decided and this one cannot
overrule them in that direction. That is the same test every input to the
elevated helper has to pass (CLAUDE.md: *may narrow, never widen*), and it is
the reason the helper may ask at all: something impersonating PolyShield gains,
at most, the power to make a clean do less. A test hands the guard an advisor
that says "clean" about everything and shows a path outside the permitted roots
is still refused.

The advisor is **injected and off by default** (`Guard(advisor=None)`), so every
bare `Guard()` — all existing tests, and any code that has not decided — never
opens a socket. The places that turn it on each do so in one visible line:
`Services` (the GUI), `scheduling/runner.py`, and both of the elevated helper's
guards. `tests/conftest.py` additionally points `PROGRAMDATA` at an empty
directory for every test, so a developer's real PolyShield can never be asked
about a temp directory the test just invented.

A flagged path surfaces as `PolyShieldFlagged`, a `GuardRefusal` subclass, so
anything that does not know about it still refuses — the safe default.

## Decision 3 — Its own benign skip reason, not `REFUSED_BY_GUARD`

`SkipReason.REFUSED_BY_GUARD` is deliberately *not* benign: the guard refusing
something the planner produced means a bug or an attack, and it is worded
loudly for that reason. A detection PolyShield holds is neither; it is an
expected, deliberate condition. Folding it into the guard's refusal would make
every clean on a machine with a single detection read as a failure. It is
`SkipReason.FLAGGED_BY_POLYSHIELD`, benign, so the run reads "left some things
alone" (`SUCCESS_WITH_SKIPS`), and it must exist in the enum for another reason
too: the helper reports skips across a process boundary, and `_skips_from` maps
a reason it does not know to `ERROR`, which is not benign.

In a scan a flagged candidate is never offered, but it is **counted**
(`RuleOutcome.withheld_by_polyshield`) and the Clean screen says so — an offer
that is quietly absent is how a cleaner ends up doing less than it appears to.

## Decision 4 — Directories before files, one operation's cache, and a latch

A scan examines tens of thousands of files and the guard looks at each. One
socket round trip per file was never viable. `PathAdvisor` keeps the question
count proportional to the part of the tree that matters:

* **Top-down.** Because `flagged` is monotonic, one question about a rule's
  root answers for the whole tree when PolyShield says no. Only along a chain
  of "yes" answers does the walk continue towards a file. Measured, not argued:
  a 300-file tree with nothing recorded costs **1** question; the same scan
  with the naive "ask about every file" mutant costs **301**, and four tests
  fail against it.
* **A cache that lives exactly one operation.** `Guard.begin()` resets it at the
  top of every scan and every execution, so an answer never outlives the
  operation it was asked in. That is what makes a plain path key enough: the
  one way a path-keyed cache goes stale — a file at that path deleted and a
  different one created in its place — cannot span a scan *and* the delete after
  it, because the delete asks afresh. A detection recorded between the two is
  therefore still seen (tested).
* **A latch.** The first time PolyShield gives no reply at all, the rest of the
  operation does not ask again.

## Decision 5 — Storage and Startup get labels, never behaviour

Where PolyShield answers, a row may say it monitors the location, or holds a
detection at or beneath it. That is annotation; "so rank it / tick it /
recommend removing it" is the short step this project exists not to take, so
the boundary is in code (`views/polyshield_notes.py`), not only in prose: the
module is handed rows already laid out and can only add a label to one. It has
no handle on order, state, selection or any control, and a test scans its
source for each such word and proves the scan can fail. A row PolyShield says
nothing about is laid out exactly as before (no empty label, no extra row), a
machine without PolyShield sees no change, and the query is lazy — only the
rows on screen (Storage shows 12 per list), in one background pass after
drawing. The text export is unchanged: a label is live state, not part of what a
scan found.

## Decision 6 — A switch, which cannot reach the helper

`polyshield_path_checks` (Settings → PolyShield, on by default) turns off every question
asked as the user: the GUI's guard, scheduled runs, and the Storage and Startup labels.
`PathAdvisor` takes it as a callable and reads it per question, so it applies
immediately and off is *exactly* UNKNOWN — the same as PolyShield being absent, which
Decision 1 already guarantees is safe. It is not a separate code path.

**It does not reach the elevated helper, and cannot.** Disabling the check *widens*
what a clean may delete, and a helper input may only narrow — an off-switch carried
in a request is exactly what a compromised GUI would send. The helper also cannot read
the user's settings (CLAUDE.md: its `%LOCALAPPDATA%` need not be the same profile). So
the `windows-temp` step still asks. The Settings text and PRIVACY.md say so, rather
than let an off switch imply more than it does.

## Consequences

- `integrations/polyshield.py` grew from three read-only commands to four; a
  test checks statically that the client can only ever send read-only commands,
  and that the check can fail.
- `_send` gained a bound on the reply (64 KB) and a deadline on the whole
  exchange. A per-`recv` timeout resets on every byte, so a listener dripping one
  byte at a time would never time out; once a privileged process can ask, "whatever
  is listening on this port" can reach it.
- The query carries a **path**, which the earlier three did not. That changes
  `docs/PRIVACY.md`, and is recorded as T33 rather than glossed over.
- Rejected: **blocking when PolyShield is absent or silent** (a hidden hard
  dependency); **treating `flagged: false` as a clearance** (the log is capped);
  **a per-file query** (301 questions for 300 files); **a time-to-live or
  file-identity cache** (an operation-scoped cache needs neither); **no way to turn it off** (first draft: with no PolyShield it is inert, so a
  switch seemed unneeded — but it is the only control over *whether paths are
  sent*, and that deserved a person's say).
- Not covered: a detection recorded after the second guard call and before the
  `unlink` (a window of microseconds), and any path PolyShield's capped log has
  already forgotten. T31.
