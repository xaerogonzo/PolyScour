# 0014 — Scheduled cleaning consents once, at creation, to an exact reviewed definition

**Status:** Accepted · **Date:** 2026-09-27

## Context

Every feature PolyScour has shipped before this one assumes a person is at
the keyboard: dry-run defaults to on, the confirmation dialog names exactly
what will happen before it happens, and the README's Administrator-rights
section states plainly that PolyScour "asks... and never on its own."
Scheduled cleaning is the first feature that runs a destructive step with
nobody watching a confirmation dialog — that is the entire point of
"scheduled." The question this ADR answers is what a schedule's consent
actually has to mean for that to still be honest, not merely convenient.

The obvious implementation — a person picks some rule ids, PolyScour re-runs
those ids on a timer — quietly assumes a rule id is a stable, permanent
description of what will happen. It is not: a rule's JSON can change after
the schedule exists, and the safety policy behind every rule can too.

## Decision 1 — Consent binds to a hash of the reviewed definition, not the rule id

A `Schedule` (`scheduling/consent.py`) stores, per rule, a canonical SHA-256
digest of that rule's JSON at the moment the schedule was created
(`canonical_rule_digest`: sorted keys, no incidental whitespace — a cosmetic
edit does not change it, any semantic change does). Before every unattended
run, `scheduling/runner.py` recomputes the current digest of each consented
rule and refuses any rule whose digest no longer matches, rather than running
whatever that rule id currently means.

This is "a rule file is data, and data is untrusted"
(`safety/policy.py`'s own words) applied to a schedule's stored consent
rather than to the rule file alone — the same principle, aimed at a place
this project had not previously needed to aim it: a decision made once that
has to keep meaning the same thing across an unbounded number of future,
unattended invocations. See `docs/THREAT_MODEL.md` T28.

A refusal here is **per rule**, not per schedule: a three-rule schedule with
one changed definition still runs the other two. There is no single failed
item to blame for a whole-schedule refusal here, unlike Recycle Bin's
remainder case (ADR 0012) — this is closer to a scan finding a rule that
fails to load, reported and skipped, everything else proceeding.

## Decision 2 — A policy-version regression refuses the whole schedule

Decision 1 catches a changed rule file. It cannot catch a change to
`safety/policy.py` itself — a new `RootFamily`, a loosened ceiling — that
widens what an *unchanged* rule id may touch without changing that rule's own
JSON at all. `safety.policy.POLICY_VERSION` exists for exactly this: a single
integer, incremented only for a change that could widen an existing rule's
reach, never for one that only narrows it (a new denylist entry, a tightened
ceiling — these can only make a scheduled run do less, the same reasoning
that already lets an exclusion be accepted from an untrusted caller).

A schedule records the version current at creation. If the running version
has since moved past it, `scheduling/consent.verify()` refuses the **whole**
schedule, not a per-rule subset — the change is about the authority behind
every rule in it, not about any one of them. See `docs/THREAT_MODEL.md` T29.

This is read as a live module attribute (`safety_policy.POLICY_VERSION`), not
imported as a bound name, specifically so the check is unit-testable within
one process — a real version bump only ever takes effect between process
launches in production, since it is a code change shipped in a release, but a
bound-name import would make that same fact untestable without starting a
second process for every test.

## Decision 3 — Elevation is not a decision this code contains, not merely one it checks

A schedule's stored `elevation_allowed` field is always `False`, recorded for
the UI and the record, and `scheduling/runner.py` never reads it to decide
whether to elevate — `Executor` is constructed with its default
`allow_elevation=False` and there is no branch in the runner that could set
it otherwise. This is deliberately stronger than "checked and refused": it is
not a possibility the function contains, rather than a possibility it
declines every time. `scheduling/consent.eligible_rule_ids()` additionally
excludes every `requires_elevation` rule from ever being offered when a
schedule is created, so the UI cannot select one in the first place. See
`docs/THREAT_MODEL.md` T30.

## Decision 4 — Disabling stops future runs; it does not revoke one already running

`scheduling/service.set_enabled()` disables both the Task Scheduler task
itself (`schtasks /change .../disable`) and the stored `Schedule.enabled`
flag the runner checks first on every invocation — either one failing alone
still leaves the other in place. Disabling never cancels an operation already
in progress: that operation follows the executor's existing cancellation
semantics (the same `cancel: threading.Event` every other operation already
respects), and the two are kept conceptually separate rather than one
silently trying to also mean the other.

## Consequences

- Delivery is Windows Task Scheduler, per-user, unelevated (`/rl LIMITED`),
  and interactive-token-only (`/it` — the task only runs while the person is
  logged on, never as a hidden background job). `polyscour.exe
  --scheduled-clean <schedule-id>` is the only thing it is ever told to run.
- `scheduling/task.py::verify()` re-checks the *live* Task Scheduler task
  against what PolyScour created before every run — not a privilege boundary
  (the task is unelevated either way), but an integrity check: a task altered
  outside PolyScour is treated as untrusted rather than assumed unchanged.
  This goes through PowerShell's `Get-ScheduledTask` rather than parsing
  `schtasks /query /xml`, because the latter was measured to silently corrupt
  long element values (`docs/gotchas/windows-subprocess.md` #7) — a real
  finding made while building this feature, not a hypothetical one.
- Every real cleanup a schedule performs still reaches History exactly like a
  manual one, through the same `ledger.record()` call inside
  `Executor.execute()` — nothing schedule-specific was added to the ledger,
  because a scheduled run is not a new kind of operation, only a new caller.
- What is *not* solved: a schedule's own stored data being hand-edited by the
  same logged-in user who created it is not a threat this defends against —
  that is the same trust boundary `settings.json` already has, not a new
  attack surface. And the discipline of correctly incrementing
  `POLICY_VERSION` for a genuinely widening change is a review responsibility
  this mechanism cannot itself enforce; it is stated as a checklist item in
  `safety/policy.py`'s own module docstring instead.
