# 0002 — Cleaning rules name symbolic root families, never paths

**Status:** Accepted · **Date:** 2026-09-05

## Context

Cleaning rules are data, loaded from `rules/cleaners/*.json`, and data is
untrusted — it can be edited, corrupted, or replaced by another local process.

The plan's stated principle was "configuration is not authority": a rule
declares what it *claims* to own, and the executor independently re-validates
each concrete target.

Review then asked the sharpening question: where does the independent authority
actually come from? Checking `target in rule.declared_roots` is **not** a safety
property. A hostile rule simply declares:

```json
{"roots": ["C:\Users\me\Documents"]}
```

and satisfies the check it was supposed to fail.

## Decision

Rules do not name paths at all.

A rule names a symbolic `RootFamily` — `USER_TEMP`, `BROWSER_CACHE_CHROME`,
`CRASH_DUMPS` — and only `polyscour/safety/policy.py` knows what a family
resolves to. `POLICY` maps each rule id to its permitted families, operations,
scope and ceilings. **A rule id absent from `POLICY` fails to load.**

Authority only narrows: a rule may declare fewer families or tighter ceilings
than its entry grants, never more.

## Why this rather than the proposed validation

Review proposed a `RuleTrustPolicy` mapping rule ids to approved root families,
validated against the rule's declaration. That is correct and would work. Going
one step further and removing the declaration entirely is strictly better:

- A rule file that **cannot contain a path** cannot widen its reach by editing
  one. The attack has nowhere to land, rather than being caught.
- Adding a cleaner becomes a **code change that goes through review** — a new
  `RootFamily`, a resolver, and a `PolicyEntry` — rather than a JSON edit.
- Wildcards (`User Data/*/Cache`) expand in code, so the glob cannot be widened
  by data either.

## Consequences

- Adding a rule is deliberately more work. This is the intended friction.
- The set of reachable locations is enumerable by reading one file, which is
  what makes `docs/SAFETY.md` checkable rather than aspirational.
- Remote rule updates, if they ever exist, can only ever adjust patterns, ages
  and ceilings *within* an already-reviewed family — never introduce a location.
