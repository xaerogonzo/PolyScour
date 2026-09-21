# Cleaning rules

A rule is **data**. It describes an intent. It does not — cannot — grant itself
permission to touch anything.

## Adding a rule is a code change

This is deliberate friction. Three things must line up, and two of them are code
that goes through review:

1. A `RootFamily` member and its resolver, in `safety/policy.py`
2. A `PolicyEntry` in `POLICY`, in `safety/policy.py`
3. A JSON file in `rules/cleaners/`

A JSON file alone will not load. `entry_for()` raises `PolicyViolation` for an
unknown rule id, and the error says why.

## The format

```json
{
  "id": "chrome-cache",
  "name": "Google Chrome cache",
  "description": "Chrome's on-disk page cache, for every profile. Rebuilt as you browse. Cookies, history and saved passwords are NOT touched.",
  "category": "Browser",
  "risk": "safe",
  "root_families": ["browser_cache_chrome"],
  "patterns": ["*"],
  "conditions": ["chrome_not_running"],
  "min_age_days": 0,
  "expected_scope": "entire_user_cache",
  "limits": { "max_candidates": 200000 },
  "requires_elevation": false
}
```

| Field | Notes |
|---|---|
| `id` | Must have a matching `PolicyEntry`, or the rule does not load |
| `description` | Shown to the user verbatim. Say what is *not* touched, too. |
| `risk` | `safe` / `low` / `moderate` / `high` / `critical`. Only `safe` is pre-ticked. |
| `root_families` | **Symbolic.** Must be a subset of the policy's families. |
| `patterns` | `fnmatch` against the filename only |
| `conditions` | e.g. `chrome_not_running`. An unknown answer counts as *not met*. |
| `min_age_days` | Files newer than this are ignored |
| `expected_scope` | Must equal the policy's scope — disagreement means one is wrong |
| `limits` | May **lower** a policy ceiling, never raise it |
| `requires_elevation` | Findings are offered but never pre-ticked |

Note what the format cannot express: **a path**. Locations are named
symbolically and resolved only by code. A test asserts no shipped rule contains
`:\`, `%TEMP%`, `..\` or anything else path-like.

## Reversibility is derived, not declared

The `operation` comes from the `PolicyEntry` — `DELETE` or `VAULT` — and
`reversible` follows from it. A rule cannot promise the user an undo its
permissions do not actually allow.

Choose `VAULT` when the data is **not regenerable** and someone might want it
back. Choose `DELETE` for caches, and accept the "Not reversible" label:
vaulting a cache would not free any space, so pretending it was recoverable
would be a lie in exchange for nothing.

## Ceilings

Every rule has `max_candidates`, `max_bytes` and `max_depth`. Exceeding one
**aborts the rule and reports**, rather than truncating. A partial figure
presented confidently is worse than an honest failure.

## Before you ship one

- [ ] Does the description say what is *not* touched?
- [ ] Is `risk` honest? `safe` means genuinely regenerable.
- [ ] Does it need a `condition` — would cleaning it while an app is open hurt?
      **Find out, don't assume:** read what the tool does when its cache vanishes
      (pip's `SafeFileCache` tolerates it), and check what Windows does to a file
      the tool holds open (it refuses the delete). Conditions match process
      *names*, so never add one you cannot actually satisfy — a check that reads
      "fine" when the tool is launched a different way is no check
      (`docs/adr/0009`, decision 2).
- [ ] Does the tool let a user **move its cache**? Then the family must name the
      *default* location and read none of the tool's configuration — an
      environment variable or ini file is data, and following it lets somebody
      else aim the rule (`docs/adr/0009`, threat T25).
- [ ] Are the ceilings tight enough that a mistake aborts rather than deletes?
      Is `max_depth` **measured against the real layout**, and is there a test that
      builds that layout and requires every file to be found? A ceiling that stops
      short leaves most of the cache behind, silently.
- [ ] Is `expected_scope` what a scan actually produces?
- [ ] Are the bytes really **yours to free**? Hardlinked or shared files free
      nothing until their last name goes (conda's package cache is 68% shared).
- [ ] Would you be happy for this to run unattended on your own machine?
