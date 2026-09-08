# 0005 — The vault stays in %LOCALAPPDATA%, and stops waiting for the installer

**Status:** Accepted · **Date:** 2026-09-07
**Supersedes:** the *Migration* section of
[0001-vault-location.md](0001-vault-location.md). Everything else in 0001 stands.

## Context

0001 chose `%LOCALAPPDATA%` for 0.1 and deferred the real answer:

> Move to `%ProgramData%\PolyScour` in 0.2, **alongside the installer and the
> elevated helper** — at the point where per-subtree ACLs can be set *before*
> the app first runs, which is the only time doing it is an improvement.

The elevated helper has now landed. Planning the installer meant writing the
ACL split down, and writing it down is what exposed the problem: **0001's
premise does not survive contact with what PolyScour actually is.**

## The thing 0001 did not check

`%ProgramData%` makes PolyShield's data a boundary because PolyShield has a
**privileged writer**. Its service runs as LocalSystem and owns the protected
subtrees; the unelevated GUI only reads them. The ACL split is meaningful
because the writer and the reader are different principals:

```
PolyShield     service (LocalSystem) writes intelligence/, quarantine/, state/
               GUI     (the user)    reads them
```

PolyScour has no such writer. `vault.store()` runs on every clean, and
`ledger.record()` on every operation, **in the unelevated GUI**:

```
PolyScour      GUI (the user) writes the vault and the ledger
               ...and that is the complete list
```

So the vault cannot be both writable by the unelevated GUI and protected from a
process running as that user. **Those are the same principal.** An ACL that lets
PolyScour write its own history lets anything else running as the user write it
too — which is T5's residual, unchanged by the move.

The draft ACL split in the plan said `Administrators:F` / `Users:Read` on the
vault and ledger. Under that, the installed product could not write its own
History. The error was not a typo; it was the first honest attempt to express a
boundary that does not exist.

## Decision

**The vault, ledger and settings stay under `%LOCALAPPDATA%\PolyScour`.**
`paths.py` keeps `data_scope="user"`. There is no migration to write, no
migration to test, and no half-boundary to explain.

`%ProgramData%` is adopted if and when a privileged component exists to own a
subtree — a supervising service, or something that writes where the user must
not. Not before.

## Why the helper is not that component

It is the obvious objection, and the answer is that the helper is deliberately
the wrong shape for it. It is launched per operation and exits; it does not
persist, does not listen, and holds nothing. That is not an incidental
limitation, it is `THREAT_MODEL.md`'s "elevation is per-operation and not
retained", and it is what keeps the helper a target only while it runs.

Making it the vault's owner would mean a UAC prompt on every clean — which is
retained elevation with extra steps, and would be refused on its own terms.

0001 was waiting for "the installer and the elevated helper". One of those
arrived and it turns out only the other one was ever load-bearing — and the
installer alone cannot create a boundary between a principal and itself.

## Rejected: move anyway

Adopting `%ProgramData%` for the shared *location* while admitting it grants no
protection was the alternative. It was rejected because the move's only stated
justification in 0001 was the boundary. Keeping the migration after the reason
for it evaporated would leave the codebase carrying migration code, migration
tests, and a paragraph explaining that the thing it was for did not happen —
paid for with the one operation in this product that can destroy a file that has
no other copy.

A move with no benefit is not neutral when the thing being moved is the only
remaining copy of a user's data.

## Consequences

- **T5 stands exactly as written.** The vault is a convenience, not a security
  boundary. That sentence was true in 0.1, is true now, and stops being
  described as temporary.
- **The installer is unblocked and gets smaller.** What it must protect is the
  **program directory** — `Administrators:F`, `Users:Read-and-Execute` on
  `C:\Program Files\PolyScour` — because an attacker who can rewrite the helper
  has defeated every rule inside it. That is T15's requirement, it is
  unambiguous, and it is unrelated to where the vault lives.
- **Per-user vaults stay per-user.** A second account gets its own, which is
  what 0001 already recorded.
- **PolyBedrock's data-root ACL asset is still worth extracting**, for the
  program directory and for PolyShield's existing use. PolyScour simply is not a
  second consumer of the *machine-scoped data tree* part of it.
- `polybedrock.paths.state_dir()`'s docstring describes a machine-scoped split
  with a service account. PolyScour never reaches it. Left alone rather than
  generalised for a consumer that does not exist.

## What would reopen this

A supervising process that outlives the GUI — the Game Mode recovery supervisor
is the candidate on the roadmap. If one ever writes state the user must not
forge, that subtree wants `%ProgramData%` and this decision gets revisited **for
that subtree**, not for the vault by association.
