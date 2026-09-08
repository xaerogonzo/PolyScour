# 0001 — The vault lives in %LOCALAPPDATA% for 0.1, not %ProgramData%

**Status:** Accepted · **Date:** 2026-09-05
**Migration superseded by** [0005](0005-the-vault-stays-user-scoped.md) — the vault stays in
`%LOCALAPPDATA%`. The reasoning below stands; only the *Migration*
section's conclusion changed, and it is left here rather than edited
because being wrong about something is part of the record.

## Context

PolyShield stores its durable data in `%ProgramData%\PolyShield`, and it moved
there for a good reason. Its Windows service runs as `NT AUTHORITY\LocalService`,
whose profile is `C:\Windows\ServiceProfiles\LocalService`. With
`%LOCALAPPDATA%`, the GUI and the service resolved **different** directories:

```
GUI           C:\Users\<user>\AppData\Local\PolyShield
LocalService  C:\Windows\ServiceProfiles\LocalService\AppData\Local\PolyShield
```

Two of the files underneath are cross-process locks. A lock file at a path each
process resolves differently does not merely fail to protect — it hands **both**
processes the lock at once, silently, over a SQLite write.

The obvious move was to inherit that answer. Review raised the right follow-up:
if PolyScour's vault sits in `%ProgramData%`, and 0.1 is unelevated with no
installer, **who creates the tree and sets its ACLs?**

## Decision

0.1 puts the vault, ledger and settings under `%LOCALAPPDATA%\PolyScour`.

`polybedrock.paths.configure()` takes an explicit `data_scope` of `"user"` or
`"machine"` with **no default**, so the choice has to be made deliberately by
every consumer rather than inherited by accident.

## Why

PolyShield needs `%ProgramData%` because a service and a GUI must resolve *one*
directory. **PolyScour 0.1 has no service and no elevated component.**
Everything that touches the vault, the ledger and the settings runs as the
logged-in user. Per-user storage is therefore both correct and gets sound ACLs
with nothing to configure.

Creating a `%ProgramData%` tree from an unelevated first run would be actively
worse than the status quo: it would inherit permissive default ACLs, leaving
another ordinary process able to tamper with the records PolyScour restores
from. That is precisely the exposure the review was worried about, and adopting
`%ProgramData%` early would have created it rather than avoided it.

## Consequences

- The vault is a **convenience, not a security boundary** in 0.1. A process
  running as the user can delete vaulted objects — but it could delete the
  originals directly too, so this does not expand what an attacker can do.
  Recorded honestly as T5 in `THREAT_MODEL.md`.
- Vault contents are per-user. A second user account gets its own.

## Migration

> **This did not happen, and will not.** See
> [0005](0005-the-vault-stays-user-scoped.md): PolyScour has no privileged
> writer, so `%ProgramData%` cannot make the vault a boundary the way it does
> for PolyShield's service. The paragraph below is the plan as it stood.

Move to `%ProgramData%\PolyScour` in 0.2, **alongside the installer and the
elevated helper** — at the point where per-subtree ACLs can be set *before* the
app first runs, which is the only time doing it is an improvement. The migration
must copy the existing vault and ledger rather than orphaning them: a vaulted
file may be the only copy the user has left.
