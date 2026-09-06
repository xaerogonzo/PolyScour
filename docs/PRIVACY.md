# Privacy

PolyScour has **no telemetry**. Not opt-in, not anonymous, not "just crash
reports". None. Adding any would require an ADR and a change to this file, and
would be a change to what the product is.

## What PolyScour reads

Only what it needs to do its job, and only while it is doing it:

| Read | Why |
|---|---|
| Directory listings and file sizes under a rule's permitted roots | To find and measure what could be cleaned |
| File modification times | To honour a rule's `min_age_days` |
| Running process **names** (via `psutil`) | To refuse to clear a browser cache while the browser is open |
| Windows health via PowerShell — pending reboot, uptime, recent KBs, device status | The dashboard's System health tile |
| Environment variables (`%TEMP%`, `%LOCALAPPDATA%`, `%USERPROFILE%`, …) | To resolve root families and the protected-locations denylist |

PolyScour does **not** read file *contents*, except to compute a SHA-256 of a
file it is about to move into the vault — and that hash never leaves the machine.

## What PolyScour stores

All of it under `%LOCALAPPDATA%\PolyScour\`, all of it on your machine:

| Stored | Contains |
|---|---|
| `config\settings.json` | Your preferences and exclusion paths |
| `history.sqlite` | What each operation did: counts, bytes, outcome, and the paths of vaulted and skipped items |
| `vault\` | Copies of files staged for undo, plus a manifest per operation |

The history does record **file paths** for vaulted and skipped items — that is
what makes "restore this" and "here is what was skipped" possible. It is a local
SQLite file you can open, inspect, or delete.

## What is sent anywhere

Nothing.

PolyScour makes exactly one kind of network-adjacent call, and it is not
network: a **loopback** TCP connection to `127.0.0.1:52614`, to ask an installed
PolyShield three read-only questions. It never leaves the machine, it carries no
information about your files, and if PolyShield is not installed the connection
is never attempted.

There is no update check, no rule download, no crash reporter, no analytics, no
account, and no advertising identifier.

## Offline

Everything in 0.1 works with no internet connection, because nothing in 0.1
needs one.
