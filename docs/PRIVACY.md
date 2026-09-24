# Privacy

PolyScour has **no telemetry**. Not opt-in, not anonymous, not "just crash
reports". None. Adding any would require an ADR and a change to this file, and
would be a change to what the product is.

## What PolyScour reads

Only what it needs to do its job, and only while it is doing it:

| Read | Why |
|---|---|
| Directory listings and file sizes under a rule's permitted roots | To find and measure what could be cleaned |
| Directory listings, file sizes and file attributes across **a whole volume, when you press Scan on the Storage screen** | To measure where the disk went. Sizes and names only; nothing is opened |
| Each fixed volume's Windows identifier (`GetVolumeNameForVolumeMountPointW`) | So a later scan is only compared with the same disk, and not with a different one that took over a drive letter |
| File modification times | To honour a rule's `min_age_days` |
| Running process **names** (via `psutil`) | To refuse to clear a browser cache while the browser is open |
| Windows health via PowerShell — pending reboot, uptime, recent KBs, device status | The dashboard's System health tile |
| The Run and `RunOnce` registry keys, the Startup folders' listings, and the list of automatic services (name, program path, account) | The Startup screen: what starts with Windows |
| Every scheduled task's definition, via `schtasks.exe /query /xml` (the program each runs, the account, when it triggers) | The Startup screen's view-only list of tasks that start at logon or boot. Read-only; nothing is stored |
| Environment variables (`%TEMP%`, `%LOCALAPPDATA%`, `%USERPROFILE%`, …) | To resolve root families and the protected-locations denylist |

PolyScour does **not** read file *contents*, except to compute a SHA-256 of a
file it is about to move into the vault — and that hash never leaves the machine.

## What PolyScour stores

All of it under `%LOCALAPPDATA%\PolyScour\`, all of it on your machine:

| Stored | Contains |
|---|---|
| `config\settings.json` | Your preferences and exclusion paths |
| `history.sqlite` | What each operation did: counts, bytes, outcome, and the paths of vaulted and skipped items |
| `storage_history.sqlite` | Each **completed** Storage scan: the volume's identifier and totals, the **paths and sizes of its largest folders (up to 500) and largest files (100)**, and bytes per file extension. The newest 20 scans per volume; older ones are pruned |
| `vault\` | Copies of files staged for undo, plus a manifest per operation |

The history does record **file paths** for vaulted and skipped items — that is
what makes "restore this" and "here is what was skipped" possible. It is a local
SQLite file you can open, inspect, or delete.

`storage_history.sqlite` records paths too, and for a different reason: it is how
the Storage screen can say what changed since the last scan. It is separate from
`history.sqlite` because a scan changed nothing on your machine and does not
belong in the record of what PolyScour did. **Settings → Saved Storage scans →
Clear saved scans** deletes them (after a confirmation), and so does deleting the
file. Nothing else depends on it — the next scan simply has no earlier one to
compare with, and the screen says so rather than saying nothing changed. A scan
that did not finish is never saved.

The button does one thing a plain delete of the rows would not: it compacts the
file afterwards. SQLite otherwise leaves a deleted row's bytes in the file until
something reuses the space, and these rows hold folder and file paths. That is
tested by reading the file's bytes, not by counting rows.

## What a copied or saved report contains

The Storage screen's **Copy report** and **Save report…** produce a plain-text
report of what is on screen. It contains **folder and file names from this
computer** — the largest ones, with their full paths — and says so as its third
line. It is produced only when you press the button, and it goes only where you
send it: the clipboard, or the file you name in the save dialog. PolyScour does
not keep a copy and does not send it anywhere.

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
