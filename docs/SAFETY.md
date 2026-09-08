# Safety

> Read this before changing anything under `src/polyscour/safety/`.

A bug in a web app is annoying. A bug here deletes someone's files. Everything
below exists because some plausible-looking alternative is silently wrong.

## The chain

Every destructive operation passes through `Guard.authorize()`, in this order.
No step may be skipped, reordered, or made conditional.

```
rule identity
  → policy lookup            an unknown rule is refused, never defaulted
  → permitted root families  resolved by code; a rule cannot name a path
  → concrete target
  → reparse inspection       unresolved, component by component
  → canonicalise + contain   re-verified against the canonical form
  → volume check
  → global denylist          independent of any rule
  → user exclusions
  → operation permitted?
  → authorised
```

The guard is deliberately **not told what the rule claims**. It is told the
rule's *identity* and looks the permissions up itself. A rule that lied about
its roots would be lying to nobody: the forged value is never read.

## 1. Rules cannot authorise themselves

The naive version of "configuration is not authority" is to check
`target in rule.declared_roots`. That is not a safety property. A corrupted or
hostile rule simply declares:

```json
{"roots": ["C:\\Users\\me\\Documents"]}
```

and passes its own check.

So **rules do not name paths at all.** A rule names a symbolic `RootFamily`, and
only `safety/policy.py` knows what a family resolves to:

```
USER_TEMP · WINDOWS_TEMP · THUMBNAIL_CACHE · SHADER_CACHE
BROWSER_CACHE_CHROME · BROWSER_CACHE_EDGE · BROWSER_CACHE_FIREFOX · CRASH_DUMPS
```

`POLICY` maps each rule id to the families it may use, the operations it may
perform, its expected scope and its ceilings. **A rule id absent from `POLICY`
fails to load.**

This eliminates the class rather than validating against it: a rule file that
never contains a path cannot widen its reach by editing one, and adding a
cleaner requires a code change that goes through review.

Authority only ever **narrows** as it flows outward. A rule may declare fewer
families than its policy grants, tighter ceilings, or the same scope. Attempting
to declare more is a load-time failure.

## 2. Reparse points are inspected *before* canonicalisation

Order of operations is the whole point.

`Path.resolve()` **follows** junctions and symlinks. Canonicalising first asks
the wrong question — "where did we end up" — after the traversal that needed
permission has conceptually already happened.

```
1. Walk the components from the root family downward
2. At each, read filesystem metadata via lstat; reject a disallowed
   FILE_ATTRIBUTE_REPARSE_POINT rather than following it
3. Only then canonicalise
4. Re-verify containment against the canonical form
5. Verify the volume did not change
```

Steps 3–5 are not redundant with step 1. Step 1 refuses a redirection we can
see; steps 3–5 catch one we could not — a component replaced between the
`lstat` and the `resolve`.

The root itself is not inspected: it arrives already resolved from
`resolve_family()`, and a machine whose `%TEMP%` is legitimately a junction is a
configuration to tolerate, not refuse. Everything *below* it is the attack
surface, and every level is checked — a junction five directories down is as
effective as one at the top.

## 3. Locked files: TOCTOU-aware, never lock-dependent

"Refuse when the target is open by another process" is race-prone in **both**
directions and must not be a safety boundary:

```
check → not open → another process opens it → PolyScour deletes it
check → looks open → app releases it → PolyScour needlessly skips it
```

The real property:

> **Never force deletion because a file is locked. Attempt the normal operation;
> on a sharing violation, skip the item, report it, and continue.**

No handle closing. No read-only bit clearing — that is forcing too, and a
read-only file is skipped as `PERMISSION`. A preflight "probably locked" check
may exist as a UI convenience; it is never a guarantee.

## 4. Blast-radius ceilings

Every rule carries `max_candidates`, `max_bytes` and `max_depth`, capped by its
policy entry. Exceeding any of them **aborts the rule and reports**:

> `chrome-cache: not scanned — matched more than the 200,000 files this rule is
> allowed to consider. Scan abandoned for this rule rather than reporting a
> partial figure as if it were complete.`

Truncating to the first 50,000 of 842,000 matches would present a wrong number
confidently, which is worse than failing.

A rule also declares an `expected_scope`. One declaring `ONE_DIRECTORY` while
producing findings across three volumes is a test failure.

## 5. The global denylist

Applied last and independently of any rule. Resolved from the environment rather
than hard-coded to `C:\`, because a machine booting from another volume would
otherwise be protected at the wrong paths — which is worse than not being
protected, because it looks like it is.

- `%SystemRoot%\System32`, `%SystemRoot%\SysWOW64`
- `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%`
- `%USERPROFILE%\{Documents, Desktop, Pictures, Videos, Music, Downloads, Favorites}`

`Downloads` is deliberately included. It is where a maintenance tool is most
tempted to look for "junk", and where users keep things they have not filed yet.

Checked in **both directions**. Being inside a denied root is the obvious case;
*containing* one is the dangerous case a containment-only check waves through —
deleting a directory that holds `Documents` takes `Documents` with it.

The denylist is **not configurable**. A user exclusion can only ever add
protection.

## 6. Hard links

Hard links are not followed as directory traversal, and cleaner semantics
operate on **directory entries** rather than presumed-unique files. `os.unlink`
removes the entry; another name for the same data is not this rule's to remove,
and the space is only reclaimed when the last link goes. A deeper policy is
future work.

## 7. Two calls, not one — three when elevated

`authorize()` runs during the scan *and* again immediately before each
destructive operation.

The scan call is not because a scanner could delete anything — it cannot — but
because a finding the guard would refuse must never reach the user as an offer.

The execution call is what makes the TOCTOU race lose. Another local process may
replace a target with a junction between the two. Re-checking costs one guard
call per item, which is nothing next to the I/O.

A `GuardRefusal` at execution time is **not benign**. It means a bug or an
attack, and it degrades the operation outcome rather than being folded in with
locked files.

### Three, when the work is elevated

Where the elevated helper does the deleting, the chain runs a third time — in a
different process, at a different privilege level, against its own copy of
`safety/policy.py`. That third call is the only one that is a security
boundary. The first two are courtesies that keep bad requests off the wire.

The helper does not trust the request to name what to delete. It is given a
`rule_id`, resolves that rule's permitted roots itself, and enumerates them
itself — so there is no caller-supplied path for it to be persuaded about. See
`docs/adr/0004` and T19.

**Per item, not per batch.** A batched elevated delete calls `authorize()`
immediately before each `unlink()`, never once for the group. Hoisting it would
turn several hundred re-checks into one check with a long window behind it,
which is exactly the property this section exists to keep.

The user's exclusions travel with the request, because the helper cannot read
the invoking user's settings — under `runas`, `%LOCALAPPDATA%` need not be the
same profile. That is safe because an exclusion can only ever *narrow* what is
deleted; a caller that lies about them causes fewer deletions, never more. It
is also necessary: without it, a path the user protected would be honoured
unelevated and deleted elevated.

## 8. Dry run

`planner.plan()` defaults to `dry_run=True`, and so does the settings key. A
rehearsal runs the **full guard chain** — the point is to find out what would
happen, including which items would be refused — and writes nothing. Asserted by
snapshotting the tree before and after, not by trusting the flag.

## 9. Game Mode: a second policy, for processes rather than paths

Suspending a process is not a filesystem operation, so it does not run through
the guard chain above. It gets its own authority in
`polyscour/gamemode/policy.py`, built to the same rule: **the selection
proposes, code disposes.** A list of ticked checkboxes is input, and input is
untrusted — a row can be stale, a PID can be recycled between the scan and the
click, and a user can tick `lsass.exe` because it was using memory.

The veto is a reviewed denylist **plus structural rules**, and the structural
rules are the ones that carry it:

| Refusal | Covers |
|---|---|
| PID ≤ 4 | The kernel processes, by number — never depending on a name we may not be able to read |
| Name on `NEVER_SUSPEND` | Named refusals: the shell, the audio graph, service hosts, security software, PolyScour and PolyShield |
| Owner is not the current user | **Everything system-owned that nobody thought to name** |
| Owner or name unreadable | Unknown behaves like dangerous, as it does in `scanner.condition_met` |
| PID is PolyScour or its parent | Never freeze ourselves, or the terminal we were launched from |

A denylist alone only refuses what somebody thought of. The ownership rule is
what makes the policy hold against a process nobody has heard of.

**The veto runs twice**, for the same reason `authorize()` does: once when the
list is built, once inside `GameSession.suspend` immediately before the freeze.
A PID recycled in between is exactly the race the second call is there to lose.

### Why freezing is recorded before it happens

`NtSuspendProcess` has no timeout and no owner. A suspended process stays
suspended after the thing that suspended it is gone — it does not exit, and it
presents to the user as an application that has hung for no reason.

So the ledger row is written **before** the process is frozen, the same shape as
a vault object existing before its delete:

```
record intent  ->  suspend  ->  (later) resume  ->  mark resumed
```

Dying between the record and the freeze costs one harmless resume on recovery.
Dying between the freeze and the record — which this order makes impossible —
would leave a frozen process nothing knows how to release. `Services.__init__`
calls `gamemode.recover()` on every launch.

**The residual gap is stated rather than hidden:** nothing resumes anything
until PolyScour runs again. A hard kill with no subsequent launch leaves the
processes frozen until reboot.

Closing it needs a supervising process. The elevated helper is *not* that
process and did not close this gap — it is launched per operation and exits,
which is the opposite of what supervising requires. What the helper established
is the precedent: a second process gets a threat-model section written before
its code.

That section is now written — `THREAT_MODEL.md`, "The Game Mode supervisor",
plus T20–T22 — and it commits to three things before any code exists:

- **Unelevated.** Resuming the user's own processes needs no administrator
  rights, so asking for them would buy a standing target to pay for a
  convenience.
- **Not persistent.** Started with a session, gone when the GUI's process is.
- **Its authority is the ledger and nothing else.** It replays what the session
  recorded; it never enumerates the system looking for suspended processes.
  That would touch things PolyScour never froze — someone's debugger, an
  installer mid-operation — with no record that anything had been suspended.

And it is honest about what it buys: the window narrows from "until the user
next opens PolyScour, which may be never" to "until PolyScour's process ends".
A kill that takes both leaves the gap exactly as T12 describes it.

## 10. Startup entries: a third policy, and the first registry write

The Startup Manager is the first feature that changes registry state, so it is
worth being exact about what it writes:

    HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run

a `REG_BINARY` value per entry, named after the `Run` value it governs. Byte 0
is `0x02` for enabled and `0x03` for disabled. **The `Run` value itself is never
written, renamed or deleted.**

That choice is the safety property. Using Windows' own switch means a disable is
a *state transition* rather than a deletion: nothing is removed, Task Manager
shows the same state, and a user who uninstalls PolyScour keeps everything. The
alternative — delete the `Run` value and stash a copy — would make PolyScour the
only thing that knows how to put it back.

`startup/policy.py` is the authority, in the same shape as the other two:

It answers two questions, deliberately kept apart. `veto()` is absolute and
holds at any privilege level:

| Refusal | Why |
|---|---|
| PolyScour's own entry | A product that can switch off its own autorun can make itself unfindable |
| An entry with no name | It cannot be addressed reliably, so it cannot be changed safely |

`requires_elevation()` reports a **cost**, not a refusal:

| Cost | Why |
|---|---|
| `scope != "user"` | `HKLM` affects every account, so changing it asks for administrator rights |

A cost is something a user can choose to pay; a refusal is not. Collapsing them
into one string — which is what this file described until the helper landed —
either hides an available action or offers an impossible one.

Machine-wide entries are listed, switchable, and honest about what changing one
means. Hiding them would make the screen a misleading account of what starts
up. That they are no longer *refused* is a real loss of a limit, weighed and
recorded in `THREAT_MODEL.md` T14 rather than presented as a free improvement.

### Order, and what undo checks

    veto  ->  record in the ledger  ->  write the registry

Dying between the record and the write shows a change in History that did not
happen — visible and correctable. The reverse order would alter the machine with
nothing to say so.

Undo compares the recorded `raw_value` against what the entry launches **now**.
An installer rewriting a `Run` value between the change and the undo is
ordinary, and re-enabling it anyway would restore a decision the user never
made, using PolyScour to do it. A mismatch is reported and the record stays
open.

For a machine-wide entry that comparison happens **twice**: once here, to keep
a pointless prompt off the screen, and once inside the helper, which is the
copy that matters because it is the only one a compromised GUI cannot reach.
The helper is sent what the entry launched when we looked; like an exclusion,
that can only ever cause a refusal, which is what makes it safe to accept from
an untrusted caller.

The write is then **read back**. `SetValueEx` returning without error is not
evidence the value is what was asked for, and "verify rather than assume" is
what the cleaning path already does when it re-scans afterwards.

## What is tested

`tests/test_safety.py` and `tests/test_executor.py`, in full:

- a rule with no policy entry cannot load, and is refused by the guard too
- a rule cannot claim a family its policy withholds, invent a family, or raise a
  ceiling
- shipped rules contain no path-like strings at all
- junction out of the root, junction several levels down, the junction itself,
  a junction that must not taint its siblings
- `..` cannot walk out of a permitted root
- inside a protected location, and *containing* one
- exclusions apply, and do not over-apply to siblings
- a family that resolves to nothing means "do nothing", not "no constraint"
- a locked file and a read-only file are skipped and **survive**
- a junction planted between scan and execution is refused at execution
- `dry_run=True` writes nothing, asserted by tree snapshot

`tests/test_elevation.py`, for the boundary the helper is:

- an excluded path is refused **at privilege** — the negative control for the
  whole exclusion-crossing design, and the one that failed before it existed
- an exclusion protects descendants, and survives being written with the wrong
  case, a trailing separator, `.` or `..` segments
- the request the executor sends contains a rule id and no path, ever
- an unknown rule id is refused before anything is walked
- a file younger than the **policy's** age floor is not deleted, even though the
  rule file could have said otherwise
- cancelling stops between items, and what was deleted stays deleted
- the staging directory is removed on all six exit paths, including the error
  ones nobody exercises by hand
- a helper reporting progress does not trip the timeout; a silent one
  does — both driven by a fake clock the test advances, because the
  first version used real sleeps against a 0.15 s deadline and failed
  on a loaded machine after passing twice in CI. A test that is usually
  right is worse than one that is wrong: a real regression reads as
  "flaky again"

`tests/test_ledger.py`, because a history file must survive an upgrade:

- a 0.1 database opens, keeps its rows, and gains the new columns
- migrating repeatedly changes nothing

`tests/conftest.py` refuses to let any test launch the real helper. Three tests
reached `ShellExecute("runas")` for real during this work — a UAC prompt raised
by `pytest`, which is exactly the speculative elevation the threat model
forbids, and worse than the ordinary kind because a prompt that appears while
someone is doing something else is a prompt they will click away.
