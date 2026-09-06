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

## 7. Two calls, not one

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

## 8. Dry run

`planner.plan()` defaults to `dry_run=True`, and so does the settings key. A
rehearsal runs the **full guard chain** — the point is to find out what would
happen, including which items would be refused — and writes nothing. Asserted by
snapshotting the tree before and after, not by trusting the flag.

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
