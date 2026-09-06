# 0003 — Naming: why the project is not called CleanForge

**Status:** Accepted · **Date:** 2026-09-05

> Historical note: this ADR discusses the names **CleanForge** and **WinForge**,
> which the project no longer uses. They appear here deliberately — this is the
> record of why they were abandoned.

The plan listed a name check as a Phase 0 task because it is "cheap now,
expensive after 0.1". It was done, and the answer was worse than assumed.

## What was found

PyPI was clear for every candidate. GitHub was not, and the collisions were not
in unrelated fields — they were the same product.

**CleanForge — 14 repos.** The decisive one:

- `JohnPitter/cleanforge` — *"The Ultimate Windows Performance Suite — System
  cleanup, gaming optimization, startup manager, network tuning, privacy guard,
  and system toolkit in one app."* That is, feature for feature, this project's
  own roadmap.
- Also `Nyyko990/CleanForge`, `denjs18/CleanForge`, `R4nkW0rld/cleanforge`,
  `Kumkum-Mishra/CleanForge` (AI data cleaning), `Ahercode/CleanForge_CLI`.

**WinForge — 54 repos**, several of them Windows optimisation toolkits:

- `mhsalomar/winforge` — *"Local-first Windows inspection, cleanup, gaming
  optimization and rollback toolkit."* Same product, and it independently
  arrived at the same "local-first" and "rollback" framing.
- `tomytate/WinForge` — Windows 11 optimisation toolkit, TUI + GUI, debloating,
  privacy hardening, snapshots.
- `alemgir0/WinForge`, `JoHnHacKerScriPT/WinForge` (*"Windows utilities,
  refined"*), `IamPavanGS/WinForge`, and ~48 more.

There is also **CleanForge Labs** (cleanforge.ca), IoT dMRV hardware for carbon
projects. That was the *least* serious issue — different field, different Nice
class. The discoverability collision was the real cost: someone searching for
this project would find another one doing the same thing.

## Intermediate candidate, also rejected

**Poly-Cleaner** was proposed next and fails on the same evidence:
`FelipeFTN/PolyCleaner` is *"System Cache & Temporary files Cleaner"* — the same
category again, in a field of 6 repos.

The pattern is that the obvious compounds are taken *because* they are the
obvious constructions. `PolyBase` is worse still — 128 repos, and it is a
Microsoft SQL Server feature name.

## Decision

**PolyScour** for the maintenance application, **PolyBedrock** for the shared
substrate — joining **PolyShield** as a coherent suite.

Verified clear at the time of the decision:

| Name | GitHub repos | PyPI |
|---|---|---|
| PolyScour | **0** | free (404) |
| PolyBedrock | **0** | free (404) |

Runners-up: `PolyTidy` (0 repos, but "tidy" undersells a tool that moves 39 GB
and maintains an undo vault) and `PolyPurge` (1 unrelated repo, but "purge"
oversells a product whose default is a dry run).

### On the substrate's neutrality

ADR 0001 in PolyBedrock asks that a third, unrelated application could plausibly
consume the substrate, and a `Poly*` name arguably signals it belongs to this
suite. Accepted anyway: *poly-* reads as "many", so **PolyBedrock** parses as
"many-foundation" rather than "PolyShield's library", and coherence across three
projects was judged worth more than the residual ambiguity.

## What changed

The `polybedrock` namespace across both distributions, the `polyscour` package
and every import, `POLYSCOUR_DATA_DIR`, `%LOCALAPPDATA%\PolyScour`, PolyShield's
four shim modules and its `build.ps1` include flags, and the documentation in
all three repositories.

Nothing had been published, so the cost was a find-and-replace rather than a
broken URL, a stale package name and users stranded on the old one. That is
exactly why the plan put this check in Phase 0 rather than before release.

## Outstanding

The folder could not be *renamed*, because three `bash` processes belonging to
the session doing the work had it as their working directory, and Windows will
not rename a directory any process is sitting in. Killing them would have killed
the tooling doing the rename.

Worked around by moving the **contents** into a new `PolyScour\` folder rather
than renaming the old one — Windows permits moving children out of a directory
it will not let you rename. Verified afterwards: 115 tests pass from the new
path, and the package, data root and rules all resolve correctly.

One item resisted the move: `.tokensave\tokensave.db` and its WAL, held open by
the tokensave MCP server. Those files are all that remain in the old
`CleanForge\` shell. The index needs re-syncing at the new root regardless, so
the leftovers can simply be deleted once the MCP server releases them:

```
rmdir /s /q "D:\Random Projects\CleanForge"
```

then `tokensave sync` from `PolyScour\` to rebuild the graph.
