# 0010 — A cache is cleaned file by file only if every partial state is safe

**Status:** Accepted · **Date:** 2026-09-21

## Context

adr/0009 settled *where* a developer-tool cache is. This settles a different
question that pip's rule did not force, because pip's cache happens to be safe
either way: **what does the tool do if only part of its cache is gone?**

It matters here because of what PolyScour is. The executor unlinks **files**, one
at a time, and never a directory. It can therefore always stop partway: the person
cancels a large clean, a file is locked and skipped, the process is killed. So
every cleaner leaves behind, at some point, a *partial deletion*, and "the tool
regenerates its cache" is only a safe premise if it regenerates from **any**
partial state and not only from empty.

That is not a hypothetical. It was measured, for the three candidates the pip rule
was followed by, and it split them.

## The evidence

Every experiment ran in a throwaway copy or a throwaway `CARGO_HOME` /
`GRADLE_USER_HOME` — never the real cache — emulating the executor exactly: unlink
files, keep directories, skip what Windows refuses, continue.

### npm `_cacache` — safe from every state (shipped)

Built a minimal cache from a real one (the index, plus the content for
`is-number@7.0.0` and its registry response), then deleted **every non-empty
subset** of its four files and ran an offline install twice each. 15 subsets, and
none left npm stuck: each ended as a working install or a clean `ENOTCACHED`
miss. The single non-instant state is the one npm's source predicts
(`make-fetch-happen`, `entry.js`): content missing while its index entry survives
gives **one** `ENOENT`, the entry is invalidated, and the next run is a clean miss.
`npm cache clean` describes itself the same way — the cache "self-heals from
corruption issues by treating integrity mismatches as cache misses", and deleting it
"can only make npm go slower".

### Cargo `registry/cache` — safe (shipped); `registry/src` — **not safe** (refused)

| State, in a throwaway `CARGO_HOME`, offline | Result |
|---|---|
| all present | builds |
| a crate's source dir deleted whole, `.crate` kept | builds — cargo re-extracts |
| **some sources deleted, `.cargo-ok` marker kept** | **fails: "couldn't read `lib.rs`"** |
| some sources and the marker deleted | builds |
| every source deleted, marker kept | fails |
| only the marker deleted | builds |
| `.crate` deleted, sources kept | tries to download (fails only offline) |

Cargo trusts `.cargo-ok` and does not self-heal. A half-removed crate directory
whose marker survives is a **broken build the tool cannot recover from**, and a
cancelled clean or a skipped locked file produces exactly that. So `registry/src`
(1.2 GB of the 1.3 GB registry on the measured machine) is not cleaned.
`registry/cache` holds independent `.crate` files, so any partial state is safe;
the cost of cleaning it is a re-download.

### Gradle `caches` — **not safe** (refused)

Gradle's documentation says the caches are created, used and cleaned
automatically (by age, 7–30 days) and **says nothing** about deleting them, partial
deletion, or deleting under a running daemon. So it was tested, offline, in a
throwaway `GRADLE_USER_HOME`:

- deleting **every** file (directories left) is fine — everything regenerates;
- deleting a random 50% broke a dependency-free `help` build with
  "Could not load compiled classes for settings file", and it **did not recover**
  across three further runs;
- a sweep of six seeds: **10% deleted broke it in 2 of 6; 50% in 4 of 6**, and every
  broken state stayed broken on the second run.

Whether it breaks depends on which files survive — worse than failing every time,
because it passes a spot check. A file-by-file cleaner cannot offer the atomicity
Gradle's compiled-script cache needs, so there is no Gradle rule.

### pip — safe by design

pip's `SafeFileCache` is documented as "safe to use even when the target directory
may not exist" and swallows `OSError` on every read, write and delete (adr/0009).

## Decision

**A cache is eligible for a file-by-file rule only if a partial deletion cannot
leave the tool broken.** Established by testing the tool on a throwaway copy — an
exhaustive or seeded-random sweep of partial states — not by reading its
documentation, and not by the directory's own claims:

- `CACHEDIR.TAG` does **not** settle it. Cargo tags `registry/` and Gradle tags
  `caches/` as caches, and both were broken by partial deletion. The tag says
  *disposable*; it does not say *divisible*.
- "It regenerates" does not settle it either — see the Cargo and Gradle rows.

Shipped: `npm-cache` (`_cacache` only), `cargo-registry-cache` (`registry/cache`
only, `*.crate`). Refused, with the reason recorded: Cargo `registry/src`, Cargo
`git/`, Gradle `caches/`, npm `_npx` (installed package trees — a marker-like
structure that was not tested safe), conda `pkgs` (adr/0009).

## Consequences

- **Every later family is tested this way first.** The eligibility question is a
  step in `docs/CLEANING_RULES.md` and a threat in `docs/THREAT_MODEL.md` (T26).
- **The refusals are guarded by a test.** No rule's root may be, sit inside, or
  contain Cargo's `registry/src`, Gradle's `caches`, or npm's `_npx`; nor may a root
  be a parent that holds both a safe cache and things that are not caches (`~/.cargo`
  holds installed tools). Adding one means reading this record and changing the test
  on purpose.
- **A directory-level delete would change this.** The executor has none, on purpose.
  A future one that removed a crate directory *whole* would make Cargo's `src` a
  candidate (the experiment shows a whole-directory delete is safe) — but only if
  it were atomic with respect to cancellation, and that is a much larger design.
- **Residual costs, stated in the rules' descriptions:** an offline build or install
  needs its packages back after either rule runs; and if npm is mid-fetch when its
  rule runs, one fetch may fail once and then succeed.
