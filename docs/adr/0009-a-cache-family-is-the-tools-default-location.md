# 0009 — A cache family is the tool's default location, never its configured one

**Status:** Accepted · **Date:** 2026-09-21

## Context

The first cleaner for a developer tool is pip's download cache. On the machine it
was built on it holds 6.5 GB across 3,405 files, none of it hardlinked, and it is
the largest cache PolyScour can defensibly remove there (the biggest number on the
list, conda's package cache, is 68% hardlinked into environments and would free at
most a third of what it appears to).

Every tool like this lets a user move its cache. pip does it three ways: the
`PIP_CACHE_DIR` environment variable, a `--cache-dir` flag, and `cache-dir` in any
of several `pip.ini` files. The obvious implementation of a pip `RootFamily` asks
pip where its cache is. That is the wrong implementation, and the reason is the
rule this project is built on.

## Decision 1 — The family resolves the default location and reads no configuration

`RootFamily.PIP_CACHE` is `%LOCALAPPDATA%\pip\Cache`. It does not read
`PIP_CACHE_DIR`, any `pip.ini`, or anything else pip would consult.

**Configuration is not authority.** An environment variable or an ini file is data
somebody else controls, and `cache-dir = C:\Users\me\Documents` would turn "delete
pip's cache" into "delete Documents" using nothing PolyScour wrote. The denylist
would still refuse `Documents`, but it is a list of places somebody thought of;
the family is supposed to make the question unaskable, not answer it well.

So a person whose cache is redirected simply has nothing to scan here, and the
rule's own description says the default location is the only one covered. That is
a smaller cleaner, and it is the correct trade.

**Alternatives rejected**

- *Follow the redirect and validate it* (must contain `pip`, must not be under a
  protected location). A name check is a guess about data, and every guess is a
  path an attacker or a typo can pass. It restores exactly what a family exists to
  remove.
- *Ask pip:* `pip cache dir`. That runs whatever `pip` is first on `PATH` — an
  executable PolyScour did not choose — to read the same configuration. It swaps
  reading untrusted data for executing an untrusted program.
- *Ask the user to pick the folder.* A user-supplied root **widens** what may be
  touched, which is the one thing every parameter in this codebase is forbidden to
  do (`CLAUDE.md`: a request may narrow, never widen). It needs its own threat
  model first, as the duplicate finder does.

## Decision 2 — No "pip is not running" condition

Browser rules carry `chrome_not_running` because clearing a cache under a live
profile can corrupt it. The same reflex says pip needs one. It does not, and a
version of it that could be written would be worse than none.

**pip does not need one.** Its cache class is documented as "safe to use even when
the target directory may not exist": reads, writes and deletes all swallow
`OSError`, and writes are atomic (temporary file, then replace). A pip that loses
cache files degrades to a cache miss. That is in pip's source, not an assumption.

**On Windows the OS already covers the live case.** A file a running pip holds open
cannot be deleted — measured: `os.remove` on an open file raises `WinError 32` —
so the executor's ordinary "in use, skipped and reported" path is the guard, and a
test holds a real handle to prove it.

**A name-based condition would be false comfort.** Conditions match process names.
`pip.exe` exists, but so does `python.exe -m pip`, which is just `python.exe`.
Distinguishing them means reading other processes' command lines, which can carry
credentials (a private index URL with a token in it) and which this product does
not read: `docs/PRIVACY.md` says process *names*, and that boundary is not moved
for a cache. A check that fires only when pip is launched one way, and reads
"fine" when it is launched the other, is indistinguishable from no check.

**Residual, stated:** between pip finding a cached wheel and opening it there is a
window of milliseconds in which a deletion would make that one install fail with a
missing file. It succeeds on retry, and it costs a re-download.

**Addendum — the risk label is `low`, not `safe`.** The first version of these
rules shipped as `safe`, on the reading that `SAFE` means "losing it costs a
rebuild". That is true, and it is the wrong bar for a *pre-ticked* box. For a
browser or shader cache the worst case is a slower first use. For a package
cache the rebuild needs the network: offline, or on a metered or restricted
connection, "a rebuild" is a failed install or build that nothing on the Clean
screen warned about, and on this machine the pip cache alone is 6.5 GB. The
default action of someone who clicks straight through should not be that. So
pip, npm and Cargo are `low` — offered, described, and unticked — the same
standing as the temporary-file rules. The data-safety findings (ADR 0010) are
unchanged; this is a decision about the default, not about whether the clean is
sound.

## Decision 3 — The blast radius is set by ceilings and a real layout

`max_depth` is 8 against a measured layout of 6 (`http-v2/a/b/c/d/e/<hash>`): deep
enough that the entire real tree is reachable, shallow enough that a planted
structure cannot make a walk unbounded. A ceiling that stopped short would leave
most of the cache behind and say nothing, so the layout is asserted in a test that
builds pip's real shape and requires every file to be found.

`max_bytes` is 32 GiB and `max_candidates` 200,000. A cache larger than that
aborts the rule rather than being partially reported, as every rule's ceilings do.

## Consequences

- **Every developer-tool family after this one follows Decision 1.** npm, Cargo,
  Gradle and the rest all have configurable cache locations; each resolves its
  default and reads none of it. This is written into `docs/SAFETY.md` and the
  "before you ship a rule" checklist so it is not rediscovered per tool.
- **The conda package cache is not proposed.** Its bytes are mostly shared with
  environments, its index is the tool's to maintain (`conda clean`), and a
  path-based rule would free far less than it claims. `C:\Windows\Installer` is not
  proposed either: it is not a cache — it holds installers needed to repair or
  uninstall programs. A finding is not a recommendation.
- `docs/THREAT_MODEL.md` T25 records the redirect threat and its residuals.
- Empty directories are left behind, as with every other rule: the executor only
  ever removes files, and this rule does not change that.
