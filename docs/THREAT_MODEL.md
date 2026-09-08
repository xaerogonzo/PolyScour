# Threat model

Two things are easy to conflate, and the difference will matter enormously once
driver management and privileged helpers exist.

**Accidental safety** — the user, or PolyScour itself, does something
regrettable. This is what [SAFETY.md](SAFETY.md) primarily addresses, and what
0.1 is built around.

**Adversarial local security** — another local process acting *deliberately*.
0.1 does not need a large security architecture, and several items below are
explicitly accepted risks at this stage. What it needs is the distinction
written down, with each item marked honestly.

## Assets

| Asset | Why it matters |
|---|---|
| The user's files | The thing PolyScour could destroy |
| `rules/cleaners/*.json` | Describes what gets deleted |
| `safety/policy.py` | **The authority.** Decides what may be deleted |
| The vault (`%LOCALAPPDATA%\PolyScour\vault`) | Holds the only copy of restorable data |
| The ledger (`history.sqlite`) | The record of what happened, and what can be undone |
| The PolyShield IPC token | Authenticates the optional integration |

## Trust boundaries

```
  user (trusted)
    │
    ▼
  PolyScour GUI ── unelevated. No service, ever.
    │              ├─ elevated helper: launched per operation, exits.
    │              │  Treats THIS process as untrusted. See its section below.
    │              └─ Game Mode supervisor: unelevated, same user, lives only
    │                 as long as a session. Holds no privilege to lend.
    │
    ├── rules/*.json ......... DATA. Untrusted. Cannot grant authority.
    ├── safety/policy.py ..... CODE. Trusted. Ships in the build, reviewed.
    ├── the filesystem ....... hostile-capable: junctions, races, locks
    └── PolyShield IPC ....... optional, read-only, authenticated, fails closed
```

## Threats

### T1 — A modified cleaning rule tries to widen what is deleted

**Mitigated, by design.** Rules name symbolic `RootFamily` values, never paths.
A family resolves only through `safety/policy.py`. A rule id with no
`PolicyEntry` fails to load; a rule claiming a family its entry does not grant
fails to load; a rule raising a ceiling fails to load. A rule file that cannot
contain a path cannot widen its reach by editing one.

**Narrowed further by an installed build.** Rules ship *inside* the binary
rather than beside it — `paths.rules_dir()` resolves them from the module tree,
so a packaged build carries them in its own payload. There is no rules folder
on an installed machine for anyone to edit. That is not the reason it was done
(adding a rule already requires a reviewed `PolicyEntry`, so an editable folder
would offer the appearance of configurability with none of the authority) but
it is a real consequence worth stating.

A source checkout still reads `rules/cleaners/*.json` from disk, and there the
mitigation is the one above: a rule file that cannot contain a path cannot
widen its reach by editing one.

Residual: someone who can modify `policy.py` can change anything — but they can
already modify the whole application, so this is not a boundary PolyScour can
defend from inside. What *can* be defended is who may write those files at all,
which is T15's installed-location requirement. Signed builds remain the further
mitigation and are not yet done.

### T2 — A junction or symlink redirects a delete out of its permitted root

**Mitigated.** Component-by-component reparse inspection *before*
canonicalisation, then containment re-verified on the canonical form, then a
volume check. Tested against junctions at the root, several levels down, on the
target itself, and beside legitimate siblings.

### T3 — A target is replaced between the scan and the execution (TOCTOU)

**Mitigated.** The guard runs again immediately before each destructive
operation; the scan's verdict is never carried forward. Tested: a junction
planted after the scan is refused at execution, and the pointed-at file survives.

Residual: the window between the guard's final check and `os.unlink` cannot be
closed from user space without a transactional filesystem API. It is
sub-millisecond and requires an attacker already running as this user.

### T4 — Another process races PolyScour for the same file

**Accepted, and made harmless.** Nothing is forced. A file that vanishes is
`VANISHED`; one that is locked is `LOCKED`; both are benign, reported, and the
run continues. PolyScour never escalates to win a race.

### T5 — The vault or its manifests are tampered with

**Partially mitigated.** Restore verifies the recorded SHA-256 and refuses on
mismatch, so corrupt data is never handed back as if it were fine. Restore never
overwrites an existing path.

**Accepted, and no longer described as temporary.** The vault lives under
`%LOCALAPPDATA%\PolyScour`, which is writable by the user and therefore by
anything running as them. A process running as the user could delete vaulted
objects. It could also delete the originals directly, so this does not expand
what an attacker can do — but it does mean the vault is not a security boundary,
only a convenience.

This was originally recorded as a 0.1 concession pending a move to
`%ProgramData%`. `docs/adr/0005` retires that plan: PolyScour has no privileged
writer, so a machine-wide tree cannot wall the vault off from the one
unelevated process that writes it on every clean. The residual is permanent
until something exists that writes where the user must not.

**Known gap, documented rather than hidden:** an *unreadable* manifest currently
causes its objects to be treated as unreferenced and collected. The conservative
behaviour would be to keep them. `test_vault.py` asserts the current behaviour
explicitly so the gap is visible rather than assumed away.

### T6 — Something else binds `127.0.0.1:52614` and impersonates PolyShield

**Mitigated.** `localhost` is not a trust boundary. The client requires the
shared token from `%ProgramData%\PolyShield\state\service_token.txt` — with no
token it does not connect at all — and **fails closed** on any unexpected
response shape. A non-dict reply, an `ok: false`, or garbage all mean "no
PolyShield", never a degraded yes.

Consequence is bounded anyway: the integration is read-only, and there is no
code path from PolyScour that asks PolyShield to *act*. A successful
impersonation could at most lie about security posture in one dashboard tile.

### T7 — PolyShield being installed silently grants PolyScour new authority

**Mitigated by omission.** There is no `SCAN_PATH`, no quarantine call, no
configuration write. Three read-only commands exist and nothing else. Adding one
requires a concrete committed feature and an update to this document.

### T8 — A rule matches vastly more than intended

**Mitigated.** Per-rule ceilings on candidate count, total bytes and traversal
depth abort the rule and report, rather than presenting 700 GB of someone's
filesystem as cache. Also caught in review by `expected_scope`.

### T9 — Two PolyScour processes mutate at once

**Mitigated.** One cross-process file lock covers the ledger and the vault
together, because a vault write and its ledger row are a single logical change.
A second process is told to try again rather than queued.

### T10 — Elevation is abused

**Not applicable in 0.1.** PolyScour runs entirely unelevated and skips
anything needing admin, reporting it plainly. The helper's own section is
below — written before the helper exists, as this entry required, and it is a
specification the implementation has to satisfy rather than a description of
something already built.

### T11 — Game Mode is aimed at a process that must not be frozen

**Mitigated, in two layers.** `gamemode/policy.py` refuses by number (kernel
PIDs), by reviewed name (`NEVER_SUSPEND` — shell, audio, service hosts,
security software, PolyScour and PolyShield), and structurally: a process not
owned by the current user is refused whether or not anyone named it. The last
rule is the one that covers what a list cannot.

The veto runs **twice**, at list time and again immediately before the freeze,
because a PID can be recycled onto something else in between. This is the same
two-call design the cleaner uses, for the same reason.

The interface is also part of the mitigation. Nothing arrives pre-selected;
the list is sorted by memory because that is a fact, not because the top of it
is a recommendation. Refused processes are shown greyed **with their reason**
rather than hidden, so the policy is visible instead of appearing as an absence.

### T12 — PolyScour dies while processes are suspended

**Mitigated, with a stated residual.** A frozen process outlives whatever froze
it and looks like a hung application. Every suspension is written to the ledger
*before* the freeze, and `Services.__init__` resumes anything still open on the
next launch, guarding against PID reuse by comparing the recorded process
creation time.

**Residual:** if PolyScour is hard killed and never launched again, the
processes stay frozen until reboot.

A supervising process **narrows** that residual and does not remove it — see
"The Game Mode supervisor" below, and T20. The window becomes "until
PolyScour's process ends" rather than "until the user next opens PolyScour,
which may be never". A kill that takes both processes leaves things exactly
where this paragraph found them.

The elevated helper is not that supervisor and was never going to be: it is
launched per operation and exits, which is the opposite shape. It did establish
the precedent this follows — a second process gets a threat-model section
written before its code.

### T13 — A startup entry is changed to something the user did not intend

**Mitigated.** PolyScour writes only the approval byte in
`HKCU\...\StartupApproved\Run`; it never writes, renames or deletes a `Run`
value. So the worst a bug here can do is switch something on or off — it cannot
change *what* an entry launches, and it cannot destroy one.

`startup/policy.py` now answers two different questions. `veto()` refuses
absolutely — PolyScour's own entry, and unnamed entries — and those stay refused
at any privilege, because neither becomes acceptable with administrator rights.
`requires_elevation()` reports a *cost*: machine-wide entries can be changed,
through the helper, after a prompt. Collapsing a cost and a refusal into one
string either hides an available action or offers an impossible one.

Both run again immediately before the write, because the list a user is looking
at was built earlier and the registry is shared. For a machine-wide entry the
absolute vetoes run **a third time, inside the helper**, along with a comparison
of what the entry launches against what the GUI saw and a read-back afterwards:
`SetValueEx` returning without error is not evidence the value is what was
asked for.

**Undo is guarded against a substituted target.** Between a change and its undo,
an installer can rewrite the `Run` value. Re-enabling it then would restore a
decision nobody made, with PolyScour's name on it — so the `raw_value` recorded
at change time is compared, and a mismatch refuses rather than writes.

### T14 — The Startup Manager is used to make a machine less safe

**Less mitigated than it was, and this section says so rather than being
quietly left as it stood.**

A user can disable their own security software's autorun; PolyScour lists it
like anything else. Until the elevated helper, one of the three things limiting
that was a blanket refusal:

> ~~`HKLM` entries — where most security software registers — are refused
> outright.~~

**That mitigation is gone.** Machine-wide entries now have a working switch,
and the screen this feature is demonstrated against contains
`SecurityHealth` — Windows Security's own machine-wide autorun. Pretending
otherwise because the refusal was convenient to cite would be exactly the
invented reassurance this product exists to avoid.

What is left:

- **A UAC prompt stands between the click and the change**, and the operation
  is one Windows itself gates on administrator consent. Someone who can grant
  that can already do this in Task Manager, `regedit`, or Autoruns.
- Nothing is pre-selected and nothing is recommended, so a disable is always an
  explicit act rather than a consequence of clicking *Apply*. This is the one
  that does most of the work, and it is a **product** decision rather than a
  technical control: PolyScour never suggests turning anything off, so it never
  becomes the tool that talked someone into it.
- The `Run` value itself is still never written, so a disable stays a state
  transition that Task Manager displays and can reverse.

**Not mitigated:** a determined user with administrator rights can switch off
machine-wide security software from this screen. That is authority they already
had, and a maintenance tool that silently refused a change Windows permits
would be lying about what it does — but the refusal was doing real work as a
speed bump, and removing it is a cost, not a free improvement. Weighed against
`windows-temp` and machine-wide entries being permanently unusable, it was
judged worth paying; that judgement is recorded here so it can be revisited
rather than rediscovered.

## The elevated helper

*Written before the helper existed, as T10 required: a specification the
implementation had to satisfy rather than a description of something already
built. The helper now exists and satisfies it. The order is kept deliberately
-- T19 was likewise written before the operation it governs, and the day this
section starts being edited to match code that already shipped is the day it
stops being a threat model.*

PolyScour 0.1 runs entirely unelevated and skips whatever needs administrator
rights — the `windows-temp` rule ships and is always reported as skipped, and
machine-wide startup entries are listed and refused. Doing that work needs a
process running as administrator, and introducing one is the largest single
change to this product's threat model.

### The shape

```
  PolyScour GUI (unelevated, may be buggy or compromised)
        │
        │  one typed request, one response
        ▼
  polyscour-helper.exe (elevated, launched per operation via UAC)
        │
        └── re-runs the SAME guard chain the GUI ran
```

**The helper assumes the GUI is lying.** Not as a pose — as the design
constraint that produces every rule below. An unelevated process is easier to
compromise than an elevated one, so a helper that trusts its caller has simply
moved the attacker's target rather than raised the bar. If the GUI could
persuade the helper to delete an arbitrary path, PolyScour would be a
privilege-escalation tool with a maintenance UI.

### The API is named operations, never a command

There is no `ExecuteCommand(string)`, no `RunPowerShell(script)`, no
`DeletePath(path)` that takes an arbitrary path and obeys. The surface is a
closed set of named operations with structured parameters:

| Operation | Parameters | Exists because |
|---|---|---|
| `DeleteApprovedPath` | `rule_id`, `path` | `windows-temp` is skipped without it |
| `DeleteApprovedPathsForRule` | `rule_id`, `exclusions` | per-file elevation is several hundred prompts — T19 |
| `SetMachineStartupApproval` | `value_name`, `enabled`, `expected_raw_value` | HKLM startup entries are refused without it |

Note what the second row does *not* take. It is the only operation here that
cannot be told which file to act on, and that is the point of it.

Adding an operation is a code change to the helper, reviewed, in this
repository — the same friction a cleaning rule already has. **A generic
operation would defeat the entire design**: the value of a closed set is that
the worst thing a compromised GUI can ask for is the worst thing on the list.

### Server-side validation is the whole point

The helper does not accept a path because the GUI says it is fine. For every
request it independently re-runs the guard chain from `polyscour.safety` —
policy lookup, root resolution, reparse inspection, containment, denylist —
using **its own** copy of the code, against the path as it exists at that
moment.

That is not redundant with the GUI's check for the same reason `authorize()` is
already called twice: the two calls happen at different times, in different
processes, at different privilege levels, and only the second one is the one
that matters. The GUI's check is a courtesy that keeps bad requests off the
wire. The helper's is the security boundary.

The `rule_id` travels with the request so the helper can look up what that rule
is permitted to touch. A request naming a rule that does not exist is refused;
a path outside that rule's permitted roots is refused; a reparse point
encountered anywhere in the walk is refused.

### What runs at privilege is kept small on purpose

The helper and the GUI are one executable, dispatched on one argument before
anything is imported. That argument is checked in `entry.py`, which imports
neither branch at module scope.

This matters because `app.py` imports CustomTkinter, and importing that imports
Tk and Tcl. Entering the helper through it would put a GUI toolkit inside an
elevated process. No named vulnerability follows from that — it is simply tens
of thousands of lines running as administrator to delete one file, in a design
whose stated property is that the elevated part is small enough to read.

Asserted rather than intended: a subprocess test runs a real elevated operation
and checks that `customtkinter`, `tkinter`, `PIL` and `pystray` are all absent
from `sys.modules` afterwards.

Unknown arguments are refused, not ignored — the same reason
`Request.from_json` refuses an unexpected parameter rather than proceeding on
the overlap. See `docs/adr/0006`.

### Elevation is per-operation and not retained

The helper is launched for a unit of work and exits when it is done. It does
not install a service, does not persist, does not sit waiting for a second
request, and there is no "keep me elevated" option. A long-lived elevated
process is a standing target; a short-lived one is only a target while it runs.

The cost is honest and is accepted: the user sees a UAC prompt per elevated
*operation* rather than one per session. What an operation covers is a
deliberate decision rather than an accident of implementation, because "one
prompt, many deletes" is a materially different bargain from "one prompt, one
delete".

That second bargain has since been taken, for one operation and with its own
entry: **T19** below. It was not taken to save clicks. Per-file elevation makes
`windows-temp` several hundred UAC prompts, and a prompt a user cannot
realistically read is not consent — it is a habit, which is the thing T18
already says nothing here can fix. The operation that batches is narrower than
the one that does not.

### T15 — A compromised GUI asks the helper for something harmful

**Mitigated by construction.** The operation set is closed and every parameter
is validated by the helper against policy it holds itself. The worst a
compromised GUI can achieve is the worst thing on the list, performed on a path
the guard chain independently approves — which is what an honest GUI could have
asked for anyway.

**Not mitigated by anything inside the helper:** an attacker who can modify
PolyScour's *installed files* can modify the helper too, and then no rule
inside it means anything.

That is why the installed location must be one only administrators can write —
and as of 0.2 that is enforced rather than assumed. `installer/polyscour.iss`
requires administrator rights for exactly this, and
`installer/set_program_acls.ps1` sets the program directory to
`Administrators:F`, `SYSTEM:F`, `Users:ReadAndExecute`, with inheritance
disabled and **ownership set to Administrators** — an owner can rewrite a DACL
whatever it says, so leaving the installing user as owner would leave them able
to grant themselves write access afterwards.

`{autopf}` is already administrator-only on a default Windows installation. The
script exists because "already, by default, probably" is not a boundary: an
install into a non-default directory inherits whatever ACL its parent had, and
nothing would report it.

**None of it helps if the elevated process is not the installed one.** That was
T23, and it is why the two are worth reading together: protecting the program
directory and elevating something outside it are independently plausible and
jointly useless.

**It is verified in both directions, and the verification only counts
unelevated.** `-Verify` inspects the DACL, and when run as an ordinary user
also *tries to cross the boundary*: it must fail to write into the program
directory, and must still be able to read the executable. An administrator can
write anywhere, so an elevated check would describe the boundary rather than
prove it — the script says so, and skips the probe rather than reporting a
pass it did not earn.

Identities are well-known SIDs rather than names, because the built-in *Users*
group is localised — it is *Benutzer* on a German Windows. A script matching
the English string would silently fail to find the entry it meant to remove,
and report success.

### T16 — Something impersonates the helper, or the GUI's request is tampered with

**Mitigated by direction.** The GUI launches the helper itself, rather than
connecting to something already listening, so there is no port or pipe for
another process to claim first. The response is advisory — it tells the GUI
what happened so it can be recorded — and nothing security-relevant depends on
believing it.

A request tampered with in flight is covered by the previous section: the
helper validates whatever arrives, from whatever source, and a tampered request
is just an untrusted request like every other.

### T17 — The helper is used to escalate by a *different* local process

**Mitigated.** The helper takes its work from arguments given at launch by the
process that started it, and exits. It does not accept work from anything else,
because it is not listening for anything. A local attacker who can launch it
can only ask it for a validated operation on a policy-approved path — which is
not an escalation, because they could have asked the elevated user to run the
GUI and click the button.

### T18 — A user consents to elevation without understanding what for

**Partially mitigated, and the residue is real.** The UAC prompt names
PolyScour, not the operation, so the specific consent lives in PolyScour's own
UI: the confirmation says exactly which rule and how many items, and elevation
is never requested speculatively or "in advance". Dry run stays the default at
every level, including here.

**Not mitigated:** a user who habitually clicks through UAC is not protected by
any of this. Nothing in a maintenance tool can fix that, and pretending
otherwise would be the invented reassurance this product exists to avoid.

### T19 — One prompt authorises many deletes

**Mitigated by making the batched operation narrower than the single one.**

`DeleteApprovedPathsForRule` takes a `rule_id` and nothing else that names a
target. The helper resolves that rule's permitted roots from its own copy of
`safety/policy.py`, enumerates them itself, and authorises every candidate it
finds. **The caller cannot name a path at all** — so the batched operation
removes a parameter the single-path form has, rather than adding reach. A
compromised GUI's best move is to name a rule that was already in the reviewed
policy table, and ask for exactly what an honest GUI would have asked for.

What one consent now covers is therefore bounded by reviewed code rather than
by the request: *everything this rule is permitted to delete, that exists right
now, and that the guard approves individually*. The user is told the rule and
the count before the prompt, per T18.

**The batch is not a transaction, and the guard is not called once for it.**
`authorize()` runs immediately before each item's `unlink()`, never once for
the group — the same reason it is already called twice rather than once. A
batch that authorised four hundred paths and then deleted four hundred paths
would collapse the TOCTOU protection of T3 into a single check with a long
window behind it.

**Residual, stated rather than hidden:** `os.unlink()` resolves a path, so a
window remains between an item's authorisation and its deletion, of the order
of one syscall. Closing it entirely means deleting by handle — `CreateFileW`
with `FILE_FLAG_OPEN_REPARSE_POINT`, then `FileDispositionInfo` — so that the
object deleted is provably the object inspected. That is recorded in
`docs/adr/0004` as a known residual with its mitigation named. It is narrowed,
not closed, by the component-wise reparse check of T2, which is what makes the
window hard to drive rather than merely brief.

**A user exclusion crosses the privilege boundary with the request.** The
helper cannot read the invoking user's settings: launched through `runas`, its
`%LOCALAPPDATA%` need not be the same profile. So exclusions travel in the
request — and this is safe for a reason worth stating plainly, because it is
the only place untrusted input shapes what the helper does:

> An exclusion can only ever *narrow* what is deleted. A caller that lies about
> them can cause the helper to delete less, never more.

The same argument licenses `expected_raw_value` in T13's undo check. Anything
that can only subtract from the permitted set is safe to accept from an
untrusted caller; nothing that could add to it ever is.

Without this, a path the user explicitly protected would be honoured on the
unelevated path and deleted on the elevated one — the setting would mean two
different things depending on which privilege level happened to reach the file.

### T23 — The elevated process is not the binary that was installed

**Found by the first real build, and it had shipped in every line of reasoning
before it.**

`_helper_command()` named `sys.executable` for a frozen build. Under Nuitka
onefile that is not the installed executable. Measured:

```
sys.executable               %TEMP%\onefile_<n>\python.exe
sys.argv[0]                  <install>\PolyScour.exe
__compiled__.original_argv0  <install>\PolyScour.exe
```

The extraction directory is under `%LOCALAPPDATA%\Temp` and is **writable by
the user** — measured too, in the same run.

So `ShellExecute("runas", sys.executable, ...)` would have raised a consent
prompt naming PolyScour for a binary that anything running as that user could
replace first. Accepting the prompt would run the attacker's code as
administrator.

This defeats T15 completely and from the side: the program directory can be
perfectly locked down, and it does not matter, because the thing being elevated
was never in it.

**Mitigated.** `paths.running_executable()` prefers
`__compiled__.original_argv0`, falling back to `sys.argv[0]`, and is the only
thing `entry.child_argv()` will launch. `sys.executable` is used only when not
frozen, where it is the development interpreter and T15 does not apply.

**Mitigated again, on purpose.** `elevation/client._launch()` refuses outright
to elevate an image whose directory this process can write. It probes by
attempting to create a file rather than by reading the DACL, because
`os.access(..., W_OK)` on Windows reports the read-only attribute and knows
nothing about permissions — it answers the wrong question in both directions.
Two mitigations for one bug is deliberate: the first is correct and the second
is what makes a regression fail closed instead of escalating.

**Caught in future by `tools/build_probe.py`**, which now fails a build whose
launch target is inside the extraction directory, or whose launch directory is
writable. Frozen-only: in a checkout the venv lives under the repo root, and a
probe that cries wolf on every developer run is one nobody reads on the run
that matters.

### The lesson, recorded because it is the fourth of its kind

Four bugs in this family have now been found, and every one of them was
invisible from source and harmless in development:

| | |
|---|---|
| `sys.frozen` | Nuitka does not set it; the frozen branch never ran |
| `parents[2]` | a build has no `src/` level; rules were never found |
| bare `python` in `build.ps1` | compiled the wrong interpreter's environment |
| `sys.executable` | **elevated a binary in a user-writable temp directory** |

The first three were correctness failures. The fourth was a privilege
escalation, and the only reason it is in this table rather than in a release is
that something was compiled and run.

**Reasoning about a packaged build is not evidence about a packaged build.**
`tools/build_probe.py` exists to turn that into a gate, and `build.ps1` fails
on it.

## The Game Mode supervisor

*Written before the supervisor existed, the same way the elevated helper's
section was: a specification the implementation had to satisfy rather than a
description of something already built. It now exists and satisfies it. The
order is kept deliberately — the day this section starts being edited to match
code that already shipped is the day it stops being a threat model.*

Game Mode freezes background programs and resumes them afterwards. T12 records
the residual it ships with:

> if PolyScour is hard killed and never launched again, the processes stay
> frozen until reboot

A frozen process does not exit, keeps its memory, and presents to the user as
an application that has hung for no reason. Nothing else on the machine knows
how to release it. `Services.__init__` calls `gamemode.recover()` on every
launch, so the gap closes the next time PolyScour runs — and stays open
indefinitely if it never does.

Closing it needs a second process that outlives the GUI's death by exactly long
enough to clean up after it.

### What it is not

**Not elevated.** Suspending and resuming the user's own processes needs no
administrator rights at all; `gamemode/session.py` already does both
unelevated. A supervisor that asked for privilege would be buying a standing
elevated target to pay for a convenience — the trade the helper's
"per-operation and not retained" section exists to refuse.

**Not a service, and not persistent.** It is started with a Game Mode session
and exits when that session's process is gone. It does not install, does not
survive a reboot, and there is nothing to uninstall. A resident process that
watches for PolyScour is a different product with a different threat model.

**Not the elevated helper.** The helper is launched per operation and exits;
that is the opposite shape from supervising, and `docs/adr/0005` already
records that it is therefore not the privileged component this product lacks.
The supervisor does not change that: it holds no privilege to lend.

### The shape

```
  PolyScour GUI (unelevated)
        │  starts a Game Mode session, freezes N processes
        │  spawns, passing its own pid and process start time
        ▼
  supervisor (unelevated, same user)
        │  opens a HANDLE to the parent, verifies the start time
        │  waits on that handle — no polling, no PID comparisons
        │
        ├── parent exits cleanly  → the ledger has no open rows → nothing to do
        └── parent is hard killed → gamemode.recover(ledger) → resume, record
```

Then it exits. In both cases it runs exactly the same code the next launch
would have run, just sooner.

### Its authority is the ledger, and nothing else

The supervisor replays the recovery set the session recorded. It **never**
enumerates the system looking for suspended processes.

That distinction is the whole of its safety. "Find everything that is suspended
and resume it" would touch processes PolyScour never froze — something else's
debugger, an installer mid-operation, a program a user deliberately paused —
and would do it with no record that anything was ever suspended in the first
place. `gamemode/policy.py` remains the authority over what may be touched, and
the ledger remains the record of what actually was.

Concretely: it calls `gamemode.recover(ledger)`, which is the function the GUI
already calls at startup. Not a copy of it. A second implementation of "resume
what we froze" is a second place for the PID-reuse guard to be forgotten.

### PID reuse, on both sides

PIDs are recycled freely, so "resume 1234" can mean an unrelated process by the
time anyone acts on it. This is already handled for the *suspended* processes:
each ledger row records the process creation time, and `_identify()` compares
it before resuming, reporting `recycled` rather than touching a stranger.

The supervisor introduces the same problem pointed at the *parent*. Waiting on
"the process with pid N" would, after a recycle, mean waiting on something
else — and then either never cleaning up, or cleaning up while PolyScour is
still running and resuming processes the user is still playing over.

So the supervisor is given the parent's pid **and its creation time**, opens a
handle immediately, and verifies the creation time before it waits. A handle
refers to a specific process object rather than to a number, so once opened it
cannot be redirected by a recycle. If the verification fails, the supervisor
exits without doing anything: it was aimed at the wrong process, and doing
nothing is the correct response to that.

### T20 — The supervisor is killed too

**Not mitigated, and this is a shorter window rather than a guarantee.**

A hard kill that takes both processes — a power loss, `taskkill /T` on the
tree, a bugcheck — leaves the suspended processes exactly where T12 left them:
frozen until PolyScour runs again, or until reboot.

The supervisor narrows the window from "until the user next opens PolyScour",
which may be never, to "until the moment PolyScour's process ends". It does not
close it. `README.md` must say so in those words, and must not say *processes
will always be restored*: resume-at-next-launch remains the fallback, and a
maintenance tool that overstates its own recovery is doing the thing this
product exists not to do.

### T21 — The supervisor resumes something it should not

**Mitigated by construction, twice over.**

It acts only on rows the session wrote, and every row carries the creation time
of the process it describes. A recycled PID is identified and skipped rather
than resumed blindly — the same check the startup path already makes, because
it is literally the same function.

Resuming is also the *safe* direction. The dangerous operation in this feature
is suspending, and the supervisor has no path to it: there is no code in it
that can freeze anything, only code that unfreezes what the ledger says was
frozen. A supervisor that behaves completely wrongly resumes a process that was
already running, which is a no-op.

### T22 — The supervisor is launched by something else

**Not a privilege boundary, and does not need to be.**

Anyone who can run the supervisor can already run PolyScour, as themselves,
with the same rights. Doing so gains them nothing they did not have: the worst
available outcome is resuming processes that the *same user* previously
suspended through PolyScour, which that user could do from Task Manager.

It takes a pid and a creation time, and both only narrow what it will do — an
argument that fails to match a running process means it exits without acting.
That is the same test every parameter crossing into the elevated helper has to
pass, applied here even though nothing here is privileged, because a parameter
that can only cause less action is one nobody has to reason about again.

The supervisor holds no elevated rights to lend, opens no port, and listens for
nothing.

### The ledger is now written by two processes

It already can be — the cross-process mutation lock in `ledger.py` exists
because a second PolyScour may be running — and the supervisor is one more
writer of the same kind, taking the same lock for the same brief writes.

The ordering that makes this safe is the one Game Mode already has: the
suspension is recorded **before** the process is frozen. A supervisor that
wakes to find a row for a process that was never actually suspended performs a
harmless resume on something already running. The reverse ordering would leave
a frozen process with no row, which nothing — supervisor or startup — would
ever find.

## Non-goals

PolyScour is not an antivirus and does not try to be. It can say an item is
*unusual*; it will not say it is *malware*. Where PolyShield is present, that
question belongs to PolyShield.

PolyScour does not defend against an attacker who already has administrator
rights, or who can modify its own installed code. Neither is defensible from
inside an unelevated user-mode application.
