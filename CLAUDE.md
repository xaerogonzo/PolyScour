@D:\Claude Co worker\Token Save Manager Source\templates\project-baseline.md

# PolyScour — Claude Project Instructions

## The invariants

These are not style preferences. They are what the product is.

> **A finding is not a recommendation.** PolyScour must never treat the
> existence of a Windows mechanism as evidence that modifying it is beneficial.
> Detection, diagnosis, recommendation and modification are four separate
> decisions.

This matters most in the features that are still ahead — services, registry,
startup, drivers, scheduled tasks — where the easy chain of reasoning is
"unused startup item → disable it" when the correct answer is usually "startup
impact is negligible → leave it alone." It has already bitten once: the
dashboard briefly headlined *"63 devices not reporting OK"*, which is what
`Get-PnpDevice | Where Status -ne 'OK'` returns on any normal machine because
every USB device ever plugged in keeps an entry. That is exactly the
alarming-but-meaningless number this product exists to replace.

> **Configuration is not authority.** A cleaning rule is data, and data is
> untrusted. What a rule may touch lives in `polyscour/safety/policy.py`, which
> is code and goes through review. Rules name *symbolic root families*; they
> cannot name a path at all.

> **Every feature that changes Windows state must document the exact mechanism
> it modifies.** "Startup Manager → `HKCU\...\CurrentVersion\Run` registry key",
> never "Startup Manager → some Windows startup thing."

> **Never force.** No handle closing, no read-only bit clearing, no aggressive
> deletion. A locked file is a normal condition on a live machine. Skip it,
> report it, continue.

## Tokensave: use it first

Tokensave is active. **Before reaching for `Read` or `Grep`, try a tokensave
tool.** `tokensave_context` for exploration, `tokensave_search` for a known
symbol, `tokensave_callers`/`tokensave_callees` for call graphs. Fall back to
`Read` only when you need an implementation body to edit it.

## Project overview

**Name:** PolyScour — a transparent, evidence-based Windows maintenance suite
**Stack:** Python 3.11+, CustomTkinter, Windows-only
**Entry point:** `python -m polyscour.app` → `App.mainloop()`
**Venv:** `venv/`
**Shared substrate:** [PolyBedrock](../PolyBedrock) — `polybedrock-core` (platform) and
`polybedrock-ui` (theming), installed editable. See `../PolyBedrock/docs/adr/`.

## Project structure

```
src/polyscour/
├── app.py            CTk shell — sidebar nav, lazy view factories, Services
├── paths.py          polybedrock.paths shim; app_name="PolyScour", scope="user"
├── settings.py       polybedrock.settings shim + PolyScour DEFAULTS
├── contracts.py      Finding, ScanResult, ActionPlan, ActionResult, outcomes
├── safety/
│   ├── policy.py     RootFamily, RuleTrustPolicy, POLICY — THE AUTHORITY
│   ├── reparse.py    Component-wise reparse inspection, before canonicalising
│   └── guard.py      The chain: policy → roots → reparse → contain → denylist
├── ledger.py         SQLite history + reversals + the cross-process mutation lock
├── vault.py          Staged deletion: content-addressed objects + manifests
├── cleaning/
│   ├── rules.py      Load JSON, reconcile against policy (narrow only)
│   ├── scanner.py    DISCOVER → ANALYZE. Deletes nothing, ever.
│   ├── planner.py    Findings → recommendations → ActionPlan
│   └── executor.py   EXECUTE → VERIFY → LOG. The only code that removes things.
├── integrations/
│   └── polyshield.py Optional, read-only, three commands, fails closed
└── views/            dashboard, clean, history, settings
rules/cleaners/*.json  Data only. Never executable, never authority.
tools/uishot/         Headless GUI capture — scenes + entry-point wiring.
                      Machinery lives in polybedrock.ui.uishot.
tests/golden/ui/      Recorded expected look. Tracked; artifacts/ is not.
```

## Testing the GUI without it being on screen

```powershell
venv\Scripts\python.exe tools\uishot\__main__.py            # capture every scene
venv\Scripts\python.exe tools\uishot\__main__.py --list
venv\Scripts\python.exe tools\uishot\__main__.py --check    # fail on visual drift
venv\Scripts\python.exe tools\uishot\__main__.py --update-golden
```

No visible window, no focus stealing, **no mouse control** — the window lives on
a hidden Win32 desktop. Widgets are driven through Tk (`invoke()`, calling a
handler directly), never by synthesising input.

Scenes **construct** their state rather than reaching it naturally: a real scan
takes ~39 seconds and returns different numbers every run. `@scene(name,
golden=False)` marks a scene whose content is live and therefore not comparable
(`settings`, whose protected-locations list is this machine's environment).

The harness redirects `POLYSCOUR_DATA_DIR` to a temp directory before importing
anything, so a capture never touches the real vault or ledger.

**`--check` against the committed goldens is a local gate and must stay one.**
`tests/test_uishot.py::test_check_passes_against_the_recorded_goldens` skips
when `CI` is set, because the PNGs encode this machine's font rasterisation and
DPI. That skip is deliberate — do not "fix" it by committing runner goldens or
by loosening the tolerance; a tolerance wide enough for cross-machine fonts is
wide enough to miss a moved button. The portable half still runs everywhere:
record-into-tmp, compare, and a negative control proving a corrupted golden is
actually caught. Set `POLYSCOUR_GOLDEN_GATE=1` to force the comparison anyway.

## Documentation files

| File | Covers |
|---|---|
| `README.md` | What it is, what it refuses to do, how to run it |
| `docs/SAFETY.md` | The guard chain, in detail. Read before touching `safety/`. |
| `docs/THREAT_MODEL.md` | Accidental safety vs adversarial local security |
| `docs/ARCHITECTURE.md` | Module responsibilities, data flow, threading |
| `docs/CLEANING_RULES.md` | The rule format and how to add one |
| `docs/PRIVACY.md` | What is read, what is stored, what is never sent |
| `docs/SUPPORT_MATRIX.md` | Windows versions and per-feature availability |
| `docs/adr/` | Decisions with their reasoning |

## Documentation discipline

After any code change, update docs **in the same response** when the change
affects behaviour, architecture or the public interface.

| What changed | Update |
|---|---|
| New module, symbol or pattern | **CLAUDE.md** — structure table |
| The guard, the policy, root families | **docs/SAFETY.md** *and* **docs/THREAT_MODEL.md** |
| Data flow, threading, module responsibilities | **docs/ARCHITECTURE.md** |
| A new cleaning rule or rule-format field | **docs/CLEANING_RULES.md** |
| Anything user-visible | **README.md** |
| A decision with a real alternative | a new **docs/adr/** entry |

Skip doc updates for pure internal refactors with no behaviour change.

## Project-specific rules

- **Adding a cleaning rule is a code change.** A JSON file alone cannot ship: it
  needs a reviewed `PolicyEntry` in `safety/policy.py`, and a `RootFamily` with
  a resolver if the location is new. This is deliberate friction.
- **Dry run is the default** at every level — `planner.plan()` defaults
  `dry_run=True`, and so does the settings key. A caller that wants to change
  the machine says so explicitly.
- **The guard is called twice** — once during the scan, once immediately before
  each destructive operation. The second call is not redundant; it is what makes
  the TOCTOU race lose.
- **0.1 runs entirely unelevated.** Anything needing admin is skipped and
  reported plainly. The elevated helper is a 0.2 concern.
- **No telemetry, ever.** Not opt-in, not anonymous, not "just crash reports"
  without an explicit decision recorded in an ADR.
- **Performance work needs a measurement, not a guess.** The scan went from
  >90s to 39s by finding that `permitted_roots()` was globbing the Chrome
  profile tree once per candidate file — 7.2 ms × 36,000. It was found by
  timing it, after a guess would have blamed the reparse walk.
