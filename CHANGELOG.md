# Changelog

One line per change, newest first. The pull request holds the reasoning; the
ADR holds the decision. Backfilled from merge history on 2026-10-23.

## 0.4.0 — 2026-10-23

- Game Mode: the screen's USER-object cost is bounded however many processes
  run, and its caps are stated (#39).
- Live driver: runs a JSON script inside the real app, sandboxed, with no mouse
  or keyboard, and can read the app's console and logs (#38, adr/0016).
- PolyShield path awareness: a path PolyShield has a recorded detection at is
  left alone, and a setting turns the questions off. It can only ever refuse
  (#37, adr/0015).
- Scheduling consumes PolyBedrock's shared `schtasks.exe` invocation.
- Scheduled cleaning: unattended runs that consent once to an exact rule digest
  and never elevate (#36, adr/0014).
- Uninstall: lists installed programs and launches each one's own uninstaller,
  parsed and unelevated (#35, adr/0013).
- Fix: the dashboard's PolyShield tile read a field PolyShield never sends (#34).
- Recycle Bin: emptied as a Shell operation, `moderate` and irreversible, never
  pre-ticked (#33, adr/0012).

## 0.3.0 — 2026-09-25

- Startup: a pending administrator request is visible and cancellable (#31).
- pip, npm and Cargo caches are `low` risk, so they arrive unticked (#30).
- npm and Cargo cache rules, and the measured reason Gradle has none (#25,
  adr/0010).
- A Clean rule for pip's download cache (#24, adr/0009).
- Startup: a row is locked while its administrator request is pending (#28).
- Startup: 32-bit machine-wide entries use their own approval record (#27).
- Startup: a view-only list of everything else that starts with Windows (#26,
  adr/0011).
- Storage: clear saved scans; Clean points at Storage after a real cleanup (#23).
- Storage: says what changed since the last scan, without inventing a number
  (#21, #22, adr/0008).

## 0.2.0 — 2026-09-21

- `run.bat` launches the source GUI (#19).
- The Storage Analyser: a budgeted read-only walk that names what it could not
  read (#18, adr/0007).
- The installed build is measured, and the boundary it was missing is added
  (#15–#17).
- Game Mode recovery supervisor, after its threat model (#13, #14).
- The program directory becomes a boundary (#12).
- One executable, two programs: the elevated branch never imports a GUI (#11,
  adr/0006).
- The vault stays in `%LOCALAPPDATA%` (#9, adr/0005).
- The elevated helper, after its threat model (#6–#8, adr/0004).
- Startup Manager (#5) and Game Mode (#4).

## 0.1 — 2026-09-05

- Foundation and the first vertical slice: scan → findings → plan → confirm →
  clean → verify → record → undo.
