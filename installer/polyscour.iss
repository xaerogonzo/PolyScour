; ============================================================================
;  polyscour.iss - PolyScour setup program
; ============================================================================
;
;   build.ps1 -Target installer        (compiles this with ISCC.exe)
;
;  TRACKED ON PURPOSE, for the same reason build.ps1 is: a release artifact
;  that cannot be reproduced from the repository is not reproducible.
;
;  Expects a completed dist\PolyScour.exe -- build with:
;      .\build.ps1
;
;  What this installs, and what it deliberately does not:
;
;    Program files    {autopf}\PolyScour  (PolyScour.exe, and nothing else)
;                     ACLs tightened AFTER install -- see [Run] below and
;                     installer\set_program_acls.ps1
;
;    NOT a data root  PolyScour has no privileged writer: the vault, ledger and
;                     settings are written by the unelevated GUI on every run,
;                     so they live in %LOCALAPPDATA% and the application creates
;                     them itself on first launch. See docs/adr/0005 for why a
;                     %ProgramData% tree would be a boundary in the
;                     documentation and nowhere else.
;
;    NOT a service    there is none. The elevated helper is the same executable
;                     under an argument, launched per operation through
;                     Windows' own consent prompt, and it exits when done.
;
;    NOT a rules dir  cleaning rules ship INSIDE the binary. Adding one already
;                     requires a reviewed PolicyEntry in code, so an editable
;                     rules folder would offer the appearance of configurability
;                     with none of the authority. See docs/adr/0006.
;
;    NOT an autorun   PolyScour does not start with Windows. A maintenance tool
;                     that installs its own autorun while shipping a screen that
;                     declines to recommend disabling anyone else's would be
;                     saying two different things.
;
;  Why this needs administrator rights: for the ACLs, and only for those. The
;  program directory must be one an ordinary user cannot write, because an
;  attacker who can rewrite PolyScour.exe has rewritten the elevated helper --
;  and then no rule inside it means anything. That is THREAT_MODEL.md T15, and
;  it is the whole reason installing beats unzipping.
; ============================================================================

#define AppName        "PolyScour"
#define AppVersion     "0.2.0"
#define AppPublisher   "Alexander L Corthell"
#define AppExeName     "PolyScour.exe"
#define DistDir        "..\dist"

[Setup]
AppId={{4E9A7C31-6D82-4F15-9C0B-3A7E5D1F8B24}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\dist
OutputBaseFilename=PolyScour-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Required for the ACLs below, and that is the only thing it is required for.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
LicenseFile=..\LICENSE
; Restart Manager is deliberately off. PolyShield turned it on and paid for it
; twice: it applies to uninstall as well as install, and a /VERYSILENT
; uninstall sat idle indefinitely waiting on it, producing no report at all.
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#DistDir}\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; The ACL script travels with the installation rather than only running from
; the installer's temp directory, so the boundary can be re-checked -- and
; re-applied -- on a machine long after setup has been deleted.
Source: "set_program_acls.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; \
    GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
; The reason this installer exists. {autopf} is already administrator-only on a
; default Windows installation -- but "already, by default, probably" is not a
; security boundary, and an installation into a non-default DefaultDirName
; would inherit whatever ACL that parent had. Set it explicitly, and verify it.
;
; Runs BEFORE the "launch now" step below, so the program is never started from
; a directory whose permissions have not been established.
Filename: "powershell.exe"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\set_program_acls.ps1"" -Root ""{app}"""; \
    StatusMsg: "Securing the program directory..."; \
    Flags: runhidden waituntilterminated

; Verify, do not assume -- the same discipline the cleaning path uses when it
; re-scans after a run. A failure here is surfaced rather than swallowed:
; an installation whose ACLs did not take is one where T15 is a claim only.
Filename: "powershell.exe"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\set_program_acls.ps1"" -Root ""{app}"" -Verify"; \
    StatusMsg: "Checking the program directory permissions..."; \
    Flags: runhidden waituntilterminated

Filename: "{app}\{#AppExeName}"; Description: "Start {#AppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Nothing here removes user data. The vault may hold the only remaining copy of
; a file someone deleted through PolyScour, and an uninstaller is not the place
; to make that decision for them -- %LOCALAPPDATA%\PolyScour is left alone, and
; the README says where it is so anyone who wants it gone can remove it.
Type: files; Name: "{app}\set_program_acls.ps1"
