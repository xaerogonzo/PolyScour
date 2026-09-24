r"""Everything else that starts with Windows -- read, and never changed.

``manager.py`` covers the registry ``Run`` values and can flip their switch.
Those are a minority of what actually starts. This module lists the rest:

    Startup folders            %APPDATA% / %PROGRAMDATA% ...\Start Menu\Programs\Startup
    RunOnce keys               HKCU / HKLM (and the 32-bit view) ...\CurrentVersion\RunOnce
    Scheduled tasks            those with a LogonTrigger or BootTrigger
    Services                   Win32 services whose start type is Automatic

**There is no writer here, and no switch anywhere on the screen that shows
it.** Changing a task or a service is a different mechanism with a different
threat model (ADR 0011); this is the "detection" half of the four separate
decisions and stops there. Nothing in this module scores, ranks, or says
that anything is unnecessary.

How each source is read, and what it cannot tell us
---------------------------------------------------

* **Startup folders** -- a directory listing, plus the ``StartupApproved``
  ``StartupFolder`` byte Task Manager uses. A ``.lnk`` file's *target* is not
  read (that needs COM, and a shortcut is listed as the file it is).
* **RunOnce** -- registry values. Windows deletes them after running, so
  seeing one means it has not run yet; it has no on/off switch to report.
* **Scheduled tasks** -- ``schtasks.exe /query /xml ONE``, by absolute path,
  no shell, no user input in the command line. ``%SystemRoot%\System32\Tasks``
  is not listable without administrator rights (measured: WinError 5), and the
  registry ``TaskCache`` is not either; ``schtasks`` is the unelevated door.
  If it fails, the source is reported **unread**, which is not the same as
  "no tasks".
* **Services** -- ``HKLM\SYSTEM\CurrentControlSet\Services``, readable by any
  account. For a service hosted by ``svchost.exe`` the program that actually
  runs is its ``Parameters\ServiceDll``, so *that* is what is looked at.

The one filter, and what it does not claim
------------------------------------------

Scheduled tasks and services number in the hundreds and most are Windows'
own. A task or service whose program lives **inside the Windows folder** is
counted and not listed. That is a statement about a *location*, not about
trust: a file in the Windows folder is not thereby harmless, and the count is
shown so that nothing is silently absent. Anything whose program cannot be
worked out is listed, never hidden -- an unknown is not a reason to drop a row.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import winreg
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from polybedrock.startup import extract_path

from polyscour.startup.manager import TargetState

_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
_ENABLED_BYTE_DISABLED = 0x03
_SCHTASKS_TIMEOUT_S = 60


class Source(Enum):
    STARTUP_FOLDER = "Startup folder"
    RUN_ONCE = "RunOnce key"
    SCHEDULED_TASK = "Scheduled task"
    SERVICE = "Service"


@dataclass(frozen=True)
class InventoryEntry:
    """One thing that starts with Windows, named by the mechanism that does it.

    ``mechanism`` is the exact place it was read from -- a registry path, a
    folder, a task path, a service key -- so that the screen can say what is
    being described rather than gesture at "some Windows startup thing".
    ``state`` is a fact about the entry ("enabled", "disabled in Task Manager",
    "task disabled") or ``None`` when the source has no such notion.
    """
    source: Source
    name: str
    mechanism: str
    launches: str            # the command line / file / image, as recorded
    target_path: str         # "" when none could be worked out
    target: TargetState
    runs_as: str             # "" when the source does not say
    state: str | None = None


@dataclass(frozen=True)
class SourceStatus:
    """How a source read went. ``error`` set means UNREAD, not empty."""
    source: Source
    error: str | None = None
    listed: int = 0
    in_windows_folder: int = 0     # counted, not listed (see module docstring)


@dataclass
class Inventory:
    entries: list[InventoryEntry] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)

    def of(self, source: Source) -> list[InventoryEntry]:
        return [e for e in self.entries if e.source is source]

    def status(self, source: Source) -> SourceStatus:
        for s in self.statuses:
            if s.source is source:
                return s
        raise KeyError(source)


# ── shared helpers ───────────────────────────────────────────────────────────

def _windows_dir() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


def in_windows_folder(path: str) -> bool:
    r"""Whether ``path`` is inside the Windows folder. A location, not a verdict.

    Compared on normalised, case-folded path *components*, so
    ``C:\Windows.old\x.exe`` and ``C:\WindowsApps\x.exe`` are not "inside".
    """
    if not path:
        return False
    norm = os.path.normcase(os.path.normpath(os.path.expandvars(path)))
    base = os.path.normcase(os.path.normpath(_windows_dir()))
    return norm == base or norm.startswith(base + os.sep)


def _target_state(path: str) -> TargetState:
    if not path or "\ufffd" in path:
        return TargetState.UNRESOLVED
    try:
        return TargetState.PRESENT if Path(path).exists() else TargetState.MISSING
    except OSError:
        return TargetState.UNRESOLVED


def _expanded(command: str) -> str:
    return os.path.expandvars(command.strip().strip('"'))


# ── startup folders ──────────────────────────────────────────────────────────

_FOLDERS = [
    ("user", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
     winreg.HKEY_CURRENT_USER),
    ("machine", r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp",
     winreg.HKEY_LOCAL_MACHINE),
]
_FOLDER_APPROVED = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                    r"\StartupApproved\StartupFolder")


def _folder_approvals(hive) -> dict[str, bool]:
    out: dict[str, bool] = {}
    try:
        with winreg.OpenKey(hive, _FOLDER_APPROVED) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if isinstance(value, bytes) and value:
                    out[name.lower()] = value[0] != _ENABLED_BYTE_DISABLED
    except OSError:
        pass
    return out


def read_startup_folders() -> tuple[list[InventoryEntry], SourceStatus]:
    entries: list[InventoryEntry] = []
    errors: list[str] = []
    for scope, template, hive in _FOLDERS:
        folder = os.path.expandvars(template)
        try:
            names = os.listdir(folder)
        except FileNotFoundError:
            continue                     # no such folder is a normal machine
        except OSError as exc:
            errors.append(f"{folder}: {exc}")
            continue
        approvals = _folder_approvals(hive)
        for name in sorted(names, key=str.lower):
            if name.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, name)
            enabled = approvals.get(name.lower(), True)
            entries.append(InventoryEntry(
                source=Source.STARTUP_FOLDER, name=name, mechanism=folder,
                launches=full, target_path=full, target=_target_state(full),
                runs_as="every account" if scope == "machine" else "you",
                state="enabled" if enabled else "disabled in Task Manager"))
    return entries, SourceStatus(Source.STARTUP_FOLDER,
                                 error="; ".join(errors) or None,
                                 listed=len(entries))


# ── RunOnce ──────────────────────────────────────────────────────────────────

_RUNONCE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
_RUNONCE_KEYS = [
    ("HKCU", winreg.HKEY_CURRENT_USER, _RUNONCE, "you"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, _RUNONCE, "every account"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
     "every account"),
]


def read_run_once() -> tuple[list[InventoryEntry], SourceStatus]:
    entries: list[InventoryEntry] = []
    errors: list[str] = []
    for label, hive, path, runs_as in _RUNONCE_KEYS:
        try:
            with winreg.OpenKey(hive, path, access=winreg.KEY_READ
                                | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    target = extract_path(str(value))
                    entries.append(InventoryEntry(
                        source=Source.RUN_ONCE, name=name,
                        mechanism=f"{label}\\{path}", launches=str(value),
                        target_path=target, target=_target_state(target),
                        runs_as=runs_as,
                        state="runs once, then Windows removes it"))
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{label}\\{path}: {exc}")
    return entries, SourceStatus(Source.RUN_ONCE,
                                 error="; ".join(errors) or None,
                                 listed=len(entries))


# ── scheduled tasks ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _TaskFacts:
    uri: str
    triggers: tuple[str, ...]      # only the boot/logon ones, by element name
    trigger_enabled: tuple[bool, ...]
    task_enabled: bool
    commands: tuple[str, ...]      # <Exec><Command>, raw
    com_classes: tuple[str, ...]   # <ComHandler><ClassId>, a CLSID
    has_other_actions: bool        # e.g. SendEmail: nothing to compare
    runs_as: str


def _text(node, path: str) -> str:
    found = node.find(path)
    return (found.text or "").strip() if found is not None else ""


def parse_task_xml(document: str) -> _TaskFacts | None:
    """Facts from one task's XML, or ``None`` when it is not a boot/logon task.

    Raises ``ET.ParseError`` on a document that is not XML, so the caller can
    count it as unreadable rather than as "not a startup task".
    """
    root = ET.fromstring(document)
    triggers = root.find(f"{_TASK_NS}Triggers")
    boot_logon = [t for t in (triggers if triggers is not None else [])
                  if t.tag in (f"{_TASK_NS}LogonTrigger", f"{_TASK_NS}BootTrigger")]
    if not boot_logon:
        return None

    actions = root.find(f"{_TASK_NS}Actions")
    commands, classes, other = [], [], False
    for action in (actions if actions is not None else []):
        if action.tag == f"{_TASK_NS}Exec":
            commands.append(_text(action, f"{_TASK_NS}Command"))
        elif action.tag == f"{_TASK_NS}ComHandler":
            classes.append(_text(action, f"{_TASK_NS}ClassId"))
        else:
            other = True

    principal = root.find(f"{_TASK_NS}Principals/{_TASK_NS}Principal")
    runs_as = ""
    if principal is not None:
        runs_as = (_text(principal, f"{_TASK_NS}UserId")
                   or _text(principal, f"{_TASK_NS}GroupId"))
    return _TaskFacts(
        uri=_text(root, f"{_TASK_NS}RegistrationInfo/{_TASK_NS}URI"),
        triggers=tuple(t.tag.replace(_TASK_NS, "") for t in boot_logon),
        trigger_enabled=tuple(
            _text(t, f"{_TASK_NS}Enabled").lower() != "false" for t in boot_logon),
        task_enabled=_text(root, f"{_TASK_NS}Settings/{_TASK_NS}Enabled").lower()
        != "false",
        commands=tuple(c for c in commands if c),
        com_classes=tuple(c for c in classes if c),
        # An Exec with an empty Command, or a ComHandler with no class, is an
        # action we could not read: it must not be counted as "nothing".
        has_other_actions=other or not all(commands) or not all(classes),
        runs_as=runs_as)


_CLSID_KEYS = (r"SOFTWARE\Classes\CLSID\{}\InprocServer32",
               r"SOFTWARE\Classes\CLSID\{}\LocalServer32")


def com_server(clsid: str) -> str:
    """The program a COM class loads, or ``""`` when it cannot be found.

    Read from the machine-wide class registration only (HKLM). A class
    registered per-user, or not at all, is "not found" -- shown, never hidden.
    """
    for template in _CLSID_KEYS:
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    template.format(clsid),
                                    access=winreg.KEY_READ | view) as key:
                    value = winreg.QueryValueEx(key, "")[0]
            except OSError:
                continue
            if value:
                return _expanded(extract_path(str(value)) or str(value))
    return ""


_WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone", "S-1-5-4": "whoever is signed in (Interactive)",
    "S-1-5-11": "Authenticated Users", "S-1-5-18": "SYSTEM",
    "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators group", "S-1-5-32-545": "Users group",
}


def account_name(sid: str) -> str:
    """A readable account for a SID, or the SID itself if it cannot be resolved.

    Never guesses: a SID that does not resolve is shown as the SID.
    """
    if sid in _WELL_KNOWN_SIDS:
        return _WELL_KNOWN_SIDS[sid]
    if not sid.startswith("S-1-"):
        return sid                      # already a name
    try:
        advapi, kernel = ctypes.windll.advapi32, ctypes.windll.kernel32
        psid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
            return sid
        try:
            name = ctypes.create_unicode_buffer(256)
            domain = ctypes.create_unicode_buffer(256)
            n, d = ctypes.c_uint32(256), ctypes.c_uint32(256)
            use = ctypes.c_uint32()
            if not advapi.LookupAccountSidW(None, psid, name, ctypes.byref(n),
                                            domain, ctypes.byref(d),
                                            ctypes.byref(use)):
                return sid
            return f"{domain.value}\\{name.value}" if domain.value else name.value
        finally:
            kernel.LocalFree(psid)
    except (AttributeError, OSError):          # pragma: no cover - non-Windows
        return sid


def _task_entry(facts: _TaskFacts, resolve_com=com_server) -> InventoryEntry:
    programs = [_expanded(c) for c in facts.commands]
    notes = list(facts.commands)
    for clsid in facts.com_classes:
        server = resolve_com(clsid)
        notes.append(f"COM class {clsid} -> {server or 'no registered server found'}")
        if server:
            programs.append(server)
    target = programs[0] if programs else ""
    when = " and ".join(sorted({t.replace("Trigger", "").lower()
                                for t in facts.triggers}))
    if not facts.task_enabled:
        state = "task disabled"
    elif not any(facts.trigger_enabled):
        state = "its boot/logon trigger is disabled"
    else:
        state = "enabled"
    launches = " ; ".join(notes) if notes \
        else "(no program: it runs some other kind of action)"
    return InventoryEntry(
        source=Source.SCHEDULED_TASK,
        name=facts.uri.rsplit("\\", 1)[-1] or facts.uri or "(unnamed task)",
        mechanism=f"Task Scheduler {facts.uri or '(no path)'}, at {when}",
        launches=launches, target_path=target, target=_target_state(target),
        runs_as=account_name(facts.runs_as), state=state)


def task_is_windows_own(facts: _TaskFacts, resolve_com=com_server) -> bool:
    """True only when every program it runs is inside the Windows folder.

    An action we cannot read (empty command, unregistered COM class, an action
    type with nothing to compare) makes this False, so it stays in the list.
    """
    if facts.has_other_actions:
        return False
    programs = [_expanded(c) for c in facts.commands]
    for clsid in facts.com_classes:
        server = resolve_com(clsid)
        if not server:
            return False
        programs.append(server)
    return bool(programs) and all(in_windows_folder(p) for p in programs)


def _oem_encoding() -> str:
    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except (AttributeError, OSError):                      # pragma: no cover
        return "utf-8"


def _run_schtasks() -> bytes:
    exe = os.path.join(_windows_dir(), "System32", "schtasks.exe")
    result = subprocess.run(
        [exe, "/query", "/xml", "ONE"], capture_output=True, shell=False,
        timeout=_SCHTASKS_TIMEOUT_S,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
    if result.returncode != 0:
        raise OSError(f"schtasks exited {result.returncode}: "
                      f"{result.stderr.decode(_oem_encoding(), 'replace')[:200]}")
    return result.stdout


#: ``<Task`` followed by a space, so the ``<Tasks>`` wrapper is not matched.
_TASK_DOCUMENT = re.compile(r"<Task .*?</Task>", re.DOTALL)


def split_task_documents(raw: bytes) -> list[str]:
    """One XML document per task, from ``schtasks /query /xml ONE``.

    Measured, not assumed: piped, the output is a single ``<Tasks>`` wrapper
    holding ``<!-- (the task path) -->`` comments and ``<Task>`` elements, with no
    ``<?xml`` headers at all -- the first version of this function looked for
    headers, found none, and reported "no scheduled tasks" without an error.
    The wrapper is not parsed as a whole because a comment containing ``--``
    (a task named ``a--b``) would make the entire document invalid; each
    ``<Task>`` is cut out and parsed alone, so one bad task costs one row.

    The bytes are the console's OEM code page. A character that does not
    survive the decode becomes U+FFFD and stays visible, not repaired: a path
    that might be wrong must not become a confident "missing".
    """
    text = raw.decode(_oem_encoding(), errors="replace")
    return _TASK_DOCUMENT.findall(text)


def read_scheduled_tasks() -> tuple[list[InventoryEntry], SourceStatus]:
    try:
        raw = _run_schtasks()
        documents = split_task_documents(raw)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], SourceStatus(Source.SCHEDULED_TASK, error=str(exc))
    if raw.strip() and not documents:
        # Output we do not recognise is UNREAD, never "no tasks". This is the
        # exact silent failure the first version had.
        return [], SourceStatus(Source.SCHEDULED_TASK,
                                error="schtasks printed output in a shape "
                                      "this version does not recognise")
    if not documents:
        return [], SourceStatus(Source.SCHEDULED_TASK,
                                error="schtasks listed no tasks at all, which "
                                      "no Windows machine does; treating the "
                                      "list as unread")

    entries: list[InventoryEntry] = []
    windows_own = unparsed = 0
    for document in documents:
        try:
            facts = parse_task_xml(document)
        except ET.ParseError:
            unparsed += 1
            continue
        if facts is None:
            continue
        if task_is_windows_own(facts):
            windows_own += 1
            continue
        entries.append(_task_entry(facts))
    error = (f"{unparsed} task definition(s) could not be parsed and are "
             f"missing from this list" if unparsed else None)
    return entries, SourceStatus(Source.SCHEDULED_TASK, error=error,
                                 listed=len(entries),
                                 in_windows_folder=windows_own)


# ── services ─────────────────────────────────────────────────────────────────

_SERVICES = r"SYSTEM\CurrentControlSet\Services"
_SERVICE_WIN32 = 0x30            # own process (0x10) | shared process (0x20)
_START_AUTO = 2


def _query(key, name: str):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def service_entry(name: str, values: dict, service_dll: str | None
                  ) -> InventoryEntry | None:
    """An entry for an automatic Win32 service, or ``None`` if it is not one.

    ``values`` are the raw registry values (``Type``, ``Start``, ``ImagePath``,
    ``DisplayName``, ``ObjectName``, ``DelayedAutostart``). Split out from the
    registry read so the selection can be tested against constructed values.
    """
    stype, start = values.get("Type"), values.get("Start")
    if not isinstance(stype, int) or not stype & _SERVICE_WIN32:
        return None                       # a driver, not a service
    if start != _START_AUTO:
        return None
    image = str(values.get("ImagePath") or "")
    program = extract_path(image) if image else ""
    # svchost only hosts: the code that runs is the ServiceDll.
    if service_dll and os.path.basename(program).lower() == "svchost.exe":
        program = _expanded(service_dll)
    display = str(values.get("DisplayName") or "")
    if display.startswith("@"):           # a resource string, not a name
        display = ""
    delayed = values.get("DelayedAutostart") == 1
    return InventoryEntry(
        source=Source.SERVICE, name=display or name,
        mechanism=f"HKLM\\{_SERVICES}\\{name}",
        launches=image or "(no ImagePath)", target_path=program,
        target=_target_state(program),
        runs_as=str(values.get("ObjectName") or ""),
        state="automatic (delayed start)" if delayed else "automatic")


def read_services() -> tuple[list[InventoryEntry], SourceStatus]:
    entries: list[InventoryEntry] = []
    windows_own = 0
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES)
    except OSError as exc:
        return [], SourceStatus(Source.SERVICE, error=str(exc))
    with root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, name) as key:
                    values = {v: _query(key, v) for v in (
                        "Type", "Start", "ImagePath", "DisplayName",
                        "ObjectName", "DelayedAutostart")}
                    dll = None
                    try:
                        with winreg.OpenKey(key, "Parameters") as params:
                            dll = _query(params, "ServiceDll")
                    except OSError:
                        pass
            except OSError:
                continue          # a key we cannot open is not evidence of a service
            entry = service_entry(name, values, dll)
            if entry is None:
                continue
            if entry.target_path and in_windows_folder(entry.target_path):
                windows_own += 1
                continue
            entries.append(entry)
    entries.sort(key=lambda e: e.name.lower())
    return entries, SourceStatus(Source.SERVICE, listed=len(entries),
                                 in_windows_folder=windows_own)


# ── the whole picture ────────────────────────────────────────────────────────

def read_inventory() -> Inventory:
    """Every source, each independent: one failing does not blank the others."""
    inventory = Inventory()
    for reader in (read_startup_folders, read_run_once,
                   read_scheduled_tasks, read_services):
        try:
            entries, status = reader()
        except Exception as exc:                            # noqa: BLE001
            # A reader bug must degrade to "this source unread", never to a
            # crashed screen or, worse, a quiet empty list.
            source = {read_startup_folders: Source.STARTUP_FOLDER,
                      read_run_once: Source.RUN_ONCE,
                      read_scheduled_tasks: Source.SCHEDULED_TASK,
                      read_services: Source.SERVICE}[reader]
            entries, status = [], SourceStatus(source, error=f"{type(exc).__name__}: {exc}")
        inventory.entries.extend(entries)
        inventory.statuses.append(status)
    return inventory


def describe(entry: InventoryEntry) -> str:
    """A factual line about what this entry launches. No verdict.

    Same phrasing rule as ``policy.describe_target``: "not on disk" is a
    fact; "safe to remove" would be a recommendation.
    """
    if entry.target is TargetState.PRESENT:
        return entry.target_path
    if entry.target is TargetState.MISSING:
        return f"{entry.target_path} — not on disk"
    return f"{entry.launches} — could not work out what this launches"
