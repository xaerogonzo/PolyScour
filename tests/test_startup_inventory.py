r"""tests/test_startup_inventory.py -- the view-only list of everything else.

What carries this module:

**An unread source is not an empty one.** The first version of the task reader
looked for ``<?xml`` headers that ``schtasks`` does not print when piped, found
none, and reported "no scheduled tasks" with no error -- on a machine with 226.
Every test below that feeds the reader something it cannot use asserts an
*error*, never an empty success.

**A location filter is not a verdict.** Programs inside the Windows folder are
counted and not listed; anything that cannot be worked out stays in the list.

**It reads and never writes.** Checked statically as well as by behaviour, and
the static check is shown able to fail.
"""
from __future__ import annotations

import os
import re
import uuid
import winreg
from pathlib import Path

import pytest

from polyscour.startup import inventory as inv
from polyscour.startup.inventory import (Inventory, InventoryEntry, Source,
                                         SourceStatus)
from polyscour.startup.manager import TargetState

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only product")

NS = 'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"'


def task_xml(uri=r"\Vendor\Updater", trigger="LogonTrigger", *, command=None,
             com=None, task_enabled=True, trigger_enabled=True,
             principal="S-1-5-18", extra_actions=""):
    actions = ""
    if command is not None:
        actions += f"<Exec><Command>{command}</Command></Exec>"
    if com is not None:
        actions += f"<ComHandler><ClassId>{com}</ClassId></ComHandler>"
    actions += extra_actions
    triggers = (f"<{trigger}><Enabled>{str(trigger_enabled).lower()}</Enabled>"
                f"</{trigger}>") if trigger else ""
    return (f'<Task version="1.2" {NS}>'
            f"<RegistrationInfo><URI>{uri}</URI></RegistrationInfo>"
            f"<Triggers>{triggers}</Triggers>"
            f"<Principals><Principal><UserId>{principal}</UserId></Principal>"
            f"</Principals>"
            f"<Settings><Enabled>{str(task_enabled).lower()}</Enabled></Settings>"
            f"<Actions>{actions}</Actions></Task>")


def schtasks_output(*documents, comment_paths=None):
    """The shape measured on a real machine: one <Tasks> wrapper, comments,
    CRCRLF line ends, and no ``<?xml`` header anywhere."""
    body = "".join(f"\r\n<!-- {(comment_paths or {}).get(i, 'task')} -->\r\n\r\r\n"
                   f"{doc}\r\n" for i, doc in enumerate(documents))
    return f"\r\n<Tasks>\r\n{body}\r\n</Tasks>\r\n".encode("cp437")


@pytest.fixture
def fake_windows(monkeypatch):
    """A Windows folder that exists nowhere, so nothing depends on this machine."""
    monkeypatch.setenv("SystemRoot", r"Z:\Windows")
    monkeypatch.setattr(inv, "_target_state", lambda p: TargetState.PRESENT
                        if p else TargetState.UNRESOLVED)


# ── the location filter ──────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    r"Z:\Windows\System32\svchost.exe", r"z:\WINDOWS\system32\x.exe",
    r"Z:\Windows", r"Z:\Windows\.\System32\..\notepad.exe"])
def test_paths_inside_the_windows_folder_are_recognised(fake_windows, path):
    assert inv.in_windows_folder(path)


@pytest.mark.parametrize("path", [
    r"Z:\Windows.old\x.exe",              # a sibling with the same prefix
    r"Z:\WindowsApps\x.exe",
    r"Z:\Windows\..\Evil\x.exe",          # normalises to outside
    r"Z:\Program Files\App\a.exe", "", r"Y:\Windows\x.exe"])
def test_paths_that_only_look_like_the_windows_folder_are_not(fake_windows, path):
    """The control for the test above: without it, `startswith("Z:\\Windows")`
    would pass every case in the previous test and be wrong here."""
    assert not inv.in_windows_folder(path)


# ── shaping the schtasks output ──────────────────────────────────────────────

def test_the_real_output_shape_yields_one_document_per_task():
    raw = schtasks_output(task_xml(uri=r"\A"), task_xml(uri=r"\B"),
                          task_xml(uri=r"\C"))
    docs = inv.split_task_documents(raw)
    assert len(docs) == 3
    assert all(inv.parse_task_xml(d) is not None for d in docs)


def test_a_task_named_with_double_hyphen_costs_one_row_not_the_list():
    r"""`<!-- \a--b -->` is not valid XML, so parsing the wrapper as a whole
    would lose every task. Each Task is cut out and parsed alone."""
    raw = schtasks_output(task_xml(uri=r"\a--b"), task_xml(uri=r"\ok"),
                          comment_paths={0: r"\a--b"})
    assert len(inv.split_task_documents(raw)) == 2


def test_the_wrapper_element_is_not_mistaken_for_a_task():
    assert inv.split_task_documents(b"<Tasks>\r\n</Tasks>") == []


# ── reading one task ─────────────────────────────────────────────────────────

def test_a_logon_task_is_a_startup_task_and_a_daily_one_is_not():
    assert inv.parse_task_xml(task_xml(command="a.exe")) is not None
    assert inv.parse_task_xml(task_xml(trigger="CalendarTrigger",
                                       command="a.exe")) is None
    assert inv.parse_task_xml(task_xml(trigger=None, command="a.exe")) is None


def test_boot_and_logon_are_both_startup_triggers():
    boot = inv.parse_task_xml(task_xml(trigger="BootTrigger", command="a.exe"))
    assert boot.triggers == ("BootTrigger",)


def test_disabled_states_are_reported_as_what_they_are(fake_windows):
    on = inv._task_entry(inv.parse_task_xml(task_xml(command="a.exe")))
    off = inv._task_entry(inv.parse_task_xml(
        task_xml(command="a.exe", task_enabled=False)))
    trig = inv._task_entry(inv.parse_task_xml(
        task_xml(command="a.exe", trigger_enabled=False)))
    assert on.state == "enabled"
    assert off.state == "task disabled"
    assert trig.state == "its boot/logon trigger is disabled"


def test_a_document_that_is_not_xml_raises_rather_than_reading_as_not_a_task():
    with pytest.raises(inv.ET.ParseError):
        inv.parse_task_xml("<Task><unclosed>")


# ── which tasks are the Windows folder's own ─────────────────────────────────

def owned(**kw):
    return inv.task_is_windows_own(inv.parse_task_xml(task_xml(**kw)),
                                   resolve_com=kw.get("resolver", lambda c: ""))


def test_a_task_running_only_windows_programs_is_counted_not_listed(fake_windows):
    assert owned(command=r"%SystemRoot%\System32\x.exe")


def test_one_outside_program_keeps_the_task_listed(fake_windows):
    """The control for the test above."""
    assert not owned(command=r"Z:\Vendor\x.exe")


def test_a_task_that_runs_a_windows_program_and_a_foreign_one_is_listed(fake_windows):
    doc = task_xml(command=r"Z:\Windows\a.exe",
                   extra_actions=r"<Exec><Command>Z:\Vendor\b.exe</Command></Exec>")
    facts = inv.parse_task_xml(doc)
    assert not inv.task_is_windows_own(facts)


@pytest.mark.parametrize("kwargs", [
    dict(command=""),                     # an Exec we could not read
    dict(),                               # no action at all
    dict(extra_actions="<SendEmail/>"),   # an action with nothing to compare
])
def test_an_action_that_cannot_be_read_is_never_hidden(fake_windows, kwargs):
    assert not owned(**kwargs)


def test_one_unreadable_action_keeps_a_task_listed_even_beside_a_windows_one(fake_windows):
    """The Windows program alone would hide it; the action we cannot read must
    not be silently dropped from the judgement."""
    facts = inv.parse_task_xml(task_xml(command=r"Z:\Windows\a.exe",
                                        extra_actions="<SendEmail/>"))
    assert not inv.task_is_windows_own(facts)
    assert inv.task_is_windows_own(inv.parse_task_xml(
        task_xml(command=r"Z:\Windows\a.exe")))          # the control


def test_an_unregistered_com_class_keeps_a_task_listed_beside_a_windows_program(fake_windows):
    facts = inv.parse_task_xml(task_xml(command=r"Z:\Windows\a.exe", com="{ABC}"))
    assert not inv.task_is_windows_own(facts, resolve_com=lambda c: "")
    assert inv.task_is_windows_own(
        facts, resolve_com=lambda c: r"Z:\Windows\System32\x.dll")   # the control


def test_a_com_task_is_judged_by_the_server_its_class_loads(fake_windows):
    inside = lambda c: r"Z:\Windows\System32\thing.dll"       # noqa: E731
    outside = lambda c: r"Z:\Vendor\thing.dll"                # noqa: E731
    facts = inv.parse_task_xml(task_xml(com="{ABC}"))
    assert inv.task_is_windows_own(facts, resolve_com=inside)
    assert not inv.task_is_windows_own(facts, resolve_com=outside)


def test_a_com_class_with_no_registered_server_stays_listed(fake_windows):
    facts = inv.parse_task_xml(task_xml(com="{ABC}"))
    assert not inv.task_is_windows_own(facts, resolve_com=lambda c: "")
    entry = inv._task_entry(facts, resolve_com=lambda c: "")
    assert "no registered server found" in entry.launches
    assert entry.target is TargetState.UNRESOLVED


# ── the scheduled-task reader end to end ─────────────────────────────────────

def patch_schtasks(monkeypatch, raw=None, error=None):
    def run():
        if error:
            raise error
        return raw
    monkeypatch.setattr(inv, "_run_schtasks", run)
    monkeypatch.setattr(inv, "com_server", lambda c: "")


def test_counts_add_up_to_every_startup_task(fake_windows, monkeypatch):
    raw = schtasks_output(
        task_xml(uri=r"\Own1", command=r"Z:\Windows\a.exe"),
        task_xml(uri=r"\Own2", command=r"Z:\Windows\b.exe"),
        task_xml(uri=r"\Theirs", command=r"Z:\Vendor\c.exe"),
        task_xml(uri=r"\Daily", trigger="CalendarTrigger", command="d.exe"))
    patch_schtasks(monkeypatch, raw)
    entries, status = inv.read_scheduled_tasks()
    assert status.error is None
    assert [e.name for e in entries] == ["Theirs"]
    assert status.listed == 1 and status.in_windows_folder == 2


def test_output_that_yields_no_tasks_is_unread_not_empty(monkeypatch):
    """The exact bug the first version had, as a permanent regression."""
    patch_schtasks(monkeypatch, b"\r\nsomething unexpected\r\n")
    entries, status = inv.read_scheduled_tasks()
    assert entries == [] and status.error
    assert "recognise" in status.error


def test_no_output_at_all_is_unread_not_empty(monkeypatch):
    patch_schtasks(monkeypatch, b"")
    entries, status = inv.read_scheduled_tasks()
    assert entries == [] and status.error


@pytest.mark.parametrize("error", [OSError("schtasks exited 1: denied"),
                                   FileNotFoundError("no schtasks")])
def test_a_failing_schtasks_is_unread_not_empty(monkeypatch, error):
    patch_schtasks(monkeypatch, error=error)
    entries, status = inv.read_scheduled_tasks()
    assert entries == [] and status.error


def test_one_unparseable_task_is_reported_and_the_rest_survive(fake_windows,
                                                               monkeypatch):
    raw = schtasks_output(task_xml(uri=r"\Good", command=r"Z:\Vendor\a.exe"),
                          "<Task version='1.2'><broken></Task>")
    patch_schtasks(monkeypatch, raw)
    entries, status = inv.read_scheduled_tasks()
    assert [e.name for e in entries] == ["Good"]
    assert "could not be parsed" in status.error


def test_a_character_that_did_not_survive_decoding_is_never_called_missing(monkeypatch):
    monkeypatch.setattr(inv, "_oem_encoding", lambda: "ascii")
    monkeypatch.setenv("SystemRoot", r"Z:\Windows")
    raw = schtasks_output(task_xml(command=r"Z:\Vendor\caf\xe9.exe"))
    raw = raw.replace(b"caf\\xe9", "café".encode("latin-1"))
    patch_schtasks(monkeypatch, raw)
    entries, _ = inv.read_scheduled_tasks()
    assert entries[0].target is TargetState.UNRESOLVED


# ── services ─────────────────────────────────────────────────────────────────

def svc(**over):
    v = {"Type": 0x10, "Start": 2, "ImagePath": r'"Z:\Vendor\svc.exe" -run',
         "DisplayName": "Vendor Service", "ObjectName": "LocalSystem",
         "DelayedAutostart": 0}
    v.update(over)
    return v


def test_an_automatic_win32_service_is_an_entry(fake_windows):
    e = inv.service_entry("VendorSvc", svc(), None)
    assert e.name == "Vendor Service" and e.state == "automatic"
    assert e.target_path == r"Z:\Vendor\svc.exe"          # the args are not in it
    assert e.runs_as == "LocalSystem"
    assert e.mechanism.endswith(r"Services\VendorSvc")


@pytest.mark.parametrize("over", [
    dict(Type=1), dict(Type=2), dict(Type=8),      # drivers
    dict(Start=3), dict(Start=4), dict(Start=0), dict(Start=1),
    dict(Type=None), dict(Start=None)])
def test_drivers_and_non_automatic_services_are_not_entries(fake_windows, over):
    assert inv.service_entry("X", svc(**over), None) is None


def test_delayed_start_is_stated(fake_windows):
    assert inv.service_entry("X", svc(DelayedAutostart=1), None).state \
        == "automatic (delayed start)"


def test_a_resource_string_is_not_used_as_a_name(fake_windows):
    e = inv.service_entry("RealName", svc(DisplayName="@%SystemRoot%\\x.dll,-5"), None)
    assert e.name == "RealName"


def test_an_svchost_service_is_judged_by_its_dll_not_by_svchost(fake_windows):
    """Otherwise a third-party service hosted by svchost would sit under
    C:\\Windows\\System32\\svchost.exe and be counted as Windows' own."""
    host = svc(Type=0x20, ImagePath=r"Z:\Windows\System32\svchost.exe -k netsvcs")
    foreign = inv.service_entry("S", host, r"Z:\Vendor\hosted.dll")
    own = inv.service_entry("S", host, r"Z:\Windows\System32\real.dll")
    assert foreign.target_path == r"Z:\Vendor\hosted.dll"
    assert not inv.in_windows_folder(foreign.target_path)
    assert inv.in_windows_folder(own.target_path)


def test_a_service_with_no_image_path_is_kept_and_unresolved(fake_windows):
    e = inv.service_entry("X", svc(ImagePath=None), None)
    assert e is not None and e.target is TargetState.UNRESOLVED


def test_the_real_service_list_is_consistent_with_the_registry():
    """Counted independently: every automatic Win32 service is either listed or
    counted, and nothing listed is inside the Windows folder."""
    entries, status = inv.read_services()
    assert status.error is None
    total = 0
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inv._SERVICES) as root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, name) as k:
                    t = winreg.QueryValueEx(k, "Type")[0]
                    s = winreg.QueryValueEx(k, "Start")[0]
            except OSError:
                continue
            total += bool(t & 0x30 and s == 2)
    assert status.listed + status.in_windows_folder == total
    assert all(not inv.in_windows_folder(e.target_path) for e in entries)


# ── startup folders ──────────────────────────────────────────────────────────

def test_a_startup_folder_lists_files_and_skips_desktop_ini(tmp_path, monkeypatch):
    (tmp_path / "b.lnk").write_bytes(b"x")
    (tmp_path / "A.lnk").write_bytes(b"x")
    (tmp_path / "desktop.ini").write_bytes(b"x")
    monkeypatch.setattr(inv, "_FOLDERS",
                        [("user", str(tmp_path), winreg.HKEY_CURRENT_USER)])
    monkeypatch.setattr(inv, "_folder_approvals", lambda hive: {"b.lnk": False})
    entries, status = inv.read_startup_folders()
    assert [e.name for e in entries] == ["A.lnk", "b.lnk"]
    assert [e.state for e in entries] == ["enabled", "disabled in Task Manager"]
    assert status.error is None and status.listed == 2


def test_the_approval_byte_means_what_task_manager_means_by_it(monkeypatch):
    """0x02 enabled, 0x03 disabled, and a name with no record is enabled --
    read from a throwaway key, since inverting this would report every
    Task-Manager-disabled shortcut as running."""
    path = rf"Software\PolyScourTest-{uuid.uuid4().hex}\StartupFolder"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, "On.lnk", 0, winreg.REG_BINARY, bytes([2]) + bytes(11))
        winreg.SetValueEx(key, "Off.LNK", 0, winreg.REG_BINARY, bytes([3]) + bytes(11))
    monkeypatch.setattr(inv, "_FOLDER_APPROVED", path)
    try:
        approvals = inv._folder_approvals(winreg.HKEY_CURRENT_USER)
    finally:
        parent = path.rsplit("\\", 1)[0]
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
    assert approvals == {"on.lnk": True, "off.lnk": False}      # keys folded


def test_a_missing_startup_folder_is_a_normal_machine_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "_FOLDERS", [("user", str(tmp_path / "nope"),
                                           winreg.HKEY_CURRENT_USER)])
    entries, status = inv.read_startup_folders()
    assert entries == [] and status.error is None


def test_a_startup_folder_that_cannot_be_listed_is_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "_FOLDERS", [("machine", str(tmp_path),
                                           winreg.HKEY_LOCAL_MACHINE)])
    def deny(path):
        raise PermissionError("denied")
    monkeypatch.setattr(inv.os, "listdir", deny)
    entries, status = inv.read_startup_folders()
    assert entries == [] and "denied" in status.error


# ── RunOnce, against a throwaway key ─────────────────────────────────────────

@pytest.fixture
def scratch_key():
    """A private HKCU key, removed afterwards. Never touches a real RunOnce."""
    path = rf"Software\PolyScourTest-{uuid.uuid4().hex}\RunOnce"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, "Installer", 0, winreg.REG_SZ,
                          r'"Z:\Vendor\setup.exe" /finish')
    yield path
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path.rsplit("\\", 1)[0],
                        access=winreg.KEY_ALL_ACCESS) as parent:
        winreg.DeleteKey(parent, "RunOnce")
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path.rsplit("\\", 1)[0])


def test_run_once_values_are_read_with_their_mechanism(scratch_key, monkeypatch):
    monkeypatch.setattr(inv, "_RUNONCE_KEYS",
                        [("HKCU", winreg.HKEY_CURRENT_USER, scratch_key, "you")])
    entries, status = inv.read_run_once()
    assert status.error is None and len(entries) == 1
    e = entries[0]
    assert e.name == "Installer" and e.mechanism == f"HKCU\\{scratch_key}"
    assert e.target_path == r"Z:\Vendor\setup.exe"
    assert e.target is TargetState.MISSING


def test_an_absent_run_once_key_is_empty_and_not_an_error(monkeypatch):
    monkeypatch.setattr(inv, "_RUNONCE_KEYS", [(
        "HKCU", winreg.HKEY_CURRENT_USER,
        rf"Software\PolyScourTest-{uuid.uuid4().hex}\RunOnce", "you")])
    entries, status = inv.read_run_once()
    assert entries == [] and status.error is None


# ── the whole picture ────────────────────────────────────────────────────────

def test_one_reader_failing_marks_only_its_own_source(monkeypatch):
    def boom():
        raise RuntimeError("reader bug")
    monkeypatch.setattr(inv, "read_scheduled_tasks", boom)
    result = inv.read_inventory()
    assert result.status(Source.SCHEDULED_TASK).error.startswith("RuntimeError")
    assert result.status(Source.SERVICE).error is None
    assert len(result.statuses) == 4


def test_every_source_reports_a_status_on_the_real_machine():
    result = inv.read_inventory()
    assert {s.source for s in result.statuses} == set(Source)


# ── wording ──────────────────────────────────────────────────────────────────

def entry(target, path=r"Z:\a.exe", launches="a.exe /x"):
    return InventoryEntry(Source.SERVICE, "n", "m", launches, path, target, "")


def test_describe_states_facts_and_never_advises():
    text = " ".join(inv.describe(entry(t)) for t in TargetState)
    assert "not on disk" in text and "could not work out" in text
    for word in ("safe", "recommend", "unnecessary", "remove", "disable"):
        assert word not in text.lower()


# ── it never writes ──────────────────────────────────────────────────────────

_WRITERS = re.compile(
    r"SetValueEx|SetValue\(|CreateKey|DeleteValue|DeleteKey|\.unlink\(|"
    r"os\.remove|os\.rename|shutil\.|\.write\(|\.write_text|\.write_bytes|"
    r"\.mkdir\(|/change|/delete|/create|sc\.exe", re.IGNORECASE)


def writers_in(source: str) -> list[str]:
    return _WRITERS.findall(source)


def test_the_inventory_source_contains_no_writing_call():
    text = Path(inv.__file__).read_text(encoding="utf-8")
    # Strip the docstring/comments, which may name what is NOT done.
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    code = re.sub(r'"""(?:.|\n)*?"""', "", code)
    assert writers_in(code) == []


def test_the_writing_check_can_fail():
    """Negative control: a planted write is found, so the check above is live."""
    for planted in ("winreg.SetValueEx(k, 'a', 0, 1, 'b')", "os.remove(p)",
                    "subprocess.run(['schtasks', '/change', '/tn', 'x'])",
                    "Path(p).write_text('x')"):
        assert writers_in(planted), planted


def test_schtasks_is_only_ever_asked_to_query(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        class R: returncode, stdout, stderr = 0, b"", b""
        return R
    monkeypatch.setattr(inv.subprocess, "run", fake_run)
    inv._run_schtasks()
    cmd = seen["cmd"]
    assert cmd[1:] == ["/query", "/xml", "ONE"]
    assert os.path.isabs(cmd[0]) and cmd[0].lower().endswith("schtasks.exe")
    assert seen["kw"]["shell"] is False
