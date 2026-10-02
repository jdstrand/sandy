"""Entry-path confinement parity (specs/security-parity.md items 1 and 5).

Every attach (`exec`, `bash`, and `-u root`) must run with the container
payload's seccomp filters and capability bounding set, also while `up` starts
the container. These properties need the real kernel, systemd-nspawn, and
sandy, so unit mocks cannot prove them.
"""

from __future__ import annotations

import base64
import ctypes
import importlib.machinery
import importlib.util
import json
import os
import platform
import select
import shlex
import signal
import subprocess
import threading
import time
from pathlib import Path
from types import ModuleType

from tests.e2e.support import (
    SANDY,
    SLICE,
    SLICE_CGROUP,
    SYSTEMD_MACHINES,
    CommandResult,
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
)

STATUS_FIELDS = ("Seccomp", "Seccomp_filters", "CapBnd", "CapEff", "NoNewPrivs")
EPERM = 1
ENTRY_FAILURE = 125
STABILITY_RUNS = 150
# Attaches in a loop while up -d starts the container (item 5). The start
# window is short, so this is a regression check, not a proof.
START_SAMPLERS = 3
START_ATTACHES_AFTER_UP = 2
START_TIMEOUT = 300
# Starts in which the Leader is stopped as soon as machined reports it. A
# start in which the payload already exists at the stop is repeated.
HOLD_ATTEMPTS = 3
HOLD_STOP_TIMEOUT = 10
MACHINES_STATE = Path("/run/systemd/machines")
# <linux/ptrace.h>: requests, options, and events that hold the payload at its
# fork. sandy defines PTRACE_SEIZE and PTRACE_DETACH.
PTRACE_CONT = 7
PTRACE_GETEVENTMSG = 0x4201
PTRACE_FORK_OPTIONS = 0x02 | 0x04 | 0x08
PTRACE_FORK_EVENTS = (1, 2, 3)
# Without the S2 fix, up returned in this time after an attach worked.
KEEPALIVE_HOLD_SECONDS = 3
KEEPALIVE_DIR_GLOB = "sandy-keepalive-*"
# aarch64 has 7 of the 10 denied syscalls, and 5.15 hides bpf.
MIN_OBSERVABLE_DENIED = 6
# Orphans that a session leaves to the Leader. Their entries in the Leader's
# child list take more than one read chunk of the payload search.
ADOPTED_ORPHANS = 1000
ORPHAN_COMMAND = b"sleep\x003333\x00"
ORPHANS_GONE_TIMEOUT = 30
# Denied by Docker's default profile and by nspawn's filter; the nsenter path
# reached the kernel with each of them (specs/security-parity.md item 1).
DENIED_SYSCALLS = (
    "add_key",
    "request_key",
    "keyctl",
    "perf_event_open",
    "bpf",
    "iopl",
    "ioperm",
    "clock_adjtime",
    "quotactl",
    "uselib",
)
# Nested agent sandboxes need Landlock, so it must stay allowed.
ALLOWED_SYSCALLS = ("landlock_create_ruleset",)
SYSCALL_NUMBERS = {
    "x86_64": {
        "add_key": 248,
        "request_key": 249,
        "keyctl": 250,
        "perf_event_open": 298,
        "bpf": 321,
        "iopl": 172,
        "ioperm": 173,
        "clock_adjtime": 305,
        "quotactl": 179,
        "uselib": 134,
        "landlock_create_ruleset": 444,
    },
    # aarch64 has no iopl, ioperm, or uselib.
    "aarch64": {
        "add_key": 217,
        "request_key": 218,
        "keyctl": 219,
        "perf_event_open": 241,
        "bpf": 280,
        "clock_adjtime": 266,
        "quotactl": 60,
        "landlock_create_ruleset": 444,
    },
}
# Each call gets invalid arguments, so the kernel rejects it before it has an
# effect. EPERM means a seccomp denial; any other errno reached the kernel.
PROBE_SOURCE = """
import ctypes, json, sys
numbers = json.loads(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 7
result = {}
for name, number in sorted(numbers.items()):
    ctypes.set_errno(0)
    failed = libc.syscall(number, -1, -1, -1, -1, -1, -1) == -1
    result[name] = ctypes.get_errno() if failed else 0
print("PROBE " + json.dumps(result, sort_keys=True))
"""
# ptrace(PTRACE_SEIZE) numbers, for a second tracer that blocks extraction.
PTRACE_NUMBERS = {"x86_64": 101, "aarch64": 117}
TRACER_SOURCE = """
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.syscall.argtypes = [ctypes.c_long] * 5
if libc.syscall(int(sys.argv[1]), 0x4206, int(sys.argv[2]), 0, 0) != 0:
    sys.exit(ctypes.get_errno())
print("TRACING", flush=True)
sys.stdin.read()
"""


def _load_sandy_module() -> ModuleType:
    """Load the extensionless Sandy implementation without running its CLI."""
    loader = importlib.machinery.SourceFileLoader("sandy_e2e_confinement", str(SANDY))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise E2EFailure("Could not load the Sandy implementation")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _parse_status(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in STATUS_FIELDS:
            fields[key] = value.strip()
    if set(fields) != set(STATUS_FIELDS):
        raise E2EFailure(f"Incomplete status fields: {fields!r}")
    return fields


def _host_status(pid: int) -> dict[str, str]:
    return _parse_status(Path(f"/proc/{pid}/status").read_text(encoding="ascii"))


def _children(pid: int) -> list[int]:
    try:
        text = Path(f"/proc/{pid}/task/{pid}/children").read_text(encoding="ascii")
    except FileNotFoundError:
        return []
    return [int(value) for value in text.split()]


def _cmdline(pid: int) -> bytes:
    """Return the command line of pid, or b"" when the process is gone."""
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return b""


def _payload_pid(leader: int) -> int:
    """Return the payload: the Leader's child with the lowest container PID."""
    candidates = []
    for child in _children(leader):
        for line in Path(f"/proc/{child}/status").read_text().splitlines():
            if line.startswith("NSpid:"):
                candidates.append((int(line.split()[-1]), child))
    if not candidates:
        raise E2EFailure("The container Leader has no payload process")
    return min(candidates)[1]


def _probe_command() -> tuple[str, str]:
    machine = platform.machine()
    if machine not in SYSCALL_NUMBERS:
        raise E2EFailure(f"No syscall table for {machine}")
    encoded = base64.b64encode(PROBE_SOURCE.encode()).decode()
    code = f"import base64;exec(base64.b64decode('{encoded}'))"
    numbers = json.dumps(SYSCALL_NUMBERS[machine], separators=(",", ":"))
    return code, numbers


def _parse_probe(output: str) -> dict[str, int]:
    for line in output.splitlines():
        if line.startswith("PROBE "):
            return json.loads(line[len("PROBE ") :])
    raise E2EFailure(f"No probe result in output:\n{output[-2000:]}")


class _Session:
    """A background `sandy exec` whose entry helper and session can be found."""

    def __init__(self, context: E2EContext, command: str) -> None:
        self.command = command
        arguments = [
            str(SANDY),
            "--workspace",
            context.workspace.name,
            "--shared",
            context.shared.name,
            "--user",
            context.main_user,
            "--container",
            context.main_name,
            "exec",
            "--",
            command,
        ]
        print(f"    $ {shlex.join(arguments)} &", flush=True)
        self.process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=context.root,
            env=context.safe_environment(),
        )

    def session_pid(self, timeout: float = 20) -> int:
        """Return the session: the only child of the entry helper.

        The helper has other only children first: machinectl during the
        extraction, then the middle process, and then the session before its
        execve, a fork of the helper that has not installed the filters yet.
        So accept only a child whose command line holds the session command
        and is not the helper's.
        """
        command = self.command.encode()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for helper in _children(self.process.pid):
                if b"__sandy-entry-helper" in _cmdline(helper):
                    sessions = _children(helper)
                    if len(sessions) == 1:
                        cmdline = _cmdline(sessions[0])
                        if (
                            command in cmdline
                            and b"__sandy-entry-helper" not in cmdline
                        ):
                            return sessions[0]
            time.sleep(0.1)
        raise E2EFailure("The entry helper session did not start")

    def finish(self, timeout: int = 60) -> int:
        try:
            return self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=10)


class _StartSampler(threading.Thread):
    """Run one attach after the other until up has returned, and keep results.

    Each result is (started after up returned, exit status, output). The
    sampler stops after START_ATTACHES_AFTER_UP attaches that started after
    up returned.
    """

    def __init__(
        self,
        arguments: list[str],
        environment: dict[str, str],
        cwd: Path,
        up_done: threading.Event,
    ) -> None:
        super().__init__(daemon=True)
        self.arguments = arguments
        self.environment = environment
        self.cwd = cwd
        self.up_done = up_done
        self.results: list[tuple[bool, int, str]] = []
        self.error: BaseException | None = None

    def run(self) -> None:
        after_up = 0
        try:
            while after_up < START_ATTACHES_AFTER_UP:
                started_after_up = self.up_done.is_set()
                if started_after_up:
                    after_up += 1
                completed = subprocess.run(
                    self.arguments,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=120,
                    shell=False,
                    cwd=self.cwd,
                    env=self.environment,
                )
                self.results.append(
                    (
                        started_after_up,
                        completed.returncode,
                        completed.stdout + completed.stderr,
                    )
                )
        except BaseException as exc:  # reported by the main thread
            self.error = exc


def _machined_leader(name: str) -> int:
    """Return the Leader from machined's state file, or 0 when there is none.

    Reading the file is faster than starting machinectl for each poll.
    """
    try:
        text = (MACHINES_STATE / name).read_text(encoding="ascii", errors="replace")
    except FileNotFoundError:
        return 0
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == "LEADER" and value.isdigit():
            return int(value)
    return 0


def _pidfd_alive(pidfd: int) -> bool:
    """Return whether the process of pidfd has not exited."""
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return not poller.poll(0)


def _open_scope_process(pid: int, unit: str) -> int:
    """Return a pidfd for pid after a check that pid runs in unit's cgroup.

    The check reads /proc/<pid>/cgroup. The process is alive after the read,
    so the read and the pidfd refer to the same process.
    """
    pidfd = os.pidfd_open(pid)
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").strip()
        scope = f"0::/sandy.slice/{unit}"
        if cgroup != scope and not cgroup.startswith(scope + "/"):
            raise E2EFailure(f"PID {pid} is not in {unit}: {cgroup!r}")
        if not _pidfd_alive(pidfd):
            raise E2EFailure(f"PID {pid} exited during the check")
    except BaseException:
        os.close(pidfd)
        raise
    return pidfd


def _wait_for_cgroup(pid: int, cgroup: str) -> None:
    """Wait until /proc/<pid>/cgroup names cgroup, a path below /sys/fs/cgroup."""
    expected = f"0::{cgroup}"
    deadline = time.monotonic() + HOLD_STOP_TIMEOUT
    while True:
        current = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").strip()
        if current == expected:
            return
        if time.monotonic() > deadline:
            raise E2EFailure(f"PID {pid} runs in {current!r}, not in {expected!r}")
        time.sleep(0.01)


def _process_state(pid: int) -> str:
    """Return the state letter of pid from /proc/<pid>/stat."""
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    return text.rsplit(")", 1)[1].split()[0]


def _is_payload(pid: int, leader: int) -> bool:
    """Return whether pid is the Leader's child with container PID 2."""
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="ascii", errors="replace")
    except (FileNotFoundError, ProcessLookupError):
        return False
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.split()
    return fields.get("PPid") == [str(leader)] and fields.get("NSpid") == [
        str(pid),
        "2",
    ]


def _has_payload(leader: int) -> bool:
    """Return whether the Leader has a child with container PID 2."""
    return any(_is_payload(child, leader) for child in _children(leader))


def _hold_payload_at_fork(sandy: ModuleType, leader: int, pidfd: int) -> int:
    """Hold the payload in its first ptrace stop, before it runs execve.

    Seize the Leader with the fork options and wait for the fork of its
    child with container PID 2. Release the Leader at once, so that an
    attach can seize it. Return the payload, which stays stopped until the
    caller detaches it, or 0 when the payload already existed. pidfd pins
    the Leader: it is alive after the seize, so the seized process is the
    Leader.
    """

    def ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
        return sandy._entry_syscall("ptrace", request, pid, addr, data)

    ptrace(sandy.PTRACE_SEIZE, leader, 0, PTRACE_FORK_OPTIONS)
    stopped = False
    try:
        if not _pidfd_alive(pidfd):
            raise E2EFailure("The Leader exited before the seize")
        if _has_payload(leader):
            return 0
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            pid, status = os.waitpid(leader, sandy.WAIT_ALL | os.WNOHANG)
            if pid == 0:
                time.sleep(0.001)
                continue
            if not os.WIFSTOPPED(status):
                raise E2EFailure("The Leader exited before its payload started")
            stopped = True
            event = status >> 16
            signal_number = 0
            if event in PTRACE_FORK_EVENTS:
                message = ctypes.c_ulong()
                ptrace(PTRACE_GETEVENTMSG, leader, 0, ctypes.addressof(message))
                child = message.value
                # The new child starts traced, in a ptrace stop.
                os.waitpid(child, sandy.WAIT_ALL)
                if _is_payload(child, leader):
                    return child
                ptrace(sandy.PTRACE_DETACH, child)
            elif not event:
                # Give back the signal that a signal-delivery-stop took.
                signal_number = os.WSTOPSIG(status)
            ptrace(PTRACE_CONT, leader, 0, signal_number)
            stopped = False
        raise E2EFailure("The Leader did not start its payload")
    finally:
        try:
            signal_number = 0 if stopped else sandy._stop_seized_tracee(leader)
            sandy._ptrace_detach(leader, signal_number)
        except OSError:
            # The Leader exited, which ended the trace.
            pass


def _entry_failure_reason(output: str) -> str:
    """Return the helper's error message from an attach output."""
    for line in output.replace("\r", "").splitlines():
        if "Container entry failed" in line:
            return line.strip()
    return "(no helper message)"


def _exec(context: E2EContext, command: str, *, user: str | None = None, **kwargs):
    return context.sandy(
        ["exec", "--", command],
        name=context.main_name,
        user=user or context.main_user,
        **kwargs,
    )


# up mounts the workspace and shared directories as soon as the payload exists,
# and polls every 0.5 s. Until then an attach fails closed (status 125, "Container
# is still starting"), also while the payload is held.
MOUNTS_WAIT_TIMEOUT = 30


def _exec_when_mounted(context: E2EContext, command: str) -> CommandResult:
    """Run a command in the main container as soon as up has mounted its directories.

    Retry only the refusal for a container that is still starting.
    """
    deadline = time.monotonic() + MOUNTS_WAIT_TIMEOUT
    while True:
        result = _exec(context, command, expected=None)
        if result.returncode == 0:
            return result
        if result.returncode != ENTRY_FAILURE or "still starting" not in result.output:
            raise E2EFailure(
                f"Unexpected result {result.returncode}: {result.output[-2000:]}"
            )
        if time.monotonic() >= deadline:
            raise E2EFailure("up did not mount the directories in time")
        time.sleep(0.1)


def _status_via(context: E2EContext, arguments: list[str], user: str) -> dict:
    result = context.sandy(arguments, name=context.main_name, user=user)
    return _parse_status(result.stdout)


def test_main(context: E2EContext) -> None:
    """Prove that every entry path has the payload's confinement."""
    sandy = _load_sandy_module()
    leader_text = context.machine_leader(context.main_name)
    if leader_text is None:
        raise E2EFailure("The lifecycle tests must leave the main machine running")
    leader = int(leader_text)
    payload = _payload_pid(leader)
    payload_status = _host_status(payload)
    grep_status = "grep -E '^(Seccomp|Seccomp_filters|CapBnd|CapEff|NoNewPrivs):' /proc/self/status"

    with context.case("exec, bash, and -u root match the payload's status fields"):
        if payload_status["Seccomp"] != "2" or payload_status["Seccomp_filters"] == "0":
            raise E2EFailure(f"The payload is not filtered: {payload_status!r}")
        # The payload is the keepalive, which runs as container root.
        if payload_status["CapEff"] != payload_status["CapBnd"]:
            raise E2EFailure(f"The payload is not container root: {payload_status!r}")
        user_expected = dict(payload_status, CapEff="0000000000000000")
        paths = {
            "exec": _status_via(context, ["exec", "--", grep_status], "developer"),
            "bash": _status_via(context, ["bash", "-c", grep_status], "developer"),
        }
        for path, status in paths.items():
            if status != user_expected:
                raise E2EFailure(f"{path}: {status!r} != {user_expected!r}")
        for arguments in (["exec", "--", grep_status], ["bash", "-c", grep_status]):
            root = _status_via(context, arguments, "root")
            if root != payload_status:
                raise E2EFailure(
                    f"-u root {arguments[0]}: {root!r} != payload {payload_status!r}"
                )

    with context.case(
        "the session's seccomp programs are the payload's, byte for byte"
    ):
        session = _Session(context, "sleep 10")
        try:
            session_pid = session.session_pid()
            session_filters = sandy._read_seccomp_filters(session_pid)
            session_status = _host_status(session_pid)
        finally:
            returncode = session.finish()
        payload_filters = sandy._read_seccomp_filters(payload)
        leader_filters = sandy._read_seccomp_filters(leader)
        if not payload_filters or session_filters != payload_filters:
            raise E2EFailure(
                f"Session filters differ: {len(session_filters)} programs, "
                f"payload {len(payload_filters)} programs"
            )
        if leader_filters != payload_filters:
            raise E2EFailure("The Leader and payload filters differ")
        if session_status != user_expected:
            raise E2EFailure(f"{session_status!r} != {user_expected!r}")
        if returncode != 0:
            raise E2EFailure(f"The background exec failed with {returncode}")

    with context.case("denied syscalls get EPERM only on confined paths"):
        code, numbers = _probe_command()
        shell_probe = shlex.join(["python3", "-c", code, numbers])
        baseline = _parse_probe(
            context.run(
                context._machine_command(
                    context.main_name,
                    context.main_user,
                    ["python3", "-c", code, numbers],
                )
            ).stdout
        )
        # A syscall that the kernel already refuses with EPERM before it checks
        # its arguments cannot show a seccomp denial. Measured: with
        # unprivileged_bpf_disabled=2, bpf() does this on 5.15 but not on 6.8
        # or 6.12. The byte-for-byte filter case above still covers it.
        observable = [
            name
            for name in DENIED_SYSCALLS
            if name in baseline and baseline[name] != EPERM
        ]
        hidden = sorted(set(baseline) & set(DENIED_SYSCALLS) - set(observable))
        print(f"    not observable by errno on this kernel: {hidden}", flush=True)
        if len(observable) < MIN_OBSERVABLE_DENIED:
            raise E2EFailure(
                f"Only {observable!r} are observable; the probe is too weak"
            )
        for name in ALLOWED_SYSCALLS:
            if baseline[name] == EPERM:
                raise E2EFailure(
                    f"Unconfined {name} gave EPERM; the probe proves nothing"
                )
        results = {
            "exec": _parse_probe(_exec(context, shell_probe).stdout),
            "bash": _parse_probe(
                context.sandy(
                    ["bash", "-c", shell_probe],
                    name=context.main_name,
                    user=context.main_user,
                ).stdout
            ),
            "exec -u root": _parse_probe(
                _exec(context, shell_probe, user="root").stdout
            ),
        }
        for path, result in results.items():
            for name in observable:
                if result[name] != EPERM:
                    raise E2EFailure(f"{path}: {name} reached the kernel: {result!r}")
            for name in ALLOWED_SYSCALLS:
                if result[name] != baseline[name]:
                    raise E2EFailure(f"{path}: {name} changed: {result!r}")

    with context.case(f"{STABILITY_RUNS} confined exec runs complete"):
        for _ in range(STABILITY_RUNS):
            _exec(context, "true")

    with context.case("an inherited descriptor does not stop an attach"):
        # sudo closes descriptors above 2, but root can run sandy directly.
        # The pty path kept such a descriptor, and the helper refused to run.
        arguments = [
            str(SANDY),
            "--workspace",
            context.workspace.name,
            "--shared",
            context.shared.name,
            "--user",
            context.main_user,
            "--container",
            context.main_name,
            "exec",
            "--",
            "true",
        ]
        descriptor = os.open("/dev/null", os.O_RDONLY)
        try:
            print(f"    $ {shlex.join(arguments)} {descriptor}</dev/null", flush=True)
            inherited = subprocess.run(
                arguments,
                pass_fds=(descriptor,),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
                shell=False,
                cwd=context.root,
                env=context.safe_environment(),
            )
        finally:
            os.close(descriptor)
        if inherited.returncode != 0:
            output = (inherited.stdout + inherited.stderr)[-2000:]
            raise E2EFailure(
                f"exec with an inherited descriptor failed with "
                f"{inherited.returncode}: {output}"
            )

    with context.case("a group-writable sandy refuses an attach with an error"):
        refused = context.sandy(
            ["exec", "--", "true"],
            name=context.main_name,
            user=context.main_user,
            expected=1,
            executable=context.group_writable_sandy(),
        )
        assert_contains(refused, "E: Could not prepare the container entry")
        assert_not_contains(refused, "Traceback")

    with context.case("the attach environment is the allow-list"):
        environment = sandy._container_environment("developer", "/home/developer")
        environment["TERM"] = (
            context.safe_environment().get("TERM") or environment["TERM"]
        )
        lines = _exec(context, "env").stdout.replace("\r", "").splitlines()
        attach = dict(line.split("=", 1) for line in lines if "=" in line)
        shell_added = {"PWD", "OLDPWD", "SHLVL", "_"}
        unexpected = set(attach) - set(environment) - shell_added
        missing = set(environment) - set(attach)
        if unexpected or missing:
            raise E2EFailure(
                f"unexpected={sorted(unexpected)} missing={sorted(missing)}"
            )
        for key in ("HOME", "USER", "LOGNAME", "PATH"):
            if attach[key] != environment[key]:
                raise E2EFailure(
                    f"{key}={attach[key]!r}, expected {environment[key]!r}"
                )
        payload_keys = {
            item.split(b"=", 1)[0].decode()
            for item in Path(f"/proc/{payload}/environ").read_bytes().split(b"\0")
            if b"=" in item
        }
        # Recorded for the step 2 console comparison; not asserted here.
        print(
            f"    payload-only keys: {sorted(payload_keys - set(attach))}; "
            f"attach-only keys: {sorted(set(attach) - payload_keys)}",
            flush=True,
        )

    with context.case("an extraction failure refuses the command"):
        machine = platform.machine()
        marker = context.workspace / "extraction-refused-marker"
        tracer = subprocess.Popen(
            ["python3", "-c", TRACER_SOURCE, str(PTRACE_NUMBERS[machine]), str(leader)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=context.root,
            env=context.safe_environment(),
        )
        try:
            assert tracer.stdout is not None
            if tracer.stdout.readline().strip() != "TRACING":
                raise E2EFailure("The second tracer did not attach to the Leader")
            refused = _exec(
                context,
                f"touch /home/developer/workspace/{marker.name}",
                expected=ENTRY_FAILURE,
            )
            assert_contains(refused, "Container entry failed")
            if marker.exists():
                raise E2EFailure("The command ran although extraction failed")
        finally:
            tracer.communicate(timeout=30)
        _exec(context, "true")

    with context.case("init.sh ran through the entry helper and set the address"):
        address = _exec(context, "ip -4 -o addr show host0")
        assert_contains(address, "inet ")
        root_identity = _exec(context, "id -u; id -G", user="root")
        if root_identity.stdout.split() != ["0", "0"]:
            raise E2EFailure(f"-u root identity: {root_identity.stdout!r}")

    # Item 5: before the payload exists, the Leader's confinement may not be
    # final, so the helper refuses an attach. The main container restarts in
    # these cases, and the scope tests use it next.
    common = [
        str(SANDY),
        "--workspace",
        context.workspace.name,
        "--shared",
        context.shared.name,
        "--user",
        context.main_user,
        "--container",
        context.main_name,
    ]
    up_arguments = common + ["up", "--detach", "--persistent", "--network", "lenient"]
    start_environment = context.safe_environment()

    with context.case("attaches while up -d starts the container are refused or final"):
        # Every attach that runs must have the final confinement.
        context.stop_container(context.main_name, context.main_user)
        attach = common + ["exec", "--", grep_status]
        environment = start_environment
        up_done = threading.Event()
        samplers = [
            _StartSampler(attach, environment, context.root, up_done)
            for _ in range(START_SAMPLERS)
        ]
        print(f"    $ {shlex.join(attach)}  # {START_SAMPLERS} loops", flush=True)
        for sampler in samplers:
            sampler.start()
        up_log = context.root / "start-window-up.log"
        print(f"    $ {shlex.join(up_arguments)}", flush=True)
        up_returncode: int | None = None
        try:
            with up_log.open("w", encoding="utf-8") as stream:
                up = subprocess.Popen(
                    up_arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=context.root,
                    env=environment,
                )
                try:
                    up_returncode = up.wait(timeout=START_TIMEOUT)
                finally:
                    if up.poll() is None:
                        up.kill()
                        up.wait(timeout=10)
        finally:
            up_done.set()
            for sampler in samplers:
                sampler.join(timeout=START_TIMEOUT)
        if any(sampler.is_alive() for sampler in samplers):
            raise E2EFailure("An attach sampler did not finish")
        if up_returncode != 0:
            output = up_log.read_text(encoding="utf-8", errors="replace")
            raise E2EFailure(f"up -d exited {up_returncode}: {output[-2000:]}")
        context.wait_for_machine(context.main_name, running=True)
        new_leader = context.machine_leader(context.main_name)
        if new_leader is None:
            raise E2EFailure("The restarted container has no Leader")
        final = dict(
            _host_status(_payload_pid(int(new_leader))), CapEff="0000000000000000"
        )
        counts = {"confined": 0, "not running": 0, "refused": 0}
        refusals: dict[str, int] = {}
        for sampler in samplers:
            if sampler.error is not None:
                raise E2EFailure(f"An attach sampler failed: {sampler.error!r}")
            for after_up, returncode, output in sampler.results:
                if returncode == 0:
                    status = _parse_status(output)
                    if status != final:
                        raise E2EFailure(
                            f"An attach ran with {status!r}, not the final "
                            f"confinement {final!r}"
                        )
                    counts["confined"] += 1
                elif after_up:
                    raise E2EFailure(
                        f"An attach after up returned failed with {returncode}: "
                        f"{output[-2000:]}"
                    )
                elif returncode == 1 and "not found or not running" in output:
                    counts["not running"] += 1
                elif returncode == ENTRY_FAILURE:
                    counts["refused"] += 1
                    reason = _entry_failure_reason(output)
                    refusals[reason] = refusals.get(reason, 0) + 1
                else:
                    raise E2EFailure(
                        f"Unexpected attach result {returncode}: {output[-2000:]}"
                    )
        print(f"    attaches: {counts}; refusals: {refusals}", flush=True)
        if counts["confined"] < START_SAMPLERS * START_ATTACHES_AFTER_UP:
            raise E2EFailure(f"Too few attaches ran: {counts}")

    with context.case("an attach before the payload exists is refused"):
        # Stop the Leader as soon as machined reports it. While it is
        # stopped, it cannot start its payload, so an attach must fail
        # closed and must not run its command.
        marker = context.workspace / "start-refused-marker"
        unit = f"sandy-{context.main_name}.scope"
        held_in = 0
        for attempt in range(1, HOLD_ATTEMPTS + 1):
            context.stop_container(context.main_name, context.main_user)
            print(f"    $ {shlex.join(up_arguments)}", flush=True)
            hold_log = context.root / f"start-hold-up-{attempt}.log"
            with hold_log.open("w", encoding="utf-8") as stream:
                up = subprocess.Popen(
                    up_arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=context.root,
                    env=start_environment,
                )
            try:
                leader = 0
                deadline = time.monotonic() + START_TIMEOUT
                while not leader and up.poll() is None:
                    if time.monotonic() > deadline:
                        raise E2EFailure("The container did not register")
                    leader = _machined_leader(context.main_name)
                if not leader:
                    raise E2EFailure(f"up exited {up.returncode} before registration")
                pidfd = _open_scope_process(leader, unit)
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                    try:
                        deadline = time.monotonic() + HOLD_STOP_TIMEOUT
                        while _process_state(leader) != "T":
                            if time.monotonic() > deadline:
                                raise E2EFailure("The Leader did not stop")
                            time.sleep(0.01)
                        if not _has_payload(leader):
                            held_in = attempt
                            refused = _exec(
                                context,
                                f"touch /home/developer/workspace/{marker.name}",
                                expected=ENTRY_FAILURE,
                            )
                            assert_contains(refused, "Container is still starting")
                            if marker.exists():
                                raise E2EFailure("The command ran before the payload")
                    finally:
                        try:
                            signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
                finally:
                    os.close(pidfd)
                returncode = up.wait(timeout=START_TIMEOUT)
            finally:
                if up.poll() is None:
                    up.kill()
                    up.wait(timeout=10)
            if returncode != 0:
                output = hold_log.read_text(encoding="utf-8", errors="replace")
                raise E2EFailure(
                    f"up -d exited {returncode} after the hold: {output[-2000:]}"
                )
            if held_in:
                break
        if not held_in:
            raise E2EFailure(
                f"The payload existed at the stop in all {HOLD_ATTEMPTS} starts"
            )
        print(f"    held before the payload in start {held_in}", flush=True)
        context.wait_for_machine(context.main_name, running=True)
        _exec(context, "true")

    with context.case("an attach before the payload exists is refused without mounts"):
        # In the case above, up has directories to mount, so the scope check
        # or the mounts-pending marker refuses the attach before the payload
        # check runs. Without directories, up makes no marker. nspawn moves
        # the stopped Leader into the payload cgroup, and then only the
        # payload check stops an attach. Start up with names of directories
        # that do not exist, and hold the Leader there.
        missing = ("missing-workspace", "missing-shared")
        for name in missing:
            if os.path.lexists(context.root / name):
                raise E2EFailure(f"{name} exists in the run root")
        bare_arguments = [
            str(SANDY),
            "--workspace",
            missing[0],
            "--shared",
            missing[1],
            "--user",
            context.main_user,
            "--container",
            context.main_name,
            "up",
            "--detach",
            "--persistent",
            "--network",
            "lenient",
        ]
        unit = f"sandy-{context.main_name}.scope"
        pending = SLICE_CGROUP / unit / "mounts-pending"
        marker_name = "bare-start-refused-marker"
        marker = (
            SYSTEMD_MACHINES
            / f"sandy.{context.main_name}"
            / "home"
            / context.main_user
            / marker_name
        )
        held_in = 0
        for attempt in range(1, HOLD_ATTEMPTS + 1):
            context.stop_container(context.main_name, context.main_user)
            print(f"    $ {shlex.join(bare_arguments)}", flush=True)
            bare_log = context.root / f"bare-hold-up-{attempt}.log"
            with bare_log.open("w", encoding="utf-8") as stream:
                up = subprocess.Popen(
                    bare_arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=context.root,
                    env=start_environment,
                )
            try:
                leader = 0
                deadline = time.monotonic() + START_TIMEOUT
                while not leader and up.poll() is None:
                    if time.monotonic() > deadline:
                        raise E2EFailure("The container did not register")
                    leader = _machined_leader(context.main_name)
                if not leader:
                    raise E2EFailure(f"up exited {up.returncode} before registration")
                pidfd = _open_scope_process(leader, unit)
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                    try:
                        deadline = time.monotonic() + HOLD_STOP_TIMEOUT
                        while _process_state(leader) != "T":
                            if time.monotonic() > deadline:
                                raise E2EFailure("The Leader did not stop")
                            time.sleep(0.01)
                        if not _has_payload(leader):
                            held_in = attempt
                            _wait_for_cgroup(leader, f"/{SLICE}/{unit}/payload")
                            if pending.exists():
                                raise E2EFailure(
                                    "up made a mounts-pending marker with no "
                                    "directory to mount"
                                )
                            refused = _exec(
                                context,
                                f"touch /home/{context.main_user}/{marker_name}",
                                expected=ENTRY_FAILURE,
                            )
                            assert_contains(refused, "Container is still starting")
                            if marker.exists():
                                raise E2EFailure("The command ran before the payload")
                            if _has_payload(leader):
                                raise E2EFailure("The held Leader started its payload")
                    finally:
                        try:
                            signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
                finally:
                    os.close(pidfd)
                returncode = up.wait(timeout=START_TIMEOUT)
            finally:
                if up.poll() is None:
                    up.kill()
                    up.wait(timeout=10)
            output = bare_log.read_text(encoding="utf-8", errors="replace")
            if returncode != 0:
                raise E2EFailure(
                    f"up -d exited {returncode} after the hold: {output[-2000:]}"
                )
            for name in missing:
                if f"Could not find '{name}'" not in output:
                    raise E2EFailure(f"up did not skip {name}: {output[-2000:]}")
            if held_in:
                break
        if not held_in:
            raise E2EFailure(
                f"The payload existed at the stop in all {HOLD_ATTEMPTS} starts"
            )
        print(f"    held in the payload cgroup in start {held_in}", flush=True)
        context.wait_for_machine(context.main_name, running=True)
        # The next cases need the main container with its directories.
        context.stop_container(context.main_name, context.main_user)
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=context.main_name,
            user=context.main_user,
            timeout=START_TIMEOUT,
        )
        _exec_when_mounted(context, "true")

    with context.case("an attach finds the payload among many adopted orphans"):
        # The Leader adopts the orphans of its container while the session
        # that made them runs. With 1000 orphans the Leader's child list takes
        # more than one read chunk; the payload stays its first entry, because
        # the kernel adds an adopted orphan at the end, and an attach works.
        # A test VM cannot hold enough processes for a list above the old
        # 1 MiB limit; the unit tests of the payload search cover that size.
        leader_now = int(context.machine_leader(context.main_name) or 0)
        if not leader_now:
            raise E2EFailure("The main container is not running")
        session = _Session(
            context,
            f"for i in $(seq {ADOPTED_ORPHANS}); do "
            "(sleep 3333 </dev/null >/dev/null 2>&1 &); done; sleep 300",
        )
        try:
            deadline = time.monotonic() + START_TIMEOUT
            while True:
                children = _children(leader_now)
                orphans = [
                    child for child in children if _cmdline(child) == ORPHAN_COMMAND
                ]
                if len(orphans) >= ADOPTED_ORPHANS:
                    break
                if session.process.poll() is not None:
                    raise E2EFailure("The session ended before its orphans existed")
                if time.monotonic() > deadline:
                    raise E2EFailure(f"Only {len(orphans)} orphans reached the Leader")
                time.sleep(0.1)
            listing = Path(f"/proc/{leader_now}/task/{leader_now}/children")
            size = len(listing.read_bytes())
            if size <= sandy.PROC_READ_CHUNK_BYTES:
                raise E2EFailure(f"The Leader's child list has only {size} bytes")
            if not _is_payload(children[0], leader_now):
                raise E2EFailure("The payload is not the Leader's first child")
            print(f"    {len(children)} children, {size} bytes", flush=True)
            _exec(context, "true")
        finally:
            session.process.terminate()
            session.finish()
        # The end of the session kills its leaf, and the orphans in it.
        deadline = time.monotonic() + ORPHANS_GONE_TIMEOUT
        while any(_cmdline(child) == ORPHAN_COMMAND for child in _children(leader_now)):
            if time.monotonic() > deadline:
                raise E2EFailure("The orphans outlived their session")
            time.sleep(0.1)

    with context.case("the keepalive files stay until the payload opened its script"):
        # Review finding S2: up removed the keepalive files as soon as an
        # attach worked, before the payload had started the keepalive. Hold
        # the payload at its fork, before execve: an attach works, and up
        # must wait and keep the files. Then release it.
        unit = f"sandy-{context.main_name}.scope"
        # sandy gets no TMPDIR from the E2E environment.
        tmp = Path("/tmp")
        held_in = 0
        for attempt in range(1, HOLD_ATTEMPTS + 1):
            context.stop_container(context.main_name, context.main_user)
            print(f"    $ {shlex.join(up_arguments)}", flush=True)
            keepalive_log = context.root / f"keepalive-up-{attempt}.log"
            with keepalive_log.open("w", encoding="utf-8") as stream:
                up = subprocess.Popen(
                    up_arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=context.root,
                    env=start_environment,
                )
            try:
                leader = 0
                deadline = time.monotonic() + START_TIMEOUT
                while not leader and up.poll() is None:
                    if time.monotonic() > deadline:
                        raise E2EFailure("The container did not register")
                    leader = _machined_leader(context.main_name)
                if not leader:
                    raise E2EFailure(f"up exited {up.returncode} before registration")
                pidfd = _open_scope_process(leader, unit)
                try:
                    payload = _hold_payload_at_fork(sandy, leader, pidfd)
                finally:
                    os.close(pidfd)
                if payload:
                    held_in = attempt
                    try:
                        # The readiness probe of up is an attach too. It needs the
                        # mounts, which up makes while the payload is held.
                        _exec_when_mounted(context, "true")
                        time.sleep(KEEPALIVE_HOLD_SECONDS)
                        if up.poll() is not None:
                            raise E2EFailure(
                                "up returned before the payload opened its script"
                            )
                        held_dirs = sorted(tmp.glob(KEEPALIVE_DIR_GLOB))
                        if len(held_dirs) != 1:
                            raise E2EFailure(
                                f"Keepalive directories while held: {held_dirs!r}"
                            )
                    finally:
                        sandy._ptrace_detach(payload)
                returncode = up.wait(timeout=START_TIMEOUT)
            finally:
                if up.poll() is None:
                    up.kill()
                    up.wait(timeout=10)
            if returncode != 0:
                output = keepalive_log.read_text(encoding="utf-8", errors="replace")
                raise E2EFailure(f"up -d exited {returncode}: {output[-2000:]}")
            if held_in:
                break
        if not held_in:
            raise E2EFailure(
                f"The payload existed at the seize in all {HOLD_ATTEMPTS} starts"
            )
        print(f"    held the payload at its fork in start {held_in}", flush=True)
        context.wait_for_machine(context.main_name, running=True)
        new_leader = context.machine_leader(context.main_name)
        if new_leader is None:
            raise E2EFailure("The container stopped after the payload was released")
        comm = Path(f"/proc/{_payload_pid(int(new_leader))}/comm").read_text()
        if comm.strip() != "sandy-keepalive":
            raise E2EFailure(f"Payload comm is {comm.strip()!r}")
        leftovers = sorted(tmp.glob(KEEPALIVE_DIR_GLOB))
        if leftovers:
            raise E2EFailure(f"Keepalive directories remain: {leftovers!r}")
        _exec(context, "true")
