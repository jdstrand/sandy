"""Entry-path confinement parity (security-parity.md item 1).

Every attach (`exec`, `bash`, and `-u root`) must run with the container
payload's seccomp filters and capability bounding set. These properties need
the real kernel, systemd-nspawn, and sandy, so unit mocks cannot prove them.
"""

from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
import os
import platform
import shlex
import subprocess
import time
from pathlib import Path
from types import ModuleType

from tests.e2e.support import (
    SANDY,
    E2EContext,
    E2EFailure,
    assert_contains,
)

STATUS_FIELDS = ("Seccomp", "Seccomp_filters", "CapBnd", "CapEff", "NoNewPrivs")
EPERM = 1
ENTRY_FAILURE = 125
STABILITY_RUNS = 150
# aarch64 has 7 of the 10 denied syscalls, and 5.15 hides bpf.
MIN_OBSERVABLE_DENIED = 6
# Denied by Docker's default profile and by nspawn's filter; the nsenter path
# reached the kernel with each of them (security-parity.md item 1).
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
        """Return the session: the only child of the entry helper."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for helper in _children(self.process.pid):
                cmdline = Path(f"/proc/{helper}/cmdline").read_bytes()
                if b"__sandy-entry-helper" in cmdline:
                    sessions = _children(helper)
                    # Before its execve, the session is a fork of the helper
                    # that has not installed the filters yet.
                    if len(sessions) == 1 and b"__sandy-entry-helper" not in (
                        Path(f"/proc/{sessions[0]}/cmdline").read_bytes()
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


def _exec(context: E2EContext, command: str, *, user: str | None = None, **kwargs):
    return context.sandy(
        ["exec", "--", command],
        name=context.main_name,
        user=user or context.main_user,
        **kwargs,
    )


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
