"""The container's own systemd scope, the keepalive payload, and attaches.

These properties need systemd, the kernel's cgroup v2, and real sandy
processes, so unit mocks cannot prove them.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from typing import BinaryIO
from contextlib import ExitStack, contextmanager
from pathlib import Path

from tests.e2e.support import (
    LIFECYCLE_LOCK,
    PORT_LOCK,
    PORT_STATE,
    SANDY,
    SHARED_LIMITS,
    SLICE,
    SLICE_CGROUP,
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
    holds_flock,
    waits_for_flock,
)

CGROUP_SLICE = SLICE_CGROUP
ONLINE_CPUS = Path("/sys/devices/system/cpu/online")
THREADS_MAX = Path("/proc/sys/kernel/threads-max")
PID_MAX = Path("/proc/sys/kernel/pid_max")
ATTACH_LEAF = re.compile(r"attach-[0-9a-f]{32}")
MIB = 1024 * 1024
GIB = 1024 * MIB
DEFAULT_TMP_SIZE = 512 * MIB
KEEPALIVE_COMM = "sandy-keepalive"
WAIT_TIMEOUT = 30
# The markers that up makes in the scope of the container that it starts.
SCOPE_MARKERS = ("mounts-pending", "up-console")
# The host port that an up publishes when a check under the lock refuses it.
REFUSED_UP_PORT = 18089
# The host port of an up that finds the port mapping lock busy.
BUSY_LOCK_UP_PORT = 18090
# up waits for the port mapping lock under the lifecycle lock for 5 seconds
# (PORT_MAPPINGS_LOCK_TIMEOUT of sandy), and attaches wait for the lifecycle
# lock for 10 (LIFECYCLE_LOCK_TIMEOUT).
PORT_LOCK_WAIT = 5
LIFECYCLE_LOCK_WAIT = 10
# The host port of an up that gets SIGINT while it waits for the port mapping
# lock, and how long it may take to exit then.
INTERRUPTED_UP_PORT = 18091
INTERRUPTED_UP_EXIT = 3
# The host port of an up whose supervisor does not start.
FAILED_START_PORT = 18092


def _wait_for_the_publish_wait(
    up: subprocess.Popen[bytes], lock: BinaryIO, log_path: Path, *, blocking: bool
) -> None:
    """Return when up waits for the port mapping lock to publish its ports.

    The caller holds the lock through lock. At its start, up also waits for
    the lock, to remove the stale port rules and state of its name. Let that
    removal through, and take the lock back at once: up then needs only some
    milliseconds to come to the publish. A woken waiter must try again, so
    the caller can get the lock first; up then waits again, and the loop lets
    it through again. "I: Limits of this container" is the last line before
    the publish. Without the lifecycle lock, up then waits in flock(2), and
    /proc/locks shows it as a waiter. Under the lifecycle lock, up polls with
    LOCK_NB for PORT_LOCK_WAIT seconds; it starts in much less than one
    second.
    """
    deadline = time.monotonic() + WAIT_TIMEOUT
    while True:
        if up.poll() is not None or time.monotonic() >= deadline:
            raise E2EFailure("up did not wait to publish its ports")
        # Look at the waits first: up prints nothing while it waits.
        waiting = waits_for_flock(up.pid, PORT_LOCK)
        limits = "I: Limits of this container" in log_path.read_text(
            encoding="utf-8", errors="replace"
        )
        if limits and not blocking:
            time.sleep(1)
            break
        if waiting:
            if limits:
                break
            fcntl.flock(lock, fcntl.LOCK_UN)
            fcntl.flock(lock, fcntl.LOCK_EX)
            continue
        time.sleep(0.01)
    if up.poll() is not None:
        raise E2EFailure("up did not wait to publish its ports")


class _PortStateReader:
    """Read the port state under the port mapping lock in a loop, as up does.

    Count the reads, and the reads that find one key.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        self.reads = 0
        self.found = 0
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._read, daemon=True)

    def __enter__(self) -> "_PortStateReader":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=WAIT_TIMEOUT)
        if self._thread.is_alive():
            raise E2EFailure("The port state reader did not stop")

    def _read(self) -> None:
        try:
            while not self._stop.is_set():
                with PORT_LOCK.open("rb") as lock:
                    fcntl.flock(lock, fcntl.LOCK_SH)
                    try:
                        if PORT_STATE.exists():
                            state = json.loads(PORT_STATE.read_text(encoding="utf-8"))
                            if self.key in state:
                                self.found += 1
                        self.reads += 1
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                time.sleep(0.001)
        except BaseException as exc:  # reported by the case
            self.errors.append(exc)


def _unit(name: str) -> str:
    return f"sandy-{name}.scope"


def _unit_dir(name: str) -> Path:
    return CGROUP_SLICE / _unit(name)


def _show(context: E2EContext, name: str, prop: str) -> str:
    return context.run(
        ["systemctl", "show", _unit(name), "-p", prop, "--value"]
    ).stdout.strip()


def _systemd_version(context: E2EContext) -> int:
    first = context.run(["systemctl", "--version"]).stdout.splitlines()[0]
    return int(first.split()[1])


def _read_cgroup_file(path: Path) -> str | None:
    """Return the text of a cgroup file, or None when its cgroup is gone.

    sandy removes attach leaves while the tests poll them. A removal before
    the open gives ENOENT; a removal between the open and the read gives
    ENODEV (seen on systemd 257).
    """
    try:
        return path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno != errno.ENODEV:
            raise
        return None


def _leaves(name: str) -> dict[str, bool]:
    """Return each attach leaf of the scope and whether it has processes."""
    unit_dir = _unit_dir(name)
    if not unit_dir.is_dir():
        return {}
    leaves = {}
    for path in unit_dir.iterdir():
        if ATTACH_LEAF.fullmatch(path.name):
            events = _read_cgroup_file(path / "cgroup.events")
            if events is not None:
                leaves[path.name] = "populated 1" in events
    return leaves


def _cgroup(pid: int) -> str:
    return Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").strip()


def _status(pid: int, key: str) -> str:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    raise E2EFailure(f"No {key} in /proc/{pid}/status")


def _children(pid: int) -> list[int]:
    try:
        text = Path(f"/proc/{pid}/task/{pid}/children").read_text(encoding="ascii")
    except FileNotFoundError:
        return []
    return [int(value) for value in text.split()]


def _payload(leader: int) -> int:
    """Return the Leader's child with the lowest container PID."""
    candidates = []
    for child in _children(leader):
        container_pid = int(_status(child, "NSpid").split()[-1])
        candidates.append((container_pid, child))
    if not candidates:
        raise E2EFailure("The container Leader has no payload process")
    return min(candidates)[1]


def _has_new_only_child(pid: int, old_child: int) -> bool:
    """Return whether pid has exactly one child, and it is not old_child.

    Read the children once: the list can change between two reads, for
    example when the keepalive reaps the killed sleep before it starts the
    next one.
    """
    children = _children(pid)
    return len(children) == 1 and children[0] != old_child


def _cpu_set(text: str) -> set[int]:
    """Parse a CPU list of the kernel (0-3,8) or of systemctl (0-3 8)."""
    cpus: set[int] = set()
    for part in text.replace(",", " ").split():
        first, _, last = part.partition("-")
        cpus.update(range(int(first), int(last or first) + 1))
    return cpus


def _group_defaults() -> tuple[set[int], int, int]:
    """Return the default CPUs, memory, and tasks of sandy.slice on this host.

    specs/security-parity.md item 2: the host keeps its 4 lowest-numbered
    online CPUs of 16 or more, 2 of 8 or more, otherwise 1. It keeps 25% of
    its memory, at least 4 GiB, never more than half. The containers get the
    same share of the system task limit (the smaller of threads-max and
    pid_max).
    """
    online = sorted(_cpu_set(ONLINE_CPUS.read_text(encoding="ascii")))
    reserved = 4 if len(online) >= 16 else 2 if len(online) >= 8 else 1
    shared = online[len(online) - max(1, len(online) - reserved) :]
    memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    reserve = min(max(memory * 25 // 100, 4 * GIB), memory // 2)
    shared_memory = (memory - reserve) // MIB * MIB
    task_limit = min(
        int(THREADS_MAX.read_text(encoding="ascii")),
        int(PID_MAX.read_text(encoding="ascii")),
    )
    return set(shared), shared_memory, max(1, task_limit * shared_memory // memory)


def _container_tasks_default(group_tasks: int) -> int:
    """25% of the shared process limit, at least 8192, at most half of it."""
    return max(1, min(max(group_tasks * 25 // 100, 8192), group_tasks // 2))


def _default_limits() -> dict[str, str]:
    """Return the scope properties of the default limits of up.

    A container has no CPU or memory limit of its own, no swap, and a share
    of the shared process limit.
    """
    return {
        "TasksMax": str(_container_tasks_default(_group_defaults()[2])),
        "MemoryMax": "infinity",
        "MemorySwapMax": "0",
        "CPUQuotaPerSecUSec": "infinity",
    }


def _slice_show(context: E2EContext, prop: str) -> str:
    return context.run(
        ["systemctl", "show", SLICE, "-p", prop, "--value"]
    ).stdout.strip()


def _kernel_limit(text: str) -> int | None:
    """Parse memory.max or pids.max; None for max."""
    text = text.strip()
    return None if text == "max" else int(text)


def _check_group_limits(
    context: E2EContext,
    name: str | None,
    expected: tuple[set[int], int | None, int | None] | None = None,
) -> None:
    """Check the limits of sandy.slice in systemd and in the kernel.

    With a running container name, also check the CPUs that its processes
    see: the CPU set is the only limit that they can see (measured).
    """
    if expected is None:
        expected = _group_defaults()
    cpus, memory, tasks = expected

    def value(limit: int | None) -> str:
        return "infinity" if limit is None else str(limit)

    shown = (
        _cpu_set(_slice_show(context, "AllowedCPUs")),
        _slice_show(context, "MemoryMax"),
        _slice_show(context, "TasksMax"),
    )
    if shown != (cpus, value(memory), value(tasks)):
        raise E2EFailure(f"{SLICE} has {shown!r}, not {expected!r}")
    if name is None:
        return
    kernel = (
        _cpu_set((CGROUP_SLICE / "cpuset.cpus").read_text(encoding="ascii")),
        _kernel_limit((CGROUP_SLICE / "memory.max").read_text(encoding="ascii")),
        _kernel_limit((CGROUP_SLICE / "pids.max").read_text(encoding="ascii")),
    )
    if kernel != (cpus, memory, tasks):
        raise E2EFailure(f"The kernel limits of {SLICE} are {kernel!r}")
    inside = context.sandy(
        ["exec", "--", "nproc; grep Cpus_allowed_list /proc/self/status"], name=name
    ).stdout.split()
    if inside[0] != str(len(cpus)) or _cpu_set(inside[-1]) != cpus:
        raise E2EFailure(f"Processes inside see the CPUs {inside!r}")


def _oom_score_adj(pid: int) -> int:
    return int(Path(f"/proc/{pid}/oom_score_adj").read_text(encoding="ascii"))


OOM_STATUS = re.compile(
    r"OOM kills: ([0-9]+) \(memory limit reached: ([0-9]+) times? by all Sandy "
    r"containers, ([0-9]+) times? inside this container\)"
)


def _oom_status(context: E2EContext, name: str) -> tuple[int, int, int]:
    """Return the OOM kills, shared-limit OOMs, and own OOMs from status."""
    status = context.sandy(["status"], name=name)
    match = OOM_STATUS.search(status.stdout)
    if match is None:
        raise E2EFailure(f"No OOM line in status: {status.stdout[-2000:]}")
    kills, shared, own = (int(value) for value in match.groups())
    return kills, shared, own


def _tmp_size(context: E2EContext, name: str) -> int:
    """Return the size of /tmp in the container, in bytes."""
    result = context.sandy(
        ["exec", "--", "df -B1 --output=size /tmp | tail -n 1"], name=name
    )
    return int(result.stdout.strip())


def _comm(pid: int) -> str:
    return Path(f"/proc/{pid}/comm").read_text(encoding="ascii").strip()


def _wait_for(description: str, predicate, timeout: float = WAIT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise E2EFailure(f"Timed out waiting until {description}")


def _pids_with_comm_in_cgroup(name: str, leaf: str) -> list[int]:
    text = _read_cgroup_file(_unit_dir(name) / leaf / "cgroup.procs")
    return [int(value) for value in (text or "").split()]


def _wait_for_leaf_commands(
    name: str, leaf: str, commands: tuple[bytes, ...]
) -> list[int]:
    """Wait until each command line runs in the leaf; return its processes.

    leaf() returns when the helper has any child. That is already true
    before the session has started its commands, so the leaf can still
    have only two processes (seen on systemd 249 and 255).
    """

    def running() -> bool:
        found = set()
        for pid in _pids_with_comm_in_cgroup(name, leaf):
            try:
                found.add(Path(f"/proc/{pid}/cmdline").read_bytes())
            except (FileNotFoundError, ProcessLookupError):
                continue
        return set(commands) <= found

    _wait_for(f"the attach commands run in {leaf}", running)
    return _pids_with_comm_in_cgroup(name, leaf)


class _Attach:
    """A background `sandy exec` whose processes can be found and signaled."""

    def __init__(self, context: E2EContext, name: str, command: str) -> None:
        self.context = context
        self.name = name
        arguments = [
            str(SANDY),
            "--workspace",
            context.workspace.name,
            "--shared",
            context.shared.name,
            "--container",
            name,
            "exec",
            "--",
            command,
        ]
        self.output = context.root / f"attach-{time.monotonic_ns()}.log"
        with self.output.open("w", encoding="utf-8") as stream:
            self.process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
                cwd=context.root,
                env=context.safe_environment(),
            )

    def helper(self) -> int:
        """Return the entry helper once its session runs."""
        found: list[int] = []

        def started() -> bool:
            for child in _children(self.process.pid):
                cmdline = Path(f"/proc/{child}/cmdline").read_bytes()
                if b"__sandy-entry-helper" in cmdline and _children(child):
                    found.append(child)
                    return True
            return False

        _wait_for("the attach session starts", started)
        return found[0]

    def leaf(self) -> str:
        """Return the attach leaf once the helper has joined it.

        During extraction the helper already has a child (machinectl), so
        wait for the cgroup, not only for a child.
        """
        pattern = re.compile(
            rf"0::/{re.escape(SLICE)}/{re.escape(_unit(self.name))}/"
            r"(attach-[0-9a-f]{32})"
        )
        found: list[str] = []

        def joined() -> bool:
            match = pattern.fullmatch(_cgroup(self.helper()))
            if match is not None:
                found.append(match.group(1))
            return match is not None

        _wait_for("the entry helper joins its attach leaf", joined)
        return found[0]

    def finish(self, timeout: int = 60) -> tuple[int, str]:
        try:
            returncode = self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=10)
        return returncode, self.output.read_text(encoding="utf-8", errors="replace")


class _Console:
    """`sandy up` without -d; its console reads commands from a pipe."""

    def __init__(self, context: E2EContext, name: str, *extra: str) -> None:
        arguments = [
            str(SANDY),
            "--workspace",
            context.workspace.name,
            "--shared",
            context.shared.name,
            "--container",
            name,
            "up",
            "--persistent",
            "--network",
            "host",
            *extra,
        ]
        self.output = context.root / f"console-{time.monotonic_ns()}.log"
        with self.output.open("w", encoding="utf-8") as stream:
            self.process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=stream,
                stderr=subprocess.STDOUT,
                cwd=context.root,
                env=context.safe_environment(),
            )

    def send(self, text: str) -> None:
        # The pty relay spins on an EOF stdin, so the pipe stays open.
        assert self.process.stdin is not None
        self.process.stdin.write(text.encode())
        self.process.stdin.flush()

    def finish(self, timeout: int = 60) -> tuple[int, str]:
        try:
            returncode = self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=10)
            if self.process.stdin is not None:
                self.process.stdin.close()
        return returncode, self.output.read_text(encoding="utf-8", errors="replace")


def _wait_for_console(context: E2EContext, name: str) -> None:
    context.wait_for_machine(name, running=True)
    _wait_for("the console attach starts", lambda: any(_leaves(name).values()))


def _wait_stopped(context: E2EContext, name: str) -> None:
    context.wait_for_machine(name, running=False)
    _wait_for(
        "the scope is gone", lambda: _show(context, name, "LoadState") == "not-found"
    )


@contextmanager
def _up_while_its_scope_appears(
    context: E2EContext, name: str, user: str, arguments: list[str]
) -> Iterator[tuple[int, str]]:
    """Run up of name so that the scope of name appears while up waits for the lock.

    up checks for a running container and for its scope first, makes other
    host changes, and then waits for the lifecycle lock. Hold the lock until
    up waits for it ("Limits of this container" is its last line before the
    lock), make a scope of the name in sandy.slice, and release the lock.
    Yield the exit status and the output of up, while the scope still exists;
    then stop the scope. up waits for the lock for at most 10 seconds
    (LIFECYCLE_LOCK_TIMEOUT of sandy); this needs about one.
    """
    log_path = context.root / f"lock-wait-{name}.log"
    command = [
        str(SANDY),
        "--workspace",
        context.workspace.name,
        "--shared",
        context.shared.name,
        "--user",
        user,
        "--container",
        name,
        *arguments,
    ]
    up: subprocess.Popen[bytes] | None = None
    blocker: subprocess.Popen[bytes] | None = None
    try:
        with LIFECYCLE_LOCK.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(f"    $ {shlex.join(command)} &", flush=True)
            with log_path.open("w", encoding="utf-8") as stream:
                up = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=context.root,
                    env=context.safe_environment(),
                )
            _wait_for(
                "up waits for the lifecycle lock",
                lambda: "I: Limits of this container"
                in log_path.read_text(encoding="utf-8", errors="replace"),
            )
            blocker = subprocess.Popen(
                [
                    "systemd-run",
                    "--scope",
                    "--quiet",
                    f"--unit={_unit(name)}",
                    f"--slice={SLICE}",
                    "--",
                    "sleep",
                    "300",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait_for(
                "the blocking scope exists",
                lambda: _show(context, name, "ActiveState") == "active",
            )
        # The close released the lock; up takes it now.
        returncode = up.wait(timeout=WAIT_TIMEOUT)
        yield returncode, log_path.read_text(encoding="utf-8", errors="replace")
    finally:
        if up is not None and up.poll() is None:
            up.kill()
            up.wait(timeout=10)
        if blocker is not None:
            context.run(["systemctl", "stop", _unit(name)], expected=None)
            blocker.wait(timeout=30)
    _wait_for(
        "the blocking scope is gone",
        lambda: _show(context, name, "LoadState") == "not-found",
    )


def test_main(context: E2EContext) -> None:
    """Prove the scope, keepalive, attach, and lifecycle design."""
    name = context.main_name
    version = _systemd_version(context)
    leader_text = context.machine_leader(name)
    if leader_text is None:
        raise E2EFailure("The main container is not running")
    leader = int(leader_text)

    with context.case("the container runs in its own scope with the default limits"):
        expected = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "ControlGroup": f"/{SLICE}/{_unit(name)}",
            "Description": f"Sandy container {name} (detached)",
            "Delegate": "yes",
            **_default_limits(),
        }
        # Scope units accept OOMPolicy= only from systemd 253.
        if version >= 253:
            expected["OOMPolicy"] = "continue"
        actual = {prop: _show(context, name, prop) for prop in expected}
        if actual != expected:
            raise E2EFailure(f"Scope properties {actual!r} != {expected!r}")
        machine_unit = context.run(
            ["machinectl", "show", name, "-p", "Unit", "--value"]
        ).stdout.strip()
        if machine_unit != _unit(name):
            raise E2EFailure(f"Machine unit is {machine_unit!r}")
        if _tmp_size(context, name) != DEFAULT_TMP_SIZE:
            raise E2EFailure(f"/tmp has {_tmp_size(context, name)} bytes")
        supervisors = [
            int(pid)
            for pid in (_unit_dir(name) / "supervisor" / "cgroup.procs")
            .read_text()
            .split()
        ]
        if len(supervisors) != 1 or _comm(supervisors[0]) != "systemd-nspawn":
            raise E2EFailure(f"Unexpected supervisor processes {supervisors!r}")
        nspawn = supervisors[0]
        stat_fields = Path(f"/proc/{nspawn}/stat").read_text().rsplit(")", 1)[1].split()
        # Fields after the command: state ppid pgrp session tty_nr.
        if stat_fields[4] != "0" or int(stat_fields[3]) != nspawn:
            raise E2EFailure(
                f"nspawn has a terminal or no own session: {stat_fields[:5]}"
            )
        if not _cgroup(leader).startswith(f"0::/{SLICE}/{_unit(name)}/payload"):
            raise E2EFailure(f"Leader cgroup {_cgroup(leader)!r}")

    with context.case("all containers share the CPUs, memory, and tasks of the slice"):
        _check_group_limits(context, name)

    with context.case("the keepalive is PID 2, container root, and survives users"):
        payload = _payload(leader)
        if _comm(payload) != KEEPALIVE_COMM:
            raise E2EFailure(f"Payload comm is {_comm(payload)!r}")
        if _status(payload, "NSpid").split()[-1] != "2":
            raise E2EFailure(f"Keepalive NSpid {_status(payload, 'NSpid')!r}")
        if _status(payload, "Uid").split()[0] != _status(leader, "Uid").split()[0]:
            raise E2EFailure("The keepalive and the Leader have different uids")
        root_identity = context.sandy(
            ["exec", "--", "stat -c %u /proc/2"], name=name, user="root"
        )
        if root_identity.stdout.strip() != "0":
            raise E2EFailure(f"PID 2 is not container root: {root_identity.stdout!r}")
        environ = Path(f"/proc/{payload}/environ").read_bytes().split(b"\0")
        if any(item.startswith(b"BASH_ENV=") for item in environ):
            raise E2EFailure("The keepalive has BASH_ENV")
        sleeps = _children(payload)
        if len(sleeps) != 1 or _comm(sleeps[0]) != "sleep":
            raise E2EFailure(f"Keepalive children {sleeps!r}")
        context.sandy(
            ["exec", "--", "kill -9 2; kill -9 -1"],
            name=name,
            user=context.main_user,
            expected=None,
        )
        if not context.machine_running(name) or _payload(leader) != payload:
            raise E2EFailure("A container user stopped the keepalive")
        os.kill(sleeps[0], signal.SIGKILL)
        _wait_for(
            "the keepalive restarts sleep",
            lambda: _has_new_only_child(payload, sleeps[0]),
        )
        leftovers = sorted(Path("/tmp").glob("sandy-keepalive-*"))
        if leftovers:
            raise E2EFailure(f"Keepalive directories remain: {leftovers!r}")
        run_sandy = context.sandy(["exec", "--", "ls -A /run/sandy"], name=name)
        if run_sandy.stdout.strip():
            raise E2EFailure(f"/run/sandy is not empty: {run_sandy.stdout!r}")

    with context.case("attaches run in their own leaf and leave nothing behind"):
        inside = context.sandy(["exec", "--", "cat /proc/self/cgroup"], name=name)
        if not re.fullmatch(r"0::/\.\./attach-[0-9a-f]{32}", inside.stdout.strip()):
            raise E2EFailure(f"Attach cgroup inside: {inside.stdout!r}")
        bash = context.sandy(["bash", "-c", "cat /proc/self/cgroup"], name=name)
        assert_contains(bash, "0::/../attach-")
        attach = _Attach(context, name, "sleep 300 & sleep 2; exit 0")
        leaf = attach.leaf()
        returncode, output = attach.finish()
        if returncode != 0:
            raise E2EFailure(f"Attach failed with {returncode}: {output[-2000:]}")
        # The background sleep is killed with the leaf.
        if leaf in _leaves(name):
            raise E2EFailure(f"Attach leaf {leaf} remains")
        stray = context.run(["pgrep", "-f", "sleep 300"], expected=None)
        if stray.returncode == 0:
            raise E2EFailure(f"Attach processes remain: {stray.stdout!r}")

    for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
        label = signal.Signals(signum).name
        with context.case(f"{label} to sandy ends its whole attach"):
            attach = _Attach(context, name, "sleep 301 & sleep 302")
            leaf = attach.leaf()
            # Both sleeps must run, so that the signal has a whole attach
            # to end: the helper, the session, and a background process.
            members = _wait_for_leaf_commands(
                name, leaf, (b"sleep\x00301\x00", b"sleep\x00302\x00")
            )
            if len(members) < 3:
                raise E2EFailure(f"Attach leaf has {members!r}")
            attach.process.send_signal(signum)
            attach.finish()
            _wait_for(
                f"the leaf is empty after {label}",
                lambda: not _leaves(name).get(leaf, False),
            )
            if signum != signal.SIGKILL and leaf in _leaves(name):
                raise E2EFailure(f"Leaf {leaf} remains after {label}")
            stray = context.run(["pgrep", "-f", "sleep 30[12]"], expected=None)
            if stray.returncode == 0:
                raise E2EFailure(f"Attach processes remain: {stray.stdout!r}")
            if not context.machine_running(name):
                raise E2EFailure(f"{label} stopped the container")
    # An empty leaf left by SIGKILL is removed by the next attach count or by
    # the scope stop.

    with context.case("a stop of the terminal's scope keeps the container"):
        terminal = f"e2e-terminal-{os.getpid()}.scope"
        arguments = [
            "systemd-run",
            "--scope",
            "--quiet",
            f"--unit={terminal}",
            "--",
            str(SANDY),
            "--workspace",
            context.workspace.name,
            "--shared",
            context.shared.name,
            "--container",
            name,
            "exec",
            "--",
            "sleep 303",
        ]
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=context.root,
            env=context.safe_environment(),
        )
        try:
            _wait_for("the terminal attach starts", lambda: any(_leaves(name).values()))
            context.run(["systemctl", "stop", terminal])
            process.wait(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        _wait_for("the attach ends", lambda: not any(_leaves(name).values()))
        if not context.machine_running(name) or _payload(leader) != payload:
            raise E2EFailure("Stopping the terminal's scope stopped the container")
        stray = context.run(["pgrep", "-f", "sleep 303"], expected=None)
        if stray.returncode == 0:
            raise E2EFailure(f"Attach processes remain: {stray.stdout!r}")

    with context.case("an OOM in an attach kills only that process and is reported"):
        # A test-only limit of this scope; sandy sets none.
        context.run(
            ["systemctl", "set-property", "--runtime", _unit(name), "MemoryMax=256M"]
        )
        try:
            idle = _Attach(context, name, "sleep 304")
            idle.leaf()
            hog = context.sandy(
                ["exec", "--", "python3 -c 'b = bytearray(1 << 30)'"],
                name=name,
                expected=None,
            )
            if hog.returncode == 0:
                raise E2EFailure("The memory hog was not killed")
            assert_contains(
                hog,
                f"W: The kernel ended 1 process in '{name}' during this session "
                "because memory ran out",
            )
            assert_contains(hog, "The container reached a memory limit of its own")
            assert_not_contains(hog, "share")
            if _show(context, name, "ActiveState") != "active":
                raise E2EFailure("The OOM stopped the scope")
            if _payload(leader) != payload or not context.machine_running(name):
                raise E2EFailure("The OOM stopped the keepalive")
            if idle.process.poll() is not None:
                raise E2EFailure("The OOM ended another attach")
            idle.process.send_signal(signal.SIGTERM)
            idle.finish()
            kills, shared_ooms, own_ooms = _oom_status(context, name)
            if (kills, shared_ooms) != (1, 0) or own_ooms < 1:
                raise E2EFailure(f"OOM counts {(kills, shared_ooms, own_ooms)!r}")
            quiet = context.sandy(["exec", "--", "true"], name=name)
            assert_not_contains(quiet, "W: The kernel ended")
        finally:
            context.run(
                [
                    "systemctl",
                    "set-property",
                    "--runtime",
                    _unit(name),
                    "MemoryMax=infinity",
                ]
            )

    second = context.scope_name
    with context.case("a second container gets its own scope"):
        context.build_minimal(second, context.cache_user)
        for container in (name, second):
            if _show(context, container, "ActiveState") != "active":
                raise E2EFailure(f"{_unit(container)} is not active")
        second_inside = context.sandy(
            ["exec", "--", "cat /proc/self/cgroup"], name=second
        )
        assert_contains(second_inside, "0::/../attach-")
        if _show(context, second, "ControlGroup") != f"/{SLICE}/{_unit(second)}":
            raise E2EFailure(f"{_unit(second)} is not in {SLICE}")
        _check_group_limits(context, second)

    with context.case(
        "update --shared changes running containers and saves the limits"
    ):
        online = sorted(_cpu_set(ONLINE_CPUS.read_text(encoding="ascii")))
        # The lowest CPU, which the host keeps by default.
        changed = ({online[0]}, GIB, 4096)
        update = context.sandy(
            [
                "update",
                "--shared",
                "--cpuset-cpus",
                str(online[0]),
                "-m",
                "1g",
                "--pids-limit",
                "4096",
            ]
        )
        assert_contains(
            update,
            f"I: Limits of all Sandy containers: CPUs {online[0]} (saved), memory "
            "1.0 GiB (saved), 4096 tasks (saved)",
        )
        # The change applies at once, also to running processes (measured).
        _check_group_limits(context, second, changed)
        cpus = _cpu_set(_status(_payload(leader), "Cpus_allowed_list"))
        if cpus != changed[0]:
            raise E2EFailure(f"The running keepalive has the CPUs {cpus!r}")
        saved = SHARED_LIMITS.stat()
        if (saved.st_uid, saved.st_gid, saved.st_mode & 0o777) != (0, 0, 0o600):
            raise E2EFailure(f"Unsafe saved limits {saved!r}")
        text = SHARED_LIMITS.read_text(encoding="ascii")
        if text != f'{{"cpus":"{online[0]}","memory":{GIB},"tasks":4096}}\n':
            raise E2EFailure(f"Saved limits {text!r}")
        # Errors change nothing.
        for arguments, message in (
            ([], "update --shared needs at least one of"),
            (["--reset", "-m", "2g"], "--reset cannot be used with"),
            (["--cpuset-cpus", "4095"], "--cpuset-cpus must name online CPUs"),
        ):
            refused = context.sandy(["update", "--shared", *arguments], expected=1)
            assert_contains(refused, message)
        refused = context.sandy(
            ["update", "--shared", "-m", "2g"], name=second, expected=1
        )
        assert_contains(refused, "update --shared cannot be used with --container")
        refused = context.sandy(["update", "-m", "2g"], name=second, expected=1)
        assert_contains(refused, "--memory need --shared")
        _check_group_limits(context, None, changed)
        reset = context.sandy(["update", "--shared", "--reset"])
        assert_not_contains(reset, "(saved)")
        _check_group_limits(context, second)
        if SHARED_LIMITS.read_text(encoding="ascii") != "{}\n":
            raise E2EFailure("--reset kept saved limits")

    with context.case("down stops the container and its scope in one step"):
        down = context.sandy(["down"], name=second)
        assert_not_contains(down, "No machine")
        # No wait: the next up must find no machine and no scope.
        if context.machine_running(second):
            raise E2EFailure("The machine still runs after down")
        if _show(context, second, "LoadState") != "not-found":
            raise E2EFailure("The scope remains after down")

    with context.case("up refuses a name whose scope already exists"):
        blocker = subprocess.Popen(
            [
                "systemd-run",
                "--scope",
                "--quiet",
                f"--unit={_unit(second)}",
                "--",
                "sleep",
                "300",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for(
                "the blocking scope exists",
                lambda: _show(context, second, "ActiveState") == "active",
            )
            refused = context.sandy(
                ["up", "--detach", "--persistent", "--network", "host"],
                name=second,
                expected=1,
            )
            assert_contains(refused, f"Unit '{_unit(second)}' already exists")
            if context.machine_running(second):
                raise E2EFailure("up started the container anyway")
        finally:
            context.run(["systemctl", "stop", _unit(second)], expected=None)
            blocker.wait(timeout=30)
        _wait_for(
            "the blocking scope is gone",
            lambda: _show(context, second, "LoadState") == "not-found",
        )

    with context.case("an up that waited for the lock leaves a scope of its name"):
        # Another start can make the scope of the name while up waits for the
        # lock. up must then refuse: no marker in that scope, and no mount
        # into it.
        with _up_while_its_scope_appears(
            context,
            second,
            "developer",
            ["up", "--detach", "--persistent", "--network", "host"],
        ) as (returncode, output):
            for marker in SCOPE_MARKERS:
                if (_unit_dir(second) / marker).exists():
                    raise E2EFailure(
                        f"up made {marker} in a scope that it did not start"
                    )
            if returncode != 1:
                raise E2EFailure(f"up exited {returncode}: {output[-2000:]}")
            assert_contains_text(output, f"Unit '{_unit(second)}' already exists")
            if context.machine_running(second):
                raise E2EFailure("up started the container anyway")

    with context.case("the console is an attach, and its exit stops the container"):
        console = _Console(context, second)
        _wait_for_console(context, second)
        if _show(context, second, "Description") != (
            f"Sandy container {second} (attached)"
        ):
            raise E2EFailure("The scope does not record an attached up")
        # While the console runs, no attach exit may stop the container.
        if not (_unit_dir(second) / "up-console").is_dir():
            raise E2EFailure("The up-console marker is missing")
        console_inside = context.sandy(
            ["exec", "--", "cat /proc/self/cgroup"], name=second
        )
        assert_contains(console_inside, "0::/../attach-")
        if not context.machine_running(second):
            raise E2EFailure("An exec exit stopped the container while the console ran")
        console.send("exit\n")
        returncode, output = console.finish()
        if returncode != 0:
            raise E2EFailure(f"Console up exited {returncode}: {output[-2000:]}")
        assert_contains_text(output, "no session is attached")
        _wait_stopped(context, second)

    with context.case("the last attach out stops the container, once"):
        console = _Console(context, second)
        _wait_for_console(context, second)
        first = _Attach(context, second, "sleep 4")
        other = _Attach(context, second, "sleep 4")
        first.leaf()
        other.leaf()
        console.send("exit\n")
        returncode, console_output = console.finish()
        if returncode != 0:
            raise E2EFailure(f"Console up exited {returncode}")
        if not context.machine_running(second):
            raise E2EFailure("The console exit stopped the container with attaches")
        outputs = [console_output]
        for attach in (first, other):
            attach_returncode, attach_output = attach.finish()
            if attach_returncode != 0:
                raise E2EFailure(f"Attach exited {attach_returncode}: {attach_output}")
            outputs.append(attach_output)
        _wait_stopped(context, second)
        stops = sum(text.count("no session is attached") for text in outputs)
        if stops != 1:
            raise E2EFailure(f"The container was stopped {stops} times: {outputs!r}")
        joined = "\n".join(outputs)
        if any(
            warning in joined
            for warning in (
                "not found or not running",
                "did not stop",
                "Could not check the sessions",
                "Could not remove attach cgroup",
            )
        ):
            raise E2EFailure(f"Unexpected warnings: {joined[-2000:]}")

    with context.case("a console hangup keeps the container until the last attach"):
        console = _Console(context, second)
        _wait_for_console(context, second)
        attach = _Attach(context, second, "sleep 4")
        attach.leaf()
        console.process.send_signal(signal.SIGHUP)
        returncode, console_output = console.finish()
        if returncode != 128 + signal.SIGHUP:
            raise E2EFailure(
                f"Console up exited {returncode}: {console_output[-2000:]}"
            )
        if not context.machine_running(second):
            raise E2EFailure("A console hangup stopped the container")
        if (_unit_dir(second) / "up-console").exists():
            raise E2EFailure("The up-console marker remains after the hangup")
        attach_returncode, attach_output = attach.finish()
        if attach_returncode != 0:
            raise E2EFailure(f"Attach exited {attach_returncode}: {attach_output}")
        assert_contains_text(attach_output, "no session is attached")
        _wait_stopped(context, second)

    with context.case("the last attach out does not wait long for the port lock"):
        # Regression test: the stop after the last session waited for the port
        # mapping lock with no limit under the lifecycle lock. While another
        # process held the port mapping lock (for example, rm --cache), each
        # attach, to any container, then failed after 10 s. Hold the port
        # mapping lock while the console of an attached up exits: the stop
        # must give up after 5 s and keep the container running, and an
        # attach to another container must work meanwhile.
        if not context.machine_running(name):
            raise E2EFailure(f"The other container {name} is not running")
        console = _Console(context, second)
        _wait_for_console(context, second)
        returncode, output = None, ""
        with PORT_LOCK.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            console.send("exit\n")
            # The stop decides under the lifecycle lock, and then waits for
            # the port mapping lock there.
            _wait_for(
                "the stop holds the lifecycle lock",
                lambda: holds_flock(console.process.pid, LIFECYCLE_LOCK),
            )
            attached = context.sandy(["exec", "--", "true"], name=name, expected=None)
            try:
                returncode, output = console.finish(timeout=LIFECYCLE_LOCK_WAIT)
            except subprocess.TimeoutExpired:
                raise E2EFailure(
                    "The stop waited for the port mapping lock with no limit"
                ) from None
        if attached.returncode != 0:
            raise E2EFailure(
                f"An attach to {name} failed during the stop: "
                f"{attached.output[-2000:]}"
            )
        if returncode != 0 or (
            f"W: Did not stop '{second}': the port mapping lock stayed busy"
            not in output
        ):
            raise E2EFailure(f"Console up exited {returncode}: {output[-2000:]}")
        if not context.machine_running(second):
            raise E2EFailure(
                "The stop with a busy port mapping lock stopped the container"
            )
        context.sandy(["down"], name=second)
        _wait_stopped(context, second)

    with context.case("an entry setup failure stops up with an error"):
        # The readiness probe cannot prepare the entry helper. The started
        # container must stop, and up must report the cause.
        refused = context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"],
            name=second,
            expected=1,
            executable=context.group_writable_sandy(),
        )
        assert_contains(refused, "E: Could not prepare the container entry")
        assert_not_contains(refused, "Traceback")
        _wait_stopped(context, second)

    with context.case("up applies --pids-limit, --tmp-size, and --oom-score-adj"):
        started = context.sandy(
            [
                "up",
                "--detach",
                "--persistent",
                "--network",
                "host",
                "--tmp-size",
                "16m",
                "--pids-limit",
                "512",
                "--oom-score-adj",
                "-500",
            ],
            name=second,
        )
        context.wait_for_machine(second, running=True)
        assert_contains(
            started,
            "I: Limits of this container: 512 tasks, /tmp 16.0 MiB, no swap, OOM "
            "score adjustment -500",
        )
        expected = {"TasksMax": "512", "MemorySwapMax": "0", "MemoryMax": "infinity"}
        actual = {prop: _show(context, second, prop) for prop in expected}
        if actual != expected:
            raise E2EFailure(f"Scope properties {actual!r} != {expected!r}")
        if (_unit_dir(second) / "pids.max").read_text(encoding="ascii") != "512\n":
            raise E2EFailure("The kernel process limit of the scope is not 512")
        if _tmp_size(context, second) != 16 * MIB:
            raise E2EFailure(f"/tmp has {_tmp_size(context, second)} bytes")
        # A full /tmp gives ENOSPC, below the shared memory.
        full = context.sandy(
            ["exec", "--", "dd if=/dev/zero of=/tmp/fill bs=1M count=32; rm /tmp/fill"],
            name=second,
            expected=None,
        )
        assert_contains(full, "No space left on device")
        # The container and each session have the value; nspawn's own
        # option fails with --private-users (measured).
        second_leader = int(context.machine_leader(second) or 0)
        for pid in (second_leader, _payload(second_leader)):
            if _oom_score_adj(pid) != -500:
                raise E2EFailure(
                    f"PID {pid} has OOM score adjustment {_oom_score_adj(pid)}"
                )
        for user in (context.cache_user, "root"):
            session = context.sandy(
                ["exec", "--", "cat /proc/self/oom_score_adj"], name=second, user=user
            )
            if session.stdout.strip() != "-500":
                raise E2EFailure(f"A session of {user} has {session.stdout!r}")
            # Even container root cannot go lower; any user can go higher.
            lower = context.sandy(
                ["exec", "--", "echo -600 > /proc/self/oom_score_adj"],
                name=second,
                user=user,
                expected=None,
            )
            if lower.returncode == 0:
                raise E2EFailure(
                    f"A session of {user} lowered its OOM score adjustment"
                )
            context.sandy(
                ["exec", "--", "echo -400 > /proc/self/oom_score_adj"],
                name=second,
                user=user,
            )

    with context.case("an OOM at the shared memory ends the unprotected process"):
        # Two containers: this one with the default value, and the second with
        # -500. A test-only shared memory leaves 256 MiB above the use now.
        current = int((CGROUP_SLICE / "memory.current").read_text(encoding="ascii"))
        limit = (current // MIB + 256) * MIB
        context.sandy(["update", "--shared", "-m", f"{limit // MIB}m"])
        try:
            holder = _Attach(
                context,
                second,
                "python3 -c 'b = bytearray(150 << 20); import time; time.sleep(120)'",
            )
            holder.leaf()

            def holding() -> bool:
                used = (_unit_dir(second) / "memory.current").read_text(
                    encoding="ascii"
                )
                return int(used) >= 150 * MIB

            _wait_for("the protected container holds its memory", holding)
            # More than the whole limit, so that page cache reclaim cannot
            # make room.
            hog = context.sandy(
                ["exec", "--", f"python3 -c 'b = bytearray({limit + 64 * MIB})'"],
                name=name,
                expected=None,
            )
            if hog.returncode == 0:
                raise E2EFailure("The memory hog was not killed")
            assert_contains(hog, f"W: The kernel ended 1 process in '{name}'")
            assert_contains(
                hog, "The Sandy containers reached the memory limit that they share"
            )
            assert_not_contains(hog, "of its own")
            if holder.process.poll() is not None:
                raise E2EFailure("The OOM ended the protected container's process")
            for container in (name, second):
                if not context.machine_running(container):
                    raise E2EFailure(f"The OOM stopped {container}")
            if _payload(leader) != payload:
                raise E2EFailure("The OOM stopped the keepalive")
            holder.process.send_signal(signal.SIGTERM)
            holder.finish()
            # The second kill of this container; the first was at its own
            # test-only limit.
            kills, shared_ooms, now_own = _oom_status(context, name)
            if (kills, now_own) != (2, own_ooms) or shared_ooms < 1:
                raise E2EFailure(f"OOM counts {(kills, shared_ooms, now_own)!r}")
        finally:
            context.sandy(["update", "--shared", "--reset"])
        _check_group_limits(context, name)
        context.sandy(["down"], name=second)
        _wait_stopped(context, second)

    with context.case("-1 and 0: no process limit of its own and the tmpfs default"):
        context.sandy(
            [
                "up",
                "--detach",
                "--persistent",
                "--network",
                "host",
                "--tmp-size",
                "0",
                "--pids-limit",
                "-1",
            ],
            name=second,
        )
        context.wait_for_machine(second, running=True)
        if _show(context, second, "TasksMax") != "infinity":
            raise E2EFailure("--pids-limit -1 kept a process limit")
        # The tmpfs default: half of the pages of the host memory.
        half = os.sysconf("SC_PHYS_PAGES") // 2 * os.sysconf("SC_PAGE_SIZE")
        if _tmp_size(context, second) != half:
            raise E2EFailure(f"/tmp has {_tmp_size(context, second)} bytes, not {half}")
        context.sandy(["down"], name=second)
        _wait_stopped(context, second)

    with context.case("invalid limits and a malformed saved file stop up"):
        for arguments in (
            ["--pids-limit", "0"],
            ["--tmp-size", "1k"],
            ["--oom-score-adj", "-1000"],
            # A container has no CPU, memory, or swap option of its own.
            ["--cpus", "2"],
            ["-m", "1g"],
        ):
            refused = context.sandy(
                ["up", "--detach", "--network", "host", *arguments],
                name=second,
                expected=2,
            )
            assert_not_contains(refused, "Traceback")
        before = tuple(
            _slice_show(context, prop) for prop in ("AllowedCPUs", "MemoryMax")
        )
        SHARED_LIMITS.write_text('{"memory":"8g"}\n', encoding="ascii")
        SHARED_LIMITS.chmod(0o600)
        refused = context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"],
            name=second,
            expected=1,
        )
        assert_contains(
            refused,
            "E: The saved shared memory is invalid. Reset them with: sandy update "
            "--shared --reset",
        )
        after = tuple(
            _slice_show(context, prop) for prop in ("AllowedCPUs", "MemoryMax")
        )
        if after != before:
            raise E2EFailure(f"A malformed saved file changed {SLICE}: {after!r}")
        if context.machine_running(second):
            raise E2EFailure("up started the container anyway")
        if _show(context, second, "LoadState") != "not-found":
            raise E2EFailure("up created the scope anyway")
        context.sandy(["update", "--shared", "--reset"])
        if SHARED_LIMITS.read_text(encoding="ascii") != "{}\n":
            raise E2EFailure("--reset did not replace the malformed file")

    with context.case("update changes the process limit of a running container"):
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"], name=second
        )
        context.wait_for_machine(second, running=True)
        updated = context.sandy(["update", "--pids-limit", "256"], name=second)
        assert_contains(updated, f"I: Updated '{second}': TasksMax=256")
        if (_unit_dir(second) / "pids.max").read_text(encoding="ascii") != "256\n":
            raise E2EFailure("update did not change the kernel process limit")
        context.sandy(["update", "--pids-limit", "-1"], name=second)
        if (_unit_dir(second) / "pids.max").read_text(encoding="ascii") != "max\n":
            raise E2EFailure("update --pids-limit -1 kept a process limit")
        none = context.sandy(["update"], name=second, expected=1)
        assert_contains(none, "update needs --pids-limit")
        context.sandy(["down"], name=second)
        _wait_stopped(context, second)
        # The change ends with the scope: update of a stopped container fails
        # and leaves no drop-in, and the next up has the defaults.
        stopped = context.sandy(
            ["update", "--pids-limit", "5"], name=second, expected=1
        )
        assert_contains(stopped, "not found or not running")
        for directory in ("/run/systemd/system.control", "/run/systemd/transient"):
            if Path(directory, f"{_unit(second)}.d").exists():
                raise E2EFailure(f"A drop-in of {_unit(second)} remains in {directory}")
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"], name=second
        )
        context.wait_for_machine(second, running=True)
        actual = {prop: _show(context, second, prop) for prop in _default_limits()}
        if actual != _default_limits():
            raise E2EFailure(f"Scope properties after update {actual!r}")
        context.sandy(["down"], name=second)
        _wait_stopped(context, second)

    with context.case("up -d is never stopped by an attach exit"):
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"], name=second
        )
        context.wait_for_machine(second, running=True)
        context.sandy(["exec", "--", "true"], name=second)
        context.sandy(["bash", "-c", "true"], name=second)
        if not context.machine_running(second):
            raise E2EFailure("An attach exit stopped a detached container")
        context.remove_container(second, context.cache_user)
        if _show(context, second, "LoadState") != "not-found":
            raise E2EFailure("The scope remains after rm")

    with context.case("an up that the check under the lock refuses publishes no port"):
        # The refused up must also leave no port rule and no port state. It
        # had published its ports before it waited for the lock, so they
        # forwarded to the container of the other start until it stopped. The
        # main container has a lenient network and the address in /init.sh.
        context.stop_container(name, context.main_user)
        _wait_stopped(context, name)
        port = f"tcp:{REFUSED_UP_PORT}:80"
        with _up_while_its_scope_appears(
            context,
            name,
            context.main_user,
            ["up", "--detach", "--persistent", "--network", "lenient", "--port", port],
        ) as (returncode, output):
            if returncode != 1:
                raise E2EFailure(f"up exited {returncode}: {output[-2000:]}")
            assert_contains_text(output, f"Unit '{_unit(name)}' already exists")
            rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
            assert_not_contains(rules, f"--dport {REFUSED_UP_PORT}")
            key = f"tcp:{REFUSED_UP_PORT}"
            if PORT_STATE.exists() and key in context.port_state():
                raise E2EFailure("The refused up left its port state")
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=context.main_user,
        )
        context.wait_for_machine(name, running=True)

    with context.case("an up waits for a busy port mapping lock for a short time"):
        # up publishes its ports under the lifecycle lock, which each attach
        # waits for. Hold the port mapping lock from the time that up waits
        # for the lifecycle lock: up must then fail before the start, with no
        # port rule and no port state, and free the lifecycle lock in time.
        context.stop_container(name, context.main_user)
        _wait_stopped(context, name)
        port = f"tcp:{BUSY_LOCK_UP_PORT}:80"
        with ExitStack() as held:
            taken: list[float] = []

            def hold_the_port_lock() -> None:
                lock = held.enter_context(PORT_LOCK.open("rb"))
                fcntl.flock(lock, fcntl.LOCK_EX)
                taken.append(time.monotonic())

            refused = context.up_with_a_change_while_it_waits(
                name,
                context.main_user,
                [
                    "up",
                    "--detach",
                    "--persistent",
                    "--network",
                    "lenient",
                    "--port",
                    port,
                ],
                hold_the_port_lock,
            )
            # The lifecycle lock is free now: up exited.
            waited = time.monotonic() - taken[0]
        if refused.returncode != 1:
            raise E2EFailure(
                f"up exited {refused.returncode}: {refused.output[-2000:]}"
            )
        assert_contains(
            refused,
            f"E: Could not publish the ports of '{name}': Timed out waiting for "
            "the Sandy port mapping lock",
        )
        assert_not_contains(refused, "Starting")
        if not PORT_LOCK_WAIT <= waited < LIFECYCLE_LOCK_WAIT:
            raise E2EFailure(f"up held the lifecycle lock for {waited:.1f} seconds")
        rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
        assert_not_contains(rules, f"--dport {BUSY_LOCK_UP_PORT}")
        if PORT_STATE.exists() and f"tcp:{BUSY_LOCK_UP_PORT}" in context.port_state():
            raise E2EFailure("The up with a busy lock left its port state")
        if context.machine_running(name):
            raise E2EFailure("The up with a busy lock started the container")
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=context.main_user,
        )
        context.wait_for_machine(name, running=True)

    with context.case("a Ctrl-C while up waits for the port mapping lock stops up"):
        # Regression test: up removed its ports on each exit after it began
        # the publish, also on a Ctrl-C in the wait for the port mapping lock.
        # That removal waited for the busy lock again, so the first Ctrl-C did
        # not stop up. Hold the port mapping lock, and send SIGINT to an up
        # that waits for it to publish its ports: up must exit at once, with
        # no port rule and no port state. Without directories to mount (they
        # do not exist), up waits in flock(2) with no limit; with them, it
        # polls under the lifecycle lock.
        context.stop_container(name, context.main_user)
        _wait_stopped(context, name)
        arguments = [
            "up",
            "--detach",
            "--persistent",
            "--network",
            "lenient",
            "--port",
            f"tcp:{INTERRUPTED_UP_PORT}:80",
        ]
        for label, directory in (("no-mounts", "no-such-directory"), ("mounts", None)):
            with PORT_LOCK.open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                up, log_path = context.start_up(
                    name,
                    context.main_user,
                    arguments,
                    f"interrupted-{label}",
                    workspace=directory,
                    shared=directory,
                )
                try:
                    _wait_for_the_publish_wait(
                        up, lock, log_path, blocking=directory is not None
                    )
                    up.send_signal(signal.SIGINT)
                    try:
                        up.wait(timeout=INTERRUPTED_UP_EXIT)
                    except subprocess.TimeoutExpired:
                        raise E2EFailure(
                            f"up ({label}) did not stop at the first Ctrl-C"
                        ) from None
                finally:
                    if up.poll() is None:
                        up.kill()
                        up.wait(timeout=10)
            output = log_path.read_text(encoding="utf-8", errors="replace")
            if up.returncode == 0 or "Starting" in output:
                raise E2EFailure(
                    f"up ({label}) exited {up.returncode}: {output[-2000:]}"
                )
            rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
            assert_not_contains(rules, f"--dport {INTERRUPTED_UP_PORT}")
            key = f"tcp:{INTERRUPTED_UP_PORT}"
            if PORT_STATE.exists() and key in context.port_state():
                raise E2EFailure(f"up ({label}) left its port state")
            if context.machine_running(name):
                raise E2EFailure(f"up ({label}) started the container")
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=context.main_user,
        )
        context.wait_for_machine(name, running=True)

    with context.case("no other process finds the ports of a start that failed"):
        # Regression test: up released the port mapping lock after the publish
        # of its ports, and then its start failed. A process that took the
        # lock before the removal found the ports of that start, so an up of
        # another name could refuse its own start ("already allocated"). Read
        # the port state under the lock in a loop, as each up reads it, while
        # an up publishes its ports and its supervisor does not start: no read
        # may find those ports.
        context.stop_container(name, context.main_user)
        _wait_stopped(context, name)
        key = f"tcp:{FAILED_START_PORT}"
        command = context.with_a_broken_systemd_run(
            [
                str(SANDY),
                "--workspace",
                context.workspace.name,
                "--shared",
                context.shared.name,
                "--user",
                context.main_user,
                "--container",
                name,
                "up",
                "--detach",
                "--persistent",
                "--network",
                "lenient",
                "--port",
                f"{key}:80",
            ]
        )
        with _PortStateReader(key) as reader:
            failed = context.run(command, expected=1)
        if reader.errors:
            raise E2EFailure(f"The port state reader failed: {reader.errors[0]!r}")
        # The ports were published: "Starting" comes after the publish.
        assert_contains(failed, f"I: Starting '{name}'")
        assert_contains(failed, f"E: Could not start '{name}': ")
        if reader.reads == 0 or reader.found:
            raise E2EFailure(
                f"{reader.found} of {reader.reads} reads found the ports of the "
                "start that failed"
            )
        rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
        assert_not_contains(rules, f"--dport {FAILED_START_PORT}")
        if PORT_STATE.exists() and key in context.port_state():
            raise E2EFailure("The start that failed left its port state")
        if context.machine_running(name):
            raise E2EFailure("The start that failed started the container")
        context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=context.main_user,
        )
        context.wait_for_machine(name, running=True)

    with context.case("update --shared works before the first container"):
        context.stop_container(name, context.main_user)
        _wait_stopped(context, name)
        # Test-only: the harness owns sandy.slice; return it to no state.
        context.remove_shared_slice()
        update = context.sandy(
            ["update", "--shared", "-m", "512m", "--pids-limit", "4096"]
        )
        assert_contains(update, "memory 512.0 MiB (saved), 4096 tasks (saved)")
        changed = (_group_defaults()[0], 512 * MIB, 4096)
        _check_group_limits(context, None, changed)
        if _slice_show(context, "ActiveState") != "inactive":
            raise E2EFailure(f"update --shared started {SLICE}")
        # The next up starts the slice with the saved limits; a container
        # gets half of a small shared process limit.
        started = context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=context.main_user,
        )
        context.wait_for_machine(name, running=True)
        assert_contains(started, "memory 512.0 MiB (saved), 4096 tasks (saved)")
        assert_contains(started, "I: Limits of this container: 2048 tasks")
        _check_group_limits(context, name, changed)
        context.sandy(["update", "--shared", "--reset"])
        _check_group_limits(context, name)
        # A container keeps the process limit that up gave it.
        if _show(context, name, "TasksMax") != "2048":
            raise E2EFailure("--reset changed the process limit of a container")


def assert_contains_text(text: str, expected: str) -> None:
    if expected not in text:
        raise E2EFailure(f"Expected {expected!r} in output:\n{text[-2000:]}")
