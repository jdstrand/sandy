"""The container's own systemd scope, the keepalive payload, and attaches.

These properties need systemd, the kernel's cgroup v2, and real sandy
processes, so unit mocks cannot prove them.
"""

from __future__ import annotations

import errno
import os
import re
import signal
import subprocess
import time
from pathlib import Path

from tests.e2e.support import (
    SANDY,
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
)

CGROUP_SLICE = Path("/sys/fs/cgroup/system.slice")
ATTACH_LEAF = re.compile(r"attach-[0-9a-f]{32}")
DEFAULT_TASKS_MAX = "16384"
KEEPALIVE_COMM = "sandy-keepalive"
WAIT_TIMEOUT = 30


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
            rf"0::/system\.slice/{re.escape(_unit(self.name))}/(attach-[0-9a-f]{{32}})"
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
        environment = context.safe_environment()
        environment["SUDO_UID"] = "1000"
        with self.output.open("w", encoding="utf-8") as stream:
            self.process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=stream,
                stderr=subprocess.STDOUT,
                cwd=context.root,
                env=environment,
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


def test_main(context: E2EContext) -> None:
    """Prove the scope, keepalive, attach, and lifecycle design."""
    name = context.main_name
    version = _systemd_version(context)
    leader_text = context.machine_leader(name)
    if leader_text is None:
        raise E2EFailure("The main container is not running")
    leader = int(leader_text)

    with context.case("the container runs in its own scope with today's limits"):
        expected = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "ControlGroup": f"/system.slice/{_unit(name)}",
            "Description": f"Sandy container {name} (detached)",
            "Delegate": "yes",
            "TasksMax": DEFAULT_TASKS_MAX,
            "MemoryMax": "infinity",
            "MemorySwapMax": "infinity",
            "CPUQuotaPerSecUSec": "infinity",
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
        if not _cgroup(leader).startswith(f"0::/system.slice/{_unit(name)}/payload"):
            raise E2EFailure(f"Leader cgroup {_cgroup(leader)!r}")

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

    with context.case("an OOM in an attach kills only that process"):
        # A test-only limit; sandy sets none by default.
        context.run(
            [
                "systemctl",
                "set-property",
                "--runtime",
                _unit(name),
                "MemoryMax=256M",
                "MemorySwapMax=0",
            ]
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
            if _show(context, name, "ActiveState") != "active":
                raise E2EFailure("The OOM stopped the scope")
            if _payload(leader) != payload or not context.machine_running(name):
                raise E2EFailure("The OOM stopped the keepalive")
            if idle.process.poll() is not None:
                raise E2EFailure("The OOM ended another attach")
            idle.process.send_signal(signal.SIGTERM)
            idle.finish()
        finally:
            context.run(
                [
                    "systemctl",
                    "set-property",
                    "--runtime",
                    _unit(name),
                    "MemoryMax=infinity",
                    "MemorySwapMax=infinity",
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


def assert_contains_text(text: str, expected: str) -> None:
    if expected not in text:
        raise E2EFailure(f"Expected {expected!r} in output:\n{text[-2000:]}")
