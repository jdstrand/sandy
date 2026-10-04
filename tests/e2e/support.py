#!/usr/bin/env python3

"""Shared helpers for sandy's privileged end-to-end tests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
SANDY = REPO_ROOT / "sandy"
# sandy and the helper scripts that it requires next to itself.
SANDY_SCRIPT_NAMES = (
    "sandy",
    "debootstrap.sh",
    "oci.sh",
    "sandy-keepalive.sh",
    "setup-container.sh",
)
MINIMAL_SETUP = Path(__file__).with_name("setup-container-minimal.sh")
INSTALL_DIR = Path("/usr/local/lib/sandy")
SYSTEMD_MACHINES = Path("/var/lib/machines")
CACHE_DIR = SYSTEMD_MACHINES / "sandy.__cache"
PORT_STATE = CACHE_DIR / "port_mappings.json"
PORT_LOCK = CACHE_DIR / "port_mappings.lock"
LIFECYCLE_LOCK = CACHE_DIR / "lifecycle.lock"
SHARED_LIMITS = CACHE_DIR / "shared_limits.json"
SHARED_LIMITS_LOCK = CACHE_DIR / "shared_limits.lock"
ADDRESSES_LOCK = CACHE_DIR / "addresses.lock"
# Product code never removes these stable lock inodes.
PERSISTENT_LOCKS = (PORT_LOCK, LIFECYCLE_LOCK, SHARED_LIMITS_LOCK, ADDRESSES_LOCK)
# Nor the saved shared limits, which are configuration (rm --cache keeps them).
PERSISTENT_FILES = (*PERSISTENT_LOCKS, SHARED_LIMITS)
# up waits for the lifecycle lock for at most 10 seconds (LIFECYCLE_LOCK_TIMEOUT
# of sandy); it gets to the lock in a few.
LIFECYCLE_WAIT_TIMEOUT = 60
BACKGROUND_UP_TIMEOUT = 120
# The up lock of a container name (_acquire_up_lock of sandy). Sandy never
# removes one either.
UP_LOCK_PATTERN = re.compile(r"up-[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.lock")
# All Sandy containers run in this slice, which holds their shared limits.
SLICE = "sandy.slice"
SLICE_CGROUP = Path("/sys/fs/cgroup") / SLICE
SLICE_STATE_PROPERTIES = ("ActiveState", "FragmentPath", "DropInPaths")
BRIDGE_NAME = "sandybr0"
NAME_PATTERN = re.compile(r"^e2e-[a-z0-9-]{1,48}$")
DEFAULT_TIMEOUT = 120
BUILD_TIMEOUT = 1800
FULL_BUILD_TIMEOUT = 7200
OUTPUT_TAIL_LENGTH = 12000
# The workspace and shared directories belong to a host user whose ids are not
# the ids of the container user: Sandy maps the owner and the group of each
# directory to the image user (see README.md, "Workspace and shared
# directories"). These ids are the owner and the group, and the ids of the host
# user. Without SANDY_E2E_HOST_UID, they differ from each other and from the
# container user of the default image (1000:1000) and of the Ubuntu 26.04
# image (1001:1001; uid 1000 is `ubuntu`). So a map that swaps the uid and the
# gid, or that keeps a host id, fails the mount cases. SANDY_E2E_HOST_UID sets
# the uid and the gid to one value.
HOST_UID_VARIABLE = "SANDY_E2E_HOST_UID"
DEFAULT_HOST_UID = 1234
DEFAULT_HOST_GID = 2345
HOST_UID_MAX = 60000
HOST_UID_PATTERN = re.compile(r"[1-9][0-9]{0,4}")
# SANDY_E2E_BASE_IMAGE selects the base image of every build (Sandy reads it as
# SANDY_BOOTSTRAP_BASE), such as ubuntu:26.04. Unset: Sandy's default image.
# Sandy accepts only ^[a-z][a-z0-9._:-]{0,127}$ (_validate_image_name), and it
# checks the value only when a later case runs it. So the runner accepts only
# NAME:TAG values that Sandy accepts too: lowercase, no '/', a letter first, and
# at most 128 characters.
BASE_IMAGE_VARIABLE = "SANDY_E2E_BASE_IMAGE"
BASE_IMAGE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,62}:[a-z0-9][a-z0-9._-]{0,63}")
# Scratch file systems that a case mounts on a directory of its run root.
SCRATCH_FILESYSTEMS = ("ramfs", "tmpfs")
MOUNTINFO = Path("/proc/self/mountinfo")
# up makes a private directory for each of its two binds, in /tmp, and removes
# it when it ends. One remains when a case kills an up that runs in the
# background. sandy gets no TMPDIR from the E2E environment.
UP_TEMPORARY_ROOT = Path("/tmp")
UP_TEMPORARY_PATTERNS = ("sandy-keepalive-*", "sandy-init-*")
MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")
HOST_SECRET_NAME = "SANDY_HOST_SECRET"
HOST_SECRET_VALUE = "must-not-enter-container"
DIRECTORY_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PATH_OPEN_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
IPTABLES_CHAINS = (
    ("filter", "sandy-fwd"),
    ("filter", "sandy-out"),
    ("filter", "sandy-rej"),
    ("nat", "sandy-nat-out"),
    ("nat", "sandy-nat-post"),
    ("nat", "sandy-nat-pre"),
)
IP6TABLES_CHAINS = (
    ("filter", "sandy-fwd6"),
    ("filter", "sandy-rej6"),
)
# Sandy uses nftables only when iptables is missing. To test that backend, run
# sandy in a private mount namespace where an empty, non-executable file is
# bound over the iptables binary. The host stays unchanged. The script is
# static; the paths and the sandy command are positional arguments.
HIDE_IPTABLES_SCRIPT = 'mount --bind -- "$1" "$2" && shift 2 && exec "$@"'
IPTABLES_BINARY_DIRS = (Path("/usr/sbin"), Path("/sbin"))
# To make the start of the supervisor fail, the same script binds a file that
# has mode 0755 but is not an executable over systemd-run. sandy finds the
# tool, and the exec of the supervisor fails with ENOEXEC.
SYSTEMD_RUN_BINARY_DIRS = (Path("/usr/bin"), Path("/bin"))
# To make a machine query fail with an error that does not mean "no such
# machine", the same script binds an empty file over the socket of the system
# bus. machinectl then exits 1 with "Connection refused" (measured on systemd
# 249 and 257). Other processes keep the bus.
SYSTEM_BUS_SOCKET = Path("/run/dbus/system_bus_socket")
# To make a stop fail, a second script binds the real machinectl at a side
# path and a stand-in over machinectl, in a private mount namespace. The
# stand-in does nothing for poweroff and terminate, and runs the real binary
# at the side path for each other command. The path is in the stand-in, not
# in the environment: the entry helper of sandy runs with the environment of
# the container session. Measured on systemd 249 and 257.
MACHINECTL_BINARY_DIRS = (Path("/usr/bin"), Path("/bin"))
STAND_IN_MACHINECTL_SCRIPT = (
    'mount --bind -- "$1" "$2" && mount --bind -- "$3" "$1" && shift 3 && exec "$@"'
)
STAND_IN_MACHINECTL = """#!/bin/sh
# E2E stand-in: poweroff and terminate do nothing. Each other command runs
# the real machinectl, which the harness binds at the path below.
case "$1" in
poweroff | terminate) exit 0 ;;
esac
exec {real} "$@"
"""
# The locks of the host, with the processes that wait for them.
PROC_LOCKS = Path("/proc/locks")
NFTABLES_TABLES = (
    ("ip", "sandy"),
    ("ip6", "sandy"),
)


class E2EFailure(RuntimeError):
    """Raised when an end-to-end assertion fails."""


@dataclass(frozen=True)
class FilesystemFixtureIdentity:
    """Identity of a root-owned E2E filesystem fixture claimed by this run."""

    dev: int
    ino: int
    file_type: int


@dataclass(frozen=True)
class CommandResult:
    """Captured result from one external command."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return f"{self.stdout}{self.stderr}"


def _bounded_tail(value: object) -> str:
    text = str(value or "")
    return text[-OUTPUT_TAIL_LENGTH:]


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(command)
    if not normalized or not all(isinstance(arg, str) and arg for arg in normalized):
        raise E2EFailure("Refusing to execute an invalid command")
    return normalized


def assert_contains(result: CommandResult, expected: str) -> None:
    """Assert that captured command output contains a fixed string."""
    if expected not in result.output:
        raise E2EFailure(
            f"Expected {expected!r} in output from {shlex.join(result.command)}:\n"
            f"{_bounded_tail(result.output)}"
        )


def assert_not_contains(result: CommandResult, unexpected: str) -> None:
    """Assert that captured command output omits a fixed string."""
    if unexpected in result.output:
        raise E2EFailure(
            f"Did not expect {unexpected!r} in output from "
            f"{shlex.join(result.command)}:\n{_bounded_tail(result.output)}"
        )


def waits_for_flock(pid: int, path: Path) -> bool:
    """Return True when process pid waits in flock(2) for the lock of path.

    /proc/locks shows each waiter after the lock that blocks it, as
    "N: -> FLOCK  ADVISORY  WRITE <pid> <major>:<minor>:<inode> 0 EOF".
    """
    inode = str(path.stat().st_ino)
    for line in PROC_LOCKS.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if (
            len(fields) >= 7
            and fields[1:3] == ["->", "FLOCK"]
            and fields[5] == str(pid)
            and fields[6].rsplit(":", 1)[-1] == inode
        ):
            return True
    return False


def holds_flock(pid: int, path: Path) -> bool:
    """Return True when process pid holds a flock(2) lock of path.

    /proc/locks shows a held lock as
    "N: FLOCK  ADVISORY  WRITE <pid> <major>:<minor>:<inode> 0 EOF".
    """
    inode = str(path.stat().st_ino)
    for line in PROC_LOCKS.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if (
            len(fields) >= 6
            and fields[1] == "FLOCK"
            and fields[4] == str(pid)
            and fields[5].rsplit(":", 1)[-1] == inode
        ):
            return True
    return False


def up_temporary_directories() -> list[Path]:
    """Return the directories that up made for its binds, sorted."""
    return sorted(
        path
        for pattern in UP_TEMPORARY_PATTERNS
        for path in UP_TEMPORARY_ROOT.glob(pattern)
    )


def parse_mountinfo(text: str) -> list[tuple[str, frozenset[str]]]:
    """Return the mount point and the mount options of each mountinfo line.

    The kernel writes a space, a tab, a newline, and a backslash in a mount
    point as an octal escape, such as \\040. A line that is too short is skipped.
    """
    mounts = []
    for line in text.replace("\r", "").splitlines():
        fields = line.split(" ")
        if len(fields) < 6:
            continue
        mount_point = MOUNTINFO_ESCAPE.sub(
            lambda match: chr(int(match[1], 8)), fields[4]
        )
        mounts.append((mount_point, frozenset(fields[5].split(","))))
    return mounts


def parse_host_ids(value: str | None) -> tuple[int, int]:
    """Return the uid and the gid of the host user from SANDY_E2E_HOST_UID.

    A value is the uid and the gid. Only decimal digits without a leading zero
    are valid, from 1 to HOST_UID_MAX. Unset gives DEFAULT_HOST_UID and
    DEFAULT_HOST_GID.
    """
    if value is None:
        return DEFAULT_HOST_UID, DEFAULT_HOST_GID
    if not HOST_UID_PATTERN.fullmatch(value) or int(value) > HOST_UID_MAX:
        raise E2EFailure(
            f"Invalid {HOST_UID_VARIABLE} {value!r}: use a number from 1 to "
            f"{HOST_UID_MAX}"
        )
    return int(value), int(value)


def parse_base_image(value: str | None) -> str | None:
    """Return the base image from SANDY_E2E_BASE_IMAGE; None when unset."""
    if value is None:
        return None
    if not BASE_IMAGE_PATTERN.fullmatch(value):
        raise E2EFailure(
            f"Invalid {BASE_IMAGE_VARIABLE} {value!r}: use a lowercase NAME:TAG "
            "without '/', such as ubuntu:26.04"
        )
    return value


class E2EContext:
    """Own all mutable state created by one end-to-end run."""

    def __init__(self) -> None:
        suffix = secrets.token_hex(3)
        self.cache_name = f"e2e-cache-{suffix}"
        self.cache_miss_name = f"e2e-cache-miss-{suffix}"
        self.filesystem_name = f"e2e-filesystem-{suffix}"
        self.main_name = f"e2e-main-{suffix}"
        self.full_name = f"e2e-full-{suffix}"
        self.scope_name = f"e2e-scope-{suffix}"
        self.other_name = f"e2e-other-{suffix}"
        self.mounts_name = f"e2e-mounts-{suffix}"
        self.nft_name = f"e2e-nft-{suffix}"
        self.nft_other_name = f"e2e-nft-other-{suffix}"
        self.scan_name = f"e2e-scan-{suffix}"
        self.cache_user = "developer"
        self.cache_miss_user = "e2emiss"
        self.main_user = "developer"
        self.full_user = "developer"
        self._validate_names()
        # Validate the environment before anything is created.
        self.host_uid, self.host_gid = parse_host_ids(os.environ.get(HOST_UID_VARIABLE))
        self.base_image = parse_base_image(os.environ.get(BASE_IMAGE_VARIABLE))

        self.root = Path(tempfile.mkdtemp(prefix="sandy-e2e-", dir="/tmp"))
        os.chmod(self.root, 0o755)
        self.workspace = self.root / "workspace"
        self.shared = self.root / "shared"
        self.workspace.mkdir(mode=0o755)
        self.shared.mkdir(mode=0o755)
        for mount_path in (self.workspace, self.shared):
            os.chown(mount_path, self.host_uid, self.host_gid)

        self.filesystem_image_root = Path("/var/lib") / f"sandy-e2e-image-{suffix}"
        self.filesystem_host_target = Path("/var/lib") / f"sandy-e2e-host-{suffix}"
        self.filesystem_machine_link = (
            SYSTEMD_MACHINES / f"sandy.{self.filesystem_name}"
        )
        self.owned_containers: dict[str, str] = {}
        self.fixture_processes: list[subprocess.Popen[str]] = []
        self.full_build_started = False
        self.passed = 0
        self._ip_forward_original: str | None = None
        self._host_state_owned = False
        self._install_dir_owned = False
        self._filesystem_fixtures_reserved = False
        self._filesystem_fixtures_owned = False
        self._filesystem_fixture_identities: dict[
            Path,
            FilesystemFixtureIdentity,
        ] = {}
        self._filesystem_mounts: list[Path] = []
        self._scratch_mounts: list[Path] = []
        # When True, every sandy call runs without a visible iptables.
        self.hide_iptables = False

    def _validate_names(self) -> None:
        for name in (
            self.cache_name,
            self.cache_miss_name,
            self.filesystem_name,
            self.main_name,
            self.full_name,
            self.scope_name,
            self.other_name,
            self.mounts_name,
            self.nft_name,
            self.nft_other_name,
            self.scan_name,
        ):
            if not NAME_PATTERN.fullmatch(name):
                raise E2EFailure(f"Generated unsafe container name: {name!r}")

    def safe_environment(
        self, overrides: Mapping[str, str] | None = None
    ) -> dict[str, str]:
        """Return a small allow-listed environment without host credentials."""
        environment = {
            "HOME": "/root",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SYSTEMD_COLORS": "0",
            "TERM": "xterm-256color",
        }
        if self.base_image is not None:
            environment["SANDY_BOOTSTRAP_BASE"] = self.base_image
        if overrides:
            for key, value in overrides.items():
                if not re.fullmatch(r"SANDY_[A-Z_]{1,48}", key):
                    raise E2EFailure(f"Refusing unsafe environment key: {key!r}")
                if not isinstance(value, str) or not value or "\x00" in value:
                    raise E2EFailure(f"Refusing unsafe environment value for {key}")
                environment[key] = value
        return environment

    def run(
        self,
        command: Sequence[str],
        *,
        expected: int | None = 0,
        timeout: int = DEFAULT_TIMEOUT,
        environment: Mapping[str, str] | None = None,
        input_text: str | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        """Run one command without a shell and capture bounded diagnostics."""
        normalized = _validate_command(command)
        print(f"    $ {shlex.join(normalized)}", flush=True)
        try:
            completed = subprocess.run(
                normalized,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                cwd=str(cwd or self.root),
                env=dict(environment or self.safe_environment()),
                input=input_text,
            )
        except subprocess.TimeoutExpired as exc:
            raise E2EFailure(
                f"Command timed out after {timeout}s: {shlex.join(normalized)}\n"
                f"{_bounded_tail(exc.stdout)}{_bounded_tail(exc.stderr)}"
            ) from exc

        result = CommandResult(
            command=normalized,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if expected is not None and result.returncode != expected:
            raise E2EFailure(
                f"Expected exit {expected}, got {result.returncode}: "
                f"{shlex.join(normalized)}\n{_bounded_tail(result.output)}"
            )
        return result

    def sandy(
        self,
        arguments: Sequence[str],
        *,
        name: str | None = None,
        user: str = "developer",
        expected: int | None = 0,
        timeout: int = DEFAULT_TIMEOUT,
        environment: Mapping[str, str] | None = None,
        input_text: str | None = None,
        executable: Path | None = None,
        workspace: str | None = None,
        shared: str | None = None,
    ) -> CommandResult:
        """Invoke sandy with the E2E workspace and optional owned container.

        executable selects another copy of sandy, such as the one from
        group_writable_sandy(). workspace and shared name other directories,
        relative to the run root where sandy runs.
        """
        command = [
            str(executable or SANDY),
            "--workspace",
            workspace or self.workspace.name,
            "--shared",
            shared or self.shared.name,
            "--user",
            user,
        ]
        if name is not None:
            if not NAME_PATTERN.fullmatch(name):
                raise E2EFailure(f"Refusing unsafe container name: {name!r}")
            command.extend(["--container", name])
        command.extend(arguments)
        if self.hide_iptables:
            command = self.without_iptables(command)
        return self.run(
            command,
            expected=expected,
            timeout=timeout,
            environment=environment,
            input_text=input_text,
        )

    def group_writable_sandy(self) -> Path:
        """Return a copy of sandy that its group can write, with its scripts.

        The copy is in this run's root directory, which cleanup removes. The
        checkout does not change.
        """
        directory = self.root / "sandy-group-writable"
        directory.mkdir(mode=0o755, exist_ok=True)
        for name in SANDY_SCRIPT_NAMES:
            shutil.copy2(REPO_ROOT / name, directory / name)
        copy = directory / "sandy"
        copy.chmod(0o775)
        return copy

    def without_iptables(self, command: Sequence[str]) -> list[str]:
        """Return command wrapped so that it sees no iptables binary."""
        located = shutil.which("iptables", path=self.safe_environment()["PATH"])
        if located is None:
            raise E2EFailure("iptables is not installed")
        target = Path(located).resolve()
        if target.parent not in IPTABLES_BINARY_DIRS or not target.is_file():
            raise E2EFailure(f"Unexpected iptables binary: {target}")
        blocker = self.root / "no-iptables"
        if not blocker.exists():
            blocker.write_bytes(b"")
            blocker.chmod(0o644)
        return [
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "--",
            "/bin/sh",
            "-c",
            HIDE_IPTABLES_SCRIPT,
            "sh",
            str(blocker),
            str(target),
            *command,
        ]

    def with_a_hidden_system_bus(self, command: Sequence[str]) -> list[str]:
        """Return command wrapped so that it cannot connect to the system bus."""
        try:
            socket_mode = SYSTEM_BUS_SOCKET.lstat().st_mode
        except FileNotFoundError:
            raise E2EFailure(f"No system bus socket at {SYSTEM_BUS_SOCKET}")
        if not stat.S_ISSOCK(socket_mode):
            raise E2EFailure(f"Unexpected system bus socket: {SYSTEM_BUS_SOCKET}")
        blocker = self.root / "hidden-system-bus"
        if not blocker.exists():
            blocker.write_bytes(b"")
            blocker.chmod(0o644)
        return [
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "--",
            "/bin/sh",
            "-c",
            HIDE_IPTABLES_SCRIPT,
            "sh",
            str(blocker),
            str(SYSTEM_BUS_SOCKET),
            *command,
        ]

    def with_a_machinectl_that_stops_nothing(
        self, command: Sequence[str]
    ) -> tuple[list[str], dict[str, str]]:
        """Return command wrapped so that machinectl poweroff and terminate do
        nothing, and the environment that the stand-in needs."""
        located = shutil.which("machinectl", path=self.safe_environment()["PATH"])
        if located is None:
            raise E2EFailure("machinectl is not installed")
        target = Path(located).resolve()
        if target.parent not in MACHINECTL_BINARY_DIRS or not target.is_file():
            raise E2EFailure(f"Unexpected machinectl binary: {target}")
        stand_in = self.root / "stand-in-machinectl"
        real = self.root / "real-machinectl"
        if not stand_in.exists():
            stand_in.write_text(
                STAND_IN_MACHINECTL.format(real=shlex.quote(str(real))),
                encoding="ascii",
            )
            stand_in.chmod(0o755)
        if not real.exists():
            real.write_bytes(b"")
            real.chmod(0o755)
        command = [
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "--",
            "/bin/sh",
            "-c",
            STAND_IN_MACHINECTL_SCRIPT,
            "sh",
            str(target),
            str(real),
            str(stand_in),
            *command,
        ]
        return command, self.safe_environment()

    def with_a_broken_systemd_run(self, command: Sequence[str]) -> list[str]:
        """Return command wrapped so that systemd-run is found but cannot run."""
        located = shutil.which("systemd-run", path=self.safe_environment()["PATH"])
        if located is None:
            raise E2EFailure("systemd-run is not installed")
        target = Path(located).resolve()
        if target.parent not in SYSTEMD_RUN_BINARY_DIRS or not target.is_file():
            raise E2EFailure(f"Unexpected systemd-run binary: {target}")
        blocker = self.root / "broken-systemd-run"
        if not blocker.exists():
            blocker.write_bytes(b"not an executable\n")
            blocker.chmod(0o755)
        return [
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "--",
            "/bin/sh",
            "-c",
            HIDE_IPTABLES_SCRIPT,
            "sh",
            str(blocker),
            str(target),
            *command,
        ]

    def start_up(
        self,
        name: str,
        user: str,
        arguments: Sequence[str],
        log_name: str,
        *,
        workspace: str | None = None,
        shared: str | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> tuple[subprocess.Popen[bytes], Path]:
        """Start up of name in the background; return the process and its log.

        workspace and shared name other directories, relative to the run root
        where sandy runs, as for sandy(). environment replaces the safe
        environment, as for run(): a build passes minimal_environment(). The
        caller waits for the process.
        """
        if not NAME_PATTERN.fullmatch(name):
            raise E2EFailure(f"Refusing unsafe container name: {name!r}")
        if not re.fullmatch(r"[a-z0-9-]{1,48}", log_name):
            raise E2EFailure(f"Refusing unsafe log name: {log_name!r}")
        log_path = self.root / f"{log_name}-{name}.log"
        command = (
            str(SANDY),
            "--workspace",
            workspace or self.workspace.name,
            "--shared",
            shared or self.shared.name,
            "--user",
            user,
            "--container",
            name,
            *arguments,
        )
        print(f"    $ {shlex.join(command)} &", flush=True)
        # A case can send SIGINT to this up. execve keeps an ignored signal
        # ignored, and the runner can start with SIGINT ignored (for example,
        # as a background job of a shell). So give sandy the default action:
        # execve resets a handler to it. A blocked SIGINT stays blocked in
        # sandy too, so refuse to start then.
        if signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, ()):
            raise E2EFailure("SIGINT is blocked, so up would not get it")
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        try:
            with log_path.open("w", encoding="utf-8") as stream:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    cwd=self.root,
                    env=dict(environment or self.safe_environment()),
                )
        finally:
            signal.signal(
                signal.SIGINT, signal.SIG_DFL if previous is None else previous
            )
        return process, log_path

    @contextmanager
    def case(self, name: str) -> Iterator[None]:
        """Report one ordered E2E case."""
        print(f"\n[ RUN      ] {name}", flush=True)
        started = time.monotonic()
        try:
            yield
        except Exception:
            elapsed = time.monotonic() - started
            print(f"[  FAILED  ] {name} ({elapsed:.1f}s)", flush=True)
            raise
        elapsed = time.monotonic() - started
        self.passed += 1
        print(f"[       OK ] {name} ({elapsed:.1f}s)", flush=True)

    def preflight(self) -> None:
        """Refuse to run on a host with pre-existing Sandy state."""
        if os.getuid() != 0:
            raise E2EFailure("E2E tests must run as root")
        if os.environ.get("SANDY_E2E") != "1":
            raise E2EFailure("E2E tests require SANDY_E2E=1")
        if not SANDY.is_file() or not os.access(SANDY, os.X_OK):
            raise E2EFailure(f"Missing executable sandy script: {SANDY}")
        if not MINIMAL_SETUP.is_file() or not os.access(MINIMAL_SETUP, os.X_OK):
            raise E2EFailure(f"Missing executable minimal setup: {MINIMAL_SETUP}")
        if not SYSTEMD_MACHINES.is_dir():
            raise E2EFailure(f"Missing {SYSTEMD_MACHINES}")
        if INSTALL_DIR.exists() or INSTALL_DIR.is_symlink():
            raise E2EFailure(f"Refusing to replace existing install: {INSTALL_DIR}")
        for fixture_path in (
            self.filesystem_image_root,
            self.filesystem_host_target,
            self.filesystem_machine_link,
        ):
            if fixture_path.exists() or fixture_path.is_symlink():
                raise E2EFailure(
                    f"Refusing to replace existing filesystem fixture: {fixture_path}"
                )

        required_tools = (
            "curl",
            "debootstrap",
            "ip",
            "ip6tables",
            "iptables",
            "machinectl",
            "make",
            "mount",
            "nft",
            "nsenter",
            "runuser",
            "setpriv",
            "skopeo",
            "sysctl",
            "systemd-machine-id-setup",
            "systemd-nspawn",
            "tar",
            "umount",
            "umoci",
        )
        missing = [tool for tool in required_tools if shutil.which(tool) is None]
        if missing:
            raise E2EFailure(f"Missing E2E prerequisites: {', '.join(missing)}")

        existing = sorted(path.name for path in SYSTEMD_MACHINES.glob("sandy.*"))
        if existing:
            raise E2EFailure(
                "Refusing to run with pre-existing Sandy state: " + ", ".join(existing)
            )
        leftovers = up_temporary_directories()
        if leftovers:
            raise E2EFailure(
                "Refusing to run with pre-existing Sandy temporary directories: "
                + ", ".join(str(path) for path in leftovers)
            )
        if self.bridge_exists():
            raise E2EFailure(f"Refusing to use existing bridge {BRIDGE_NAME}")
        if self._sandy_firewall_exists():
            raise E2EFailure("Refusing to use pre-existing Sandy firewall state")
        slice_state = self.slice_artifacts()
        if slice_state:
            raise E2EFailure(
                f"Refusing to use pre-existing {SLICE} state: " + ", ".join(slice_state)
            )

        ip_forward = self.run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
        if ip_forward not in {"0", "1"}:
            raise E2EFailure(f"Unexpected net.ipv4.ip_forward value: {ip_forward!r}")
        self._ip_forward_original = ip_forward
        # Every global Sandy namespace was absent at preflight, so subsequent
        # Sandy state belongs to this run and is safe for cleanup to remove.
        self._host_state_owned = True
        self._filesystem_fixtures_reserved = True

    def claim_install_dir(self) -> None:
        """Claim the known-absent default install path for guarded cleanup."""
        if self._install_dir_owned:
            raise E2EFailure(f"Install path is already owned: {INSTALL_DIR}")
        if INSTALL_DIR.exists() or INSTALL_DIR.is_symlink():
            raise E2EFailure(f"Install path appeared during the test: {INSTALL_DIR}")
        self._install_dir_owned = True

    def _sandy_firewall_exists(self) -> bool:
        return bool(self.firewall_artifacts())

    def firewall_artifacts(self) -> list[str]:
        """Return every Sandy-owned firewall object visible on the host."""
        checks: list[tuple[str, list[str]]] = []
        for table, chain in IPTABLES_CHAINS:
            checks.append(
                (
                    f"iptables {table}/{chain}",
                    ["iptables", "-t", table, "-S", chain],
                )
            )
        for table, chain in IP6TABLES_CHAINS:
            checks.append(
                (
                    f"ip6tables {table}/{chain}",
                    ["ip6tables", "-t", table, "-S", chain],
                )
            )
        for family, table in NFTABLES_TABLES:
            checks.append(
                (
                    f"nftables {family}/{table}",
                    ["nft", "list", "table", family, table],
                )
            )

        return [
            description
            for description, command in checks
            if self.run(command, expected=None).returncode == 0
        ]

    def sandy_state_artifacts(self) -> list[str]:
        """Return persistent Sandy machine, bridge, and firewall state."""
        artifacts = []
        for path in sorted(SYSTEMD_MACHINES.glob("sandy.*")):
            if path == CACHE_DIR and self._cache_holds_only_safe_locks():
                continue
            artifacts.append(str(path))
        if self.bridge_exists():
            artifacts.append(f"bridge {BRIDGE_NAME}")
        artifacts.extend(self.firewall_artifacts())
        return artifacts

    def assert_no_sandy_state(self) -> None:
        """Fail if any persistent Sandy-owned host state remains."""
        artifacts = self.sandy_state_artifacts()
        if artifacts:
            raise E2EFailure("Sandy state remains: " + ", ".join(artifacts))

    def slice_artifacts(self) -> list[str]:
        """Return the state of sandy.slice: active, a unit file, or drop-ins.

        A slice without state is inactive, with no unit file, no drop-ins,
        and no cgroup. systemctl set-property creates the cgroup of an
        inactive slice (measured on systemd 249, 255, and 257).
        """
        command = ["systemctl", "show", SLICE]
        for name in SLICE_STATE_PROPERTIES:
            command.extend(["-p", name])
        values = {}
        for line in self.run(command).stdout.splitlines():
            name, separator, value = line.partition("=")
            if separator and name in SLICE_STATE_PROPERTIES:
                values[name] = value
        if set(values) != set(SLICE_STATE_PROPERTIES):
            raise E2EFailure(f"Unexpected systemctl show output for {SLICE}")
        artifacts = []
        if values["ActiveState"] != "inactive":
            artifacts.append(f"{SLICE} is {values['ActiveState']}")
        if values["FragmentPath"]:
            artifacts.append(f"{SLICE} unit file {values['FragmentPath']}")
        if values["DropInPaths"]:
            artifacts.append(f"{SLICE} drop-ins {values['DropInPaths']}")
        if SLICE_CGROUP.exists():
            artifacts.append(f"cgroup {SLICE_CGROUP}")
        return artifacts

    def remove_shared_slice(self) -> None:
        """Revert and stop sandy.slice once no process of the run is in it.

        Preflight proved that the slice had no state, so its state belongs to
        this run. A stop would also stop the units in the slice, so the slice
        must be empty.
        """
        if not self.slice_artifacts():
            return
        events = SLICE_CGROUP / "cgroup.events"
        if (
            events.exists()
            and "populated 0" not in events.read_text(encoding="ascii").splitlines()
        ):
            raise E2EFailure(f"Refusing to stop {SLICE}: it still has processes")
        self.run(["systemctl", "revert", SLICE])
        self.run(["systemctl", "stop", SLICE])
        remaining = self.slice_artifacts()
        if remaining:
            raise E2EFailure(f"{SLICE} state remains: " + ", ".join(remaining))

    def _filesystem_fixture_paths(self) -> tuple[Path, ...]:
        return (
            self.filesystem_machine_link,
            self.filesystem_image_root,
            self.filesystem_host_target,
        )

    @contextmanager
    def _defer_filesystem_fixture_interrupts(self) -> Iterator[None]:
        """Defer operator interrupts while a fixture is created and claimed."""
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGINT, signal.SIGTERM},
        )
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    @staticmethod
    def _filesystem_fixture_identity(
        fixture_stat: os.stat_result,
    ) -> FilesystemFixtureIdentity:
        return FilesystemFixtureIdentity(
            dev=fixture_stat.st_dev,
            ino=fixture_stat.st_ino,
            file_type=stat.S_IFMT(fixture_stat.st_mode),
        )

    def _prepare_filesystem_fixture_creation(self, fixture_path: Path) -> None:
        if not self._filesystem_fixtures_reserved:
            raise E2EFailure("Filesystem fixtures were not reserved at preflight")
        if fixture_path not in self._filesystem_fixture_paths():
            raise E2EFailure(f"Unexpected filesystem fixture path: {fixture_path}")
        if fixture_path.exists() or fixture_path.is_symlink():
            raise E2EFailure(f"Filesystem fixture already exists: {fixture_path}")

    def _remove_unclaimed_created_fixture(
        self,
        fixture_path: Path,
        created_identity: FilesystemFixtureIdentity,
    ) -> None:
        try:
            fixture_stat = fixture_path.lstat()
        except FileNotFoundError:
            return
        if not self._identity_matches(fixture_stat, created_identity):
            return
        if stat.S_ISDIR(fixture_stat.st_mode):
            fixture_path.rmdir()
        else:
            fixture_path.unlink()

    def create_filesystem_fixture_directory(
        self,
        fixture_path: Path,
        *,
        mode: int = 0o755,
    ) -> None:
        """Create and claim one top-level root fixture without an interrupt gap."""
        self._prepare_filesystem_fixture_creation(fixture_path)
        with self._defer_filesystem_fixture_interrupts():
            fixture_path.mkdir(mode=mode)
            created_identity = self._filesystem_fixture_identity(fixture_path.lstat())
            try:
                self.claim_filesystem_fixture(fixture_path)
            except Exception:
                self._remove_unclaimed_created_fixture(fixture_path, created_identity)
                raise

    def create_filesystem_fixture_symlink(
        self,
        fixture_path: Path,
        target_path: Path,
    ) -> None:
        """Create and claim one top-level symlink fixture without an interrupt gap."""
        self._prepare_filesystem_fixture_creation(fixture_path)
        with self._defer_filesystem_fixture_interrupts():
            fixture_path.symlink_to(target_path, target_is_directory=True)
            created_identity = self._filesystem_fixture_identity(fixture_path.lstat())
            try:
                self.claim_filesystem_fixture(fixture_path)
            except Exception:
                self._remove_unclaimed_created_fixture(fixture_path, created_identity)
                raise

    def claim_filesystem_fixture(self, fixture_path: Path) -> None:
        """Claim one exact top-level fixture inode after successful creation."""
        if not self._filesystem_fixtures_reserved:
            raise E2EFailure("Filesystem fixtures were not reserved at preflight")
        if fixture_path not in self._filesystem_fixture_paths():
            raise E2EFailure(f"Unexpected filesystem fixture path: {fixture_path}")

        try:
            fixture_stat = fixture_path.lstat()
        except OSError as exc:
            raise E2EFailure(
                f"Could not inspect filesystem fixture: {fixture_path}"
            ) from exc
        if (fixture_stat.st_uid, fixture_stat.st_gid) != (0, 0):
            raise E2EFailure(
                f"Filesystem fixture has unexpected ownership: {fixture_path}"
            )
        if not (
            stat.S_ISDIR(fixture_stat.st_mode)
            or stat.S_ISREG(fixture_stat.st_mode)
            or stat.S_ISLNK(fixture_stat.st_mode)
        ):
            raise E2EFailure(f"Unsafe filesystem fixture type: {fixture_path}")

        identity = self._filesystem_fixture_identity(fixture_stat)
        existing_identity = self._filesystem_fixture_identities.get(fixture_path)
        if existing_identity is not None and existing_identity != identity:
            raise E2EFailure(f"Filesystem fixture changed after claim: {fixture_path}")

        self._filesystem_fixture_identities[fixture_path] = identity
        self._filesystem_fixtures_owned = True

    def claim_filesystem_fixtures(self) -> None:
        """Claim exact fixture inodes after a test creates them successfully."""
        for fixture_path in self._filesystem_fixture_paths():
            if fixture_path.exists() or fixture_path.is_symlink():
                self.claim_filesystem_fixture(fixture_path)

        if not self._filesystem_fixture_identities:
            raise E2EFailure("No filesystem fixtures were created to claim")

    @staticmethod
    def _identity_matches(
        fixture_stat: os.stat_result,
        identity: FilesystemFixtureIdentity,
    ) -> bool:
        return (
            fixture_stat.st_dev == identity.dev
            and fixture_stat.st_ino == identity.ino
            and stat.S_IFMT(fixture_stat.st_mode) == identity.file_type
        )

    @staticmethod
    def _fd_mount_id(fd: int) -> int:
        with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii") as fdinfo:
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    value = line.removeprefix("mnt_id:").strip()
                    if value.isdecimal():
                        return int(value)
        raise E2EFailure("Could not determine fixture descriptor mount ID")

    def _remove_directory_contents(
        self,
        directory_fd: int,
        root_device: int,
        root_mount_id: int,
    ) -> None:
        for entry in os.listdir(directory_fd):
            entry_stat = os.stat(
                entry,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(entry_stat.st_mode):
                if entry_stat.st_dev != root_device:
                    raise E2EFailure(
                        "Refusing to clean filesystem fixture across a device boundary"
                    )
                child_fd = os.open(entry, DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
                try:
                    opened_stat = os.fstat(child_fd)
                    if not self._identity_matches(
                        opened_stat,
                        FilesystemFixtureIdentity(
                            dev=entry_stat.st_dev,
                            ino=entry_stat.st_ino,
                            file_type=stat.S_IFMT(entry_stat.st_mode),
                        ),
                    ):
                        raise E2EFailure(
                            "Filesystem fixture directory changed during cleanup"
                        )
                    if self._fd_mount_id(child_fd) != root_mount_id:
                        raise E2EFailure(
                            "Refusing to clean filesystem fixture across a mount"
                        )
                    self._remove_directory_contents(
                        child_fd,
                        root_device,
                        root_mount_id,
                    )
                finally:
                    os.close(child_fd)

                current_stat = os.stat(
                    entry,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if not self._identity_matches(
                    current_stat,
                    FilesystemFixtureIdentity(
                        dev=entry_stat.st_dev,
                        ino=entry_stat.st_ino,
                        file_type=stat.S_IFMT(entry_stat.st_mode),
                    ),
                ):
                    raise E2EFailure(
                        "Filesystem fixture directory changed before removal"
                    )
                os.rmdir(entry, dir_fd=directory_fd)
            else:
                entry_fd = os.open(entry, PATH_OPEN_FLAGS, dir_fd=directory_fd)
                try:
                    opened_stat = os.fstat(entry_fd)
                    if not self._identity_matches(
                        opened_stat,
                        FilesystemFixtureIdentity(
                            dev=entry_stat.st_dev,
                            ino=entry_stat.st_ino,
                            file_type=stat.S_IFMT(entry_stat.st_mode),
                        ),
                    ):
                        raise E2EFailure(
                            "Filesystem fixture entry changed during cleanup"
                        )
                    if self._fd_mount_id(entry_fd) != root_mount_id:
                        raise E2EFailure(
                            "Refusing to clean filesystem fixture across a mount"
                        )
                finally:
                    os.close(entry_fd)

                current_stat = os.stat(
                    entry,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if not self._identity_matches(
                    current_stat,
                    FilesystemFixtureIdentity(
                        dev=entry_stat.st_dev,
                        ino=entry_stat.st_ino,
                        file_type=stat.S_IFMT(entry_stat.st_mode),
                    ),
                ):
                    raise E2EFailure("Filesystem fixture entry changed before removal")
                os.unlink(entry, dir_fd=directory_fd)

    def _remove_claimed_filesystem_fixture(self, fixture_path: Path) -> None:
        identity = self._filesystem_fixture_identities[fixture_path]
        parent_fd = os.open(fixture_path.parent, DIRECTORY_OPEN_FLAGS)
        fixture_fd: int | None = None
        try:
            try:
                fixture_stat = os.stat(
                    fixture_path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if not self._identity_matches(fixture_stat, identity):
                raise E2EFailure(
                    f"Refusing to remove replaced filesystem fixture: {fixture_path}"
                )

            if stat.S_ISDIR(fixture_stat.st_mode):
                fixture_fd = os.open(
                    fixture_path.name,
                    DIRECTORY_OPEN_FLAGS,
                    dir_fd=parent_fd,
                )
                opened_stat = os.fstat(fixture_fd)
                if not self._identity_matches(opened_stat, identity):
                    raise E2EFailure(
                        f"Filesystem fixture changed during open: {fixture_path}"
                    )
                root_mount_id = self._fd_mount_id(fixture_fd)
                self._remove_directory_contents(
                    fixture_fd,
                    opened_stat.st_dev,
                    root_mount_id,
                )
                os.close(fixture_fd)
                fixture_fd = None

                current_stat = os.stat(
                    fixture_path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if not self._identity_matches(current_stat, identity):
                    raise E2EFailure(
                        f"Filesystem fixture changed before removal: {fixture_path}"
                    )
                os.rmdir(fixture_path.name, dir_fd=parent_fd)
            else:
                fixture_fd = os.open(
                    fixture_path.name,
                    PATH_OPEN_FLAGS,
                    dir_fd=parent_fd,
                )
                opened_stat = os.fstat(fixture_fd)
                if not self._identity_matches(opened_stat, identity):
                    raise E2EFailure(
                        f"Filesystem fixture changed during open: {fixture_path}"
                    )
                os.close(fixture_fd)
                fixture_fd = None

                current_stat = os.stat(
                    fixture_path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if not self._identity_matches(current_stat, identity):
                    raise E2EFailure(
                        f"Filesystem fixture changed before removal: {fixture_path}"
                    )
                os.unlink(fixture_path.name, dir_fd=parent_fd)
        finally:
            if fixture_fd is not None:
                os.close(fixture_fd)
            os.close(parent_fd)

    def remove_filesystem_fixtures(self) -> None:
        """Remove only root filesystem fixtures with a recorded identity."""
        if (
            not self._filesystem_fixtures_owned
            or not self._filesystem_fixture_identities
        ):
            raise E2EFailure("Filesystem fixtures are not claimed by this E2E run")
        if self._filesystem_mounts:
            raise E2EFailure(
                "Refusing to remove filesystem fixtures while tracked mounts remain"
            )
        for fixture_path in self._filesystem_fixture_paths():
            if fixture_path not in self._filesystem_fixture_identities:
                continue
            self._remove_claimed_filesystem_fixture(fixture_path)
        self._filesystem_fixture_identities = {}
        self._filesystem_fixtures_owned = False

    def mount_filesystem_file(
        self,
        source_path: Path,
        mount_path: Path,
    ) -> None:
        """Bind mount one owned fixture file and track it before host mutation."""
        if not self._filesystem_fixtures_owned:
            raise E2EFailure("Filesystem fixtures are not owned by this E2E run")
        expected_parents = (
            (source_path, self.filesystem_host_target),
            (mount_path, self.filesystem_machine_link),
        )
        for path, expected_parent in expected_parents:
            try:
                path_stat = path.lstat()
            except OSError as exc:
                raise E2EFailure(
                    f"Could not inspect filesystem fixture {path}"
                ) from exc
            if (
                path.parent != expected_parent
                or not stat.S_ISREG(path_stat.st_mode)
                or (path_stat.st_uid, path_stat.st_gid) != (0, 0)
            ):
                raise E2EFailure(f"Unsafe filesystem fixture file: {path}")
        if mount_path in self._filesystem_mounts:
            raise E2EFailure(f"Filesystem fixture is already mounted: {mount_path}")

        # Register before invoking mount so global cleanup covers command
        # interruption or a command failure after the kernel creates the mount.
        self._filesystem_mounts.append(mount_path)
        self.run(
            [
                "mount",
                "--bind",
                str(source_path),
                str(mount_path),
            ]
        )

    def unmount_filesystem_file(self, mount_path: Path) -> None:
        """Unmount one tracked fixture and forget it only after success."""
        if mount_path not in self._filesystem_mounts:
            raise E2EFailure(f"Filesystem fixture mount is not tracked: {mount_path}")
        result = self.run(
            ["umount", "--", str(mount_path)],
            expected=None,
        )
        if result.returncode != 0:
            raise E2EFailure(f"Could not unmount filesystem fixture: {mount_path}")
        self._filesystem_mounts.remove(mount_path)

    def _require_scratch_directory(self, path: Path) -> None:
        """Require an existing directory below this run's root, not a link."""
        if (
            not path.is_absolute()
            or ".." in path.parts
            or self.root not in path.parents
            or path.is_symlink()
            or not path.is_dir()
        ):
            raise E2EFailure(f"Unsafe scratch mount directory: {path}")

    def is_mount_point(self, path: Path) -> bool:
        """Return whether the host has a mount at path, from its mountinfo.

        os.path.ismount compares device numbers, so it misses a bind mount on
        the same file system.
        """
        target = os.path.realpath(path)
        mounts = parse_mountinfo(MOUNTINFO.read_text(encoding="utf-8"))
        return any(mount_point == target for mount_point, _ in mounts)

    @property
    def scratch_mounts(self) -> tuple[Path, ...]:
        """The directories that are tracked as mounts, oldest first."""
        return tuple(self._scratch_mounts)

    def track_scratch_mount(self, path: Path) -> None:
        """Track a directory that is, or may become, a mount point.

        Cleanup unmounts it. Use it for a mount that a case does not make
        itself, such as one that the product could make by mistake, so that
        cleanup removes it also when the case fails before it can.
        """
        self._require_scratch_directory(path)
        if path in self._scratch_mounts:
            raise E2EFailure(f"Scratch mount is already tracked: {path}")
        self._scratch_mounts.append(path)

    def forget_scratch_mount(self, path: Path) -> None:
        """Stop tracking a directory; it must not be a mount point."""
        if path not in self._scratch_mounts:
            raise E2EFailure(f"Scratch mount is not tracked: {path}")
        if self.is_mount_point(path):
            raise E2EFailure(f"Scratch mount is still mounted: {path}")
        self._scratch_mounts.remove(path)

    def _mount_scratch(self, path: Path, command: Sequence[str]) -> None:
        """Run a mount command for path, which is tracked before the command.

        So cleanup also covers an interrupt, or a failure after the kernel made
        the mount. A command that failed without a mount is forgotten at once.
        """
        self.track_scratch_mount(path)
        try:
            self.run(command)
        except BaseException:
            if not self.is_mount_point(path):
                self._scratch_mounts.remove(path)
            raise

    def mount_scratch_filesystem(self, kind: str, path: Path) -> None:
        """Mount a ramfs or tmpfs on a directory of this run's root."""
        if kind not in SCRATCH_FILESYSTEMS:
            raise E2EFailure(f"Unsupported scratch file system: {kind!r}")
        self._require_scratch_directory(path)
        self._mount_scratch(path, ["mount", "-t", kind, kind, str(path)])

    def mount_scratch_bind(self, source: Path, path: Path) -> None:
        """Bind mount a directory of this run's root on another one."""
        self._require_scratch_directory(source)
        self._require_scratch_directory(path)
        self._mount_scratch(path, ["mount", "--bind", "--", str(source), str(path)])

    def unmount_scratch_filesystem(self, path: Path) -> None:
        """Unmount one tracked scratch mount; forget it only after success."""
        if path not in self._scratch_mounts:
            raise E2EFailure(f"Scratch mount is not tracked: {path}")
        result = self.run(["umount", "--", str(path)], expected=None)
        if result.returncode != 0 and self.is_mount_point(path):
            raise E2EFailure(f"Could not unmount scratch mount: {path}")
        self._scratch_mounts.remove(path)

    def host_user_command(self, command: Sequence[str]) -> tuple[str, ...]:
        """Return command wrapped to run as the host user: its ids, no groups."""
        return (
            "setpriv",
            f"--reuid={self.host_uid}",
            f"--regid={self.host_gid}",
            "--clear-groups",
            "--",
            *_validate_command(command),
        )

    def run_as_host_user(
        self,
        command: Sequence[str],
        *,
        expected: int | None = 0,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run command as the host user, as a user of `sudo sandy` would."""
        return self.run(
            self.host_user_command(command),
            expected=expected,
            input_text=input_text,
        )

    def remove_up_temporary_directories(self) -> None:
        """Remove the directories that up made for its binds and did not remove.

        Preflight proved that none existed, so the ones that exist now belong to
        this run. A link, or an entry of another owner, is not removed.
        """
        errors = []
        for path in up_temporary_directories():
            entry = path.lstat()
            if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid():
                errors.append(f"unexpected entry {path}")
                continue
            shutil.rmtree(path)
        if errors:
            raise E2EFailure("Refusing to remove: " + ", ".join(errors))

    def register_container(self, name: str, user: str) -> None:
        if not NAME_PATTERN.fullmatch(name):
            raise E2EFailure(f"Refusing unsafe container name: {name!r}")
        self.owned_containers[name] = user

    def minimal_environment(self) -> dict[str, str]:
        return self.safe_environment(
            {
                HOST_SECRET_NAME: HOST_SECRET_VALUE,
                "SANDY_SETUP_SCRIPT": str(MINIMAL_SETUP),
            }
        )

    def build_minimal(self, name: str, user: str) -> CommandResult:
        self.register_container(name, user)
        result = self.sandy(
            [
                "up",
                "--build",
                "--detach",
                "--persistent",
                "--network",
                "host",
            ],
            name=name,
            user=user,
            timeout=BUILD_TIMEOUT,
            environment=self.minimal_environment(),
        )
        self.wait_for_machine(name, running=True)
        return result

    def build_main(self) -> CommandResult:
        self.register_container(self.main_name, self.main_user)
        result = self.sandy(
            [
                "up",
                "--build",
                "--detach",
                "--persistent",
                "--network",
                "lenient",
            ],
            name=self.main_name,
            user=self.main_user,
            timeout=BUILD_TIMEOUT,
            environment=self.minimal_environment(),
        )
        self.wait_for_machine(self.main_name, running=True)
        return result

    def build_lenient(
        self, name: str, user: str, timeout: int = BUILD_TIMEOUT
    ) -> CommandResult:
        """Build a persistent machine with the bridge network; leave it running.

        A case that expects a short build passes a shorter timeout, so that a
        build that blocks fails soon.
        """
        self.register_container(name, user)
        result = self.sandy(
            ["up", "--build", "--detach", "--persistent", "--network", "lenient"],
            name=name,
            user=user,
            timeout=timeout,
            environment=self.minimal_environment(),
        )
        self.wait_for_machine(name, running=True)
        return result

    def build_full(self) -> CommandResult:
        if self.full_build_started:
            raise E2EFailure("The full setup-container.sh build may run only once")
        self.full_build_started = True
        self.register_container(self.full_name, self.full_user)
        result = self.sandy(
            [
                "up",
                "--build",
                "--detach",
                "--persistent",
                "--network",
                "lenient",
            ],
            name=self.full_name,
            user=self.full_user,
            timeout=FULL_BUILD_TIMEOUT,
        )
        self.wait_for_machine(self.full_name, running=True)
        return result

    def up_with_a_change_while_it_waits(
        self,
        name: str,
        user: str,
        arguments: list[str],
        change: Callable[[], None],
    ) -> CommandResult:
        """Run up of name, and make a change while up waits for the lifecycle lock.

        Before up waits for the lock ("Limits of this container" is its last
        line before it), it checks the mount targets in the image and removes
        stale port rules and state. Hold the lock until up waits for it, make
        the change, and release the lock. So the change comes after those
        steps and before everything that up does under the lock.
        """
        log_path = self.root / f"lock-wait-{change.__name__}-{name}.log"
        command = (
            str(SANDY),
            "--workspace",
            self.workspace.name,
            "--shared",
            self.shared.name,
            "--user",
            user,
            "--container",
            name,
            *arguments,
        )
        up: subprocess.Popen[bytes] | None = None
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
                        cwd=self.root,
                        env=self.safe_environment(),
                    )
                deadline = time.monotonic() + LIFECYCLE_WAIT_TIMEOUT
                while "I: Limits of this container" not in log_path.read_text(
                    encoding="utf-8", errors="replace"
                ):
                    if up.poll() is not None or time.monotonic() >= deadline:
                        raise E2EFailure("up did not wait for the lifecycle lock")
                    time.sleep(0.1)
                change()
            # The close released the lock; up takes it now.
            returncode = up.wait(timeout=BACKGROUND_UP_TIMEOUT)
            return CommandResult(
                command, returncode, log_path.read_text(encoding="utf-8"), ""
            )
        finally:
            if up is not None and up.poll() is None:
                up.kill()
                up.wait(timeout=10)

    def machine_running(self, name: str) -> bool:
        return self.machine_leader(name) is not None

    def machine_leader(self, name: str) -> str | None:
        if not NAME_PATTERN.fullmatch(name):
            raise E2EFailure(f"Refusing unsafe container name: {name!r}")
        result = self.run(
            ["machinectl", "show", name, "--property", "Leader", "--value"],
            expected=None,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        leader = result.stdout.strip()
        if not re.fullmatch(r"[1-9][0-9]{0,9}", leader):
            raise E2EFailure(f"Invalid leader PID for {name!r}: {leader!r}")
        return leader

    def _machine_command(
        self,
        name: str,
        user: str,
        command: Sequence[str],
    ) -> tuple[str, ...]:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise E2EFailure(f"Refusing unsafe container user: {user!r}")
        leader = self.machine_leader(name)
        if leader is None:
            raise E2EFailure(f"Container {name!r} is not running")
        normalized = _validate_command(command)
        return (
            "nsenter",
            "-t",
            leader,
            "-a",
            "--",
            "setpriv",
            f"--reuid={user}",
            f"--regid={user}",
            "--init-groups",
            "--",
            *normalized,
        )

    def start_in_machine(
        self,
        name: str,
        user: str,
        command: Sequence[str],
    ) -> subprocess.Popen[str]:
        """Start a tracked fixture process in a running machine's namespaces."""
        normalized = self._machine_command(name, user, command)
        print(f"    $ {shlex.join(normalized)}", flush=True)
        process = subprocess.Popen(
            normalized,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            cwd=self.root,
            env=self.safe_environment(),
        )
        self.fixture_processes.append(process)
        return process

    def stop_fixture_process(self, process: subprocess.Popen[str]) -> None:
        """Stop and reap one process started by start_in_machine."""
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.stderr is not None:
            process.stderr.close()
        if process in self.fixture_processes:
            self.fixture_processes.remove(process)

    def wait_for_machine(self, name: str, *, running: bool, timeout: int = 30) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.machine_running(name) is running:
                return
            time.sleep(0.5)
        state = "running" if running else "stopped"
        raise E2EFailure(f"Timed out waiting for {name!r} to become {state}")

    def stop_container(self, name: str, user: str) -> CommandResult:
        result = self.sandy(["down"], name=name, user=user)
        self.wait_for_machine(name, running=False)
        return result

    def remove_container(self, name: str, user: str) -> None:
        if self.machine_running(name):
            self.stop_container(name, user)
        machine_dir = SYSTEMD_MACHINES / f"sandy.{name}"
        if machine_dir.exists():
            self.sandy(["rm", "--force"], name=name, user=user)
        if machine_dir.exists():
            raise E2EFailure(f"Container directory was not removed: {machine_dir}")

    def cache_archives(self) -> list[Path]:
        if not CACHE_DIR.exists():
            return []
        return sorted(path for path in CACHE_DIR.glob("*.tar") if path.is_file())

    def hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def purge_cache(self) -> None:
        if CACHE_DIR.exists():
            self.sandy(["rm", "--cache", "--force"])
        for path in (*PERSISTENT_FILES, *self._up_locks()):
            if path.exists() or path.is_symlink():
                if not self._persistent_lock_is_safe(path):
                    raise E2EFailure(f"Unsafe persistent file: {path}")
                # Product code never removes a stable lock inode because a
                # waiter could still hold it, nor the saved shared limits.
                # The harness owns the otherwise-clean VM and removes them
                # only after all Sandy operations have stopped.
                path.unlink()
        if CACHE_DIR.exists() and not any(CACHE_DIR.iterdir()):
            CACHE_DIR.rmdir()
        if CACHE_DIR.exists():
            remaining = ", ".join(sorted(path.name for path in CACHE_DIR.iterdir()))
            raise E2EFailure(
                f"Cache directory remains after purge: {CACHE_DIR} ({remaining})"
            )

    def _cache_holds_only_safe_locks(self) -> bool:
        """Return whether the cache directory holds only safe persistent locks."""
        entries = list(CACHE_DIR.iterdir())
        return bool(entries) and all(
            (entry in PERSISTENT_LOCKS or UP_LOCK_PATTERN.fullmatch(entry.name))
            and self._persistent_lock_is_safe(entry)
            for entry in entries
        )

    def _up_locks(self) -> list[Path]:
        """Return the up lock files of the cache directory."""
        if not CACHE_DIR.exists():
            return []
        return sorted(
            path for path in CACHE_DIR.iterdir() if UP_LOCK_PATTERN.fullmatch(path.name)
        )

    def _persistent_lock_is_safe(self, lock: Path) -> bool:
        """Return whether a persistent lock or file has its exact safe metadata."""
        if not lock.exists() or lock.is_symlink():
            return False
        lock_stat = lock.lstat()
        return (
            stat.S_ISREG(lock_stat.st_mode)
            and (lock_stat.st_uid, lock_stat.st_gid) == (0, 0)
            and stat.S_IMODE(lock_stat.st_mode) == 0o600
            and lock_stat.st_nlink == 1
        )

    def bridge_exists(self) -> bool:
        return (
            self.run(
                ["ip", "link", "show", BRIDGE_NAME],
                expected=None,
            ).returncode
            == 0
        )

    def choose_host_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
        if not 1024 <= port <= 65535:
            raise E2EFailure(f"Unsafe ephemeral port selected: {port}")
        return port

    def port_state(self) -> dict[str, object]:
        if not PORT_STATE.is_file():
            raise E2EFailure(f"Missing port state: {PORT_STATE}")
        mode = stat.S_IMODE(PORT_STATE.stat().st_mode)
        if mode != 0o600:
            raise E2EFailure(f"Port state mode is {mode:o}, expected 600")
        try:
            state = json.loads(PORT_STATE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise E2EFailure(f"Could not read port state: {exc}") from exc
        if not isinstance(state, dict):
            raise E2EFailure("Port state is not a JSON object")
        return state

    def wait_for_http(self, port: int, expected: str, timeout: int = 30) -> None:
        deadline = time.monotonic() + timeout
        last_result: CommandResult | None = None
        while time.monotonic() < deadline:
            last_result = self.run(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "3",
                    f"http://127.0.0.1:{port}/",
                ],
                expected=None,
            )
            if last_result.returncode == 0 and expected in last_result.stdout:
                return
            time.sleep(0.5)
        detail = last_result.output if last_result else "no request attempted"
        raise E2EFailure(
            f"Timed out waiting for forwarded HTTP service:\n{_bounded_tail(detail)}"
        )

    def cleanup(self) -> list[str]:
        """Best-effort cleanup restricted to state owned by this run."""
        errors: list[str] = []
        for process in tuple(self.fixture_processes):
            try:
                self.stop_fixture_process(process)
            except Exception as exc:
                errors.append(f"fixture process {process.pid}: {exc}")

        for name, user in reversed(tuple(self.owned_containers.items())):
            try:
                self.remove_container(name, user)
            except Exception as exc:  # cleanup must continue through every target
                errors.append(f"container {name}: {exc}")

        for mount_path in reversed(tuple(self._scratch_mounts)):
            try:
                self.unmount_scratch_filesystem(mount_path)
            except Exception as exc:
                errors.append(f"scratch mount {mount_path}: {exc}")

        for mount_path in reversed(tuple(self._filesystem_mounts)):
            try:
                self.unmount_filesystem_file(mount_path)
            except Exception as exc:
                errors.append(f"filesystem mount {mount_path}: {exc}")

        if self._filesystem_fixtures_owned:
            try:
                self.remove_filesystem_fixtures()
            except Exception as exc:
                errors.append(f"filesystem fixtures: {exc}")

        if self._host_state_owned:
            try:
                # A failed case can leave the Sandy firewall without the
                # bridge (test_stale_rules deletes the bridge). rm --network
                # removes that state too: it sets up a bridge first, removes
                # it, and the ip_forward value is restored below.
                if self.bridge_exists() or self._sandy_firewall_exists():
                    self.sandy(["rm", "--network", "--force"])
            except Exception as exc:
                errors.append(f"network: {exc}")

            try:
                self.purge_cache()
            except Exception as exc:
                errors.append(f"cache: {exc}")

            try:
                self.remove_shared_slice()
            except Exception as exc:
                errors.append(f"{SLICE}: {exc}")

            try:
                self.remove_up_temporary_directories()
            except Exception as exc:
                errors.append(f"up temporary directories: {exc}")

            if self._ip_forward_original is not None:
                try:
                    self.run(
                        [
                            "sysctl",
                            "-w",
                            f"net.ipv4.ip_forward={self._ip_forward_original}",
                        ]
                    )
                except Exception as exc:
                    errors.append(f"ip_forward restore: {exc}")

            try:
                self.assert_no_sandy_state()
            except Exception as exc:
                errors.append(f"state verification: {exc}")

        if self._install_dir_owned:
            try:
                if INSTALL_DIR.is_symlink() or INSTALL_DIR.is_file():
                    INSTALL_DIR.unlink()
                elif INSTALL_DIR.is_dir():
                    shutil.rmtree(INSTALL_DIR)
            except OSError as exc:
                errors.append(f"install directory {INSTALL_DIR}: {exc}")

        if self._scratch_mounts:
            # rmtree would descend into a file system that is still mounted.
            errors.append(
                f"temporary directory {self.root} kept: mounts remain: "
                + ", ".join(str(path) for path in self._scratch_mounts)
            )
            return errors
        try:
            shutil.rmtree(self.root)
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"temporary directory {self.root}: {exc}")
        return errors
