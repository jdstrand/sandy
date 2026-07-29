#!/usr/bin/env python3

"""Shared helpers for sandy's privileged end-to-end tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
SANDY = REPO_ROOT / "sandy"
MINIMAL_SETUP = Path(__file__).with_name("setup-container-minimal.sh")
INSTALL_DIR = Path("/usr/local/lib/sandy")
SYSTEMD_MACHINES = Path("/var/lib/machines")
CACHE_DIR = SYSTEMD_MACHINES / "sandy.__cache"
PORT_STATE = CACHE_DIR / "port_mappings.json"
PORT_LOCK = CACHE_DIR / "port_mappings.lock"
BRIDGE_NAME = "sandybr0"
NAME_PATTERN = re.compile(r"^e2e-[a-z0-9-]{1,48}$")
DEFAULT_TIMEOUT = 120
BUILD_TIMEOUT = 1800
FULL_BUILD_TIMEOUT = 7200
OUTPUT_TAIL_LENGTH = 12000
CONTAINER_USER_ID = 1000
HOST_SECRET_NAME = "SANDY_HOST_SECRET"
HOST_SECRET_VALUE = "must-not-enter-container"
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
NFTABLES_TABLES = (
    ("ip", "sandy"),
    ("ip6", "sandy"),
)


class E2EFailure(RuntimeError):
    """Raised when an end-to-end assertion fails."""


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


class E2EContext:
    """Own all mutable state created by one end-to-end run."""

    def __init__(self) -> None:
        suffix = secrets.token_hex(3)
        self.cache_name = f"e2e-cache-{suffix}"
        self.cache_miss_name = f"e2e-cache-miss-{suffix}"
        self.filesystem_name = f"e2e-filesystem-{suffix}"
        self.main_name = f"e2e-main-{suffix}"
        self.full_name = f"e2e-full-{suffix}"
        self.cache_user = "developer"
        self.cache_miss_user = "e2emiss"
        self.main_user = "developer"
        self.full_user = "developer"
        self._validate_names()

        self.root = Path(tempfile.mkdtemp(prefix="sandy-e2e-", dir="/tmp"))
        os.chmod(self.root, 0o755)
        self.workspace = self.root / "workspace"
        self.shared = self.root / "shared"
        self.workspace.mkdir(mode=0o755)
        self.shared.mkdir(mode=0o755)
        for mount_path in (self.workspace, self.shared):
            os.chown(mount_path, CONTAINER_USER_ID, CONTAINER_USER_ID)

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
        self._filesystem_fixtures_owned = False
        self._filesystem_mounts: list[Path] = []

    def _validate_names(self) -> None:
        for name in (
            self.cache_name,
            self.cache_miss_name,
            self.filesystem_name,
            self.main_name,
            self.full_name,
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
    ) -> CommandResult:
        """Invoke sandy with the E2E workspace and optional owned container."""
        command = [
            str(SANDY),
            "--workspace",
            self.workspace.name,
            "--shared",
            self.shared.name,
            "--user",
            user,
        ]
        if name is not None:
            if not NAME_PATTERN.fullmatch(name):
                raise E2EFailure(f"Refusing unsafe container name: {name!r}")
            command.extend(["--container", name])
        command.extend(arguments)
        return self.run(
            command,
            expected=expected,
            timeout=timeout,
            environment=environment or self.safe_environment(),
            input_text=input_text,
        )

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
        if self.bridge_exists():
            raise E2EFailure(f"Refusing to use existing bridge {BRIDGE_NAME}")
        if self._sandy_firewall_exists():
            raise E2EFailure("Refusing to use pre-existing Sandy firewall state")

        ip_forward = self.run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
        if ip_forward not in {"0", "1"}:
            raise E2EFailure(f"Unexpected net.ipv4.ip_forward value: {ip_forward!r}")
        self._ip_forward_original = ip_forward
        # Every global Sandy namespace was absent at preflight, so subsequent
        # Sandy state belongs to this run and is safe for cleanup to remove.
        self._host_state_owned = True
        self._filesystem_fixtures_owned = True

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
            if (
                path == CACHE_DIR
                and self._persistent_port_lock_is_safe()
                and list(CACHE_DIR.iterdir()) == [PORT_LOCK]
            ):
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

    def remove_filesystem_fixtures(self) -> None:
        """Remove only root filesystem fixtures proven absent at preflight."""
        if not self._filesystem_fixtures_owned:
            raise E2EFailure("Filesystem fixtures are not owned by this E2E run")
        if self._filesystem_mounts:
            raise E2EFailure(
                "Refusing to remove filesystem fixtures while tracked mounts remain"
            )
        for fixture_path in (
            self.filesystem_machine_link,
            self.filesystem_image_root,
            self.filesystem_host_target,
        ):
            if fixture_path.is_symlink() or fixture_path.is_file():
                fixture_path.unlink()
            elif fixture_path.is_dir():
                shutil.rmtree(fixture_path)

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
        if PORT_LOCK.exists() or PORT_LOCK.is_symlink():
            if not self._persistent_port_lock_is_safe():
                raise E2EFailure(f"Unsafe persistent port lock: {PORT_LOCK}")
            # Product code never removes this stable inode because a waiter
            # could still hold it. The harness owns the otherwise-clean VM and
            # removes it only after all Sandy operations have stopped.
            PORT_LOCK.unlink()
        if CACHE_DIR.exists() and not any(CACHE_DIR.iterdir()):
            CACHE_DIR.rmdir()
        if CACHE_DIR.exists():
            remaining = ", ".join(sorted(path.name for path in CACHE_DIR.iterdir()))
            raise E2EFailure(
                f"Cache directory remains after purge: {CACHE_DIR} ({remaining})"
            )

    def _persistent_port_lock_is_safe(self) -> bool:
        """Return whether the persistent lock has its exact safe metadata."""
        if not PORT_LOCK.exists() or PORT_LOCK.is_symlink():
            return False
        lock_stat = PORT_LOCK.lstat()
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
                if self.bridge_exists():
                    self.sandy(["rm", "--network", "--force"])
            except Exception as exc:
                errors.append(f"network: {exc}")

            try:
                self.purge_cache()
            except Exception as exc:
                errors.append(f"cache: {exc}")

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

        try:
            shutil.rmtree(self.root)
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"temporary directory {self.root}: {exc}")
        return errors
