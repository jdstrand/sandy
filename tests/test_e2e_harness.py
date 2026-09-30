#!/usr/bin/env python3

"""Unit tests for safety-critical end-to-end harness control flow."""

from __future__ import annotations

import ctypes
import os
import signal
import stat
import subprocess
import tempfile
import threading
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from tests.e2e.support import (
    ACL_PROMPT_ANSWERS,
    CONTAINER_USER_ID,
    DEFAULT_TIMEOUT,
    REPO_ROOT,
    SANDY,
    SANDY_SCRIPT_NAMES,
    CommandResult,
    E2EContext,
    E2EFailure,
    FilesystemFixtureIdentity,
)
from tests.e2e.test_confinement import (
    PTRACE_CONT,
    PTRACE_FORK_OPTIONS,
    PTRACE_GETEVENTMSG,
    START_ATTACHES_AFTER_UP,
    _entry_failure_reason,
    _has_payload,
    _hold_payload_at_fork,
    _machined_leader,
    _open_scope_process,
    _Session,
    _StartSampler,
)
from tests.e2e.test_network import _wait_for_public_https
from tests.e2e.test_scope import _has_new_only_child, _leaves, _read_cgroup_file


class CleanupProbeContext(E2EContext):
    """Exercise cleanup ownership decisions without touching host state."""

    def __init__(self, root: Path, *, host_state_owned: bool) -> None:
        self.root = root
        self.fixture_processes = []
        self.owned_containers = {}
        self._ip_forward_original = None
        self._host_state_owned = host_state_owned
        self._install_dir_owned = False
        self._filesystem_fixtures_reserved = True
        self._filesystem_fixtures_owned = False
        self._filesystem_fixture_identities = {}
        self.filesystem_machine_link = root / "machine"
        self.filesystem_image_root = root / "image"
        self.filesystem_host_target = root / "host"
        self._filesystem_mounts = []
        self.bridge = False
        self.firewall: list[str] = []
        self.bridge_checks = 0
        self.firewall_checks = 0
        self.cache_purges = 0
        self.state_checks = 0
        self.sandy_calls: list[list[str]] = []

    def bridge_exists(self) -> bool:
        self.bridge_checks += 1
        return self.bridge

    def firewall_artifacts(self) -> list[str]:
        self.firewall_checks += 1
        return list(self.firewall)

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
    ) -> CommandResult:
        del name, user, expected, timeout, environment, input_text, executable
        self.sandy_calls.append(list(arguments))
        return CommandResult(("sandy", *arguments), 0, "", "")

    def purge_cache(self) -> None:
        self.cache_purges += 1

    def assert_no_sandy_state(self) -> None:
        self.state_checks += 1


class RetryContext(E2EContext):
    """Return deterministic real command results to the HTTPS retry loop."""

    def __init__(self, results: Sequence[CommandResult]) -> None:
        self.results = list(results)
        self.expected_exit_codes: list[int | None] = []
        self.main_name = "e2e-main-retry"
        self.main_user = "developer"

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
    ) -> CommandResult:
        del arguments, name, user, timeout, environment, input_text, executable
        self.expected_exit_codes.append(expected)
        if not self.results:
            raise AssertionError("HTTPS retry made too many attempts")
        return self.results.pop(0)


class CleanupOwnershipTests(unittest.TestCase):
    def _claim_fixture(self, context, fixture_path: Path) -> None:
        fixture_stat = fixture_path.lstat()
        context.filesystem_machine_link = fixture_path
        context.filesystem_image_root = fixture_path.parent / "missing-image"
        context.filesystem_host_target = fixture_path.parent / "missing-host"
        context._filesystem_fixtures_owned = True
        context._filesystem_fixture_identities = {
            fixture_path: FilesystemFixtureIdentity(
                dev=fixture_stat.st_dev,
                ino=fixture_stat.st_ino,
                file_type=stat.S_IFMT(fixture_stat.st_mode),
            )
        }

    def test_failed_preflight_cleanup_does_not_inspect_or_remove_host_state(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            root.joinpath("fixture").write_text("owned\n", encoding="utf-8")
            context = CleanupProbeContext(root, host_state_owned=False)

            self.assertEqual(context.cleanup(), [])

            self.assertFalse(root.exists())
            self.assertEqual(context.bridge_checks, 0)
            self.assertEqual(context.firewall_checks, 0)
            self.assertEqual(context.sandy_calls, [])
            self.assertEqual(context.cache_purges, 0)
            self.assertEqual(context.state_checks, 0)

    def test_successful_preflight_cleanup_verifies_owned_host_state(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=True)

            self.assertEqual(context.cleanup(), [])

            self.assertFalse(root.exists())
            self.assertEqual(context.bridge_checks, 1)
            self.assertEqual(context.cache_purges, 1)
            self.assertEqual(context.state_checks, 1)

    def test_cleanup_removes_the_network_when_the_bridge_or_firewall_remains(self):
        # Regression test: a failed case can delete the bridge and leave the
        # Sandy firewall. Mocks: the bridge and firewall checks and sandy.
        cases = (
            # bridge, firewall artifacts, firewall checks, rm --network calls
            (True, [], 0, 1),
            (False, ["nftables ip/sandy"], 1, 1),
            (False, [], 1, 0),
        )
        for bridge, firewall, firewall_checks, removals in cases:
            with self.subTest(bridge=bridge, firewall=firewall):
                with tempfile.TemporaryDirectory() as parent:
                    root = Path(parent) / "run"
                    root.mkdir()
                    context = CleanupProbeContext(root, host_state_owned=True)
                    context.bridge = bridge
                    context.firewall = firewall

                    self.assertEqual(context.cleanup(), [])

                    self.assertEqual(context.firewall_checks, firewall_checks)
                    self.assertEqual(
                        context.sandy_calls, [["rm", "--network", "--force"]] * removals
                    )
                    self.assertEqual(context.cache_purges, 1)
                    self.assertEqual(context.state_checks, 1)

    def test_cleanup_unmounts_tracked_files_before_removing_fixtures(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            mount_path = Path("/var/lib/machines/sandy.e2e/mounted-file")
            context._filesystem_fixtures_owned = True
            context._filesystem_mounts.append(mount_path)
            events = []

            def unmount(path):
                events.append(("unmount", path))
                context._filesystem_mounts.remove(path)

            def remove_fixtures():
                if context._filesystem_mounts:
                    raise AssertionError("Fixtures removed before tracked mounts")
                events.append(("remove", None))

            with patch.object(
                context,
                "unmount_filesystem_file",
                side_effect=unmount,
            ):
                with patch.object(
                    context,
                    "remove_filesystem_fixtures",
                    side_effect=remove_fixtures,
                ):
                    self.assertEqual(context.cleanup(), [])

            self.assertEqual(
                events,
                [
                    ("unmount", mount_path),
                    ("remove", None),
                ],
            )

    def test_filesystem_fixture_cleanup_rejects_replaced_fixture(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            fixture = root / "fixture"
            fixture.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            self._claim_fixture(context, fixture)

            fixture.rmdir()
            fixture.write_text("replacement\n", encoding="utf-8")

            with self.assertRaisesRegex(E2EFailure, "replaced filesystem fixture"):
                context.remove_filesystem_fixtures()

            self.assertEqual(fixture.read_text(encoding="utf-8"), "replacement\n")

    def test_filesystem_fixture_cleanup_unlinks_symlinks_without_following(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            fixture = root / "fixture"
            external = root / "external"
            fixture.mkdir()
            external.mkdir()
            external.joinpath("keep").write_text("external\n", encoding="utf-8")
            fixture.joinpath("link").symlink_to(external, target_is_directory=True)
            context = CleanupProbeContext(root, host_state_owned=False)
            self._claim_fixture(context, fixture)

            context.remove_filesystem_fixtures()

            self.assertFalse(fixture.exists())
            self.assertEqual(
                external.joinpath("keep").read_text(encoding="utf-8"),
                "external\n",
            )

    def test_create_filesystem_fixture_directory_claims_before_unblocking(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            calls = []
            previous_mask = {signal.SIGHUP}

            def pthread_sigmask(how, mask):
                calls.append((how, mask))
                return previous_mask

            def claim(fixture_path):
                self.assertEqual(fixture_path, context.filesystem_image_root)
                self.assertTrue(fixture_path.is_dir())
                self.assertEqual(
                    calls,
                    [
                        (
                            signal.SIG_BLOCK,
                            {signal.SIGINT, signal.SIGTERM},
                        )
                    ],
                )

            with patch(
                "tests.e2e.support.signal.pthread_sigmask",
                side_effect=pthread_sigmask,
            ):
                with patch.object(
                    context,
                    "claim_filesystem_fixture",
                    side_effect=claim,
                ) as claim_fixture:
                    context.create_filesystem_fixture_directory(
                        context.filesystem_image_root
                    )

            claim_fixture.assert_called_once_with(context.filesystem_image_root)
            self.assertEqual(
                calls,
                [
                    (
                        signal.SIG_BLOCK,
                        {signal.SIGINT, signal.SIGTERM},
                    ),
                    (signal.SIG_SETMASK, previous_mask),
                ],
            )
            self.assertTrue(context.filesystem_image_root.is_dir())

    def test_create_filesystem_fixture_symlink_claims_exact_link(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)

            with patch.object(context, "claim_filesystem_fixture") as claim_fixture:
                context.create_filesystem_fixture_symlink(
                    context.filesystem_machine_link,
                    context.filesystem_image_root,
                )

            claim_fixture.assert_called_once_with(context.filesystem_machine_link)
            self.assertTrue(context.filesystem_machine_link.is_symlink())

    def test_create_filesystem_fixture_directory_removes_unclaimed_failure(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)

            with patch.object(
                context,
                "claim_filesystem_fixture",
                side_effect=E2EFailure("claim failed"),
            ):
                with self.assertRaisesRegex(E2EFailure, "claim failed"):
                    context.create_filesystem_fixture_directory(
                        context.filesystem_image_root
                    )

            self.assertFalse(context.filesystem_image_root.exists())


class FilesystemMountTrackingTests(unittest.TestCase):
    def test_mount_is_tracked_before_command_and_forgotten_after_unmount(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            context._filesystem_fixtures_owned = True
            context.filesystem_host_target = Path("/var/lib/sandy-e2e-host")
            context.filesystem_machine_link = Path(
                "/var/lib/machines/sandy.e2e-filesystem"
            )
            source_path = context.filesystem_host_target / "source"
            mount_path = context.filesystem_machine_link / "mounted-file"
            safe_file = SimpleNamespace(
                st_mode=0o100600,
                st_uid=0,
                st_gid=0,
            )
            commands = []

            def run(command, **kwargs):
                commands.append((tuple(command), kwargs))
                if command[0] == "mount":
                    self.assertEqual(context._filesystem_mounts, [mount_path])
                return CommandResult(tuple(command), 0, "", "")

            with patch.object(Path, "lstat", return_value=safe_file):
                with patch.object(context, "run", side_effect=run):
                    context.mount_filesystem_file(source_path, mount_path)
                    self.assertEqual(context._filesystem_mounts, [mount_path])
                    context.unmount_filesystem_file(mount_path)

            self.assertEqual(context._filesystem_mounts, [])
            self.assertEqual(
                commands,
                [
                    (
                        (
                            "mount",
                            "--bind",
                            str(source_path),
                            str(mount_path),
                        ),
                        {},
                    ),
                    (
                        ("umount", "--", str(mount_path)),
                        {"expected": None},
                    ),
                ],
            )

    def test_failed_unmount_remains_tracked_for_cleanup_retry(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            mount_path = Path("/var/lib/machines/sandy.e2e/mounted-file")
            context._filesystem_mounts.append(mount_path)
            failure = CommandResult(("umount",), 1, "", "busy")

            with patch.object(context, "run", return_value=failure):
                with self.assertRaises(E2EFailure):
                    context.unmount_filesystem_file(mount_path)

            self.assertEqual(context._filesystem_mounts, [mount_path])


class PublicHttpsRetryTests(unittest.TestCase):
    def test_transient_command_failure_is_retried(self):
        context = RetryContext(
            [
                CommandResult(("curl",), 6, "", "temporary DNS failure"),
                CommandResult(("curl",), 0, "Example Domain", ""),
            ]
        )

        _wait_for_public_https(context, timeout=1, retry_delay=0)

        self.assertEqual(context.expected_exit_codes, [None, None])
        self.assertEqual(context.results, [])


class ConfinementSessionTests(unittest.TestCase):
    """The confinement case must read the filters of the session only."""

    def test_session_pid_waits_for_the_session_command(self):
        # Regression test: during the extraction, machinectl is the only
        # child of the entry helper. Mocks: the process tree and the command
        # lines (one snapshot for each poll) and the poll sleep.
        helper = (
            b"python3\x00-I\x00/proc/self/fd/3\x00"
            b"__sandy-entry-helper\x00sleep 10\x00"
        )
        session = b"script\x00-qec\x00sleep 10\x00/dev/null\x00"
        snapshots = (
            # machinectl, while the helper extracts the confinement.
            ({100: [200], 200: [300]}, {200: helper, 300: b"machinectl\x00show\x00"}),
            # The middle process, a fork of the helper.
            ({100: [200], 200: [400]}, {200: helper, 400: helper}),
            # The session is reparented; the exited middle has no command line.
            ({100: [200], 200: [400, 500]}, {200: helper, 400: b"", 500: helper}),
            # The session before its execve, a fork of the helper.
            ({100: [200], 200: [500]}, {200: helper, 500: helper}),
            # A child that is gone before its command line is read.
            ({100: [200], 200: [600]}, {200: helper}),
            # The session after its execve.
            ({100: [200], 200: [500]}, {200: helper, 500: session}),
        )
        poll = -1

        def children(pid: int) -> list[int]:
            nonlocal poll
            if pid == 100:
                poll += 1
            return snapshots[poll][0].get(pid, [])

        def read_bytes(path: Path) -> bytes:
            lines = snapshots[poll][1]
            pid = int(path.parts[2])
            if pid not in lines:
                raise FileNotFoundError(str(path))
            return lines[pid]

        attach = _Session.__new__(_Session)
        attach.process = MagicMock(pid=100)
        attach.command = "sleep 10"
        with patch(
            "tests.e2e.test_confinement._children", side_effect=children
        ), patch.object(
            Path, "read_bytes", autospec=True, side_effect=read_bytes
        ), patch(
            "tests.e2e.test_confinement.time.sleep"
        ) as sleep:
            self.assertEqual(attach.session_pid(), 500)
        self.assertEqual(poll, len(snapshots) - 1)
        self.assertEqual(sleep.call_count, len(snapshots) - 1)


class StartSamplerTests(unittest.TestCase):
    """The start-window case samples attaches until up has returned.

    Mocks: subprocess.run in the sampler module. No attach runs.
    """

    def test_sampler_stops_after_the_attaches_that_follow_up(self):
        up_done = threading.Event()
        outputs = iter(("before", "during", "after 1", "after 2"))

        def run(arguments, **kwargs):
            output = next(outputs)
            if output == "during":
                up_done.set()
            return subprocess.CompletedProcess(arguments, 0, output, "!")

        sampler = _StartSampler(["sandy", "exec"], {"A": "b"}, Path("/w"), up_done)
        with patch("tests.e2e.test_confinement.subprocess.run", side_effect=run) as ran:
            sampler.run()
        self.assertEqual(START_ATTACHES_AFTER_UP, 2)
        self.assertEqual(
            sampler.results,
            [
                (False, 0, "before!"),
                (False, 0, "during!"),
                (True, 0, "after 1!"),
                (True, 0, "after 2!"),
            ],
        )
        self.assertIsNone(sampler.error)
        ran.assert_called_with(
            ["sandy", "exec"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            shell=False,
            cwd=Path("/w"),
            env={"A": "b"},
        )

    def test_sampler_keeps_an_error_for_the_main_thread(self):
        error = subprocess.TimeoutExpired(["sandy"], 120)
        sampler = _StartSampler(["sandy"], {}, Path("/w"), threading.Event())
        with patch("tests.e2e.test_confinement.subprocess.run", side_effect=error):
            sampler.run()
        self.assertIs(sampler.error, error)
        self.assertEqual(sampler.results, [])

    def test_entry_failure_reason(self):
        output = "I: x\r\nE: Container entry failed: 'Container is still starting'\r\n"
        self.assertEqual(
            _entry_failure_reason(output),
            "E: Container entry failed: 'Container is still starting'",
        )
        self.assertEqual(_entry_failure_reason("E: other\n"), "(no helper message)")


class LeaderHoldTests(unittest.TestCase):
    """The hold case stops only a process of this run's container scope.

    Mocks: os.pidfd_open (a pipe stands in for the pidfd), the /proc text
    that the helpers read, and the machined state directory (a temporary
    directory).
    """

    def open_with_cgroup(self, cgroup: str, exited: bool = False) -> tuple[int, int]:
        read_fd, write_fd = os.pipe()
        try:
            if exited:
                # A readable pidfd means that the process exited.
                os.write(write_fd, b"x")
            with patch(
                "tests.e2e.test_confinement.os.pidfd_open", return_value=read_fd
            ), patch.object(Path, "read_text", return_value=cgroup):
                try:
                    return _open_scope_process(42, "sandy-e2e-main-1.scope"), read_fd
                except BaseException:
                    # The pidfd is closed on every failure.
                    with self.assertRaises(OSError):
                        os.fstat(read_fd)
                    raise
        finally:
            os.close(write_fd)

    def test_open_scope_process_accepts_only_the_scope(self):
        for cgroup in (
            "0::/system.slice/sandy-e2e-main-1.scope\n",
            "0::/system.slice/sandy-e2e-main-1.scope/payload\n",
        ):
            with self.subTest(cgroup=cgroup):
                pidfd, read_fd = self.open_with_cgroup(cgroup)
                self.assertEqual(pidfd, read_fd)
                os.close(pidfd)
        for cgroup in (
            "0::/system.slice/sandy-e2e-main-10.scope/payload\n",
            "0::/system.slice/ssh.service\n",
            "0::/\n",
        ):
            with self.subTest(cgroup=cgroup):
                with self.assertRaises(E2EFailure):
                    self.open_with_cgroup(cgroup)

    def test_open_scope_process_rejects_an_exited_process(self):
        with self.assertRaisesRegex(E2EFailure, "exited"):
            self.open_with_cgroup(
                "0::/system.slice/sandy-e2e-main-1.scope/payload\n", exited=True
            )

    def test_machined_leader_parses_the_state_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state = Path(temp_dir)
            with patch("tests.e2e.test_confinement.MACHINES_STATE", state):
                self.assertEqual(_machined_leader("e2e-main-1"), 0)
                (state / "e2e-main-1").write_text("NAME=e2e-main-1\nLEADER=4242\n")
                self.assertEqual(_machined_leader("e2e-main-1"), 4242)
                (state / "e2e-main-1").write_text("LEADER=\nLEADER=x\n")
                self.assertEqual(_machined_leader("e2e-main-1"), 0)

    def test_has_payload_requires_the_leader_and_container_pid_2(self):
        statuses = {
            "/proc/77/status": "PPid:\t42\nNSpid:\t77\t2\n",
            "/proc/78/status": "PPid:\t42\nNSpid:\t78\t9\n",
            "/proc/79/status": "PPid:\t41\nNSpid:\t79\t2\n",
            "/proc/80/status": "PPid:\t42\nNSpid:\t80\t5\t2\n",
        }

        def read_text(path: Path, **kwargs) -> str:
            if str(path) not in statuses:
                raise FileNotFoundError(str(path))
            return statuses[str(path)]

        for children, expected in (
            ([77], True),
            ([81, 78, 77], True),
            ([78, 79, 80, 81], False),
            ([], False),
        ):
            with self.subTest(children=children):
                with patch(
                    "tests.e2e.test_confinement._children", return_value=children
                ), patch.object(
                    Path, "read_text", autospec=True, side_effect=read_text
                ):
                    self.assertEqual(_has_payload(42), expected)


class PayloadForkHoldTests(unittest.TestCase):
    """The S2 case holds the payload at its fork and releases the Leader.

    Mocks: sandy's ptrace helpers (a namespace object), os.waitpid, the
    payload checks, the pidfd check, and the poll sleep.
    """

    SEIZE = 0x4206
    DETACH = 17
    WALL = 0x40000000

    def fake_sandy(self, events: "list[int]") -> SimpleNamespace:
        """Return sandy's ptrace helpers; GETEVENTMSG gives the forked child."""
        calls: list = []

        def entry_syscall(name, request, pid, addr=0, data=0):
            calls.append((request, pid, data if request != PTRACE_GETEVENTMSG else 0))
            if request == PTRACE_GETEVENTMSG:
                ctypes.c_ulong.from_address(data).value = events.pop(0)
            return 0

        return SimpleNamespace(
            calls=calls,
            _entry_syscall=entry_syscall,
            PTRACE_SEIZE=self.SEIZE,
            PTRACE_DETACH=self.DETACH,
            WAIT_ALL=self.WALL,
            _stop_seized_tracee=MagicMock(return_value=10),
            _ptrace_detach=MagicMock(),
        )

    def hold(self, sandy, waits, payloads, existing=False, alive=True):
        with patch(
            "tests.e2e.test_confinement.os.waitpid", side_effect=waits
        ) as waitpid, patch(
            "tests.e2e.test_confinement._has_payload", return_value=existing
        ), patch(
            "tests.e2e.test_confinement._is_payload",
            side_effect=lambda pid, leader: pid in payloads,
        ), patch(
            "tests.e2e.test_confinement._pidfd_alive", return_value=alive
        ), patch(
            "tests.e2e.test_confinement.time.sleep"
        ):
            return _hold_payload_at_fork(sandy, 42, 5), waitpid

    @staticmethod
    def event_stop(event: int) -> int:
        return (event << 16) | (signal.SIGTRAP << 8) | 0x7F

    def test_returns_0_and_releases_a_leader_that_has_its_payload(self):
        sandy = self.fake_sandy([])
        result, waitpid = self.hold(sandy, [], set(), existing=True)
        self.assertEqual(result, 0)
        self.assertEqual(sandy.calls, [(self.SEIZE, 42, PTRACE_FORK_OPTIONS)])
        waitpid.assert_not_called()
        # The Leader runs, so it is stopped first; its signal is given back.
        sandy._stop_seized_tracee.assert_called_once_with(42)
        sandy._ptrace_detach.assert_called_once_with(42, 10)

    def test_holds_the_payload_and_releases_the_leader_at_the_fork(self):
        sandy = self.fake_sandy([90, 77])
        waits = [
            (0, 0),
            # A signal-delivery-stop: the signal goes back to the Leader.
            (42, (signal.SIGCHLD << 8) | 0x7F),
            (42, self.event_stop(1)),
            (90, self.event_stop(128)),
            (42, self.event_stop(3)),
            (77, self.event_stop(128)),
        ]
        result, waitpid = self.hold(sandy, waits, {77})
        self.assertEqual(result, 77)
        self.assertEqual(
            sandy.calls,
            [
                (self.SEIZE, 42, PTRACE_FORK_OPTIONS),
                (PTRACE_CONT, 42, signal.SIGCHLD),
                (PTRACE_GETEVENTMSG, 42, 0),
                # Another child is released at once.
                (self.DETACH, 90, 0),
                (PTRACE_CONT, 42, 0),
                (PTRACE_GETEVENTMSG, 42, 0),
            ],
        )
        self.assertEqual(waitpid.call_args_list[-1], call(77, self.WALL))
        # The Leader is in its fork stop, so it needs no interrupt.
        sandy._stop_seized_tracee.assert_not_called()
        sandy._ptrace_detach.assert_called_once_with(42, 0)

    def test_fails_when_the_leader_exits_or_is_gone(self):
        sandy = self.fake_sandy([])
        sandy._stop_seized_tracee.side_effect = ProcessLookupError("gone")
        with self.assertRaisesRegex(E2EFailure, "exited before its payload"):
            self.hold(sandy, [(42, 0)], set())
        sandy._ptrace_detach.assert_not_called()
        sandy = self.fake_sandy([])
        with self.assertRaisesRegex(E2EFailure, "exited before the seize"):
            self.hold(sandy, [], set(), alive=False)
        sandy._ptrace_detach.assert_called_once_with(42, 10)


class CgroupPollTests(unittest.TestCase):
    """The scope tests poll attach leaves that sandy removes meanwhile.

    Mocks: Path.read_text raises the errors of a removed cgroup. The
    directory listing is a real temporary directory.
    """

    def test_a_cgroup_removed_during_the_read_is_skipped(self):
        # Regression test: a leaf removed between the open and the read gave
        # OSError ENODEV, which failed "the last attach out stops the
        # container, once" on systemd 257.
        leaf = "attach-" + "0" * 32
        with tempfile.TemporaryDirectory() as temp_dir:
            unit_dir = Path(temp_dir)
            (unit_dir / leaf).mkdir()
            for error in (FileNotFoundError(2, "x"), OSError(19, "No such device")):
                with self.subTest(error=error):
                    with patch(
                        "tests.e2e.test_scope._unit_dir", return_value=unit_dir
                    ), patch.object(Path, "read_text", side_effect=error):
                        self.assertEqual(_leaves("e2e-scope-1"), {})

    def test_other_read_errors_are_not_hidden(self):
        with patch.object(Path, "read_text", side_effect=OSError(13, "denied")):
            with self.assertRaises(OSError):
                _read_cgroup_file(Path("/sys/fs/cgroup/x/cgroup.events"))
        with patch.object(Path, "read_text", return_value="populated 1\n"):
            self.assertEqual(
                _read_cgroup_file(Path("/sys/fs/cgroup/x/cgroup.events")),
                "populated 1\n",
            )


class KeepaliveRestartTests(unittest.TestCase):
    """The keepalive restart wait reads the child list once per poll.

    Mocks: the child list of the keepalive.
    """

    def test_a_list_that_empties_between_reads_is_not_an_error(self):
        # Regression test: the predicate read the list twice. The first read
        # held the killed sleep and the second read was empty (IndexError on
        # systemd 257).
        lists = iter(([10], []))
        with patch(
            "tests.e2e.test_scope._children", side_effect=lambda pid: next(lists)
        ) as children:
            self.assertFalse(_has_new_only_child(5, 10))
        children.assert_called_once_with(5)

    def test_only_one_new_child_counts(self):
        for current, expected in (([], False), ([10], False), ([11], True)):
            with self.subTest(current=current):
                with patch("tests.e2e.test_scope._children", return_value=current):
                    self.assertEqual(_has_new_only_child(5, 10), expected)
        with patch("tests.e2e.test_scope._children", return_value=[11, 12]):
            self.assertFalse(_has_new_only_child(5, 10))


class SandyInvocationTests(unittest.TestCase):
    """The harness runs sandy as a real `sudo` user would. It mocks run()."""

    def make_context(self) -> E2EContext:
        context = E2EContext.__new__(E2EContext)
        context.workspace = Path("/tmp/sandy-e2e-test/workspace")
        context.shared = Path("/tmp/sandy-e2e-test/shared")
        context.hide_iptables = False
        return context

    def test_hidden_iptables_wraps_sandy_in_a_private_mount_namespace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "xtables-nft-multi"
            binary.write_bytes(b"")
            link = root / "iptables"
            link.symlink_to(binary)
            context = self.make_context()
            context.root = root
            context.hide_iptables = True
            with patch("tests.e2e.support.shutil.which", return_value=str(link)), patch(
                "tests.e2e.support.IPTABLES_BINARY_DIRS", (root,)
            ), patch.object(E2EContext, "run") as run:
                context.sandy(["down"])
            command = run.call_args.args[0]
            self.assertEqual(
                command[:11],
                [
                    "unshare",
                    "--mount",
                    "--propagation",
                    "private",
                    "--",
                    "/bin/sh",
                    "-c",
                    'mount --bind -- "$1" "$2" && shift 2 && exec "$@"',
                    "sh",
                    str(root / "no-iptables"),
                    str(binary),
                ],
            )
            self.assertEqual(command[-1], "down")
            blocker = root / "no-iptables"
            self.assertEqual(stat.S_IMODE(blocker.stat().st_mode), 0o644)
            self.assertEqual(blocker.read_bytes(), b"")

    def test_hidden_iptables_rejects_unexpected_binary(self):
        context = self.make_context()
        context.root = Path("/tmp/sandy-e2e-test")
        for located in (None, "/tmp/iptables"):
            with self.subTest(located=located):
                with patch("tests.e2e.support.shutil.which", return_value=located):
                    with self.assertRaises(E2EFailure):
                        context.without_iptables(["sandy"])

    def test_sandy_passes_the_invoking_user(self):
        context = self.make_context()
        with patch.object(E2EContext, "run") as run:
            context.sandy(["status"])
            context.sandy(["status"], environment={"PATH": "/usr/bin", "SANDY_X": "1"})
        default_environment = run.call_args_list[0].kwargs["environment"]
        self.assertEqual(default_environment["SUDO_UID"], str(CONTAINER_USER_ID))
        self.assertEqual(
            default_environment["PATH"], context.safe_environment()["PATH"]
        )
        self.assertEqual(
            run.call_args_list[1].kwargs["environment"],
            {"PATH": "/usr/bin", "SANDY_X": "1", "SUDO_UID": str(CONTAINER_USER_ID)},
        )

    def test_sandy_runs_the_selected_executable(self):
        context = self.make_context()
        copy = Path("/tmp/sandy-e2e-test/sandy-group-writable/sandy")
        with patch.object(E2EContext, "run") as run:
            context.sandy(["status"])
            context.sandy(["status"], executable=copy)
        self.assertEqual(run.call_args_list[0].args[0][0], str(SANDY))
        self.assertEqual(run.call_args_list[1].args[0][0], str(copy))
        self.assertEqual(
            run.call_args_list[0].args[0][1:], run.call_args_list[1].args[0][1:]
        )

    def test_group_writable_sandy_copies_the_scripts_into_the_run_root(self):
        # No mocks: the copy is made in a temporary run root. A checkout made
        # with umask 002 already has sandy at mode 0775, so compare with the
        # checkout before the call, not with a fixed mode.
        checkout_mode = SANDY.stat().st_mode
        checkout_bytes = SANDY.read_bytes()
        with tempfile.TemporaryDirectory() as temp_dir:
            context = self.make_context()
            context.root = Path(temp_dir)
            copy = context.group_writable_sandy()
            self.assertEqual(copy, context.root / "sandy-group-writable" / "sandy")
            self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o775)
            for name in SANDY_SCRIPT_NAMES:
                source = REPO_ROOT / name
                target = copy.parent / name
                self.assertEqual(target.read_bytes(), source.read_bytes())
                if name != "sandy":
                    self.assertEqual(target.stat().st_mode, source.stat().st_mode)
            # A second call reuses the directory.
            self.assertEqual(context.group_writable_sandy(), copy)
        # The checkout does not change.
        self.assertEqual(SANDY.stat().st_mode, checkout_mode)
        self.assertEqual(SANDY.read_bytes(), checkout_bytes)

    def test_builds_answer_only_the_two_acl_prompts(self):
        self.assertEqual(ACL_PROMPT_ANSWERS, "y\ny\n")
        context = self.make_context()
        context.main_name = "e2e-main-abc123"
        context.main_user = "developer"
        context.owned_containers = {}
        with patch.object(E2EContext, "sandy") as sandy_call, patch.object(
            E2EContext, "wait_for_machine"
        ), patch.object(E2EContext, "minimal_environment", return_value={}):
            context.build_main()
            context.build_minimal("e2e-cache-abc123", "developer")
        for entry in sandy_call.call_args_list:
            self.assertEqual(entry.kwargs["input_text"], ACL_PROMPT_ANSWERS)


if __name__ == "__main__":
    unittest.main()
