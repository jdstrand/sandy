#!/usr/bin/env python3

"""Unit tests for safety-critical end-to-end harness control flow."""

from __future__ import annotations

import ctypes
import os
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import ANY, MagicMock, call, patch

from tests.e2e import support
from tests.e2e import runner, test_mounts
from tests.e2e.support import (
    BASE_IMAGE_VARIABLE,
    DEFAULT_HOST_GID,
    DEFAULT_HOST_UID,
    DEFAULT_TIMEOUT,
    HOST_UID_MAX,
    HOST_UID_VARIABLE,
    REPO_ROOT,
    SANDY,
    SANDY_SCRIPT_NAMES,
    STAND_IN_MACHINECTL,
    CommandResult,
    E2EContext,
    E2EFailure,
    FilesystemFixtureIdentity,
    parse_base_image,
    parse_host_ids,
)
from tests.e2e.test_confinement import (
    ENTRY_FAILURE,
    MOUNTS_WAIT_TIMEOUT,
    PTRACE_CONT,
    PTRACE_FORK_OPTIONS,
    PTRACE_GETEVENTMSG,
    START_ATTACHES_AFTER_UP,
    _entry_failure_reason,
    _has_payload,
    _hold_payload_at_fork,
    _load_sandy_module,
    _machined_leader,
    _open_scope_process,
    _Session,
    _StartSampler,
    _exec_when_mounted,
)
from tests.e2e.test_network import _wait_for_public_https
from tests.e2e.test_scope import _has_new_only_child, _leaves, _read_cgroup_file

# The host directory in which up makes its temporary directories. No test reads
# or changes it: preflight lists entries there, and cleanup removes them.
HOST_UP_TEMPORARY_ROOT = support.UP_TEMPORARY_ROOT


def setUpModule() -> None:
    """Point the harness at a private, empty directory instead of the host /tmp.

    A test that needs entries there patches UP_TEMPORARY_ROOT again.
    """
    directory = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(directory.cleanup)
    patcher = patch.object(support, "UP_TEMPORARY_ROOT", Path(directory.name))
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


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
        self._scratch_mounts = []
        self.bridge = False
        self.firewall: list[str] = []
        self.bridge_checks = 0
        self.firewall_checks = 0
        self.cache_purges = 0
        self.slice_removals = 0
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
        workspace: str | None = None,
        shared: str | None = None,
    ) -> CommandResult:
        del name, user, expected, timeout, environment, input_text, executable
        del workspace, shared
        self.sandy_calls.append(list(arguments))
        return CommandResult(("sandy", *arguments), 0, "", "")

    def purge_cache(self) -> None:
        self.cache_purges += 1

    def remove_shared_slice(self) -> None:
        self.slice_removals += 1

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
        workspace: str | None = None,
        shared: str | None = None,
    ) -> CommandResult:
        del arguments, name, user, timeout, environment, input_text, executable
        del workspace, shared
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
            self.assertEqual(context.slice_removals, 0)
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
            self.assertEqual(context.slice_removals, 1)
            self.assertEqual(context.state_checks, 1)

    def test_cleanup_and_preflight_do_not_use_the_host_temporary_directory(self):
        # Regression test: the cleanup and preflight tests read the host /tmp.
        # cleanup removed a sandy-keepalive-* directory of the test user, and
        # preflight refused one of root. A real decoy directory in the host
        # /tmp; mocks: the host state probes of CleanupProbeContext.
        decoy = Path(
            tempfile.mkdtemp(prefix="sandy-keepalive-unit-", dir=HOST_UP_TEMPORARY_ROOT)
        )
        try:
            self.assertEqual(support.up_temporary_directories(), [])
            with tempfile.TemporaryDirectory() as parent:
                root = Path(parent) / "run"
                root.mkdir()
                context = CleanupProbeContext(root, host_state_owned=True)

                self.assertEqual(context.cleanup(), [])

            self.assertTrue(decoy.is_dir())
        finally:
            decoy.rmdir()

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


class SliceProbeContext(CleanupProbeContext):
    """Record each command; return queued output for systemctl show."""

    def __init__(self, root: Path, *, host_state_owned: bool = True) -> None:
        super().__init__(root, host_state_owned=host_state_owned)
        self.commands: list[list[str]] = []
        self.shows: list[str] = []
        self.on_stop: Callable[[], None] | None = None

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
        del expected, timeout, environment, input_text, cwd
        self.commands.append(list(command))
        if command[1] == "stop" and self.on_stop is not None:
            self.on_stop()
        stdout = self.shows.pop(0) if command[1] == "show" else ""
        return CommandResult(tuple(command), 0, stdout, "")


class SharedLimitStateTests(unittest.TestCase):
    """sandy.slice and the saved shared limits in preflight and cleanup.

    Mocks: systemctl output, the slice cgroup (a temporary path), and the
    cache paths (a temporary directory). The tests call the real E2EContext
    methods that the probe replaces. E2E runs prove the real state.
    """

    SHOW = [
        "systemctl",
        "show",
        "sandy.slice",
        "-p",
        "ActiveState",
        "-p",
        "FragmentPath",
        "-p",
        "DropInPaths",
    ]

    @staticmethod
    def show(active="inactive", fragment="", dropins=""):
        return f"ActiveState={active}\nFragmentPath={fragment}\nDropInPaths={dropins}\n"

    def test_slice_artifacts(self):
        with tempfile.TemporaryDirectory() as parent:
            cgroup = Path(parent) / "sandy.slice"
            with patch.object(support, "SLICE_CGROUP", cgroup):
                context = SliceProbeContext(Path(parent))
                context.shows = [self.show()]
                self.assertEqual(context.slice_artifacts(), [])
                self.assertEqual(context.commands, [self.SHOW])
                cgroup.mkdir()
                dropin = "/run/systemd/system.control/sandy.slice.d/50-TasksMax.conf"
                context.shows = [
                    self.show("active", "/etc/systemd/system/sandy.slice", dropin)
                ]
                self.assertEqual(
                    context.slice_artifacts(),
                    [
                        "sandy.slice is active",
                        "sandy.slice unit file /etc/systemd/system/sandy.slice",
                        f"sandy.slice drop-ins {dropin}",
                        f"cgroup {cgroup}",
                    ],
                )
                context.shows = ["ActiveState=inactive\n"]
                with self.assertRaisesRegex(E2EFailure, "Unexpected systemctl show"):
                    context.slice_artifacts()

    def test_remove_shared_slice_reverts_and_stops_an_empty_slice(self):
        with tempfile.TemporaryDirectory() as parent:
            cgroup = Path(parent) / "sandy.slice"
            events = cgroup / "cgroup.events"
            with patch.object(support, "SLICE_CGROUP", cgroup):
                context = SliceProbeContext(Path(parent))
                # No state: nothing to do.
                context.shows = [self.show()]
                E2EContext.remove_shared_slice(context)
                self.assertEqual(context.commands, [self.SHOW])
                # A slice with processes is never stopped.
                cgroup.mkdir()
                events.write_text("populated 1\nfrozen 0\n", encoding="ascii")
                context.commands.clear()
                context.shows = [self.show("active")]
                with self.assertRaisesRegex(E2EFailure, "still has processes"):
                    E2EContext.remove_shared_slice(context)
                self.assertEqual(context.commands, [self.SHOW])
                # An empty slice: revert, stop, and verify.
                events.write_text("populated 0\nfrozen 0\n", encoding="ascii")
                context.commands.clear()
                context.shows = [self.show("active", dropins="x.conf"), self.show()]

                def remove_cgroup() -> None:
                    events.unlink()
                    cgroup.rmdir()

                context.on_stop = remove_cgroup
                E2EContext.remove_shared_slice(context)
                self.assertEqual(
                    context.commands,
                    [
                        self.SHOW,
                        ["systemctl", "revert", "sandy.slice"],
                        ["systemctl", "stop", "sandy.slice"],
                        self.SHOW,
                    ],
                )
                # State that remains after the stop is an error.
                context.on_stop = None
                context.shows = [self.show("active"), self.show("active")]
                with self.assertRaisesRegex(E2EFailure, "sandy.slice state remains"):
                    E2EContext.remove_shared_slice(context)

    def test_preflight_refuses_a_pre_existing_slice(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            machines = root / "machines"
            machines.mkdir()
            context = SliceProbeContext(root / "run", host_state_owned=False)
            context.filesystem_machine_link = machines / "sandy.e2e-filesystem-x"
            context.filesystem_image_root = root / "missing-image"
            context.filesystem_host_target = root / "missing-host"
            with patch.object(support.os, "getuid", return_value=0), patch.dict(
                support.os.environ, {"SANDY_E2E": "1"}
            ), patch.object(support, "SYSTEMD_MACHINES", machines), patch.object(
                support, "INSTALL_DIR", root / "missing-install"
            ), patch.object(
                support.shutil, "which", return_value="/usr/bin/tool"
            ), patch.object(
                context, "slice_artifacts", return_value=["sandy.slice is active"]
            ):
                with self.assertRaisesRegex(
                    E2EFailure,
                    "Refusing to use pre-existing sandy.slice state: sandy.slice is "
                    "active",
                ):
                    context.preflight()
            # The run owns no host state, so cleanup leaves the slice alone.
            self.assertFalse(context._host_state_owned)
            self.assertEqual(context.commands, [])

    def test_purge_cache_removes_the_saved_limits_and_the_locks(self):
        with tempfile.TemporaryDirectory() as parent:
            cache = Path(parent) / "sandy.__cache"
            cache.mkdir()
            files = tuple(
                cache / name
                for name in (
                    "port_mappings.lock",
                    "lifecycle.lock",
                    "shared_limits.lock",
                    "shared_limits.json",
                )
            )
            for path in files:
                path.write_text("", encoding="ascii")
            # The up lock of each container name stays after rm --cache too.
            (cache / "up-e2e-main-abc123.lock").write_text("", encoding="ascii")
            context = SliceProbeContext(Path(parent))
            with patch.object(support, "CACHE_DIR", cache), patch.object(
                support, "PERSISTENT_FILES", files
            ), patch.object(context, "_persistent_lock_is_safe", return_value=True):
                E2EContext.purge_cache(context)
                self.assertEqual(context.sandy_calls, [["rm", "--cache", "--force"]])
                self.assertFalse(cache.exists())
                # An unsafe file stops the purge.
                cache.mkdir()
                files[3].write_text("{}\n", encoding="ascii")
                with patch.object(
                    context, "_persistent_lock_is_safe", return_value=False
                ):
                    with self.assertRaisesRegex(E2EFailure, "Unsafe persistent file"):
                        E2EContext.purge_cache(context)
                self.assertTrue(files[3].exists())


class CacheLockTests(unittest.TestCase):
    """Which files of the cache directory are the persistent locks.

    Mocks: the cache directory, a temporary one, and the metadata check of a
    lock file.
    """

    def test_up_locks_count_as_persistent_locks(self):
        with tempfile.TemporaryDirectory() as parent:
            cache = Path(parent) / "sandy.__cache"
            cache.mkdir()
            locks = (
                cache / "lifecycle.lock",
                cache / "up-e2e-main-abc123.lock",
                cache / "up-a.lock",
            )
            for path in locks:
                path.write_text("", encoding="ascii")
            context = SliceProbeContext(Path(parent))
            with patch.object(support, "CACHE_DIR", cache), patch.object(
                support, "PERSISTENT_LOCKS", locks[:1]
            ), patch.object(context, "_persistent_lock_is_safe", return_value=True):
                self.assertEqual(context._up_locks(), sorted(locks[1:]))
                self.assertTrue(context._cache_holds_only_safe_locks())
                for name in ("up-Bad.lock", "up-a-.lock", "up-a.lock.tmp", "x.tar"):
                    with self.subTest(name=name):
                        other = cache / name
                        other.write_text("", encoding="ascii")
                        try:
                            self.assertNotIn(other, context._up_locks())
                            self.assertFalse(context._cache_holds_only_safe_locks())
                        finally:
                            other.unlink()
            with patch.object(support, "CACHE_DIR", cache / "missing"):
                self.assertEqual(context._up_locks(), [])


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
            "0::/sandy.slice/sandy-e2e-main-1.scope\n",
            "0::/sandy.slice/sandy-e2e-main-1.scope/payload\n",
        ):
            with self.subTest(cgroup=cgroup):
                pidfd, read_fd = self.open_with_cgroup(cgroup)
                self.assertEqual(pidfd, read_fd)
                os.close(pidfd)
        for cgroup in (
            "0::/sandy.slice/sandy-e2e-main-10.scope/payload\n",
            # The scope of an earlier Sandy, outside the shared slice.
            "0::/system.slice/sandy-e2e-main-1.scope/payload\n",
            "0::/system.slice/ssh.service\n",
            "0::/\n",
        ):
            with self.subTest(cgroup=cgroup):
                with self.assertRaises(E2EFailure):
                    self.open_with_cgroup(cgroup)

    def test_open_scope_process_rejects_an_exited_process(self):
        with self.assertRaisesRegex(E2EFailure, "exited"):
            self.open_with_cgroup(
                "0::/sandy.slice/sandy-e2e-main-1.scope/payload\n", exited=True
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


class ExecWhenMountedTests(unittest.TestCase):
    """A case that attaches while up still starts waits for up's mounts.

    Mocks: the attach (sandy exec), the clock, and the sleep.
    """

    refusal = CommandResult(
        ("sandy",),
        ENTRY_FAILURE,
        "",
        "E: Container entry failed: 'Container is still starting; try again'\n",
    )
    success = CommandResult(("sandy",), 0, "out", "")

    def run_helper(self, results, **patches):
        context = SimpleNamespace(main_name="e2e-main-x", main_user="developer")
        with ExitStack() as stack:
            attach = stack.enter_context(
                patch("tests.e2e.test_confinement._exec", side_effect=results)
            )
            sleep = stack.enter_context(patch("tests.e2e.test_confinement.time.sleep"))
            for name, value in patches.items():
                stack.enter_context(
                    patch(f"tests.e2e.test_confinement.time.{name}", value)
                )
            result = _exec_when_mounted(cast(E2EContext, context), "true")
        return result, attach, sleep

    def test_returns_at_once_when_the_attach_works(self):
        result, attach, sleep = self.run_helper([self.success])
        self.assertIs(result, self.success)
        attach.assert_called_once_with(ANY, "true", expected=None)
        sleep.assert_not_called()

    def test_retries_only_the_refusal_for_a_container_that_is_starting(self):
        result, attach, sleep = self.run_helper(
            [self.refusal, self.refusal, self.success]
        )
        self.assertIs(result, self.success)
        self.assertEqual(attach.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_any_other_failure_is_reported_at_once(self):
        for failure in (
            CommandResult(("sandy",), 1, "", "E: Container not found or not running"),
            CommandResult(
                ("sandy",), ENTRY_FAILURE, "", "E: Container entry failed: x"
            ),
            CommandResult(("sandy",), 2, "", "still starting"),
        ):
            with self.subTest(failure=failure):
                with self.assertRaisesRegex(E2EFailure, "Unexpected result"):
                    self.run_helper([failure])

    def test_gives_up_when_the_mounts_do_not_come(self):
        with self.assertRaisesRegex(E2EFailure, "did not mount the directories"):
            self.run_helper(
                [self.refusal, self.refusal],
                monotonic=MagicMock(side_effect=[0.0, MOUNTS_WAIT_TIMEOUT + 1.0]),
            )


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
        context.base_image = None
        context.host_uid = DEFAULT_HOST_UID
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

    def test_broken_systemd_run_wraps_sandy_in_a_private_mount_namespace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "systemd-run"
            binary.write_bytes(b"")
            context = self.make_context()
            context.root = root
            with patch(
                "tests.e2e.support.shutil.which", return_value=str(binary)
            ), patch("tests.e2e.support.SYSTEMD_RUN_BINARY_DIRS", (root,)):
                command = context.with_a_broken_systemd_run(["sandy", "up"])
            blocker = root / "broken-systemd-run"
            self.assertEqual(
                command,
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
                    str(blocker),
                    str(binary),
                    "sandy",
                    "up",
                ],
            )
            # sandy finds the tool, and the exec of the supervisor fails with
            # ENOEXEC.
            self.assertEqual(stat.S_IMODE(blocker.stat().st_mode), 0o755)
            self.assertEqual(blocker.read_bytes(), b"not an executable\n")

    def test_hidden_system_bus_wraps_sandy_in_a_private_mount_namespace(self):
        # Mocks: the path of the system bus socket, a real socket in a
        # temporary directory.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bus = root / "system_bus_socket"
            with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as server:
                server.bind(str(bus))
                context = self.make_context()
                context.root = root
                with patch("tests.e2e.support.SYSTEM_BUS_SOCKET", bus):
                    command = context.with_a_hidden_system_bus(["sandy", "rm"])
            blocker = root / "hidden-system-bus"
            self.assertEqual(
                command,
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
                    str(blocker),
                    str(bus),
                    "sandy",
                    "rm",
                ],
            )
            self.assertEqual(blocker.read_bytes(), b"")
            self.assertEqual(stat.S_IMODE(blocker.stat().st_mode), 0o644)

    def test_hidden_system_bus_rejects_a_missing_or_unexpected_socket(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            regular = root / "regular"
            regular.write_bytes(b"")
            context = self.make_context()
            context.root = root
            for bus in (root / "missing", regular):
                with self.subTest(bus=bus.name):
                    with patch("tests.e2e.support.SYSTEM_BUS_SOCKET", bus):
                        with self.assertRaises(E2EFailure):
                            context.with_a_hidden_system_bus(["sandy"])
            self.assertFalse((root / "hidden-system-bus").exists())

    def test_stand_in_machinectl_wraps_sandy_in_a_private_mount_namespace(self):
        # Mocks: the lookup of machinectl, a file in a temporary directory.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "machinectl"
            binary.write_bytes(b"")
            context = self.make_context()
            context.root = root
            with patch(
                "tests.e2e.support.shutil.which", return_value=str(binary)
            ), patch("tests.e2e.support.MACHINECTL_BINARY_DIRS", (root,)):
                command, environment = context.with_a_machinectl_that_stops_nothing(
                    ["sandy", "rm"]
                )
            stand_in = root / "stand-in-machinectl"
            real = root / "real-machinectl"
            self.assertEqual(
                command,
                [
                    "unshare",
                    "--mount",
                    "--propagation",
                    "private",
                    "--",
                    "/bin/sh",
                    "-c",
                    'mount --bind -- "$1" "$2" && mount --bind -- "$3" "$1" '
                    '&& shift 3 && exec "$@"',
                    "sh",
                    str(binary),
                    str(real),
                    str(stand_in),
                    "sandy",
                    "rm",
                ],
            )
            self.assertEqual(environment["SANDY_TEST_MACHINECTL"], str(real))
            self.assertEqual(environment["LC_ALL"], "C.UTF-8")
            self.assertEqual(stand_in.read_text(encoding="ascii"), STAND_IN_MACHINECTL)
            self.assertEqual(stat.S_IMODE(stand_in.stat().st_mode), 0o755)
            self.assertEqual(real.read_bytes(), b"")
            self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o755)

    def test_stand_in_machinectl_rejects_unexpected_binary(self):
        context = self.make_context()
        context.root = Path("/tmp/sandy-e2e-test")
        for located in (None, "/tmp/machinectl"):
            with self.subTest(located=located):
                with patch("tests.e2e.support.shutil.which", return_value=located):
                    with self.assertRaises(E2EFailure):
                        context.with_a_machinectl_that_stops_nothing(["sandy"])

    def test_stand_in_machinectl_stops_nothing_and_runs_the_real_one(self):
        # Mocks: the real machinectl, a script that prints its arguments.
        # The stand-in itself runs in a real /bin/sh.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stand_in = root / "stand-in-machinectl"
            stand_in.write_text(STAND_IN_MACHINECTL, encoding="ascii")
            real = root / "real-machinectl"
            real.write_text('#!/bin/sh\necho "real: $*"\n', encoding="ascii")
            real.chmod(0o755)
            environment = {"PATH": "/usr/bin:/bin", "SANDY_TEST_MACHINECTL": str(real)}
            outputs = {}
            for verb in ("poweroff", "terminate", "show"):
                completed = subprocess.run(
                    ["/bin/sh", str(stand_in), verb, "e2e-main-abc123"],
                    capture_output=True,
                    text=True,
                    env=environment,
                    check=False,
                )
                outputs[verb] = (completed.returncode, completed.stdout)
        self.assertEqual(
            outputs,
            {
                "poweroff": (0, ""),
                "terminate": (0, ""),
                "show": (0, "real: show e2e-main-abc123\n"),
            },
        )

    def test_broken_systemd_run_rejects_unexpected_binary(self):
        context = self.make_context()
        context.root = Path("/tmp/sandy-e2e-test")
        for located in (None, "/tmp/systemd-run"):
            with self.subTest(located=located):
                with patch("tests.e2e.support.shutil.which", return_value=located):
                    with self.assertRaises(E2EFailure):
                        context.with_a_broken_systemd_run(["sandy"])

    def test_start_up_runs_sandy_in_the_background_with_a_log(self):
        # Mocks: subprocess.Popen.
        with tempfile.TemporaryDirectory() as temp_dir:
            context = self.make_context()
            context.root = Path(temp_dir)
            with patch("tests.e2e.support.subprocess.Popen") as popen:
                named = context.start_up(
                    "e2e-box",
                    "developer",
                    ["up", "--detach"],
                    "interrupted-no-mounts",
                    workspace="no-such-directory",
                    shared="no-such-directory",
                )
                default = context.start_up("e2e-box", "developer", ["up"], "up")
            self.assertEqual(
                named,
                (
                    popen.return_value,
                    context.root / "interrupted-no-mounts-e2e-box.log",
                ),
            )
            self.assertEqual(default[1], context.root / "up-e2e-box.log")
            self.assertTrue(named[1].is_file())
            self.assertEqual(
                [entry.args[0] for entry in popen.call_args_list],
                [
                    (
                        str(SANDY),
                        "--workspace",
                        "no-such-directory",
                        "--shared",
                        "no-such-directory",
                        "--user",
                        "developer",
                        "--container",
                        "e2e-box",
                        "up",
                        "--detach",
                    ),
                    (
                        str(SANDY),
                        "--workspace",
                        "workspace",
                        "--shared",
                        "shared",
                        "--user",
                        "developer",
                        "--container",
                        "e2e-box",
                        "up",
                    ),
                ],
            )
            options = popen.call_args_list[0].kwargs
            self.assertEqual(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["stdout"].name, str(named[1]))
            self.assertEqual(options["stderr"], subprocess.STDOUT)
            self.assertEqual(options["cwd"], context.root)
            self.assertEqual(options["env"], context.safe_environment())
            # A build passes its own environment, for the cache key of the
            # minimal setup script.
            with patch("tests.e2e.support.subprocess.Popen") as build_popen:
                context.start_up(
                    "e2e-box",
                    "developer",
                    ["up", "--build"],
                    "build",
                    environment={"PATH": "/usr/bin", "SANDY_SETUP_SCRIPT": "/m.sh"},
                )
            self.assertEqual(
                build_popen.call_args.kwargs["env"],
                {"PATH": "/usr/bin", "SANDY_SETUP_SCRIPT": "/m.sh"},
            )
            for name, log_name in (("box", "up"), ("e2e-box", "../up")):
                with self.subTest(name=name, log_name=log_name):
                    with self.assertRaises(E2EFailure):
                        context.start_up(name, "developer", ["up"], log_name)
            self.assertEqual(popen.call_count, 2)

    def test_start_up_gives_sandy_the_default_sigint_action(self):
        # Regression test: a runner that started with SIGINT ignored (for
        # example, as a background job of a shell) passed that on to sandy
        # through execve, and the SIGINT case then blamed sandy. Now the
        # parent has the Python handler during the start; execve resets a
        # handler to the default action. Mocks: subprocess.Popen, which
        # records the SIGINT handler of the parent, and fails the second time.
        seen = []

        def popen(*_args, **_kwargs):
            seen.append(signal.getsignal(signal.SIGINT))
            if len(seen) == 2:
                raise OSError("exec failed")
            return MagicMock()

        with tempfile.TemporaryDirectory() as temp_dir:
            context = self.make_context()
            context.root = Path(temp_dir)
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                with patch("tests.e2e.support.subprocess.Popen", side_effect=popen):
                    context.start_up("e2e-box", "developer", ["up"], "up")
                    self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                    with self.assertRaises(OSError):
                        context.start_up("e2e-box", "developer", ["up"], "up")
                    # The handler of the runner comes back, also on a failure.
                    self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
            finally:
                signal.signal(signal.SIGINT, previous)
        self.assertEqual(seen, [signal.default_int_handler] * 2)

    def test_start_up_refuses_a_blocked_sigint(self):
        # A blocked SIGINT stays blocked through execve. Mocks:
        # subprocess.Popen.
        with tempfile.TemporaryDirectory() as temp_dir:
            context = self.make_context()
            context.root = Path(temp_dir)
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                with patch("tests.e2e.support.subprocess.Popen") as popen:
                    with self.assertRaisesRegex(E2EFailure, "SIGINT is blocked"):
                        context.start_up("e2e-box", "developer", ["up"], "up")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        popen.assert_not_called()

    def test_flock_checks_find_only_the_flock_entries_of_the_path(self):
        # Mocks: the /proc/locks file, in the form that Linux 5.15 and 6.12
        # print for a process that waits in flock(2).
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "port_mappings.lock"
            path.write_bytes(b"")
            inode = path.stat().st_ino
            other = inode + 1
            locks = root / "locks"
            locks.write_text(
                f"1: FLOCK  ADVISORY  WRITE 100 08:02:{inode} 0 EOF\n"
                f"1: -> FLOCK  ADVISORY  WRITE 200 08:02:{inode} 0 EOF\n"
                f"2: POSIX  ADVISORY  WRITE 300 08:02:{inode} 0 EOF\n"
                f"2: -> POSIX  ADVISORY  WRITE 400 08:02:{inode} 0 EOF\n"
                f"3: FLOCK  ADVISORY  WRITE 500 00:22:{other} 0 EOF\n"
                f"3: -> FLOCK  ADVISORY  WRITE 600 00:22:{other} 0 EOF\n",
                encoding="utf-8",
            )
            with patch("tests.e2e.support.PROC_LOCKS", locks):
                self.assertTrue(support.waits_for_flock(200, path))
                # The holder, POSIX locks, and the waiters for another file
                # do not count.
                for pid in (100, 300, 400, 500, 600, 700):
                    with self.subTest(pid=pid):
                        self.assertFalse(support.waits_for_flock(pid, path))
                # Only the holder of the flock(2) lock of the path holds it.
                self.assertTrue(support.holds_flock(100, path))
                for pid in (200, 300, 400, 500, 600, 700):
                    with self.subTest(holder=pid):
                        self.assertFalse(support.holds_flock(pid, path))

    def test_sandy_passes_the_environment_unchanged(self):
        # Regression test: sandy no longer reads SUDO_UID (the ACL path is
        # gone), so the harness must not set it. Mocks: run().
        context = self.make_context()
        with patch.object(E2EContext, "run") as run:
            context.sandy(["status"])
            context.sandy(["status"], environment={"PATH": "/usr/bin", "SANDY_X": "1"})
        # No environment: run() then uses safe_environment() itself.
        self.assertIsNone(run.call_args_list[0].kwargs["environment"])
        self.assertEqual(
            run.call_args_list[1].kwargs["environment"],
            {"PATH": "/usr/bin", "SANDY_X": "1"},
        )
        self.assertNotIn("SUDO_UID", context.safe_environment())

    def test_sandy_names_the_workspace_and_shared_directories(self):
        context = self.make_context()
        with patch.object(E2EContext, "run") as run:
            context.sandy(["status"])
            context.sandy(["status"], workspace="linked", shared="other-shared")
        default, named = (call.args[0] for call in run.call_args_list)
        self.assertEqual(
            default[1:5], ["--workspace", "workspace", "--shared", "shared"]
        )
        self.assertEqual(
            named[1:5], ["--workspace", "linked", "--shared", "other-shared"]
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

    def test_builds_give_up_no_input(self):
        # Regression test: up asks no question during the start (the ACL
        # prompts are gone), so a build passes no input. Mocks: sandy().
        context = self.make_context()
        context.main_name = "e2e-main-abc123"
        context.main_user = "developer"
        context.full_name = "e2e-full-abc123"
        context.full_user = "developer"
        context.full_build_started = False
        context.owned_containers = {}
        with patch.object(E2EContext, "sandy") as sandy_call, patch.object(
            E2EContext, "wait_for_machine"
        ), patch.object(E2EContext, "minimal_environment", return_value={}):
            context.build_main()
            context.build_minimal("e2e-cache-abc123", "developer")
            context.build_lenient("e2e-lenient-abc123", "developer")
            context.build_full()
        self.assertEqual(sandy_call.call_count, 4)
        for entry in sandy_call.call_args_list:
            self.assertNotIn("input_text", entry.kwargs)

    def test_build_lenient_passes_its_timeout_to_sandy(self):
        # A case that expects a short build passes a shorter timeout, so that
        # a build that blocks fails soon. Mocks: sandy(), wait_for_machine().
        context = self.make_context()
        context.owned_containers = {}
        with patch.object(E2EContext, "sandy") as sandy_call, patch.object(
            E2EContext, "wait_for_machine"
        ), patch.object(E2EContext, "minimal_environment", return_value={}):
            context.build_lenient("e2e-lenient-abc123", "developer")
            context.build_lenient("e2e-scan-abc123", "developer", timeout=300)
        self.assertEqual(
            [entry.kwargs["timeout"] for entry in sandy_call.call_args_list],
            [support.BUILD_TIMEOUT, 300],
        )
        self.assertEqual(
            context.owned_containers,
            {"e2e-lenient-abc123": "developer", "e2e-scan-abc123": "developer"},
        )


class EnvironmentSettingTests(unittest.TestCase):
    """The host ids and the base image settings: strict parsing, nothing else."""

    def test_host_ids_default_to_ids_that_no_container_user_has(self):
        # Regression test: the owner, the group, and the container user of the
        # default image all had id 1000, so the mount cases passed for a map
        # that swapped the uid and the gid or kept a host id. The container
        # user is 1000:1000 in the default image and 1001:1001 in Ubuntu 26.04.
        self.assertEqual(parse_host_ids(None), (DEFAULT_HOST_UID, DEFAULT_HOST_GID))
        self.assertEqual((DEFAULT_HOST_UID, DEFAULT_HOST_GID), (1234, 2345))
        self.assertNotEqual(DEFAULT_HOST_UID, DEFAULT_HOST_GID)
        for container_id in (1000, 1001):
            self.assertNotIn(container_id, (DEFAULT_HOST_UID, DEFAULT_HOST_GID))

    def test_a_host_uid_value_is_the_uid_and_the_gid(self):
        for value in ("1", "999", "1000", "1234", "60000"):
            with self.subTest(value=value):
                self.assertEqual(parse_host_ids(value), (int(value), int(value)))
        self.assertEqual(HOST_UID_MAX, 60000)

    def test_host_uid_rejects_everything_else(self):
        for value in (
            "",
            "0",
            "00",
            "01234",
            "-1",
            "+5",
            "60001",
            "100000",
            " 1",
            "1 ",
            "1\n",
            "12a",
            "1e3",
            "0x10",
            "\uff11\uff12",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(E2EFailure, HOST_UID_VARIABLE):
                    parse_host_ids(value)

    def test_base_image_is_none_when_unset(self):
        self.assertIsNone(parse_base_image(None))

    ACCEPTED_BASE_IMAGES = (
        "ubuntu:26.04",
        "ubuntu:noble",
        "debian:trixie-slim",
        "a:1",
        # 128 characters, the most that Sandy accepts.
        "a" * 63 + ":" + "1" * 64,
    )
    # Sandy rejects these three too, but only when a case builds.
    SANDY_REJECTED_BASE_IMAGES = (
        "docker.io/library/debian:trixie",
        "1abc:2",
        "ubuntu:Noble",
    )

    def test_base_image_accepts_name_and_tag(self):
        for value in self.ACCEPTED_BASE_IMAGES:
            with self.subTest(value=value):
                self.assertEqual(parse_base_image(value), value)

    def test_base_image_rejects_everything_else(self):
        for value in (
            "",
            "ubuntu",
            "ubuntu:",
            ":26.04",
            "Ubuntu:26.04",
            "ubuntu:26.04 ",
            "ubuntu:26.04\n",
            "ubuntu:26.04;id",
            "ubuntu:26.04@sha256:abc",
            "-ubuntu:1",
            "ubuntu:-1",
            "a" * 64 + ":1",
            "a:" + "1" * 65,
            "a" * 63 + ":" + "1" * 65,
            "ubuntu:26.04:extra",
            *self.SANDY_REJECTED_BASE_IMAGES,
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(E2EFailure, BASE_IMAGE_VARIABLE):
                    parse_base_image(value)

    def test_base_image_accepts_only_what_sandy_accepts(self):
        # Regression test: the runner accepted a slash, a digit first, and an
        # uppercase tag. Sandy rejects them, but only when a later case builds,
        # after the run has made host changes. Nothing is mocked: this is
        # Sandy's own check.
        validate = _load_sandy_module()._validate_image_name
        for value in self.ACCEPTED_BASE_IMAGES:
            with self.subTest(value=value):
                self.assertTrue(validate(value))
        for value in self.SANDY_REJECTED_BASE_IMAGES:
            with self.subTest(value=value):
                self.assertFalse(validate(value))

    def test_context_reads_the_settings_and_chowns_the_directories(self):
        # Mocks: os.chown (the test is not root). The run root is real.
        with patch.dict(
            os.environ,
            {HOST_UID_VARIABLE: "1000", BASE_IMAGE_VARIABLE: "ubuntu:26.04"},
        ), patch.object(support.os, "chown") as chown:
            context = E2EContext()
        try:
            self.assertEqual((context.host_uid, context.host_gid), (1000, 1000))
            self.assertEqual(context.base_image, "ubuntu:26.04")
            self.assertEqual(
                chown.call_args_list,
                [
                    call(context.workspace, 1000, 1000),
                    call(context.shared, 1000, 1000),
                ],
            )
            self.assertEqual(
                context.safe_environment()["SANDY_BOOTSTRAP_BASE"], "ubuntu:26.04"
            )
        finally:
            support.shutil.rmtree(context.root)

    def test_context_defaults_without_the_settings(self):
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in (HOST_UID_VARIABLE, BASE_IMAGE_VARIABLE)
        }
        with patch.dict(os.environ, environment, clear=True), patch.object(
            support.os, "chown"
        ) as chown:
            context = E2EContext()
        try:
            self.assertEqual((context.host_uid, context.host_gid), (1234, 2345))
            self.assertIsNone(context.base_image)
            self.assertEqual(
                [entry.args[1:] for entry in chown.call_args_list],
                [(1234, 2345), (1234, 2345)],
            )
            self.assertNotIn("SANDY_BOOTSTRAP_BASE", context.safe_environment())
        finally:
            support.shutil.rmtree(context.root)

    def test_context_validates_the_settings_before_it_creates_anything(self):
        for name, value in ((HOST_UID_VARIABLE, "0"), (BASE_IMAGE_VARIABLE, "ubuntu")):
            with self.subTest(name=name):
                with patch.dict(os.environ, {name: value}), patch.object(
                    support.tempfile, "mkdtemp"
                ) as mkdtemp:
                    with self.assertRaises(E2EFailure):
                        E2EContext()
                mkdtemp.assert_not_called()

    def make_context(self, base_image):
        context = E2EContext.__new__(E2EContext)
        context.base_image = base_image
        return context

    def test_safe_environment_passes_the_base_image_to_sandy(self):
        without = self.make_context(None).safe_environment()
        self.assertNotIn("SANDY_BOOTSTRAP_BASE", without)
        selected = self.make_context("ubuntu:26.04").safe_environment()
        self.assertEqual(selected["SANDY_BOOTSTRAP_BASE"], "ubuntu:26.04")
        # Only the base image differs.
        self.assertEqual(
            {k: v for k, v in selected.items() if k != "SANDY_BOOTSTRAP_BASE"},
            without,
        )

    def test_overrides_keep_the_base_image_and_stay_validated(self):
        context = self.make_context("ubuntu:26.04")
        environment = context.safe_environment({"SANDY_SETUP_SCRIPT": "/x"})
        self.assertEqual(environment["SANDY_BOOTSTRAP_BASE"], "ubuntu:26.04")
        self.assertEqual(environment["SANDY_SETUP_SCRIPT"], "/x")
        for key, value in (("PATH", "/x"), ("SANDY_X", ""), ("SANDY_X", "a\x00b")):
            with self.subTest(key=key, value=value):
                with self.assertRaises(E2EFailure):
                    context.safe_environment({key: value})

    def test_minimal_environment_carries_the_base_image(self):
        environment = self.make_context("ubuntu:26.04").minimal_environment()
        self.assertEqual(environment["SANDY_BOOTSTRAP_BASE"], "ubuntu:26.04")
        self.assertIn("SANDY_SETUP_SCRIPT", environment)


class ScratchMountTests(unittest.TestCase):
    """The mounts that a case makes below the run root, and their cleanup.

    Mocks: run() (the mount and umount commands) and the check for a mount
    point. Real temporary directories give the paths. The E2E suite proves
    the real mounts.
    """

    @contextmanager
    def context(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            context = CleanupProbeContext(root, host_state_owned=False)
            context.host_uid = 1234
            yield context, root

    @staticmethod
    def success(command, **kwargs):
        return CommandResult(tuple(command), 0, "", "")

    def test_each_kind_is_tracked_before_the_command_and_forgotten_after(self):
        for kind in ("tmpfs", "ramfs"):
            with self.subTest(kind=kind), self.context() as (context, root):
                path = root / "mounted"
                path.mkdir()
                commands = []

                def run(command, **kwargs):
                    commands.append((tuple(command), kwargs))
                    if command[0] == "mount":
                        self.assertEqual(context.scratch_mounts, (path,))
                    return self.success(command)

                with patch.object(context, "run", side_effect=run):
                    context.mount_scratch_filesystem(kind, path)
                    self.assertEqual(context.scratch_mounts, (path,))
                    context.unmount_scratch_filesystem(path)
                self.assertEqual(context.scratch_mounts, ())
                self.assertEqual(
                    commands,
                    [
                        (("mount", "-t", kind, kind, str(path)), {}),
                        (("umount", "--", str(path)), {"expected": None}),
                    ],
                )

    def test_a_bind_mount_runs_the_exact_command(self):
        with self.context() as (context, root):
            source = root / "source"
            path = root / "target"
            source.mkdir()
            path.mkdir()
            with patch.object(context, "run", side_effect=self.success) as run:
                context.mount_scratch_bind(source, path)
            run.assert_called_once_with(
                ["mount", "--bind", "--", str(source), str(path)]
            )
            self.assertEqual(context.scratch_mounts, (path,))

    def test_a_bind_mount_needs_a_safe_source_too(self):
        with self.context() as (context, root):
            path = root / "target"
            path.mkdir()
            for source in (Path("/etc"), root / "missing", root):
                with self.subTest(source=source):
                    with patch.object(context, "run") as run:
                        with self.assertRaises(E2EFailure):
                            context.mount_scratch_bind(source, path)
                    run.assert_not_called()
            self.assertEqual(context.scratch_mounts, ())

    def test_unsupported_file_systems_run_no_command(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            for kind in ("ext4", "", "tmpfs -o x", "bind", "nfs"):
                with self.subTest(kind=kind):
                    with patch.object(context, "run") as run:
                        with self.assertRaisesRegex(E2EFailure, "Unsupported"):
                            context.mount_scratch_filesystem(kind, path)
                    run.assert_not_called()
            self.assertEqual(context.scratch_mounts, ())

    def test_only_real_directories_below_the_run_root_are_accepted(self):
        with self.context() as (context, root):
            link = root / "link"
            link.symlink_to(root)
            (root / "file").write_text("x")
            outside = Path(tempfile.gettempdir())
            for path in (
                root,
                outside,
                Path("relative"),
                root / "missing",
                root / "file",
                link,
                root / ".." / root.name,
            ):
                with self.subTest(path=path):
                    with patch.object(context, "run") as run:
                        with self.assertRaisesRegex(E2EFailure, "Unsafe"):
                            context.mount_scratch_filesystem("tmpfs", path)
                    run.assert_not_called()
            self.assertEqual(context.scratch_mounts, ())

    def test_a_directory_is_tracked_once(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            context.track_scratch_mount(path)
            with patch.object(context, "run") as run:
                with self.assertRaisesRegex(E2EFailure, "already tracked"):
                    context.mount_scratch_filesystem("tmpfs", path)
                with self.assertRaisesRegex(E2EFailure, "already tracked"):
                    context.track_scratch_mount(path)
            run.assert_not_called()
            self.assertEqual(context.scratch_mounts, (path,))

    def test_a_failed_mount_without_a_mount_point_is_forgotten(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            with patch.object(
                context, "run", side_effect=E2EFailure("mount failed")
            ), patch.object(context, "is_mount_point", return_value=False):
                with self.assertRaisesRegex(E2EFailure, "mount failed"):
                    context.mount_scratch_filesystem("tmpfs", path)
            self.assertEqual(context.scratch_mounts, ())

    def test_a_failure_after_the_mount_stays_tracked_for_cleanup(self):
        # Also an interrupt: the kernel may have made the mount already.
        for error in (E2EFailure("timed out"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with self.context() as (context, root):
                    path = root / "mounted"
                    path.mkdir()
                    with patch.object(context, "run", side_effect=error), patch.object(
                        context, "is_mount_point", return_value=True
                    ):
                        with self.assertRaises(type(error)):
                            context.mount_scratch_filesystem("tmpfs", path)
                    self.assertEqual(context.scratch_mounts, (path,))

    def test_a_failed_unmount_stays_tracked_while_the_mount_exists(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            context.track_scratch_mount(path)
            busy = CommandResult(("umount",), 32, "", "busy")
            with patch.object(context, "run", return_value=busy), patch.object(
                context, "is_mount_point", return_value=True
            ):
                with self.assertRaisesRegex(E2EFailure, "Could not unmount"):
                    context.unmount_scratch_filesystem(path)
            self.assertEqual(context.scratch_mounts, (path,))

    def test_a_failed_unmount_of_a_path_that_is_no_mount_is_forgotten(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            context.track_scratch_mount(path)
            not_mounted = CommandResult(("umount",), 32, "", "not mounted")
            with patch.object(context, "run", return_value=not_mounted), patch.object(
                context, "is_mount_point", return_value=False
            ):
                context.unmount_scratch_filesystem(path)
            self.assertEqual(context.scratch_mounts, ())

    def test_an_untracked_path_is_not_unmounted(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            with patch.object(context, "run") as run:
                with self.assertRaisesRegex(E2EFailure, "not tracked"):
                    context.unmount_scratch_filesystem(path)
                with self.assertRaisesRegex(E2EFailure, "not tracked"):
                    context.forget_scratch_mount(path)
            run.assert_not_called()

    def test_forget_refuses_a_path_that_is_still_a_mount(self):
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            context.track_scratch_mount(path)
            with patch.object(context, "is_mount_point", return_value=True):
                with self.assertRaisesRegex(E2EFailure, "still mounted"):
                    context.forget_scratch_mount(path)
            self.assertEqual(context.scratch_mounts, (path,))
            with patch.object(context, "is_mount_point", return_value=False):
                context.forget_scratch_mount(path)
            self.assertEqual(context.scratch_mounts, ())

    def test_cleanup_unmounts_before_it_removes_the_run_root(self):
        with self.context() as (context, root):
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            context.track_scratch_mount(first)
            context.track_scratch_mount(second)
            events = []

            def unmount(path):
                events.append(path)
                context._scratch_mounts.remove(path)

            with patch.object(
                context, "unmount_scratch_filesystem", side_effect=unmount
            ):
                self.assertEqual(context.cleanup(), [])
            # The newest mount first; then the root goes.
            self.assertEqual(events, [second, first])
            self.assertFalse(root.exists())

    def test_cleanup_keeps_the_run_root_when_a_mount_remains(self):
        # rmtree would descend into a file system that is still mounted.
        with self.context() as (context, root):
            path = root / "mounted"
            path.mkdir()
            (path / "inside").write_text("x")
            context.track_scratch_mount(path)
            with patch.object(
                context,
                "unmount_scratch_filesystem",
                side_effect=E2EFailure("busy"),
            ), patch.object(support.shutil, "rmtree") as rmtree:
                errors = context.cleanup()
            rmtree.assert_not_called()
            self.assertTrue((path / "inside").exists())
            self.assertEqual(len(errors), 2)
            self.assertIn(f"scratch mount {path}: busy", errors[0])
            self.assertIn("kept: mounts remain", errors[1])

    def test_is_mount_point_reads_the_mountinfo(self):
        with self.context() as (context, root):
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real)
            spaced = root / "with space"
            spaced.mkdir()
            mountinfo = root / "mountinfo"
            mountinfo.write_text(
                f"36 35 98:0 / {real} rw,relatime shared:1 - tmpfs tmpfs rw\n"
                f"37 35 98:1 / {str(spaced).replace(' ', chr(92) + '040')} "
                "rw - tmpfs tmpfs rw\n",
                encoding="utf-8",
            )
            with patch.object(support, "MOUNTINFO", mountinfo):
                self.assertTrue(context.is_mount_point(real))
                # The real path of a link is what the kernel lists.
                self.assertTrue(context.is_mount_point(link))
                self.assertTrue(context.is_mount_point(spaced))
                self.assertFalse(context.is_mount_point(root))
                # A path that only starts like a mount point is none.
                (root / "real2").mkdir()
                self.assertFalse(context.is_mount_point(root / "real2"))

    def test_parse_mountinfo(self):
        text = (
            "36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 - ext3 /dev/root rw\r\n"
            "37 36 98:0 /a /with\\040space\\011tab ro,nosuid,idmapped - tmpfs x rw\n"
            "short line\n"
            "\n"
        )
        self.assertEqual(
            support.parse_mountinfo(text),
            [
                ("/mnt2", frozenset({"rw", "noatime"})),
                ("/with space\ttab", frozenset({"ro", "nosuid", "idmapped"})),
            ],
        )


class UpTemporaryDirectoryTests(unittest.TestCase):
    """The directories that up makes for its binds, in /tmp.

    A case that kills a background up leaves them. The next preflight refuses
    them (a leftover would break the count of a later case), and cleanup removes
    the ones of this run. Real temporary directories; no host state.
    """

    @contextmanager
    def temporary_root(self):
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent)
            for name in (
                "sandy-keepalive-abc",
                "sandy-init-xyz",
                "sandy-keepalive",
                "other",
            ):
                (base / name).mkdir()
            (base / "sandy-keepalive-abc" / "keepalive.sh").write_text("x")
            with patch.object(support, "UP_TEMPORARY_ROOT", base):
                yield base

    def test_lists_the_directories_of_up_sorted(self):
        with self.temporary_root() as base:
            self.assertEqual(
                support.up_temporary_directories(),
                [base / "sandy-init-xyz", base / "sandy-keepalive-abc"],
            )

    def test_lists_nothing_when_there_is_none(self):
        with tempfile.TemporaryDirectory() as parent:
            with patch.object(support, "UP_TEMPORARY_ROOT", Path(parent)):
                self.assertEqual(support.up_temporary_directories(), [])

    def test_preflight_refuses_a_leftover_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            machines = root / "machines"
            machines.mkdir()
            context = SliceProbeContext(root / "run", host_state_owned=False)
            context.filesystem_machine_link = machines / "sandy.e2e-filesystem-x"
            context.filesystem_image_root = root / "missing-image"
            context.filesystem_host_target = root / "missing-host"
            with self.temporary_root() as base, patch.object(
                support.os, "getuid", return_value=0
            ), patch.dict(support.os.environ, {"SANDY_E2E": "1"}), patch.object(
                support, "SYSTEMD_MACHINES", machines
            ), patch.object(
                support, "INSTALL_DIR", root / "missing-install"
            ), patch.object(
                support.shutil, "which", return_value="/usr/bin/tool"
            ):
                with self.assertRaisesRegex(
                    E2EFailure,
                    f"pre-existing Sandy temporary directories: "
                    f"{base / 'sandy-init-xyz'}, {base / 'sandy-keepalive-abc'}",
                ):
                    context.preflight()
            self.assertFalse(context._host_state_owned)
            self.assertEqual(context.commands, [])

    def test_cleanup_removes_the_directories_of_a_run_that_owns_host_state(self):
        with tempfile.TemporaryDirectory() as parent:
            run = Path(parent) / "run"
            run.mkdir()
            context = CleanupProbeContext(run, host_state_owned=True)
            with self.temporary_root() as base:
                self.assertEqual(context.cleanup(), [])
                self.assertEqual(
                    sorted(path.name for path in base.iterdir()),
                    ["other", "sandy-keepalive"],
                )

    def test_cleanup_leaves_the_directories_of_a_run_without_host_state(self):
        with tempfile.TemporaryDirectory() as parent:
            run = Path(parent) / "run"
            run.mkdir()
            context = CleanupProbeContext(run, host_state_owned=False)
            with self.temporary_root() as base:
                self.assertEqual(context.cleanup(), [])
                self.assertEqual(len(support.up_temporary_directories()), 2)
                self.assertTrue(
                    (base / "sandy-keepalive-abc" / "keepalive.sh").exists()
                )

    def test_a_link_or_a_foreign_entry_is_not_removed_and_not_followed(self):
        with tempfile.TemporaryDirectory() as parent:
            run = Path(parent) / "run"
            run.mkdir()
            victim = Path(parent) / "victim"
            victim.mkdir()
            (victim / "keep").write_text("x")
            context = CleanupProbeContext(run, host_state_owned=True)
            with self.temporary_root() as base:
                (base / "sandy-init-link").symlink_to(victim, target_is_directory=True)
                (base / "sandy-init-file").write_text("x")
                errors = context.cleanup()
                # The directories are removed; the entries that are not are kept.
                self.assertEqual(
                    sorted(path.name for path in base.iterdir()),
                    ["other", "sandy-init-file", "sandy-init-link", "sandy-keepalive"],
                )
            self.assertTrue((victim / "keep").exists())
            self.assertEqual(len(errors), 1)
            self.assertIn("up temporary directories: Refusing to remove", errors[0])
            self.assertIn("sandy-init-file", errors[0])
            self.assertIn("sandy-init-link", errors[0])

    def test_an_entry_of_another_owner_is_not_removed(self):
        with tempfile.TemporaryDirectory() as parent:
            run = Path(parent) / "run"
            run.mkdir()
            context = CleanupProbeContext(run, host_state_owned=True)
            with self.temporary_root(), patch.object(
                support.os, "geteuid", return_value=os.geteuid() + 1
            ):
                errors = context.cleanup()
                self.assertEqual(len(support.up_temporary_directories()), 2)
            self.assertEqual(len(errors), 1)
            self.assertIn("unexpected entry", errors[0])


class HostUserTests(unittest.TestCase):
    """The commands that run as the host user, as a user of `sudo sandy` would."""

    def make_context(self):
        context = E2EContext.__new__(E2EContext)
        context.host_uid = 1234
        context.host_gid = 2345
        return context

    def test_host_user_command_drops_to_the_numeric_ids_without_groups(self):
        self.assertEqual(
            self.make_context().host_user_command(["tee", "-a", "/x"]),
            (
                "setpriv",
                "--reuid=1234",
                "--regid=2345",
                "--clear-groups",
                "--",
                "tee",
                "-a",
                "/x",
            ),
        )

    def test_host_user_command_rejects_an_invalid_command(self):
        for command in ([], [""], ["id", ""], [None]):
            with self.subTest(command=command):
                with self.assertRaises(E2EFailure):
                    self.make_context().host_user_command(cast(Sequence[str], command))

    def test_run_as_host_user_passes_the_wrapped_command_to_run(self):
        context = self.make_context()
        with patch.object(E2EContext, "run") as run:
            context.run_as_host_user(["rm", "--", "/x"], expected=1, input_text="in")
            context.run_as_host_user(["id"])
        self.assertEqual(
            run.call_args_list[0],
            call(
                (
                    "setpriv",
                    "--reuid=1234",
                    "--regid=2345",
                    "--clear-groups",
                    "--",
                    "rm",
                    "--",
                    "/x",
                ),
                expected=1,
                input_text="in",
            ),
        )
        self.assertEqual(run.call_args_list[1].kwargs["expected"], 0)
        self.assertIsNone(run.call_args_list[1].kwargs["input_text"])


class RunnerTests(unittest.TestCase):
    def test_the_mount_cases_run_after_lifecycle_and_before_confinement(self):
        modules = [module.__name__.rsplit(".", 1)[-1] for module in runner.TEST_MODULES]
        self.assertEqual(
            modules[modules.index("test_lifecycle") :][:3],
            ["test_lifecycle", "test_mounts", "test_confinement"],
        )
        self.assertEqual(len(modules), len(set(modules)))
        for module in runner.TEST_MODULES:
            self.assertTrue(callable(module.test_main))

    @contextmanager
    def runner_environment(self, **variables):
        environment = {"SANDY_E2E": "1", **variables}
        with patch.dict(os.environ, environment, clear=True), patch.object(
            runner.os, "getuid", return_value=0
        ), patch.object(runner.sys, "argv", ["runner"]):
            yield

    def test_the_guard_rejects_malformed_settings_before_anything_is_made(self):
        for variable, value in (
            (HOST_UID_VARIABLE, "0"),
            (HOST_UID_VARIABLE, "root"),
            (HOST_UID_VARIABLE, "60001"),
            (BASE_IMAGE_VARIABLE, "ubuntu"),
            (BASE_IMAGE_VARIABLE, "ubuntu:26.04;id"),
            (BASE_IMAGE_VARIABLE, "docker.io/library/debian:trixie"),
        ):
            with self.subTest(variable=variable, value=value):
                with self.runner_environment(**{variable: value}):
                    with self.assertRaises(E2EFailure):
                        runner._guard()

    def test_the_guard_accepts_valid_settings(self):
        with self.runner_environment(
            **{HOST_UID_VARIABLE: "1000", BASE_IMAGE_VARIABLE: "ubuntu:26.04"}
        ):
            self.assertFalse(runner._guard())
        with self.runner_environment():
            self.assertFalse(runner._guard())
            with patch.object(runner.sys, "argv", ["runner", "--full"]):
                self.assertTrue(runner._guard())


def fake_context(**attributes: object) -> E2EContext:
    """Return a stand-in with only the attributes that a helper reads."""
    return cast(E2EContext, SimpleNamespace(**attributes))


class MountCaseHelperTests(unittest.TestCase):
    """The pure helpers of tests/e2e/test_mounts.py."""

    def test_parse_owners_reads_stat_output_with_terminal_line_ends(self):
        text = "1000:1000 /home/d/workspace\r\n65534:65534 /home/d/w f\r\nnoise\r\n"
        self.assertEqual(
            test_mounts._parse_owners(text),
            {"/home/d/workspace": (1000, 1000)},
        )

    def test_host_mounts_below_lists_only_mounts_at_or_below_the_root(self):
        with tempfile.TemporaryDirectory() as parent:
            mountinfo = Path(parent) / "mountinfo"
            mountinfo.write_text(
                "1 0 8:1 / /run/x rw - tmpfs t rw\n"
                "2 1 8:1 / /run/x/sub rw - tmpfs t rw\n"
                "3 1 8:1 / /run/xy rw - tmpfs t rw\n"
                "4 1 8:1 / /run rw - tmpfs t rw\n",
                encoding="utf-8",
            )
            with patch.object(test_mounts, "MOUNTINFO", mountinfo):
                self.assertEqual(
                    test_mounts._host_mounts_below(Path("/run/x")),
                    ["/run/x", "/run/x/sub"],
                )
                self.assertEqual(test_mounts._host_mounts_below(Path("/none")), [])

    def test_host_mount_count_counts_the_lines_of_one_mount_point(self):
        with tempfile.TemporaryDirectory() as parent:
            target = Path(parent) / "pm"
            target.mkdir()
            link = Path(parent) / "link"
            link.symlink_to(target)
            mountinfo = Path(parent) / "mountinfo"
            mountinfo.write_text(
                f"1 0 8:1 / {target} rw - tmpfs t rw\n"
                f"2 1 8:1 / {target} rw - tmpfs t rw\n"
                f"3 1 8:1 / {target}/sub rw - tmpfs t rw\n"
                f"4 1 8:1 / {target}x rw - tmpfs t rw\n",
                encoding="utf-8",
            )
            with patch.object(test_mounts, "MOUNTINFO", mountinfo):
                self.assertEqual(test_mounts._host_mount_count(target), 2)
                # The kernel lists the real path.
                self.assertEqual(test_mounts._host_mount_count(link), 2)
                self.assertEqual(test_mounts._host_mount_count(Path(parent)), 0)

    def test_entries_of_root_finds_entries_of_root_as_user_or_group(self):
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent)
            (base / "dir").mkdir()
            for name in ("plain", "root-user", "root-group", "dir/inner"):
                (base / name).write_text("x")
            real_lstat = os.lstat

            def lstat(path):
                name = Path(path).name
                if name == "root-user":
                    return SimpleNamespace(st_uid=0, st_gid=1000)
                if name == "root-group":
                    return SimpleNamespace(st_uid=1000, st_gid=0)
                if name == "inner":
                    return SimpleNamespace(st_uid=0, st_gid=0)
                return real_lstat(path)

            with patch.object(test_mounts.os, "lstat", side_effect=lstat):
                found = test_mounts._entries_of_root([base])
        self.assertEqual(
            found,
            sorted([base / "root-user", base / "root-group", base / "dir" / "inner"]),
        )

    def test_remove_all_removes_trees_and_links_without_following(self):
        with tempfile.TemporaryDirectory() as parent:
            base = Path(parent)
            tree = base / "tree"
            (tree / "sub").mkdir(parents=True)
            (tree / "sub" / "file").write_text("x")
            keep = base / "keep"
            keep.mkdir()
            (keep / "kept").write_text("x")
            link = base / "link"
            link.symlink_to(keep, target_is_directory=True)
            plain = base / "plain"
            plain.write_text("x")
            test_mounts._remove_all([tree, link, plain, base / "missing"])
            self.assertFalse(tree.exists())
            self.assertFalse(link.is_symlink())
            self.assertFalse(plain.exists())
            self.assertTrue((keep / "kept").exists())

    def test_host_file_belongs_to_the_host_user(self):
        context = fake_context(host_uid=1234, host_gid=2345)
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / "file"
            with patch.object(test_mounts.os, "chown") as chown:
                result = test_mounts._host_file(context, path, "text\n", mode=0o600)
            self.assertEqual(result, path)
            self.assertEqual(path.read_text(encoding="utf-8"), "text\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            chown.assert_called_once_with(path, 1234, 2345)

    def test_exec_fails_accepts_only_a_failing_command(self):
        def result(code):
            return CommandResult(("sandy",), code, "out", "err")

        for code in (1, 2, 126):
            with patch.object(test_mounts, "_exec", return_value=result(code)):
                self.assertEqual(
                    test_mounts._exec_fails(fake_context(), "false").returncode, code
                )
        # A success, and a refused attach, are not the failure under test.
        for code in (0, test_mounts.ENTRY_FAILURE):
            with patch.object(test_mounts, "_exec", return_value=result(code)):
                with self.assertRaises(E2EFailure):
                    test_mounts._exec_fails(fake_context(), "false")

    def test_container_ids_parse_the_id_output(self):
        for stdout, expected in (
            ("1000\r\n1000\r\n", (1000, 1000)),
            ("1001 100", (1001, 100)),
        ):
            with patch.object(
                test_mounts,
                "_exec",
                return_value=CommandResult(("sandy",), 0, stdout, ""),
            ):
                self.assertEqual(test_mounts._container_ids(fake_context()), expected)
        for stdout in ("", "1000", "1000 x", "1 2 3", "-1 5"):
            with patch.object(
                test_mounts,
                "_exec",
                return_value=CommandResult(("sandy",), 0, stdout, ""),
            ):
                with self.assertRaises(E2EFailure):
                    test_mounts._container_ids(fake_context())

    def test_container_owners_requires_an_answer_for_every_path(self):
        answer = CommandResult(("sandy",), 0, "1:2 /a\r\n", "")
        with patch.object(test_mounts, "_exec", return_value=answer) as run:
            self.assertEqual(
                test_mounts._container_owners(fake_context(), "/a"), {"/a": (1, 2)}
            )
            with self.assertRaises(E2EFailure):
                test_mounts._container_owners(fake_context(), "/a", "/b")
        self.assertEqual(run.call_args_list[0].args[1], "stat -c '%u:%g %n' /a")

    def test_not_started_checks_the_machine_the_image_and_the_scope(self):
        with tempfile.TemporaryDirectory() as parent:
            machines = Path(parent)
            context = fake_context(machine_running=lambda name: False)
            with patch.object(test_mounts, "SYSTEMD_MACHINES", machines), patch.object(
                test_mounts, "_scope_loaded", return_value=False
            ):
                test_mounts._assert_not_started(context, "e2e-x")
                (machines / "sandy.e2e-x").mkdir()
                with self.assertRaisesRegex(E2EFailure, "exists"):
                    test_mounts._assert_not_started(context, "e2e-x")
                (machines / "sandy.e2e-x").rmdir()
                (machines / "sandy.e2e-x").symlink_to(machines)
                with self.assertRaisesRegex(E2EFailure, "exists"):
                    test_mounts._assert_not_started(context, "e2e-x")
                (machines / "sandy.e2e-x").unlink()
                with patch.object(test_mounts, "_scope_loaded", return_value=True):
                    with self.assertRaisesRegex(E2EFailure, "scope"):
                        test_mounts._assert_not_started(context, "e2e-x")
            running = fake_context(machine_running=lambda name: True)
            with self.assertRaisesRegex(E2EFailure, "running"):
                test_mounts._assert_not_started(running, "e2e-x")

    def test_wait_scope_gone_polls_until_the_scope_is_gone(self):
        with patch.object(
            test_mounts, "_scope_loaded", side_effect=[True, True, False]
        ), patch.object(test_mounts.time, "sleep") as sleep:
            test_mounts._wait_scope_gone(fake_context(), "e2e-x")
        self.assertEqual(sleep.call_count, 2)
        with patch.object(
            test_mounts, "_scope_loaded", return_value=True
        ), patch.object(test_mounts.time, "sleep"), patch.object(
            test_mounts.time, "monotonic", side_effect=[0.0, 1.0, 100.0]
        ):
            with self.assertRaisesRegex(E2EFailure, "did not go"):
                test_mounts._wait_scope_gone(fake_context(), "e2e-x")


if __name__ == "__main__":
    unittest.main()
