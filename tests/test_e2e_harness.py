#!/usr/bin/env python3

"""Unit tests for safety-critical end-to-end harness control flow."""

from __future__ import annotations

import signal
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.e2e.support import (
    DEFAULT_TIMEOUT,
    CommandResult,
    E2EContext,
    E2EFailure,
    FilesystemFixtureIdentity,
)
from tests.e2e.test_network import _wait_for_public_https


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
        self.bridge_checks = 0
        self.cache_purges = 0
        self.state_checks = 0

    def bridge_exists(self) -> bool:
        self.bridge_checks += 1
        return False

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
    ) -> CommandResult:
        del arguments, name, user, timeout, environment, input_text
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


if __name__ == "__main__":
    unittest.main()
