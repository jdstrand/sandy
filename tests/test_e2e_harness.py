#!/usr/bin/env python3

"""Unit tests for safety-critical end-to-end harness control flow."""

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from tests.e2e.support import (
    DEFAULT_TIMEOUT,
    CommandResult,
    E2EContext,
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
