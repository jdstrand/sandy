#!/usr/bin/env python3

"""Ordered runner for destructive sandy end-to-end tests."""

from __future__ import annotations

import os
import sys
import traceback

from tests.e2e import (
    test_cache,
    test_full,
    test_lifecycle,
    test_network,
    test_unhappy,
)
from tests.e2e.support import E2EContext, E2EFailure

TEST_MODULES = (
    test_unhappy,
    test_cache,
    test_lifecycle,
    test_network,
)


def _guard() -> bool:
    if os.environ.get("SANDY_E2E") != "1":
        raise E2EFailure("E2E tests require SANDY_E2E=1 and a disposable test machine")
    if os.getuid() != 0:
        raise E2EFailure("E2E tests must run as root")
    arguments = sys.argv[1:]
    if arguments not in ([], ["--full"]):
        raise E2EFailure("The ordered E2E runner accepts only the optional --full flag")
    return arguments == ["--full"]


def main() -> int:
    """Run all E2E phases in their required order and always clean up."""
    try:
        include_full = _guard()
    except E2EFailure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "WARNING: sandy E2E tests modify real machines, mounts, networking, "
        "firewall rules, sysctls, and cache state.",
        flush=True,
    )
    context = E2EContext()
    failure: BaseException | None = None
    try:
        context.preflight()
        for module in TEST_MODULES:
            module.test_main(context)
        if include_full:
            test_full.test_main(context)
    except (KeyboardInterrupt, E2EFailure, AssertionError) as exc:
        failure = exc
        if isinstance(exc, KeyboardInterrupt):
            print("\nInterrupted", file=sys.stderr)
        else:
            print(f"\nERROR: {exc}", file=sys.stderr)
    except BaseException as exc:
        failure = exc
        traceback.print_exc()
    finally:
        print("\nCleaning up E2E state...", flush=True)
        cleanup_errors = context.cleanup()
        for error in cleanup_errors:
            print(f"ERROR: cleanup failed: {error}", file=sys.stderr)
        if cleanup_errors and failure is None:
            failure = E2EFailure("One or more cleanup operations failed")

    print("\n------------------------")
    print("End-to-end tests summary")
    print("------------------------")
    print(f"Passed={context.passed}")
    print(f"Result={'FAIL' if failure else 'PASS'}")
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
