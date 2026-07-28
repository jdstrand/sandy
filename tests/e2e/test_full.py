"""Opt-in smoke test for the complete default setup-container.sh."""

from __future__ import annotations

from tests.e2e.support import E2EContext, E2EFailure, assert_contains


def _exec(context: E2EContext, *command: str):
    return context.sandy(
        ["exec", "--", *command],
        name=context.full_name,
        user=context.full_user,
    )


def test_main(context: E2EContext) -> None:
    """Build once with Sandy's complete defaults and verify key tools."""
    with context.case("default setup-container.sh full-build smoke test"):
        if context.cache_archives():
            raise E2EFailure("Fast E2E caches were not removed before full smoke test")

        build = context.build_full()
        assert_contains(build, "Using OCI method")
        assert_contains(build, "Done!!")
        if len(context.cache_archives()) != 1:
            raise E2EFailure("The full build did not create exactly one cache archive")

        for tool in ("ip", "python3", "rg"):
            result = _exec(context, "command", "-v", tool)
            assert_contains(result, tool)
