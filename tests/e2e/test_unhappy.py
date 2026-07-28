"""Representative unhappy paths against the real host interfaces."""

from __future__ import annotations

import shutil

from tests.e2e.support import E2EContext, SANDY, assert_contains


def test_main(context: E2EContext) -> None:
    """Run failures that should not leave persistent Sandy state."""
    with context.case("non-root execution is rejected"):
        non_root_sandy = context.root / "sandy-nonroot"
        shutil.copyfile(SANDY, non_root_sandy)
        non_root_sandy.chmod(0o555)
        result = context.run(
            ["runuser", "--user", "nobody", "--", str(non_root_sandy), "list"],
            expected=1,
        )
        assert_contains(result, "Must run as root")

    with context.case("starting a missing machine without --build fails"):
        result = context.sandy(
            ["up", "--detach", "--persistent", "--network", "host"],
            name=context.cache_name,
            user=context.cache_user,
            expected=1,
        )
        assert_contains(result, "does not exist. Use --build")

    with context.case("host networking rejects port forwarding"):
        result = context.sandy(
            [
                "up",
                "--detach",
                "--network",
                "host",
                "--port",
                "tcp:18080:80",
            ],
            name=context.cache_name,
            user=context.cache_user,
            expected=1,
        )
        assert_contains(result, "not compatible with --network=host")

    with context.case("invalid port syntax is rejected before network setup"):
        result = context.sandy(
            [
                "up",
                "--detach",
                "--network",
                "lenient",
                "--port",
                "tcp:not-a-port:80",
            ],
            name=context.cache_name,
            user=context.cache_user,
            expected=1,
        )
        assert_contains(result, "Invalid port specification")
        context.assert_no_sandy_state()

    with context.case("exec against a stopped machine fails"):
        result = context.sandy(
            ["exec", "--", "true"],
            name=context.cache_name,
            user=context.cache_user,
            expected=1,
        )
        assert_contains(result, "not found or not running")

    with context.case("removing a missing machine fails"):
        result = context.sandy(
            ["rm", "--force"],
            name=context.cache_name,
            user=context.cache_user,
            expected=1,
        )
        assert_contains(result, "not found")
        context.assert_no_sandy_state()
