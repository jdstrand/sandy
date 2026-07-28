"""Real cache miss, hit, and changed-manifest tests."""

from __future__ import annotations

from tests.e2e.support import (
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
)


def _assert_container_user(context: E2EContext, name: str, user: str) -> None:
    result = context.sandy(
        ["exec", "--", "id", "-un"],
        name=name,
        user=user,
    )
    assert_contains(result, user)


def test_main(context: E2EContext) -> None:
    """Exercise cache creation, reuse, and manifest-key invalidation."""
    with context.case("cache miss creates a minimal container archive"):
        if context.cache_archives():
            raise E2EFailure("Cache must be empty before the first cache test")

        first_build = context.build_minimal(context.cache_name, context.cache_user)
        assert_contains(first_build, "Using OCI method")
        assert_contains(first_build, "Minimal sandbox setup complete")
        assert_contains(first_build, "Creating cache")
        assert_not_contains(first_build, "Using cached container")
        _assert_container_user(context, context.cache_name, context.cache_user)

        first_archives = context.cache_archives()
        if len(first_archives) != 1:
            raise E2EFailure(f"Expected one cache archive, found {len(first_archives)}")
        first_archive = first_archives[0]
        first_hash = context.hash_file(first_archive)
        first_mtime = first_archive.stat().st_mtime_ns
        listing = context.run(["tar", "--list", "--file", str(first_archive)])
        assert_contains(listing, ".sandy.manifest")
        context.remove_container(context.cache_name, context.cache_user)

    with context.case("identical build inputs reuse the existing cache"):
        cached_build = context.build_minimal(context.cache_name, context.cache_user)
        assert_contains(cached_build, "Using cached container")
        assert_not_contains(cached_build, "Minimal sandbox setup complete")
        _assert_container_user(context, context.cache_name, context.cache_user)

        cached_archives = context.cache_archives()
        if cached_archives != [first_archive]:
            raise E2EFailure("A cache hit unexpectedly changed the archive set")
        if context.hash_file(first_archive) != first_hash:
            raise E2EFailure("A cache hit changed the archive content")
        if first_archive.stat().st_mtime_ns != first_mtime:
            raise E2EFailure("A cache hit changed the archive modification time")
        context.remove_container(context.cache_name, context.cache_user)

    with context.case("changed manifest input creates a second cache archive"):
        missed_build = context.build_minimal(
            context.cache_miss_name,
            context.cache_miss_user,
        )
        assert_contains(missed_build, "Using OCI method")
        assert_contains(missed_build, "Minimal sandbox setup complete")
        assert_contains(missed_build, "Creating cache")
        assert_not_contains(missed_build, "Using cached container")
        _assert_container_user(
            context,
            context.cache_miss_name,
            context.cache_miss_user,
        )

        missed_archives = context.cache_archives()
        if len(missed_archives) != 2:
            raise E2EFailure(
                f"Expected two cache archives after key miss, found "
                f"{len(missed_archives)}"
            )
        if first_archive not in missed_archives:
            raise E2EFailure("The original cache archive disappeared after key miss")
        context.remove_container(
            context.cache_miss_name,
            context.cache_miss_user,
        )

    with context.case("cache archives remain available for later reuse"):
        retained_archives = context.cache_archives()
        if len(retained_archives) != 2:
            raise E2EFailure(
                f"Expected two retained cache archives, found {len(retained_archives)}"
            )
        if first_archive not in retained_archives:
            raise E2EFailure("The reusable cache archive was not retained")
