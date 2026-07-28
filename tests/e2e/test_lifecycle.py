"""Cached minimal setup and real systemd-nspawn lifecycle tests."""

from __future__ import annotations

from tests.e2e.support import (
    E2EContext,
    E2EFailure,
    HOST_SECRET_NAME,
    HOST_SECRET_VALUE,
    assert_contains,
    assert_not_contains,
)


def _exec(context: E2EContext, *command: str):
    return context.sandy(
        ["exec", "--", *command],
        name=context.main_name,
        user=context.main_user,
    )


def _start_persistent(context: E2EContext) -> None:
    context.sandy(
        ["up", "--detach", "--persistent", "--network", "lenient"],
        name=context.main_name,
        user=context.main_user,
    )
    context.wait_for_machine(context.main_name, running=True)


def test_main(context: E2EContext) -> None:
    """Build from the retained cache, then reuse the resulting machine."""
    with context.case("lifecycle build reuses the minimal cache"):
        if len(context.cache_archives()) != 2:
            raise E2EFailure("Cache tests did not retain both expected archives")
        build = context.build_main()
        assert_contains(build, "Using cached container")
        assert_not_contains(build, "Minimal sandbox setup complete")

        for tool in ("curl", "ip", "python3"):
            result = _exec(context, "command", "-v", tool)
            assert_contains(result, tool)

    with context.case("status, list, exec, bash, workspace, and shared mounts work"):
        status = context.sandy(
            ["status"],
            name=context.main_name,
            user=context.main_user,
        )
        assert_contains(status, context.main_name)

        listing = context.sandy(["list"])
        assert_contains(listing, context.main_name)
        assert_contains(listing, "running")

        identity = _exec(context, "id", "-un")
        assert_contains(identity, context.main_user)

        context.workspace.joinpath("host-to-container.txt").write_text(
            "host-value\n",
            encoding="utf-8",
        )
        _exec(
            context,
            "grep",
            "-Fx",
            "host-value",
            "/home/developer/workspace/host-to-container.txt",
        )
        _exec(
            context,
            "printf",
            "container-value",
            ">",
            "/home/developer/workspace/container-to-host.txt",
        )
        if (
            context.workspace.joinpath("container-to-host.txt").read_text(
                encoding="utf-8"
            )
            != "container-value"
        ):
            raise E2EFailure("Workspace write did not reach the host")

        context.shared.joinpath("shared.txt").write_text(
            "shared-value\n",
            encoding="utf-8",
        )
        _exec(
            context,
            "grep",
            "-Fx",
            "shared-value",
            "/home/developer/shared/shared.txt",
        )

        bash = context.sandy(
            ["bash", "-c", "printf sandy-e2e-bash"],
            name=context.main_name,
            user=context.main_user,
        )
        assert_contains(bash, "sandy-e2e-bash")

    with context.case("container commands hide host environment and report failures"):
        environment = context.safe_environment(
            {
                HOST_SECRET_NAME: HOST_SECRET_VALUE,
            }
        )
        leaked_secret = context.sandy(
            ["exec", "--", "printenv", HOST_SECRET_NAME],
            name=context.main_name,
            user=context.main_user,
            expected=1,
            environment=environment,
        )
        assert_not_contains(leaked_secret, HOST_SECRET_VALUE)

        leaked_bash_secret = context.sandy(
            ["bash", "-c", "printenv", HOST_SECRET_NAME],
            name=context.main_name,
            user=context.main_user,
            expected=1,
            environment=environment,
        )
        assert_not_contains(leaked_bash_secret, HOST_SECRET_VALUE)

        context.sandy(
            ["exec", "--", "false"],
            name=context.main_name,
            user=context.main_user,
            expected=1,
        )
        context.sandy(
            ["bash", "-c", "false"],
            name=context.main_name,
            user=context.main_user,
            expected=1,
        )

    with context.case("starting an already-running machine is rejected"):
        duplicate = context.sandy(
            ["up", "--detach", "--persistent", "--network", "lenient"],
            name=context.main_name,
            user=context.main_user,
            expected=1,
        )
        assert_contains(duplicate, "is already running")

    with context.case("stopped persistent machine restarts without rebuilding"):
        _exec(context, "touch", "/home/developer/persistent-marker")
        context.stop_container(context.main_name, context.main_user)
        stopped_exec = context.sandy(
            ["exec", "--", "true"],
            name=context.main_name,
            user=context.main_user,
            expected=1,
        )
        assert_contains(stopped_exec, "not found or not running")
        _start_persistent(context)
        _exec(context, "test", "-e", "/home/developer/persistent-marker")
        _exec(context, "test", "-e", "/home/developer/workspace/host-to-container.txt")

    with context.case("ephemeral root changes are discarded"):
        context.stop_container(context.main_name, context.main_user)
        context.sandy(
            ["up", "--detach", "--network", "lenient"],
            name=context.main_name,
            user=context.main_user,
        )
        context.wait_for_machine(context.main_name, running=True)
        _exec(context, "touch", "/home/developer/ephemeral-marker")
        context.stop_container(context.main_name, context.main_user)
        _start_persistent(context)
        _exec(context, "test", "!", "-e", "/home/developer/ephemeral-marker")
