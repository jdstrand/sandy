"""Bridge, firewall, internet, port-forwarding, and cleanup tests."""

from __future__ import annotations

import time

from tests.e2e.support import (
    BRIDGE_NAME,
    PORT_STATE,
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
)


def _exec(
    context: E2EContext,
    *command: str,
    expected: int | None = 0,
):
    return context.sandy(
        ["exec", "--", *command],
        name=context.main_name,
        user=context.main_user,
        expected=expected,
    )


def _wait_for_public_https(
    context: E2EContext,
    timeout: int = 60,
    retry_delay: float = 2,
) -> None:
    expected = "Example Domain"
    deadline = time.monotonic() + timeout
    response = None
    while True:
        response = _exec(
            context,
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "5",
            "--max-time",
            "20",
            "https://example.com/",
            expected=None,
        )
        if response.returncode == 0 and expected in response.output:
            return
        if time.monotonic() >= deadline:
            raise E2EFailure(
                "Sandbox did not reach public HTTPS before the timeout:\n"
                f"{response.output[-2000:]}"
            )
        time.sleep(retry_delay)


def test_main(context: E2EContext) -> None:
    """Exercise real privileged network setup and teardown."""
    with context.case("lenient networking creates a usable bridge and firewall"):
        if not context.bridge_exists():
            raise E2EFailure(f"Missing bridge {BRIDGE_NAME}")
        bridge = context.run(["ip", "-details", "link", "show", BRIDGE_NAME])
        assert_contains(bridge, "state UP")

        route = _exec(context, "ip", "route", "show", "default")
        assert_contains(route, "default via")

        forward = context.run(["iptables", "-S", "sandy-fwd"])
        assert_contains(forward, "sandy-fwd")
        nat = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-post"])
        assert_contains(nat, "MASQUERADE")

    with context.case("sandbox can resolve DNS and reach the public internet"):
        resolver = _exec(context, "cat", "/etc/resolv.conf")
        assert_contains(resolver, "nameserver 1.1.1.1")
        _wait_for_public_https(context)

    with context.case("localhost port forwarding reaches a container service"):
        context.stop_container(context.main_name, context.main_user)
        host_port = context.choose_host_port()
        context.sandy(
            [
                "up",
                "--detach",
                "--persistent",
                "--network",
                "lenient",
                "--port",
                f"tcp:{host_port}:8000",
            ],
            name=context.main_name,
            user=context.main_user,
        )
        context.wait_for_machine(context.main_name, running=True)

        web_root = context.workspace / "web"
        web_root.mkdir(mode=0o755, exist_ok=True)
        web_root.joinpath("index.html").write_text(
            "sandy-e2e-forwarding\n",
            encoding="utf-8",
        )
        server = context.start_in_machine(
            context.main_name,
            context.main_user,
            [
                "python3",
                "-m",
                "http.server",
                "8000",
                "--bind",
                "0.0.0.0",
                "--directory",
                "/home/developer/workspace/web",
            ],
        )
        try:
            context.wait_for_http(host_port, "sandy-e2e-forwarding")
        except E2EFailure as exc:
            if server.poll() is not None and server.stderr is not None:
                detail = server.stderr.read()
                raise E2EFailure(
                    f"HTTP fixture exited with status {server.returncode}:\n{detail}"
                ) from exc
            raise
        finally:
            context.stop_fixture_process(server)

        state = context.port_state()
        key = f"tcp:{host_port}"
        entry = state.get(key)
        if not isinstance(entry, dict):
            raise E2EFailure(f"Missing port state entry {key!r}")
        if entry.get("container") != context.main_name:
            raise E2EFailure("Port state names the wrong container")
        if entry.get("container_port") != 8000:
            raise E2EFailure("Port state contains the wrong destination port")

        output_rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
        assert_contains(output_rules, f"--dport {host_port}")

    with context.case("network removal is refused while a machine is running"):
        refusal = context.sandy(
            ["rm", "--network", "--force"],
            expected=1,
        )
        assert_contains(refusal, context.main_name)
        assert_contains(refusal, "Cannot remove network while containers are running")

    with context.case("stopping a machine removes forwarding state and rules"):
        context.stop_container(context.main_name, context.main_user)
        if PORT_STATE.exists():
            raise E2EFailure(f"Port state remains after shutdown: {PORT_STATE}")
        output_rules = context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"])
        assert_not_contains(output_rules, f"--dport {host_port}")

    with context.case("container, network, and cache cleanup remove owned state"):
        context.remove_container(context.main_name, context.main_user)
        context.sandy(["rm", "--network", "--force"])
        context.purge_cache()
        context.assert_no_sandy_state()
