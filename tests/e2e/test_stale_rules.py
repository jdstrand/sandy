"""Port forwarding rules after a stop without sandy, for both firewall backends.

A container that stops without sandy leaves its forwarding rules and state.
The next `up` of that name must remove exactly those, and nothing of another
container. These cases need real firewall state, so mocks cannot prove them.
"""

from __future__ import annotations

import signal

from tests.e2e.support import (
    PORT_STATE,
    E2EContext,
    E2EFailure,
)


def _forwarded_ports(context: E2EContext, backend: str) -> str:
    """Return the host's Sandy DNAT rules as text for the backend."""
    if backend == "iptables":
        return context.run(["iptables", "-t", "nat", "-S", "sandy-nat-out"]).stdout
    return context.run(["nft", "list", "table", "ip", "sandy"]).stdout


def _has_port(context: E2EContext, backend: str, port: int) -> bool:
    marker = f"--dport {port}" if backend == "iptables" else f"dport {port}"
    return marker in _forwarded_ports(context, backend)


def _expect_ports(
    context: E2EContext, backend: str, present: tuple[int, ...], absent: tuple[int, ...]
) -> None:
    # Sandy removes the state file when no mapping is left.
    state = context.port_state() if PORT_STATE.exists() else {}
    for port in present:
        if not _has_port(context, backend, port):
            raise E2EFailure(f"{backend}: rule for port {port} is missing")
        if f"tcp:{port}" not in state:
            raise E2EFailure(f"{backend}: state for port {port} is missing")
    for port in absent:
        if _has_port(context, backend, port):
            raise E2EFailure(f"{backend}: stale rule for port {port} remains")
        if f"tcp:{port}" in state:
            raise E2EFailure(f"{backend}: stale state for port {port} remains")


def _up(context: E2EContext, name: str, user: str, *ports: int) -> None:
    arguments = ["up", "--detach", "--persistent", "--network", "lenient"]
    for port in ports:
        arguments += ["--port", f"tcp:{port}:8000"]
    context.sandy(arguments, name=name, user=user)
    context.wait_for_machine(name, running=True)


def _stop_without_sandy(context: E2EContext, name: str) -> None:
    """Container root ends PID 2; the stop also kills this attach."""
    context.sandy(
        ["exec", "--", "kill -TERM 2; sleep 30"],
        name=name,
        user="root",
        expected=128 + signal.SIGKILL,
    )
    context.wait_for_machine(name, running=False)


def run_matrix(
    context: E2EContext, backend: str, name: str, user: str, other: str
) -> None:
    """Exercise stale-rule cleanup; `other` runs with its own port throughout."""
    other_port = context.choose_host_port()
    first = context.choose_host_port()
    second = context.choose_host_port()
    if len({other_port, first, second}) != 3:
        raise E2EFailure("Could not choose three different host ports")

    with context.case(f"{backend}: a stop without sandy leaves the rules"):
        if context.machine_running(other):
            context.stop_container(other, user)
        _up(context, other, user, other_port)
        if context.machine_running(name):
            context.stop_container(name, user)
        _up(context, name, user, first)
        _expect_ports(context, backend, (other_port, first), ())
        _stop_without_sandy(context, name)
        _expect_ports(context, backend, (other_port, first), ())

    with context.case(f"{backend}: up with another port removes the stale rules"):
        _up(context, name, user, second)
        _expect_ports(context, backend, (other_port, second), (first,))

    with context.case(f"{backend}: up without ports removes the stale rules"):
        _stop_without_sandy(context, name)
        _expect_ports(context, backend, (other_port, second), (first,))
        _up(context, name, user)
        _expect_ports(context, backend, (other_port,), (first, second))

    with context.case(f"{backend}: repeated stops and starts keep other rules"):
        context.stop_container(name, user)
        repeated = context.sandy(["down"], name=name, user=user)
        if "not found or not running" not in repeated.output:
            raise E2EFailure("A second down did not report a stopped container")
        _up(context, name, user)
        context.stop_container(name, user)
        _expect_ports(context, backend, (other_port,), (first, second))
        context.stop_container(other, user)
        _expect_ports(context, backend, (), (other_port, first, second))


def test_main(context: E2EContext) -> None:
    """The iptables backend, with the main machine and a second machine."""
    context.build_lenient(context.other_name, context.main_user)
    run_matrix(
        context, "iptables", context.main_name, context.main_user, context.other_name
    )
    with context.case("iptables: the other machine is removed"):
        context.remove_container(context.other_name, context.main_user)
    # test_network expects the main machine to run.
    _up(context, context.main_name, context.main_user)
