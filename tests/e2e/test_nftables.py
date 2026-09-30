"""The nftables firewall backend: setup, stale-rule cleanup, and removal.

Sandy uses nftables only when iptables is missing. Each sandy call here runs
in a private mount namespace in which iptables is hidden (see
E2EContext.without_iptables). This module runs after test_network, which
removes the bridge, the firewall, and the cache.
"""

from __future__ import annotations

from tests.e2e.support import (
    IPTABLES_CHAINS,
    E2EContext,
    E2EFailure,
)
from tests.e2e.test_stale_rules import run_matrix


def test_main(context: E2EContext) -> None:
    """Build two machines with the nftables backend and run the matrix."""
    name = context.nft_name
    other = context.nft_other_name
    user = context.main_user
    if context.sandy_state_artifacts():
        raise E2EFailure("Sandy state remains before the nftables tests")
    context.hide_iptables = True
    try:
        with context.case("nftables: a new network uses only the nft backend"):
            build = context.build_lenient(name, user)
            if "using nftables" not in build.output:
                raise E2EFailure("Sandy did not select the nftables backend")
            context.run(["nft", "list", "table", "ip", "sandy"])
            for table, chain in IPTABLES_CHAINS:
                exists = context.run(
                    ["iptables", "-t", table, "-S", chain], expected=None
                )
                if exists.returncode == 0:
                    raise E2EFailure(f"iptables chain {table}/{chain} exists")
            context.build_lenient(other, user)

        run_matrix(context, "nftables", name, user, other)

        with context.case("nftables: machines, network, and cache are removed"):
            for container in (name, other):
                context.remove_container(container, user)
            context.sandy(["rm", "--network", "--force"])
            context.purge_cache()
            context.assert_no_sandy_state()
    finally:
        # Cleanup after a failure also needs the nftables backend.
        if not context.sandy_state_artifacts():
            context.hide_iptables = False
