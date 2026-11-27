#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test for the northbound copy-on-write dnode sharing optimization.

This test verifies that:
1. After a commit, candidate's dnode is shared with running_config
   (dnode_shared = yes)
2. After an edit, candidate's dnode is independent (dnode_shared = no)
   due to copy-on-write trigger
3. After another commit, sharing is restored (dnode_shared = yes)

The test covers both code paths:
- bgpd: uses classic CLI mode, exercises nb_cli_classic_commit()
- mgmtd: uses static routes, exercises txn_finish_commit()
"""

import os
import re
import sys

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd, pytest.mark.mgmtd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()
    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _get_nb_state(router, daemon):
    """Get northbound state from 'show northbound' for a specific daemon."""
    output = router.vtysh_cmd(f"show northbound {daemon}")
    topotest.logger.info(f"show northbound output ({daemon}):\n{output}")

    state = {}
    match = re.search(r"dnode_shared:\s*(yes|no)", output)
    state["shared"] = match.group(1) == "yes" if match else None

    match = re.search(r"cow_share_count:\s*(\d+)", output)
    state["share_count"] = int(match.group(1)) if match else 0

    match = re.search(r"cow_trigger_count:\s*(\d+)", output)
    state["trigger_count"] = int(match.group(1)) if match else 0

    return state


def test_copy_on_write():
    """
    Verify copy-on-write behavior for bgpd using config file loading.

    bgpd uses FRR_CLI_CLASSIC mode. DEFUN_YANG commands (like route-map,
    prefix-list, interface) go through northbound. DEFUN commands (like
    neighbor) bypass northbound.

    This test uses route-map commands (DEFUN_YANG) via vtysh -f to verify:
    1. After initial config load, dnode is shared (dnode_shared = yes)
    2. After loading more config via vtysh -f, trigger_count increases
    3. After commit, dnode is shared again
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # After initial config load, dnode should be shared
    state1 = _get_nb_state(router, "bgpd")
    topotest.logger.info(f"bgpd state after startup: {state1}")
    assert state1["shared"] is True, "dnode_shared should be 'yes' after config load"
    assert state1["share_count"] >= 1, "share_count should be at least 1"

    # Load more config via vtysh -f (pretty_output=False triggers batch mode)
    # Use route-map command (DEFUN_YANG) which goes through northbound
    # This should trigger COW since dnode is currently shared
    router.vtysh_multicmd(
        """
        configure terminal
        route-map TEST permit 10
         set local-preference 200
        end
        """,
        pretty_output=False,
    )

    # After config load, dnode should be shared again, and trigger_count increased
    state2 = _get_nb_state(router, "bgpd")
    topotest.logger.info(f"bgpd state after vtysh -f: {state2}")
    assert state2["shared"] is True, "dnode_shared should be 'yes' after commit"
    assert state2["share_count"] > state1["share_count"], "share_count should increase"
    assert state2["trigger_count"] > state1["trigger_count"], "trigger_count should increase after editing shared dnode"

    # Verify config was applied
    output = router.vtysh_cmd("show running-config")
    assert "route-map TEST" in output, "Route-map not configured"

    topotest.logger.info("Copy-on-write test passed for bgpd")


def test_copy_on_write_mgmtd():
    """
    Verify copy-on-write behavior for mgmtd using static routes.
    Static routes use mgmtd backend, so this exercises the COW
    optimization in mgmtd's txn_finish_commit().
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # Get initial state
    state0 = _get_nb_state(router, "mgmtd")

    # Step 1: Add a static route (uses mgmtd backend)
    router.vtysh_cmd(
        """
        configure terminal
        ip route 192.168.100.0/24 10.0.0.254
        end
        """
    )

    # After commit, dnode should be shared in mgmtd
    state1 = _get_nb_state(router, "mgmtd")
    topotest.logger.info(f"mgmtd after commit: {state1}")
    assert state1["shared"] is True, "mgmtd dnode_shared should be 'yes' after commit"
    assert state1["share_count"] >= 1, "share_count should be at least 1"

    # Step 2: Add another static route
    router.vtysh_cmd(
        """
        configure terminal
        ip route 192.168.101.0/24 10.0.0.254
        end
        """
    )

    # After second commit, dnode should still be shared
    state2 = _get_nb_state(router, "mgmtd")
    topotest.logger.info(f"mgmtd after second commit: {state2}")
    assert state2["shared"] is True, "mgmtd dnode_shared should be 'yes' after second commit"
    assert state2["share_count"] > state1["share_count"], "share_count should increase after second commit"
    assert state2["trigger_count"] > state1["trigger_count"], "trigger_count should increase after editing shared dnode"

    # Verify routes were configured (check running-config, not RIB)
    output = router.vtysh_cmd("show running-config")
    assert "ip route 192.168.100.0/24" in output, "First static route not configured"
    assert "ip route 192.168.101.0/24" in output, "Second static route not configured"

    topotest.logger.info("Copy-on-write test passed for mgmtd")


if __name__ == "__main__":
    args = ["-s", "-v", __file__]
    sys.exit(pytest.main(args))
