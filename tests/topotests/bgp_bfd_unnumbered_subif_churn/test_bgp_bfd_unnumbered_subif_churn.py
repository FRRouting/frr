#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Sougata Barik <sougatab@nvidia.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Regression test: BFD sessions must stay Up for many single-hop unnumbered
eBGP peers that share the same IPv6 link-local address, across repeated
BGP neighbor delete/re-add churn.

Topology

    R1 (AS 65001) ----[s1]---- R2 (AS 65002)

The physical link r1-eth0 <-> r2-eth0 carries NUM_VLANS tagged VLANs. Each
VLAN sub-interface hosts one single-hop unnumbered eBGP peer with BFD enabled
(fast profile). Because all sub-interfaces of a parent share the parent's MAC,
every sub-interface derives the SAME IPv6 link-local address, so all BFD
sessions share an identical (src, dst) link-local pair and are distinguishable
only by their outgoing interface (ifindex).

Bug (FRRouting BFD client library)
----------------------------------
During rapid BGP neighbor delete/re-add, bgp_peer_bfd_update_source() fires the
address setter while peer->nexthop.ifp is still NULL, so the BFD session is
registered/deregistered with no interface. With every peer sharing the same
link-local pair, all those interface-less registrations collapse onto a single
ifindex-less key in bfdd; the sessions tear each other down and most stay Down
even though BGP reaches Established.

Expected (fixed) behaviour: after each delete/re-add cycle, BGP reaches
Established AND all NUM_VLANS BFD sessions return to Up.

test_bgp_bfd_unnumbered_subif_baseline
    Sanity: all peers Established and all BFD sessions Up on first bring-up.

test_bgp_bfd_unnumbered_subif_churn_recovery
    THE regression. Repeatedly delete and re-add all unnumbered BFD peers on
    R1, then require every BFD session to come back Up. This FAILS on the
    unfixed tree (sessions collapse -> stuck Down) and PASSES with the fix.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

NUM_VLANS = 10
START_VLAN = 100
CHURN_ITERATIONS = 5

VLANS = list(range(START_VLAN, START_VLAN + NUM_VLANS))


def _subifs(rname):
    """Return the list of sub-interface names for a router."""
    return ["{}-eth0.{}".format(rname, vlan) for vlan in VLANS]


def build_topo(tgen):
    """Two routers connected via a single switch."""
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Create the VLAN sub-interfaces and load per-router configs."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        for vlan in VLANS:
            router.net.add_vlan(
                "{}-eth0.{}".format(rname, vlan), "{}-eth0".format(rname), vlan
            )

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Remove the sub-interfaces and stop the topology."""
    tgen = get_topogen()

    for rname, router in tgen.routers().items():
        for vlan in VLANS:
            router.net.del_iface("{}-eth0.{}".format(rname, vlan))

    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bgp_established_count(router):
    """Number of ipv4-unicast peers in Established state."""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    peers = output.get("ipv4Unicast", {}).get("peers", {})
    return sum(
        1 for p in peers.values() if p.get("state") == "Established"
    )


def _bfd_up_count(router):
    """Number of BFD peer sessions currently in status 'up'."""
    output = json.loads(router.vtysh_cmd("show bfd peers json"))
    if not isinstance(output, list):
        return 0
    return sum(1 for peer in output if peer.get("status") == "up")


def _check_all_up(router):
    """
    Return None when both BGP (Established) and BFD (up) reach NUM_VLANS,
    otherwise a description of what is still missing.
    """
    bgp = _bgp_established_count(router)
    bfd = _bfd_up_count(router)
    if bgp != NUM_VLANS:
        return "BGP established {}/{}".format(bgp, NUM_VLANS)
    if bfd != NUM_VLANS:
        return "BFD up {}/{} (BGP established {}/{})".format(
            bfd, NUM_VLANS, bgp, NUM_VLANS
        )
    return None


def _delete_bfd_peers(router, rname):
    """Remove all unnumbered BFD peers from the router's BGP config."""
    lines = ["configure terminal", "router bgp 65001"]
    for ifname in _subifs(rname):
        lines.append("no neighbor {} interface remote-as external".format(ifname))
    lines.append("end")
    router.vtysh_cmd("\n".join(lines))


def _add_bfd_peers(router, rname):
    """Re-add all unnumbered peers with BFD enabled."""
    lines = ["configure terminal", "router bgp 65001"]
    for ifname in _subifs(rname):
        lines.append("neighbor {} interface remote-as external".format(ifname))
        lines.append("neighbor {} bfd".format(ifname))
        lines.append("neighbor {} bfd profile fast".format(ifname))
    lines.append("end")
    router.vtysh_cmd("\n".join(lines))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_bgp_bfd_unnumbered_subif_baseline():
    """Sanity: on first bring-up all peers are Established and all BFD Up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Baseline: all {} BGP peers Established and all BFD sessions Up".format(
        NUM_VLANS))
    test_func = functools.partial(_check_all_up, r1)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Baseline did not converge on R1: {}".format(result)


def test_bgp_bfd_unnumbered_subif_churn_recovery():
    """
    Regression for the shared-link-local interface-less BFD collapse.

    Delete and re-add every unnumbered BFD peer on R1 repeatedly; after each
    cycle every BFD session must return to Up. Fails on the unfixed tree.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Make sure we start from a fully converged state.
    test_func = functools.partial(_check_all_up, r1)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Pre-churn state not converged on R1: {}".format(result)

    for i in range(1, CHURN_ITERATIONS + 1):
        step("Churn iteration {}/{}: delete all unnumbered BFD peers".format(
            i, CHURN_ITERATIONS))
        _delete_bfd_peers(r1, "r1")

        # Let the delete settle so the sessions are actually torn down.
        def _all_down():
            return None if _bgp_established_count(r1) == 0 else "peers still up"

        topotest.run_and_expect(functools.partial(_all_down), None, count=30, wait=1)

        step("Churn iteration {}/{}: re-add all unnumbered BFD peers".format(
            i, CHURN_ITERATIONS))
        _add_bfd_peers(r1, "r1")

        step("Churn iteration {}/{}: require BGP {}/{} and BFD {}/{}".format(
            i, CHURN_ITERATIONS, NUM_VLANS, NUM_VLANS, NUM_VLANS, NUM_VLANS))
        test_func = functools.partial(_check_all_up, r1)
        _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
        assert result is None, (
            "After churn iteration {}: {} - BFD sessions did not all recover "
            "(shared link-local interface-less collapse, #5131052)".format(i, result)
        )


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
