#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bfd_singlehop_overlap_subnet.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
A single-hop BGP BFD session must use the interface of the most specific
connected subnet holding the peer address.

r1 has a wide subnet on r1-eth0 and a more specific one, which holds the
peer, on r1-eth1.  The kernel routes BGP over r1-eth1.  Taking the first
connected subnet that contains the peer instead keys the session on
r1-eth0, where nobody answers, and BFD stays Down.

Topology:

  r3-eth0 10.0.0.3/16, 2001:db8::3/48 ---- r1-eth0 10.0.0.1/16, 2001:db8::1/48
  r1-eth1 10.0.1.1/24, 2001:db8:0:1::1/64 ---- r2-eth0 10.0.1.2/24, 2001:db8:0:1::2/64

r1 <-> r2: eBGP + BFD over IPv4 and IPv6.  r3 runs no BGP or BFD.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd]

PEERS = {
    "r1": {"10.0.1.2": "r1-eth1", "2001:db8:0:1::2": "r1-eth1"},
    "r2": {"10.0.1.1": "r2-eth0", "2001:db8:0:1::1": "r2-eth0"},
}


def build_topo(tgen):
    for rname in ("r1", "r2", "r3"):
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_and_bfd_up(router, peers):
    bfd = json.loads(router.vtysh_cmd("show bfd peers json"))
    output = {}
    expected = {}
    for peer, ifname in peers.items():
        neighbor = json.loads(
            router.vtysh_cmd("show bgp neighbors {} json".format(peer))
        )
        output[peer] = {
            "bgpState": neighbor.get(peer, {}).get("bgpState"),
            "bfd": [
                {"interface": s.get("interface"), "status": s.get("status")}
                for s in bfd
                if s.get("peer") == peer
            ],
        }
        expected[peer] = {
            "bgpState": "Established",
            "bfd": [{"interface": ifname, "status": "up"}],
        }
    return topotest.json_cmp(output, expected, exact=True)


def test_bgp_bfd_singlehop_overlap_subnet():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("BFD sessions must use the most specific connected subnet's interface")
    for rname, peers in PEERS.items():
        test_func = functools.partial(_bgp_and_bfd_up, tgen.gears[rname], peers)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert (
            result is None
        ), "{}: BGP/BFD not up on the expected interface: {}".format(rname, result)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
