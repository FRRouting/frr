#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bfd_reinstall_after_reset.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
A BGP BFD session must be registered again once BGP reconnects after
bgp_stop() removed it for an update-source or multihop change.

Before the fix the session was uninstalled when the Established peer went
down, but nothing installed it again: the parameters were unchanged, so
bgp_peer_bfd_update_source() saw nothing to do when the peer reconnected.
r1 kept BGP up with no BFD session, and r2's session stayed Down.

Topology:

  r1-eth0 192.0.2.1/30, 2001:db8:1::1/64 ---- r2-eth0 192.0.2.2/30, 2001:db8:1::2/64

  eBGP + BFD over IPv4 and IPv6 on both sides.
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
    "r1": ("192.0.2.2", "2001:db8:1::2"),
    "r2": ("192.0.2.1", "2001:db8:1::1"),
}
SOURCE = {"192.0.2.2": "192.0.2.1", "2001:db8:1::2": "2001:db8:1::1"}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
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
    for peer in peers:
        neighbor = json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(peer)))
        output[peer] = {
            "bgpState": neighbor.get(peer, {}).get("bgpState"),
            "bfd": [s.get("status") for s in bfd if s.get("peer") == peer],
        }
    expected = {peer: {"bgpState": "Established", "bfd": ["up"]} for peer in peers}
    return topotest.json_cmp(output, expected)


def _check_all_up(message):
    tgen = get_topogen()
    for rname, peers in PEERS.items():
        test_func = functools.partial(_bgp_and_bfd_up, tgen.gears[rname], peers)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{}: {}: {}".format(rname, message, result)


def test_bgp_bfd_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("BGP Established and BFD Up on both routers")
    _check_all_up("BGP/BFD not up")


def test_bfd_reinstalled_after_update_source_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Set update-source on r1 while BGP is Established")
    for peer, source in SOURCE.items():
        r1.vtysh_cmd(
            "configure terminal\nrouter bgp 65001\nneighbor {} update-source {}".format(
                peer, source
            )
        )
    _check_all_up("BFD not back up after update-source change")


def test_bfd_reinstalled_after_multihop_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Set disable-connected-check on r1 while BGP is Established")
    for peer in SOURCE:
        r1.vtysh_cmd(
            "configure terminal\nrouter bgp 65001\nneighbor {} disable-connected-check".format(
                peer
            )
        )
    _check_all_up("BFD not back up after disable-connected-check")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
