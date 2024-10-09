#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_auth.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_auth.py: Test BGP Md5 Authentication

                             +------+
                    +--------|      |--------+
                    | +------|  R1  |------+ |
                    | | -----|      |----+ | |
                    | | |    +------+    | | |
                    | | |                | | |
                   +------+            +------+
                   |      |------------|      |
                   |  R2  |------------|  R3  |
                   |      |------------|      |
                   +------+            +------+

setup is 3 routers with 3 links between each link in a different vrf
Default, blue, and red respectively.
Tests check various fiddling with passwords and checking that the peer
establishment is as expected and passwords are not leaked across sockets
for bgp instances.
"""
# pylint: disable=C0413

import json
import os

from lib import common_config
from lib.topogen import get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))


def vrf_str(vrf):
    if vrf == "":
        vrf_text = ""
    else:
        vrf_text = "vrf {}".format(vrf)

    return vrf_text


def peer_name(rtr, prefix, vrf):
    "generate VRF string for CLI"
    if vrf == "":
        vrf_text = ""
    else:
        vrf_text = "_" + vrf

    if prefix == "yes":
        if rtr == "R2":
            return "TWO_GROUP" + vrf_text
        else:
            return "THREE_GROUP" + vrf_text
    else:
        if rtr == "R2":
            return "2.2.2.2"
        else:
            return "3.3.3.3"


def print_diag(vrf):
    "print failure diagnostics"

    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.items():
        print(rname + ":")
        print(router.vtysh_cmd("show run"))
        print(router.vtysh_cmd(f"show ip route {vrf_str(vrf)}"))
        print(router.vtysh_cmd(f"show bgp {vrf_str(vrf)} neighbor"))


@common_config.retry(retry_timeout=190)
def _check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    neigh_output = router.vtysh_cmd(f"show bgp {vrf_str(vrf)} neighbors {peer} json")

    peer_state = "Unknown"
    neigh_output_json = json.loads(neigh_output)
    if peer in neigh_output_json:
        peer_state = neigh_output_json[peer]["bgpState"]
        if peer_state == state:
            return True
    return f"{router.name} peer with {peer} expected state {state} got {peer_state} "


def check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    assertmsg = _check_neigh_state(router, peer, state, vrf)
    assert assertmsg is True, assertmsg


def check_all_peers_established(vrf=""):
    "standard check for established peers per vrf"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    # do r1 last as he might be the dynamic one
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)


def check_vrf_peer_remove_passwords(vrf="", prefix="no"):
    "selectively remove passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        f"conf t\nrouter bgp 65001 {vrf_str(vrf)}\nno neighbor {peer_name('R2', prefix, vrf)} password"
    )

    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(f"conf t\nrouter bgp 65002 {vrf_str(vrf)}\nno neighbor 1.1.1.1 password")
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        f"conf t\nrouter bgp 65001 {vrf_str(vrf)}\nno neighbor {peer_name('R3', prefix, vrf)} password"
    )
    check_all_peers_established(vrf)
