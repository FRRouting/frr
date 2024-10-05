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


setup is 3 routers with 3 links between each each link in a different vrf
Default, blue and red respectively
Tests check various fiddling with passwords and checking that the peer
establishment is as expected and passwords are not leaked across sockets
for bgp instances
"""
# pylint: disable=C0413

import json
import os

from lib import common_config
from lib.topogen import get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))


def vrf_str(vrf):
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "vrf {}".format(vrf)

    return vrf_str


def peer_name(rtr, prefix, vrf):
    "generate VRF string for CLI"
    if vrf == "":
        vrf_str = ""
    else:
        vrf_str = "_" + vrf

    if prefix == "yes":
        if rtr == "R2":
            return "TWO_GROUP" + vrf_str
        else:
            return "THREE_GROUP" + vrf_str
    else:
        if rtr == "R2":
            return "2.2.2.2"
        else:
            return "3.3.3.3"


def print_diag(vrf):
    "print failure disagnostics"

    tgen = get_topogen()
    router_list = tgen.routers()
    for rname, router in router_list.items():
        print(rname + ":")
        print(router.vtysh_cmd("show run"))
        print(router.vtysh_cmd("show ip route {}".format(vrf_str(vrf))))
        print(router.vtysh_cmd("show bgp {} neighbor".format(vrf_str(vrf))))


@common_config.retry(retry_timeout=190)
def _check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    neigh_output = router.vtysh_cmd(
        "show bgp {} neighbors {} json".format(vrf_str(vrf), peer)
    )

    peer_state = "Unknown"
    neigh_output_json = json.loads(neigh_output)
    if peer in neigh_output_json:
        peer_state = neigh_output_json[peer]["bgpState"]
        if peer_state == state:
            return True
    return "{} peer with {} expected state {} got {} ".format(
        router.name, peer, state, peer_state
    )


def check_neigh_state(router, peer, state, vrf=""):
    "check BGP neighbor state on a router"

    assertmsg = _check_neigh_state(router, peer, state, vrf)
    assert assertmsg is True, assertmsg


def check_all_peers_established(vrf=""):
    "standard check for extablished peers per vrf"

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
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )

    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nno neighbor {} password".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 1.1.1.1 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nno neighbor 3.3.3.3 password".format(vrf_str(vrf))
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nno neighbor 2.2.2.2 password".format(vrf_str(vrf))
    )
    check_all_peers_established(vrf)


def check_vrf_peer_change_passwords(vrf="", prefix="no"):
    "selectively change passwords checking state"

    tgen = get_topogen()
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change1".format(
            vrf_str(vrf), peer_name("R2", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 1.1.1.1 password change1".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 {}\nneighbor {} password change2".format(
            vrf_str(vrf), peer_name("R3", prefix, vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Established", vrf)
    check_neigh_state(r3, "1.1.1.1", "Connect", vrf)
    check_neigh_state(r3, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    # don't check dynamic downed peers - they are removed
    if prefix == "no":
        check_neigh_state(r1, "3.3.3.3", "Connect", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 1.1.1.1 password change2".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)

    r2.vtysh_cmd(
        "conf t\nrouter bgp 65002 {}\nneighbor 3.3.3.3 password change3".format(
            vrf_str(vrf)
        )
    )
    check_neigh_state(r2, "1.1.1.1", "Established", vrf)
    check_neigh_state(r2, "3.3.3.3", "Connect", vrf)
    check_neigh_state(r3, "1.1.1.1", "Established", vrf)
    check_neigh_state(r3, "2.2.2.2", "Connect", vrf)
    check_neigh_state(r1, "2.2.2.2", "Established", vrf)
    check_neigh_state(r1, "3.3.3.3", "Established", vrf)

    r3.vtysh_cmd(
        "conf t\nrouter bgp 65003 {}\nneighbor 2.2.2.2 password change3".format(
            vrf_str(vrf)
        )
    )
    check_all_peers_established(vrf)
