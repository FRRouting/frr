#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_remove_private_as.py
#
# Copyright (C) 2022  NVIDIA Corporation
# Trey Aspelund
#

"""
test_bgp_remove_private_as.py tests the following conditions:
1. "remove-private-AS" strips all private ASNs from the AS-path unless:
    a. the ASN belongs to the peer
    b. the ASN is both local + private
    c. the AS-path is not completely comprised of public ASNs
2. "remove-private-AS all" strips all private ASNs from the AS-path unless:
    a. the ASN belongs to the peer
    b. the ASN is both local + private
3. "remove-private-AS replace-AS" swaps private ASNs with local ASN unless:
    a. the ASN belongs to the peer
    b. the AS-path is not completely comprised of public ASNs
4. "remove-private-AS all replace-AS" swaps private ASNs with local ASN unless:
    a. the ASN belongs to the peer

All conditions are tested while the local ASN is private.
All conditions are tested while the local ASN is public.
All conditions are tested against an eBGP peer in a private ASN.
All conditions are tested against an eBGP peer in a public ASN.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from functools import partial

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """
    We are effectively creating two hub/spoke topologies with r2 and r5 acting
    as hubs. "remove-private-AS" will be configured on r2/r5 towards r3/r4, and
    r1 will act as the originator of the test prefixes. AS-Path validation will
    be done on r3/r4.

    Topology:
    +-----+      +-----+     +-----+
    | r1  |----->|r2/r5|---->| r3  |
    +-----+      +-----+     +-----+
                    |
                    v
                 +-----+
                 | r4  |
                 +-----+
    ASNs:
     - r1: 65001
     - r2: 65002
     - r3: 65003
     - r4: 4444
     - r5: 5555
    """
    for routern in range(1, 6):
        tgen.add_router(f"r{routern}")

    #######################
    # Connections to r2
    #######################
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    #######################
    # Connections to r5
    #######################
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, f"{rname}/zebra.conf")
        )
        router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, f"{rname}/bgpd.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_remove_private_as():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Test routes
    prefixes = [
        "100.64.0.0/32",
        "100.64.0.1/32",
        "100.64.0.2/32",
        "100.64.0.3/32",
        "100.64.0.4/32",
    ]

    # r2/r5 are setup with remove-private-AS configs.
    tx_routers = ["r2", "r5"]

    # We will validate the paths received by r3/r4.
    rx_routers = ["r3", "r4"]

    # Config options for remove-private-AS
    remove_types = [
        "remove-private-AS",
        "remove-private-AS all",
        "remove-private-AS replace-AS",
        "remove-private-AS all replace-AS",
    ]

    # Expected as-paths for each test route from the perspective of each
    # rx_router, accounting for each variation of remove-private-AS.
    #
    # Structure:
    # expected_paths = {
    #     rx_router: {
    #         remove_type: {
    #             tx_router: {
    #                 prefix: "path"
    #             }
    #         }
    #     }
    # }
    expected_paths = {
        "r3": {
            "remove-private-AS": {
                "r2": {
                    "100.64.0.0/32": "65002",
                    "100.64.0.1/32": "65002 65003 65003",
                    "100.64.0.2/32": "65002 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "65002 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "65002 65001 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555",
                    "100.64.0.1/32": "5555 65003 65003",
                    "100.64.0.2/32": "5555 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "5555 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "5555 65001 1000 2000 2000 3000",
                },
            },
            "remove-private-AS all": {
                "r2": {
                    "100.64.0.0/32": "65002",
                    "100.64.0.1/32": "65002 65003 65003",
                    "100.64.0.2/32": "65002 1000 2000",
                    "100.64.0.3/32": "65002 65003 1000 2000 65003",
                    "100.64.0.4/32": "65002 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555",
                    "100.64.0.1/32": "5555 65003 65003",
                    "100.64.0.2/32": "5555 1000 2000",
                    "100.64.0.3/32": "5555 65003 1000 2000 65003",
                    "100.64.0.4/32": "5555 1000 2000 2000 3000",
                },
            },
            "remove-private-AS replace-AS": {
                "r2": {
                    "100.64.0.0/32": "65002 65002 65002 65002 65002",
                    "100.64.0.1/32": "65002 65002 65003 65002 65002 65002 65003",
                    "100.64.0.2/32": "65002 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "65002 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "65002 65001 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555 5555 5555 5555 5555",
                    "100.64.0.1/32": "5555 5555 65003 5555 5555 5555 65003",
                    "100.64.0.2/32": "5555 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "5555 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "5555 65001 1000 2000 2000 3000",
                },
            },
            "remove-private-AS all replace-AS": {
                "r2": {
                    "100.64.0.0/32": "65002 65002 65002 65002 65002",
                    "100.64.0.1/32": "65002 65002 65003 65002 65002 65002 65003",
                    "100.64.0.2/32": "65002 65002 65002 1000 65002 2000 65002",
                    "100.64.0.3/32": "65002 65002 65003 65002 1000 65002 2000 65002 65003",
                    "100.64.0.4/32": "65002 65002 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555 5555 5555 5555 5555",
                    "100.64.0.1/32": "5555 5555 65003 5555 5555 5555 65003",
                    "100.64.0.2/32": "5555 5555 5555 1000 5555 2000 5555",
                    "100.64.0.3/32": "5555 5555 65003 5555 1000 5555 2000 5555 65003",
                    "100.64.0.4/32": "5555 5555 1000 2000 2000 3000",
                },
            },
        },
        "r4": {
            "remove-private-AS": {
                "r2": {
                    "100.64.0.0/32": "65002",
                    "100.64.0.1/32": "65002",
                    "100.64.0.2/32": "65002 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "65002 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "65002 65001 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555",
                    "100.64.0.1/32": "5555",
                    "100.64.0.2/32": "5555 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "5555 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "5555 65001 1000 2000 2000 3000",
                },
            },
            "remove-private-AS all": {
                "r2": {
                    "100.64.0.0/32": "65002",
                    "100.64.0.1/32": "65002",
                    "100.64.0.2/32": "65002 1000 2000",
                    "100.64.0.3/32": "65002 1000 2000",
                    "100.64.0.4/32": "65002 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555",
                    "100.64.0.1/32": "5555",
                    "100.64.0.2/32": "5555 1000 2000",
                    "100.64.0.3/32": "5555 1000 2000",
                    "100.64.0.4/32": "5555 1000 2000 2000 3000",
                },
            },
            "remove-private-AS replace-AS": {
                "r2": {
                    "100.64.0.0/32": "65002 65002 65002 65002 65002",
                    "100.64.0.1/32": "65002 65002 65002 65002 65002 65002 65002",
                    "100.64.0.2/32": "65002 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "65002 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "65002 65001 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555 5555 5555 5555 5555",
                    "100.64.0.1/32": "5555 5555 5555 5555 5555 5555 5555",
                    "100.64.0.2/32": "5555 65001 4200000000 1000 4200000001 2000 4200000002",
                    "100.64.0.3/32": "5555 65001 65003 4200000000 1000 4200000001 2000 4200000002 65003",
                    "100.64.0.4/32": "5555 65001 1000 2000 2000 3000",
                },
            },
            "remove-private-AS all replace-AS": {
                "r2": {
                    "100.64.0.0/32": "65002 65002 65002 65002 65002",
                    "100.64.0.1/32": "65002 65002 65002 65002 65002 65002 65002",
                    "100.64.0.2/32": "65002 65002 65002 1000 65002 2000 65002",
                    "100.64.0.3/32": "65002 65002 65002 65002 1000 65002 2000 65002 65002",
                    "100.64.0.4/32": "65002 65002 1000 2000 2000 3000",
                },
                "r5": {
                    "100.64.0.0/32": "5555 5555 5555 5555 5555",
                    "100.64.0.1/32": "5555 5555 5555 5555 5555 5555 5555",
                    "100.64.0.2/32": "5555 5555 5555 1000 5555 2000 5555",
                    "100.64.0.3/32": "5555 5555 5555 5555 1000 5555 2000 5555 5555",
                    "100.64.0.4/32": "5555 5555 1000 2000 2000 3000",
                },
            },
        },
    }

    # Simple lookup of remote peer ip by routers in session (local --> remote).
    #
    # Structure:
    # peer_to_ip = {
    #     local_rtr: {
    #         peer_rtr: peer_ip
    #     }
    # }
    peer_to_ip = {
        "r1": {"r2": "203.0.113.1", "r5": "203.0.113.3"},
        "r2": {"r1": "203.0.113.0", "r3": "203.0.113.4", "r4": "203.0.113.8"},
        "r3": {"r2": "203.0.113.5", "r5": "203.0.113.7"},
        "r4": {"r2": "203.0.113.9", "r5": "203.0.113.11"},
        "r5": {"r1": "203.0.113.2", "r3": "203.0.113.6", "r4": "203.0.113.10"},
    }

    def __bgp_up():
        """Return True if all configured peers are Established."""
        for router in tx_routers:
            output = json.loads(
                tgen.gears[router].vtysh_cmd("show ip bgp summary json")
            )
            numPeers = output["ipv4Unicast"]["totalPeers"]
            numConverged = 0
            for peer_data in output["ipv4Unicast"]["peers"].values():
                if peer_data["state"] == "Established":
                    numConverged += 1
            if numConverged == numPeers:
                return True
        return False

    def __bgp_converged():
        """Return True if all prefixes have been received from tx_routers."""
        for router in rx_routers:
            output = json.loads(
                tgen.gears[router].vtysh_cmd("show ip bgp summary json")
            )
            numPeers = output["ipv4Unicast"]["totalPeers"]
            numConverged = 0
            for peer in tx_routers:
                peer_ip = peer_to_ip[router][peer]
                numPrefixes = output["ipv4Unicast"]["peers"][peer_ip]["pfxRcd"]
                if numPrefixes == len(prefixes):
                    numConverged += 1
            if numConverged == numPeers:
                return True
        return False

    def _routers_up(tx_rtrs, rx_rtrs):
        """Ensure all BGP sessions are up and all routes are installed."""
        # all sessions go through tx_routers, so ensure all their peers are up
        test_func = partial(__bgp_up)
        _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
        assert result == True, "Not all peers in Established state!"

        # ensure correct number of routes are installed
        test_func = partial(__bgp_converged)
        _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
        assert result == True, "Not all routes installed in time!"

    def _change_remove_type(new_type, op):
        """Update config with next remove-private-AS config variant."""
        no = "no" if op == "del" else ""
        for tr in tx_routers:
            for rr in rx_routers:
                p_ip = peer_to_ip[tr][rr]
                tgen.gears[tr].vtysh_multicmd(
                    f"""
                    configure terminal
                    router bgp
                    address-family ipv4 unicast
                    {no} neighbor {p_ip} {new_type}
                    """
                )

    def _validate_paths(remove_type):
        """Compare actual AS-Path against expected AS-Path."""
        for rtr in rx_routers:
            for peer in tx_routers:
                p_ip = peer_to_ip[rtr][peer]
                adj_rib_in = json.loads(
                    tgen.gears[rtr].vtysh_cmd(
                        f"show ip bgp neighbor {p_ip} received-routes json"
                    )
                )
                for pfx in prefixes:
                    good_path = expected_paths[rtr][remove_type][peer][pfx]
                    real_path = adj_rib_in["receivedRoutes"][pfx]["path"]
                    return real_path == good_path

    #######################
    # Begin Test
    #######################

    # make sure all peers come up and exchange routes
    _routers_up(tx_routers, rx_routers)

    # test each variation of remove-private-AS
    for rmv_type in remove_types:
        _change_remove_type(rmv_type, "add")

        test_func = partial(_validate_paths, rmv_type)
        _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
        assert result == True, "Not all routes have correct AS-Path values!"

        # each variation sets a separate peer flag in bgpd. we need to clear
        # the old flag after each iteration so we only test the flags we expect.
        _change_remove_type(rmv_type, "del")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
