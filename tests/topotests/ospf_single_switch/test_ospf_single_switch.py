#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Adriano Marto Reis <adrianomarto@gmail.com>
#

import os
import sys
import json
import subprocess
from functools import partial
import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

from lib.common_config import verify_rib
from lib.ospf import verify_ospf_rib

pytestmark = pytest.mark.ospfd

"""
A large set of routers are connected to the same switch. Each router shares a
single network. All shared networks must be reachable from all routers.
"""

TOPOLOGY = """
       net1             net2                              netN
       ---              ---                               ---
        |                |            OSPF-passive         |
        |                |                                 |
    +---+---+        +---+---+                         +---+---+
    |       |        |       |                         |       |
    |  r1   |        |  r2   |          (...)          |  rN   |
    |       |        |       |                         |       |
    +---+---+        +---+---+                         +---+---+
        |                |           OSPF-active          |
        |                |                                |
        +----------------+--------------------------------+
                             switch


"""

N_ROUTERS = 8

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


def build_topo(tgen):
    "Build the topology"

    # Create a single switch to connect all the routers
    switch = tgen.add_switch("switch")

    # Create routers
    for router_id in range(1, N_ROUTERS + 1):
        router = tgen.add_router(f"r{router_id}")
        switch.add_link(router)

        # The shared network needs to be connected to something
        dummy = tgen.add_switch(f"s{router_id}")
        dummy.add_link(router)


def setup_module(mod):
    logger.info("OSPF single switch:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}_frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Tear-down the test environment"
    tgen = get_topogen()
    tgen.stop_topology()


def is_iproute2_json_supported():
    """
    Checks if the command 'ip -j route' is supported.
    """
    try:
        output = subprocess.run(
            ["ip", "-j", "route", "get", "0.0.0.0"], stdout=subprocess.PIPE
        ).stdout.decode()
        json.loads(output)
        return True
    except json.decoder.JSONDecodeError:
        return False


@pytest.mark.skipif(
    not is_iproute2_json_supported(), reason="'ip -j route' not supported"
)
def test_all_routes_advertised():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    # networks advertised by each router and the expected next hops
    networks = {
        "r1": ("10.0.1.0/24", "203.0.113.1"),
        "r2": ("10.0.2.0/24", "203.0.113.2"),
        "r3": ("10.0.3.0/24", "203.0.113.3"),
        "r4": ("10.0.4.0/24", "203.0.113.4"),
        "r5": ("10.0.5.0/24", "203.0.113.5"),
        "r6": ("10.0.6.0/24", "203.0.113.6"),
        "r7": ("10.0.7.0/24", "203.0.113.7"),
        "r8": ("10.0.8.0/24", "203.0.113.8"),
    }

    for router_orig in tgen.routers().keys():
        for router_dest, network in networks.items():
            if router_orig != router_dest:
                input_dict = {
                    router_orig: {
                        "static_routes": [
                            {
                                "network": network[0],
                            }
                        ]
                    }
                }
                result = verify_ospf_rib(
                    tgen, router_orig, input_dict, next_hop=network[1]
                )
                assert result is True, "Error: {}".format(result)
                result = verify_rib(
                    tgen, "ipv4", router_orig, input_dict, next_hop=network[1]
                )
                assert result is True, "Error: {}".format(result)

                check_route(router_orig, network[0], network[1])


def check_route(router_name, network, expected_nexthop):
    """
    Checks if the given network is present on the given router and has the
    expected next hop.
    """
    tgen = get_topogen()
    router = tgen.gears[router_name]

    expected_response = {
        network: [
            {
                "prefix": network,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": expected_nexthop,
                        "active": True,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp,
        router,
        f"show ip route {network} json",
        expected_response,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), f"{router_name} (ospfd): no route {network} via {expected_nexthop}"

    address = network.split("/")[0]
    output = router.cmd(f"ip -j route get {address}")
    logger.info(output)
    routes = json.loads(output)
    assert (
        routes[0]["gateway"] == expected_nexthop
    ), f"{router_name} (kernel): no route {address} via {expected_nexthop}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
