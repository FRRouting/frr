#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_netlink.py
#
# Copyright (c) 2020 by
#

"""
test_zebra_netlink.py: Test some basic interactions with kernel using Netlink

"""
# pylint: disable=C0413
import ipaddress
import sys

import pytest
from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]


#####################################################
##
##   Tests starting
##
#####################################################


@pytest.fixture(scope="module")
def tgen(request):
    "Sets up the pytest environment"

    topodef = {"s1": ("r1")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # Initialize all routers.
    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_SHARP)

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def test_zebra_netlink_batching(tgen):
    "Test the situation where dataplane fills netlink send buffer entirely."
    logger.info(
        "Test the situation where dataplane fills netlink send buffer entirely."
    )
    r1 = tgen.gears["r1"]

    # Reduce the size of the buffer to hit the limit.
    r1.vtysh_cmd("conf t\nzebra kernel netlink batch-tx-buf 256 256")

    entry = {"r1-eth0": {"addresses": ["192.168.1.1/24"]}}
    ok = topotest.router_json_cmp_retry(r1, "show int brief json", entry, False, 30)
    assert ok, '"r1" Address not installed yet'

    count = 100
    r1.vtysh_cmd("sharp install routes 2.1.3.7 nexthop 192.168.1.1 " + str(count))

    # Generate expected results
    entry = {
        "protocol": "sharp",
        "distance": 150,
        "metric": 0,
        "installed": True,
        "table": 254,
        "nexthops": [
            {
                "fib": True,
                "ip": "192.168.1.1",
                "afi": "ipv4",
                "interfaceName": "r1-eth0",
                "active": True,
                "weight": 1,
            }
        ],
    }

    match = {}
    base = int(ipaddress.ip_address("2.1.3.7"))
    for i in range(base, base + count):
        pfx = str(ipaddress.ip_network((i, 32)))
        match[pfx] = [dict(entry, prefix=pfx)]

    ok = topotest.router_json_cmp_retry(r1, "show ip route json", match, False, 30)
    assert ok, '"r1" JSON output mismatches'

    r1.vtysh_cmd("sharp remove routes 2.1.3.7 " + str(count))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
