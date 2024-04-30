#!/usr/bin/env python

#
# test_zebra_netlink.py
#
# Copyright (c) 2020 by
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_zebra_netlink.py: Test some basic interactions with kernel using Netlink

"""
# pylint: disable=C0413
import ipaddress
import json
import sys
from functools import partial

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
    for rname, router in router_list.items():
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
    base = int(ipaddress.ip_address(u"2.1.3.7"))
    for i in range(base, base + count):
        pfx = str(ipaddress.ip_network((i, 32)))
        match[pfx] = [dict(entry, prefix=pfx)]

    ok = topotest.router_json_cmp_retry(r1, "show ip route json", match, False, 30)
    assert ok, '"r1" JSON output mismatches'

    r1.vtysh_cmd("sharp remove routes 2.1.3.7 " + str(count))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
