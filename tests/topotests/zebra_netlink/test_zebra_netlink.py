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
import json
import sys
from functools import partial

import pytest
from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]

DEFAULT_TABLE = 254
DEFAULT_VRF = 0

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
        router.load_config(TopoRouter.RD_STATIC)

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
    r1.vtysh_cmd("conf t\nno zebra kernel netlink batch-tx-buf")


def zebra_netlink_delete_connected(tgen, iftype, nexthop_group):
    def _gen_route_json(prefix, proto, table_id, interface):
        entry = [
            {
                "prefix": prefix,
                "protocol": proto,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "directlyConnected": True,
                        "interfaceName": interface,
                        "active": True,
                    }
                ],
            }
        ]

        if table_id == DEFAULT_TABLE:
            entry[0]["vrfId"] = DEFAULT_VRF
        else:
            entry[0]["table"] = table_id

        return entry

    def _check_zebra_routing_tables(match, step):
        for tbl, expect in match.items():
            if int(tbl) == DEFAULT_TABLE:
                cmd = "show ip route json"
            else:
                cmd = "show ip route table %s json" % tbl

            ok = topotest.router_json_cmp_retry(r1, cmd, expect)
            assert ok, '"r1" JSON output mismatches table %s - sub-step %s' % (
                tbl,
                step,
            )

    def _check_linux_routing_tables(match, step):
        for tbl, expect in match.items():
            if int(tbl) == DEFAULT_TABLE:
                cmd = "ip route"
            else:
                cmd = "ip route show table %s" % tbl

            output = tgen.gears["r1"].cmd(cmd)

            for prefix in expect.keys():
                prefix = prefix.replace("/32", "")
                found = False
                for line in output.lstrip().splitlines():
                    if prefix in line:
                        found = True

                assert found, (
                    '"r1" Sub-step %d Linux routing table %s does not contain the prefix %s'
                    % (step, tbl, prefix)
                )

    def _check_routing_tables(match, step):
        _check_zebra_routing_tables(match, step)
        _check_linux_routing_tables(match, step)

    logger.info(
        "Test kernel route sync to zebra after deleting interface addresses. %s nethop-group %sabled"
        % (iftype, "en" if nexthop_group else "dis")
    )
    r1 = tgen.gears["r1"]

    if nexthop_group:
        r1.vtysh_cmd("conf t\nzebra nexthop kernel enable")
    else:
        r1.vtysh_cmd("conf t\nno zebra nexthop kernel enable")

    for i in [1, 2]:
        ifname = "%s%d" % (iftype, i)
        if iftype == "vrf":
            r1.cmd("ip link add %s type %s table %d" % (ifname, iftype, i))
        else:
            r1.cmd("ip link add %s type %s" % (ifname, iftype))

        r1.cmd("ip link set %s up" % ifname)
        for j in [1, 2]:
            r1.cmd("ip route add 1.%d.1.%d dev %s" % (i, j, ifname))
            if iftype == "vrf":
                r1.vtysh_cmd(
                    "conf t\nip route 2.%d.1.%d/32 %s nexthop-vrf %s"
                    % (i, j, ifname, ifname)
                )
            else:
                r1.vtysh_cmd("conf t\nip route 2.%d.1.%d/32 %s" % (i, j, ifname))
            r1.cmd("ip address add 3.%d.%d.1/24 dev %s" % (i, j, ifname))

    # Generate expected results
    match = {}
    for i in [1, 2]:
        ifname = "%s%d" % (iftype, i)
        for j in [1, 2]:
            tbl_id = DEFAULT_TABLE
            table = "%d" % tbl_id
            match.setdefault(table, {})
            prefix = "1.%d.1.%d/32" % (i, j)
            match[table][prefix] = _gen_route_json(prefix, "kernel", tbl_id, ifname)
            prefix = "2.%d.1.%d/32" % (i, j)
            match[table][prefix] = _gen_route_json(prefix, "static", tbl_id, ifname)
            if iftype == "vrf":
                tbl_id = i
                table = "%d" % tbl_id
                match.setdefault(table, {})
            prefix = "3.%d.%d.0/24" % (i, j)
            match[table][prefix] = _gen_route_json(prefix, "connected", tbl_id, ifname)

    _check_routing_tables(match, 0)

    # step1: remove the first connected address of the first interface
    i = 1
    ifname = "%s%d" % (iftype, i)
    r1.cmd("ip address del 3.%d.1.1/24 dev %s" % (i, ifname))
    if iftype == "vrf":
        table = "%d" % i
    else:
        table = "%d" % DEFAULT_TABLE
    match[table].pop("3.%d.1.0/24" % i)

    _check_routing_tables(match, 1)

    # step2: remove the second and last connected address of the first interface
    r1.cmd("ip address del 3.%d.2.1/24 dev %s" % (i, ifname))
    match[table].pop("3.%d.2.0/24" % i)
    # %s0 kernel routes are expected to be removed
    for j in [1, 2]:
        match["%s" % DEFAULT_TABLE].pop("1.%d.1.%d/32" % (i, j))

    _check_routing_tables(match, 2)

    for i in [1, 2]:
        ifname = "%s%d" % (iftype, i)
        r1.cmd("ip link del %s" % ifname)

    r1.vtysh_cmd("conf t\nzebra nexthop kernel enable")


def test_zebra_netlink_delete_connected_step1(tgen):
    nexthop_group = True
    zebra_netlink_delete_connected(tgen, "dummy", nexthop_group)


def test_zebra_netlink_delete_connected_step2(tgen):
    nexthop_group = False
    zebra_netlink_delete_connected(tgen, "dummy", nexthop_group)


def test_zebra_netlink_delete_connected_step3(tgen):
    nexthop_group = True
    zebra_netlink_delete_connected(tgen, "vrf", nexthop_group)


def test_zebra_netlink_delete_connected_step4(tgen):
    nexthop_group = False
    zebra_netlink_delete_connected(tgen, "vrf", nexthop_group)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
