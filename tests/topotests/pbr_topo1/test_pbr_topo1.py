#!/usr/bin/env python

#
# test_pbr_topo1.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc.
# Donald Sharp
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
test_pbr_topo1.py: Testing PBR

"""

import os
import sys
import pytest
import json
import platform
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import shutdown_bringup_interface

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.pbrd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    "Build function"

    # Populate routers
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))

    # Populate switches
    for switchn in range(1, 6):
        switch = tgen.add_switch("sw{}".format(switchn))
        switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.10") < 0:
        tgen.errors = "Newer kernel than 4.9 needed for pbr tests"
        pytest.skip(tgen.errors)

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Install vrf into the kernel and slave eth3
        router.run("ip link add vrf-chiyoda type vrf table 1000")
        router.run("ip link set dev {}-eth3 master vrf-chiyoda".format(rname))
        router.run("ip link set vrf-chiyoda up")

        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PBRD, os.path.join(CWD, "{}/pbrd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "Waiting for PBR convergence")


def test_pbr_data():
    "Test PBR 'show ip eigrp'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify PBR Status
    logger.info("Verifying PBR routes")

    router_list = tgen.routers().values()
    for router in router_list:
        intf_file = "{}/{}/pbr-interface.json".format(CWD, router.name)
        logger.info(intf_file)

        # Read expected result from file
        expected = json.loads(open(intf_file).read())

        # Actual output from router
        test_func = partial(
            topotest.router_json_cmp, router, "show pbr interface json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"show pbr interface" mismatches on {}'.format(router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg

        map_file = "{}/{}/pbr-map.json".format(CWD, router.name)
        logger.info(map_file)

        # Read expected result from file
        expected = json.loads(open(map_file).read())

        # Actual output from router
        test_func = partial(
            topotest.router_json_cmp, router, "show pbr map json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"show pbr map" mismatches on {}'.format(router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg

        nexthop_file = "{}/{}/pbr-nexthop-groups.json".format(CWD, router.name)
        logger.info(nexthop_file)

        # Read expected result from file
        expected = json.loads(open(nexthop_file).read())

        # Actual output from router
        test_func = partial(
            topotest.router_json_cmp, router, "show pbr nexthop-groups json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"show pbr nexthop-groups" mismatches on {}'.format(router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg


def test_pbr_flap():
    "Test PBR interface flapping"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify PBR Status
    logger.info("Flapping PBR Interfaces")

    router_list = tgen.routers().values()
    for router in router_list:
        # Flap interface to see if route-map properties are intact
        # Shutdown interface

        for i in range(5):
            intf = "r1-eth{}".format(i)

            # Down and back again
            shutdown_bringup_interface(tgen, router.name, intf, False)
            shutdown_bringup_interface(tgen, router.name, intf, True)

        intf_file = "{}/{}/pbr-interface.json".format(CWD, router.name)
        logger.info(intf_file)

        # Read expected result from file
        expected = json.loads(open(intf_file).read())

        # Actual output from router
        test_func = partial(
            topotest.router_json_cmp, router, "show pbr interface json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"show pbr interface" mismatches on {}'.format(router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg


def test_rule_linux_installation():
    "Ensure that rule is installed in the kernel"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking for installed PBR rules in OS")

    def _get_router_rules(router, expected):
        actual = topotest.ip_rules(router)

        logger.info(actual)
        return topotest.json_cmp(actual, expected)

    router_list = tgen.routers().values()
    for router in router_list:
        rules_file = "{}/{}/linux-rules.json".format(CWD, router.name)

        expected = json.loads(open(rules_file).read())

        test_func = partial(_get_router_rules, router, expected)

        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = "Router {} OS rules mismatch".format(router.name)
        assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

#
# EXTRA SAUCE
#
def gather_pbr_data_on_error(router):
    logger.info(router.vtysh_cmd("show ip route"))
    logger.info(router.vtysh_cmd("show ip route vrf vrf-chiyoda"))
    logger.info(router.vtysh_cmd("show ip nht"))
    logger.info(router.vtysh_cmd("show pbr interface"))
    logger.info(router.vtysh_cmd("show pbr map"))
    logger.info(router.vtysh_cmd("show pbr nexthop-groups"))
    logger.info(router.vtysh_cmd("show nexthop-group rib singleton ip"))
    logger.info(router.vtysh_cmd("show nexthop-group rib singleton ipv6"))
    logger.info(router.vtysh_cmd("show nexthop-group rib"))
    logger.info(router.run("ip nexthop show"))
    logger.info(router.run("ip route show"))
    logger.info(router.run("ip route show table 1000"))
    logger.info(router.run("ip route show table 10000"))
    logger.info(router.run("ip -6 route show table 10000"))
    logger.info(router.run("ip route show table 10001"))
    logger.info(router.run("ip -6 route show table 10001"))
    logger.info(router.run("ip route show table 10002"))
    logger.info(router.run("ip -6 route show table 10002"))
    logger.info(router.run("ip route show table 10003"))
    logger.info(router.run("ip -6 route show table 10003"))
    logger.info(router.run("ip route show table 10004"))
    logger.info(router.run("ip -6 route show table 10004"))
    logger.info(router.run("ip route show table 10005"))
    logger.info(router.run("ip -6 route show table 10005"))
    logger.info(router.run("ip rule show"))
