#!/usr/bin/env python

#
# test_bgp-vrf-route-leak-basic.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#                    Donald Sharp
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND Cumulus Networks DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp-vrf-route-leak-basic.py.py: Test basic vrf route leaking
"""

import os
import sys
from functools import partial
import pytest
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/setup_vrfs".format(CWD))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def check_bgp_rib(router, vrf, in_fib):
    if in_fib:
        attr = [{"protocol": "bgp", "selected": True, "nexthops": [{"fib": True}]}]
    else:
        attr = [{"protocol": "bgp", "nexthops": []}]

    if vrf == "DONNA":
        expect = {
            "10.0.0.0/24": [
                {
                    "protocol": "connected",
                }
            ],
            "10.0.1.0/24": attr,
            "10.0.2.0/24": [{"protocol": "connected"}],
            "10.0.3.0/24": attr,
        }
    else:
        expect = {
            "10.0.0.0/24": attr,
            "10.0.1.0/24": [
                {
                    "protocol": "connected",
                }
            ],
            "10.0.2.0/24": attr,
            "10.0.3.0/24": [
                {
                    "protocol": "connected",
                }
            ],
        }

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route vrf %s json" % vrf, expect
    )
    return topotest.run_and_expect(test_func, None, count=10, wait=0.5)


def check_bgp_fib(router, vrf, in_rib):
    # Check FIB
    # DONNA
    # 10.0.1.0/24 dev EVA proto bgp metric 20
    # 10.0.3.0/24 dev EVA proto bgp metric 20
    # EVA
    # 10.0.0.0/24 dev DONNA proto bgp metric 20
    # 10.0.2.0/24 dev DONNA proto bgp metric 20

    if vrf == "DONNA":
        table = 1001
        nh_vrf = "EVA"
    else:
        table = 1002
        nh_vrf = "DONNA"

    negate = "" if in_rib else "! "

    cmd = "%sip route show table %s | grep %s" % (negate, table, nh_vrf)
    result = False
    retry = 5
    output = ""
    while retry:
        retry -= 1
        try:
            output = router.cmd_raises(cmd)
            result = True
            break
        except:
            time.sleep(0.1)

    logger.info("VRF %s leaked FIB content %s: %s", vrf, cmd, output)

    return result, output


def check_bgp_ping(router, vrf):
    if vrf == "DONNA":
        cmd = "ip vrf exec DONNA ping -c1 10.0.1.1 -I 10.0.0.1"
    else:
        cmd = "ip vrf exec EVA ping -c1 10.0.0.1 -I 10.0.1.1"

    result = False
    retry = 5
    output = ""
    while retry:
        retry -= 1
        try:
            output = router.cmd_raises(cmd)
            result = True
            break
        except:
            time.sleep(0.1)

    return result, output


def test_vrf_route_leak_test1():
    logger.info("Ensure that routes are leaked back and forth")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for vrf in ["EVA", "DONNA"]:
        result, diff = check_bgp_rib(r1, vrf, True)
        assert result, "BGP RIB VRF {} check failed:\n{}".format(vrf, diff)
        result, output = check_bgp_fib(r1, vrf, True)
        assert result, "BGP FIB VRF {} check failed:\n{}".format(vrf, output)
        result, output = check_bgp_ping(r1, vrf)
        assert result, "Ping from VRF {} failed:\n{}".format(vrf, output)


def test_vrf_route_leak_test2():
    logger.info(
        "Ensure that leaked are still present after VRF iface IP address deletion"
    )
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Adding and removing an IPv4 address to EVA and DONNA VRF ifaces")
    r1.cmd("ip address add 1.1.1.1/32 dev EVA && ip address del 1.1.1.1/32 dev EVA")
    r1.cmd("ip address add 2.2.2.2/32 dev DONNA && ip address del 2.2.2.2/32 dev DONNA")

    for vrf in ["EVA", "DONNA"]:
        result, diff = check_bgp_rib(r1, vrf, True)
        assert result, "BGP RIB VRF {} check failed:\n{}".format(vrf, diff)
        result, output = check_bgp_fib(r1, vrf, True)
        assert result, "BGP FIB VRF {} check failed:\n{}".format(vrf, output)
        result, output = check_bgp_ping(r1, vrf)
        assert result, "Ping from VRF {} failed:\n{}".format(vrf, output)


def test_vrf_route_leak_test3():
    logger.info("Ensure that setting down the VRF ifaces invalidates leaked routes")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Setting down EVA and DONNA VRF ifaces")
    r1.cmd("ip link set EVA down")
    r1.cmd("ip link set DONNA down")

    for vrf in ["EVA", "DONNA"]:
        result, diff = check_bgp_rib(r1, vrf, False)
        assert result, "BGP RIB VRF {} check failed:\n{}".format(vrf, diff)
        result, output = check_bgp_fib(r1, vrf, False)
        assert result, "BGP FIB VRF {} check failed:\n{}".format(vrf, output)


def test_vrf_route_leak_test4():
    logger.info("Ensure that setting up the VRF ifaces validates leaked routes")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Setting up EVA and DONNA VRF ifaces")
    r1.cmd("ip link set EVA up")
    r1.cmd("ip link set DONNA up")

    for vrf in ["EVA", "DONNA"]:
        result, diff = check_bgp_rib(r1, vrf, True)
        assert result, "BGP RIB VRF {} check failed:\n{}".format(vrf, diff)
        result, output = check_bgp_fib(r1, vrf, True)
        assert result, "BGP FIB VRF {} check failed:\n{}".format(vrf, output)
        result, output = check_bgp_ping(r1, vrf)
        assert result, "Ping from VRF {} failed:\n{}".format(vrf, output)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
