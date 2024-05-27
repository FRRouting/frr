#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp-vrf-route-leak-basic.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#                    Donald Sharp
#

"""
test_bgp-vrf-route-leak-basic.py.py: Test basic vrf route leaking
"""

import os
import sys
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping

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


def test_vrf_route_leak_donna():
    logger.info("Ensure that routes are leaked back and forth")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test DONNA VRF.
    expect = {
        "10.0.0.0/24": [
            {
                "protocol": "connected",
            }
        ],
        "10.0.1.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.2.0/24": [{"protocol": "connected"}],
        "10.0.3.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.4.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "dummy0",
                        "vrf": "default",
                        "active": True,
                    },
                ],
            },
        ],
        "172.16.101.0/24": [
            {
                "protocol": "bgp",
                "selected": None,
                "nexthops": [
                    {
                        "fib": None,
                        "interfaceName": "unknown",
                        "vrf": "Unknown",
                        "active": None,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_vrf_route_leak_eva():
    logger.info("Ensure that routes are leaked back and forth")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test EVA VRF.
    expect = {
        "10.0.0.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "DONNA",
                        "vrf": "DONNA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.1.0/24": [
            {
                "protocol": "connected",
            }
        ],
        "10.0.2.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "DONNA",
                        "vrf": "DONNA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.3.0/24": [
            {
                "protocol": "connected",
            }
        ],
        "172.16.101.0/24": [
            {
                "protocol": "bgp",
                "selected": None,
                "nexthops": [
                    {
                        "fib": None,
                        "interfaceName": "unknown",
                        "vrf": "Unknown",
                        "active": None,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf EVA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF EVA check failed:\n{}".format(diff)


def test_vrf_route_leak_default():
    logger.info("Ensure that routes are leaked back and forth")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test default VRF.
    expect = {
        "10.0.0.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "DONNA",
                        "vrf": "DONNA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.2.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "DONNA",
                        "vrf": "DONNA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.4.0/24": [
            {
                "protocol": "connected",
            }
        ],
    }

    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expect)
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF default check failed:\n{}".format(diff)


def test_ping():
    "Simple ping tests"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Ping from default to DONNA")
    check_ping("r1", "10.0.0.1", True, 10, 0.5, source_addr="10.0.4.1")


def test_vrf_route_leak_donna_after_eva_down():
    logger.info("Ensure that route states change after EVA interface goes down")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
configure
interface EVA
 shutdown
"""
    )

    # Test DONNA VRF.
    expect = {
        "10.0.1.0/24": [
            {
                "protocol": "bgp",
                "selected": None,
                "nexthops": [
                    {
                        "fib": None,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": None,
                    },
                ],
            },
        ],
        "10.0.3.0/24": [
            {
                "protocol": "bgp",
                "selected": None,
                "nexthops": [
                    {
                        "fib": None,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": None,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)

    """
    Check that "show ip route vrf DONNA json" and the JSON at key "DONNA" of
    "show ip route vrf all json" gives the same result.
    """

    def check_vrf_table(router, vrf, expect):
        output = router.vtysh_cmd("show ip route vrf all json", isjson=True)
        vrf_table = output.get(vrf, {})

        return topotest.json_cmp(vrf_table, expect)

    test_func = partial(check_vrf_table, r1, "DONNA", expect)
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_vrf_route_leak_donna_after_eva_up():
    logger.info("Ensure that route states change after EVA interface goes up")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
configure
interface EVA
 no shutdown
"""
    )

    # Test DONNA VRF.
    expect = {
        "10.0.1.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": True,
                    },
                ],
            },
        ],
        "10.0.3.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "EVA",
                        "vrf": "EVA",
                        "active": True,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_vrf_route_leak_donna_add_vrf_zita():
    logger.info("Add VRF ZITA and ensure that the route from VRF ZITA is updated")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.cmd("ip link add ZITA type vrf table 1003")

    # Test DONNA VRF.
    expect = {
        "172.16.101.0/24": [
            {
                "protocol": "bgp",
                "selected": None,
                "nexthops": [
                    {
                        "fib": None,
                        "interfaceName": "ZITA",
                        "vrf": "ZITA",
                        "active": None,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_vrf_route_leak_donna_set_zita_up():
    logger.info("Set VRF ZITA up and ensure that the route from VRF ZITA is updated")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
configure
interface ZITA
 no shutdown
"""
    )

    # Test DONNA VRF.
    expect = {
        "172.16.101.0/24": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [
                    {
                        "fib": True,
                        "interfaceName": "ZITA",
                        "vrf": "ZITA",
                        "active": True,
                    },
                ],
            },
        ],
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_vrf_route_leak_donna_delete_vrf_zita():
    logger.info("Delete VRF ZITA and ensure that the route from VRF ZITA is deleted")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.cmd("ip link delete ZITA")

    # Test DONNA VRF.
    expect = {
        "172.16.101.0/24": None,
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf DONNA json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result, "BGP VRF DONNA check failed:\n{}".format(diff)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
