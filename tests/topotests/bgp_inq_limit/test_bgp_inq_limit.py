#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_inq_limit.py
# Part of FRR Topology Tests
#

"""
test_bgp_inq_limit.py:

Test that BGP correctly handles the input-queue-limit setting.
When a receiver has a low `bgp input-queue-limit` and a sender
advertises many routes, the I/O thread blocks reads when the
queue is full. The main thread drains the queue, re-arms reads,
and all routes eventually converge.

Topology:

  r1 (AS 65001) ---- eBGP ---- r2 (AS 65002)
  192.168.1.1/24               192.168.1.2/24

r1 uses sharpd to install 1000 routes redistributed into BGP.

r2 has `bgp input-queue-limit 100` configured.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

# Number of routes originated by r1 via sharpd
ROUTE_COUNT = 1000


def build_topo(tgen):
    """Create the topology: 2 routers connected via 1 switch."""
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        if rname == "r1":
            router.load_config(TopoRouter.RD_SHARP)

    tgen.start_router()

    # Install routes via sharpd after daemons are running
    tgen.gears["r1"].vtysh_cmd(
        "sharp install routes 10.0.0.0 nexthop 192.168.1.1 {}".format(ROUTE_COUNT)
    )


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Verify eBGP session between r1 and r2 reaches Established state."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "state": "Established",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success is True, "BGP session not Established on r2: {}".format(result)


def test_bgp_inq_limit_routes_received():
    """
    Verify all 1000 routes are received on r2 despite the low
    input-queue-limit of 100. This proves the I/O read re-arm
    mechanism works correctly after the main thread drains the queue.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_routes_received():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "pfxRcd": ROUTE_COUNT,
                    "state": "Established",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_routes_received)
    success, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert success is True, "r2 did not receive all {} routes: {}".format(
        ROUTE_COUNT, result
    )


def test_bgp_inq_drain():
    """
    After all routes have converged, verify the input queue depth
    (`inq` in `show bgp summary json`) settles back to 0.
    This proves the queue is not stuck full.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_inq_drained():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "inq": 0,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_inq_drained)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success is True, "Input queue on r2 did not drain to 0: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
