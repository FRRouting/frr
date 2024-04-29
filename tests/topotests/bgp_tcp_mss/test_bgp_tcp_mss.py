#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_tcp_mss.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Abhinay Ramesh <rabhinay@vmware.com>
#

"""
bgp_tcp_mss.py:

Test if works the following commands:
router bgp 65000
  neighbor 192.168.255.2 tcp-mss 500

Need to verify if the tcp-mss value is reflected in the TCP session.
"""

import os
import sys
import json
import pytest
import functools

# add after imports, before defining classes or functions:
pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_tcp_mss():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 0}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_conf_tcp_mss(router, as_num, neigh):
        router.vtysh_cmd(
            """configure terminal
               router bgp {0}
                 neighbor {1} tcp-mss 500""".format(
                as_num, neigh
            )
        )

    def _bgp_clear_session(router):
        router.vtysh_cmd("clear bgp *")

    def _bgp_check_neighbor_tcp_mss(router, neigh):
        output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neigh)))
        expected = {
            "{}".format(neigh): {"bgpTcpMssConfigured": 500, "bgpTcpMssSynced": 488}
        }
        return topotest.json_cmp(output, expected)

    logger.info("Check if neighbor sessions are up in {}".format(router1.name))
    test_func = functools.partial(_bgp_converge, router1)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to see BGP convergence in "{}"'.format(router1.name)

    logger.info("BGP neighbor session is up in {}".format(router1.name))

    logger.info(
        "Configure tcp-mss 500 on {} and reset the session".format(router1.name)
    )
    _bgp_conf_tcp_mss(router1, "65000", "192.168.255.2")
    _bgp_clear_session(router1)

    logger.info(
        "Configure tcp-mss 500 on {} and reset the session".format(router2.name)
    )
    _bgp_conf_tcp_mss(router2, "65001", "192.168.255.1")
    _bgp_clear_session(router2)

    logger.info(
        "Check if neighbor session is up after reset in {}".format(router1.name)
    )
    test_func = functools.partial(_bgp_converge, router1)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to see BGP convergence after reset in "{}"'.format(
        router1.name
    )

    logger.info(
        "Verify if TCP MSS value is synced with neighbor in {}".format(router1.name)
    )
    test_func = functools.partial(_bgp_check_neighbor_tcp_mss, router1, "192.168.255.2")
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert (
        result is None
    ), 'Failed to sync TCP MSS value over BGP session in "{}"'.format(router1.name)
    logger.info("TCP MSS value is synced with neighbor in {}".format(router1.name))

    logger.info(
        "Verify if TCP MSS value is synced with neighbor in {}".format(router2.name)
    )
    test_func = functools.partial(_bgp_check_neighbor_tcp_mss, router2, "192.168.255.1")
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert (
        result is None
    ), 'Failed to sync TCP MSS value over BGP session in "{}"'.format(router2.name)
    logger.info("TCP MSS value is synced with neighbor in {}".format(router2.name))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
