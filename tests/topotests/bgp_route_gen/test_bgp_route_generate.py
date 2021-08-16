#!/usr/bin/env python

#
# bgp_tcp_mss.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Abhinay Ramesh <rabhinay@vmware.com>
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
bgp_route_generate.py:

Test if below command works:
router bgp 65000
 address-family ipv4 unicast
  route-generate 99.0.0.0/8 count 100000 taskscheduling
 address-family ipv6 unicast
  route-generate dad::/64 count 100000 taskscheduling

Need to verify if the command works with and without task.
"""

import os
import sys
import json
import time
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

pytestmark = [pytest.mark.bgpd]


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

def test_bgp_route_generate():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    def _bgp_converge_ipv4(router, neigh):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor {} json".format(neigh)))
        expected = {
            "{}".format(neigh): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter":0}},
            }
        }
        print(expected)
        return topotest.json_cmp(output, expected)

    def _bgp_converge_ipv6(router, neigh):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor {} json".format(neigh)))
        expected = {
                "{}".format(neigh): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv6Unicast": {"acceptedPrefixCounter":0}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_converge_ipv4_max(router, neigh):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor {} json".format(neigh)))
        expected = {
            "{}".format(neigh): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter":100000}},
            }
        }
        print(expected)
        return topotest.json_cmp(output, expected)

    def _bgp_converge_ipv6_max(router, neigh):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor {} json".format(neigh)))
        expected = {
                "{}".format(neigh): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv6Unicast": {"acceptedPrefixCounter":100000}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_conf_route_generate_ipv4(router, no, as_num, count, batch_sz, sched_intvl):
        router.vtysh_cmd(
            """configure terminal
               router bgp {}
                address-family ipv4 unicast
                 {} route-generate 99.0.0.0/8 count {} batch-size {} schedule-interval {}""".format(
                as_num, no, count, batch_sz, sched_intvl
            )
        )

    def _bgp_conf_route_generate_ipv6(router, no, as_num, count, batch_sz, sched_intvl):
        router.vtysh_cmd(
            """configure terminal
               router bgp {}
                address-family ipv6 unicast
                 {} route-generate dad::/64 count {} batch-size {} schedule-interval {}""".format(
                as_num, no, count, batch_sz, sched_intvl
            )
        )

    logger.info("Check if bgp ipv4 sessions are up in {}".format(router1.name))
    test_func = functools.partial(_bgp_converge_ipv4, router1, neigh="192.168.255.2")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to see BGP ipv4 convergence in "{}"'.format(router1.name)

    logger.info("BGP ipv4 neighbor session is up in {}".format(router1.name))

    logger.info("Check if bgp ipv6 sessions are up in {}".format(router1.name))
    test_func = functools.partial(_bgp_converge_ipv6, router1, neigh="2000::2")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to see BGP ipv6 convergence in "{}"'.format(router1.name)

    logger.info("BGP ipv6 neighbor session is up in {}".format(router1.name))

    logger.info(
        "Configure ipv4 route-generate on {}".format(router1.name)
    )

    _bgp_conf_route_generate_ipv4(router1, " ", "65000", "100000", "100000", "1")

    logger.info("Check if bgp ipv4 sessions received 100000 routes in {}".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv4_max, router2, neigh="192.168.255.1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to receive 100000 routes in "{}"'.format(router2.name)

    logger.info("BGP ipv4 neighbor received 100000 routes in {}".format(router2.name))

    _bgp_conf_route_generate_ipv4(router1, "no", "65000", "100000", "100000", "1")

    logger.info("Check if bgp ipv4 sessions withdrew 100000 routes in {}".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv4, router2, neigh="192.168.255.1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to withdraw 100000 routes in "{}"'.format(router2.name)

    logger.info("BGP ipv4 neighbor withdrew 100000 routes in {}".format(router2.name))

    _bgp_conf_route_generate_ipv4(router1, " ", "65000", "100000", "500", "10")

    logger.info("Check if bgp ipv4 sessions received 100000 routes in {} with scheduling".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv4_max, router2, neigh="192.168.255.1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to receive 100000 routes in "{}" with scheduling'.format(router2.name)

    logger.info("BGP ipv4 neighbor received 100000 routes in {} with scheduling".format(router2.name))

    _bgp_conf_route_generate_ipv4(router1, "no", "65000", "100000", "500", "10")

    logger.info("Check if bgp ipv4 sessions withdrew 100000 routes in {} with scheduling".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv4, router2, neigh="192.168.255.1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to withdraw 100000 routes in "{}" with scheduling'.format(router2.name)

    logger.info("BGP ipv4 neighbor withdrew 100000 routes in {} with scheduling".format(router2.name))


    logger.info(
        "Configure ipv6 route-generate on {}".format(router1.name)
    )

    _bgp_conf_route_generate_ipv6(router1, " ", "65000", "100000", "100000", "1")

    logger.info("Check if bgp ipv6 sessions received 100000 routes in {}".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv6_max, router2, neigh="2000::1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to receive 100000 routes in "{}"'.format(router2.name)

    logger.info("BGP ipv6 neighbor received 100000 routes in {}".format(router2.name))

    _bgp_conf_route_generate_ipv6(router1, "no", "65000", "100000", "100000", "1")

    logger.info("Check if bgp ipv6 sessions withdrew 100000 routes in {}".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv6, router2, neigh="2000::1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to withdraw 100000 routes in "{}"'.format(router2.name)

    logger.info("BGP ipv6 neighbor withdrew 100000 routes in {}".format(router2.name))

    _bgp_conf_route_generate_ipv6(router1, " ", "65000", "100000", "1000", "5")

    logger.info("Check if bgp ipv6 sessions received 100000 routes in {} with scheduling".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv6_max, router2, neigh="2000::1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to receive 100000 routes in "{}" with scheduling'.format(router2.name)

    logger.info("BGP ipv6 neighbor received 100000 routes in {} with scheduling".format(router2.name))

    _bgp_conf_route_generate_ipv6(router1, "no", "65000", "100000", "1000", "15")

    logger.info("Check if bgp ipv6 sessions withdrew 100000 routes in {} with scheduling".format(router2.name))
    test_func = functools.partial(_bgp_converge_ipv6, router2, neigh="2000::1")
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)
    assert result is None, 'Failed to withdraw 100000 routes in "{}" with scheduling'.format(router2.name)

    logger.info("BGP ipv6 neighbor withdrew 100000 routes in {} with scheduling".format(router2.name))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
