#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_maximum_prefix_out.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if `neighbor <X.X.X.X> maximum-prefix-out <Y>` is working
correctly.
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

    for _, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_maximum_prefix_out():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    # format (router to configure, command, expected received prefixes on r2)
    tests = [
        # test of the initial config
        (None, 2),
        # modifying the max-prefix-out value
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 4",
            4,
        ),
        # removing the max-prefix-out value
        (
            "router bgp\n address-family ipv4\n no neighbor 192.168.255.1 maximum-prefix-out",
            6,
        ),
        # setting a max-prefix-out value
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 3",
            3,
        ),
        # setting a max-prefix-out value - higher than the total number of prefix
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 8",
            6,
        ),
        # adding a new prefix
        ("router bgp\n int lo\n ip address 172.16.255.249/32", 7),
        # setting a max-prefix-out value - lower than the total number of prefix
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 1",
            1,
        ),
        # adding a new prefix
        ("router bgp\n int lo\n ip address 172.16.255.248/32", 1),
        # removing the max-prefix-out value
        (
            "router bgp\n address-family ipv4\n no neighbor 192.168.255.1 maximum-prefix-out 1",
            8,
        ),
        # test setting the existing neighbor into a peer-group with a max-prefix-out value
        (
            """
                router bgp
                 neighbor test peer-group
                 neighbor test remote-as 65002
                 neighbor test timers 3 10
                 address-family ipv4
                  neighbor test maximum-prefix-out 3
                 !
                 neighbor 192.168.255.1 peer-group test
            """,
            3,
        ),
        # max-prefix-out value of the neighbor must take the precedence
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 4",
            4,
        ),
        (
            "router bgp\n address-family ipv4\n no neighbor 192.168.255.1 maximum-prefix-out",
            3,
        ),
        (
            """
                router bgp
                 no neighbor 192.168.255.1 peer-group test
                 neighbor 192.168.255.1 remote-as 65002
                 neighbor 192.168.255.1 timers 3 10
            """,
            8,
        ),
        (
            "router bgp\n address-family ipv4\n neighbor 192.168.255.1 maximum-prefix-out 5",
            5,
        ),
        # test setting the existing neighbor with a max-pref-out value into a peer-group with a max-pref-out value
        ("router bgp\n neighbor 192.168.255.1 peer-group test", 5),
        (
            "router bgp\n address-family ipv4\n no neighbor 192.168.255.1 maximum-prefix-out 5",
            3,
        ),
    ]

    def _bgp_converge(router, nb_prefixes):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {"acceptedPrefixCounter": nb_prefixes}
                },
            }
        }
        return topotest.json_cmp(output, expected)

    for test in tests:
        cfg, exp_prfxs = test
        if cfg:
            cmd = (
                """
              configure terminal
               %s
            """
                % cfg
            )
            router1.vtysh_cmd(cmd)

        test_func = functools.partial(_bgp_converge, router2, exp_prfxs)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

        assert result is None, 'Failed bgp convergence in "{}"'.format(router2)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
