#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_set_aspath_replace.py
#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if `set as-path replace` is working correctly for route-maps.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


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


def test_bgp_set_aspath_replace_test1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.31/32": [{"path": "65002 65001"}],
                "172.16.255.32/32": [{"path": "65001 65001"}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with route-map"


def test_bgp_set_aspath_replace_test2():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Configuring r1 to replace the matching AS with a configured ASN")
    router = tgen.gears["r1"]
    router.vtysh_cmd(
        "configure terminal\nroute-map r2 permit 10\nset as-path replace 65003 65500\n",
        isjson=False,
    )
    router.vtysh_cmd(
        "configure terminal\nroute-map r2 permit 20\nset as-path replace any 65501\n",
        isjson=False,
    )

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.31/32": [{"path": "65002 65500"}],
                "172.16.255.32/32": [{"path": "65501 65501"}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert (
        result is None
    ), "Failed overriding incoming AS-PATH with route-map replace with configured ASN"


def test_bgp_set_aspath_replace_access_list():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd(
        """
conf
 bgp as-path access-list FIRST permit ^65
 route-map r2 permit 20
  set as-path replace as-path-access-list FIRST 65002
    """
    )

    expected = {
        "routes": {
            "172.16.255.31/32": [{"path": "65002 65500"}],
            "172.16.255.32/32": [{"path": "65002 65002"}],
        }
    }

    def _bgp_regexp_1(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_regexp_1, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with regex 1 route-map"
    r1.vtysh_cmd(
        """
conf
 bgp as-path access-list SECOND permit 2
 route-map r2 permit 10
  set as-path replace as-path-access-list SECOND 65001
    """
    )

    expected = {
        "routes": {
            "172.16.255.31/32": [{"path": "65001 65003"}],
            "172.16.255.32/32": [{"path": "65002 65002"}],
        }
    }

    test_func = functools.partial(_bgp_regexp_1, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with regex 2 route-map"

    r1.vtysh_cmd(
        """
conf
 bgp as-path access-list TER permit 3
 route-map r2 permit 10
  set as-path replace as-path-access-list TER
    """
    )
    expected = {
        "routes": {
            "172.16.255.31/32": [{"path": "65002 65001"}],
            "172.16.255.32/32": [{"path": "65002 65002"}],
        }
    }

    test_func = functools.partial(_bgp_regexp_1, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with regex 3 route-map"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
