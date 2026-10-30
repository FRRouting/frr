#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by 6WIND S.A.
# Louis Scalbert <louis.scalbert@6wind.com>
#

"""
Check the syntax of the "set extcommunity color" route-map command.

r1 announces 10.10.10.1/32 to r2 with the COLOR route-map.

Valid colors ([CO:]COLOR, CO being 00, 01, 10 or 11 and COLOR being 1 to
4294967295) are applied and received by r2. A color without CO bits is
encoded with CO bits 00.

Malformed colors are rejected by the CLI. Previously, they left a
set-action without value in the configuration and bgpd aborted on
"show running-config".
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_r2_route(ext_community):
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    if ext_community is None:
        expected_ext_community = None
    else:
        expected_ext_community = {"string": ext_community}
    expected = {
        "prefix": "10.10.10.1/32",
        "paths": [
            {
                "valid": True,
                "extendedCommunity": expected_ext_community,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 unicast 10.10.10.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" 10.10.10.1/32 has not the expected extended community'


def check_r1_route_map(rmap_name, set_clauses):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    expected = {
        "bgpd": {
            rmap_name: {
                "rules": [
                    {
                        "sequenceNumber": 10,
                        "setClauses": ["__ordered__"] + set_clauses,
                    }
                ]
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        f"show route-map {rmap_name} json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f'"r1" route-map {rmap_name} has not the expected set clauses'


def check_r1_malformed(output, color):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    assert (
        f"% Malformed color extended community {color}" in output
    ), f'"r1" color {color} is not rejected'

    # bgpd used to abort here because of a set-action without value
    r1.vtysh_cmd("show running-config")

    check_r1_route_map("MALFORMED", [])


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("r2, check 10.10.10.1/32 is received without extended community")
    check_r2_route(None)


def test_bgp_color_without_co_bits():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color without CO bits")
    r1.vtysh_cmd(
        """
configure terminal
route-map COLOR permit 10
 set extcommunity color 100
"""
    )

    check_r1_route_map("COLOR", ["extcommunity color 100"])

    logger.info("r2, check the color is received with CO bits 00")
    check_r2_route("Color:00:100")


def test_bgp_color_with_co_bits():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color with all the CO bits values")
    r1.vtysh_cmd(
        """
configure terminal
route-map COLOR permit 10
 set extcommunity color 00:200 01:300 10:400 11:4294967295
"""
    )

    check_r1_route_map(
        "COLOR", ["extcommunity color 00:200 01:300 10:400 11:4294967295"]
    )

    logger.info("r2, check the colors are received with their CO bits")
    check_r2_route("Color:00:200 Color:01:300 Color:10:400 Color:11:4294967295")


def test_bgp_color_mixed_co_bits():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color with and without CO bits")
    r1.vtysh_cmd(
        """
configure terminal
route-map COLOR permit 10
 set extcommunity color 500 10:600
"""
    )

    check_r1_route_map("COLOR", ["extcommunity color 500 10:600"])

    logger.info("r2, check the colors are received")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_not_a_number():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color abc")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color abc
"""
    )

    check_r1_malformed(output, "abc")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_color_zero():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color 0")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color 0
"""
    )

    check_r1_malformed(output, "0")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_color_too_big():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color 4294967296")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color 4294967296
"""
    )

    check_r1_malformed(output, "4294967296")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_co_bits():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color 02:100")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color 02:100
"""
    )

    check_r1_malformed(output, "02:100")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_route_target():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color 65000:100")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color 65000:100
"""
    )

    check_r1_malformed(output, "65000:100")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_in_list():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, set extcommunity color 01:100 abc")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map MALFORMED permit 10
 set extcommunity color 01:100 abc
"""
    )

    check_r1_malformed(output, "abc")

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


def test_bgp_color_malformed_existing_color():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1, replace the COLOR route-map color with a malformed one")
    output = r1.vtysh_cmd(
        """
configure terminal
route-map COLOR permit 10
 set extcommunity color abc
"""
    )

    assert (
        "% Malformed color extended community abc" in output
    ), '"r1" color abc is not rejected'

    logger.info("r1, check the previous color is kept")
    check_r1_route_map("COLOR", ["extcommunity color 500 10:600"])

    logger.info("r2, check the route is unchanged")
    check_r2_route("Color:00:500 Color:10:600")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
