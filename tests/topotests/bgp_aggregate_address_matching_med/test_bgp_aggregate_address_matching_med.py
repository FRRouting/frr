#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if aggregate-address command works fine when suppressing summary-only
and using matching-MED-only together.

Also test `bgp default aggregate-address matching-med-only` and the
per-aggregate `ignore-med` override.
"""

import os
import sys
import json
import pytest
import functools
from lib.common_config import (
    step,
)

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


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


def test_aggregate_address_matching_med():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.0/24": None,
                "172.16.255.1/32": [{"path": "65002 65001"}],
                "172.16.255.2/32": [{"path": "65002 65001"}],
                "172.16.255.3/32": [{"path": "65002 65001"}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see unsuppressed routes from R2"

    step("Change MED for 172.16.255.3/32 from 400 to 300")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map r2 permit 20
            set metric 300
    """
    )

    step("Check if 172.16.255.0/24 aggregated route was created and others suppressed")

    def _bgp_aggregated_summary_only_med_match():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.0/24": [{"path": "65002"}],
                "172.16.255.1/32": None,
                "172.16.255.2/32": None,
                "172.16.255.3/32": None,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_aggregated_summary_only_med_match)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see unsuppressed routes from R2"

    step("Change MED for 172.16.255.3/32 back to 400 from 300")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map r2 permit 20
            set metric 400
    """
    )
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see unsuppressed routes from R2"


def _bgp_not_aggregated(router):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
    expected = {
        "routes": {
            "172.16.255.0/24": None,
            "172.16.255.1/32": [{"path": "65002 65001"}],
            "172.16.255.2/32": [{"path": "65002 65001"}],
            "172.16.255.3/32": [{"path": "65002 65001"}],
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_aggregated(router):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
    expected = {
        "routes": {
            "172.16.255.0/24": [{"path": "65002"}],
            "172.16.255.1/32": None,
            "172.16.255.2/32": None,
            "172.16.255.3/32": None,
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_aggregate_match_med(router, match_med):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast aggregate-address 172.16.255.0/24 json")
    )
    expected = {"aggregates": {"172.16.255.0/24": {"matchMed": match_med}}}
    return topotest.json_cmp(output, expected)


def _check(func, *args, msg):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, msg


def test_aggregate_address_default_matching_med():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # MEDs are 300, 300 and 400 (mismatched) after the previous test.

    step("Remove matching-MED-only from the aggregate, MED should be ignored")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            address-family ipv4 unicast
                aggregate-address 172.16.255.0/24 summary-only
    """
    )
    _check(_bgp_aggregated, r3, msg="Aggregate should be created ignoring MED")
    _check(_bgp_aggregate_match_med, r2, False, msg="matchMed should be false")

    step("Enable bgp default aggregate-address matching-med-only")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            bgp default aggregate-address matching-med-only
    """
    )
    _check(_bgp_not_aggregated, r3, msg="Aggregate should be withdrawn (MED mismatch)")
    _check(_bgp_aggregate_match_med, r2, True, msg="matchMed should be true")

    step("Override the default with ignore-med for the aggregate")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            address-family ipv4 unicast
                aggregate-address 172.16.255.0/24 summary-only ignore-med
    """
    )
    _check(_bgp_aggregated, r3, msg="ignore-med should override the default")
    _check(_bgp_aggregate_match_med, r2, False, msg="matchMed should be false")

    step("Disable the default, ignore-med aggregate should not change")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            no bgp default aggregate-address matching-med-only
    """
    )
    _check(_bgp_aggregated, r3, msg="ignore-med aggregate should stay installed")

    step("Use matching-med-only alias while the default is disabled")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            address-family ipv4 unicast
                aggregate-address 172.16.255.0/24 summary-only matching-med-only
    """
    )
    _check(_bgp_not_aggregated, r3, msg="Aggregate should be withdrawn (MED mismatch)")
    _check(_bgp_aggregate_match_med, r2, True, msg="matchMed should be true")

    step("Check running configuration")
    output = r2.vtysh_cmd("show running-config")
    assert "bgp default aggregate-address matching-med-only" not in output
    assert (
        "aggregate-address 172.16.255.0/24 summary-only matching-MED-only" in output
    ), "matching-med-only should be rendered as matching-MED-only"

    step("matching-med-only and ignore-med can't be used together")
    output = r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            address-family ipv4 unicast
                aggregate-address 172.16.255.0/24 matching-med-only ignore-med
    """
    )
    assert "can't be used at the same time" in output
    output = r2.vtysh_cmd("show running-config")
    assert (
        "aggregate-address 172.16.255.0/24 summary-only matching-MED-only" in output
    ), "Aggregate configuration should not be changed"
    _check(_bgp_not_aggregated, r3, msg="Aggregate should not be changed")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
