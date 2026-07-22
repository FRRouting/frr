#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test that BGP validates attribute flag bits (Optional / Transitive / Partial)
and rejects routes with incorrect flags using treat-as-withdraw.

Per RFC 7606, malformed well-known and core optional attributes trigger
"treat-as-withdraw": the route is not installed in the RIB, but the BGP
session stays up.

Validates the fix in bgpd/bgp_attr.c that registers ENCAP (type 23) and
LINK_STATE (type 29) in attr_flags_values[].

Test flow:
1. ExaBGP announces routes with CORRECT flags
2. Verify routes are accepted and in RIB
3. ExaBGP withdraws correct routes and announces with WRONG flags
4. Verify routes are treated-as-withdraw (not in RIB)
5. Verify BGP session stays up
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.2", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_attr_flag_validation():
    """
    Test BGP attribute flag validation with dynamic route announcement.

    Phase 1: Announce routes with correct flags - should be accepted
    Phase 2: Announce routes with wrong flags - should be treat-as-withdraw
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Wait for BGP session to establish
    def _bgp_converge():
        output = json.loads(
            r1.vtysh_cmd("show bgp neighbors 10.0.0.2 json")
        )
        expected = {
            "10.0.0.2": {"bgpState": "Established"}
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP session with peer1 not established"

    # Phase 1: Verify routes with CORRECT flags are accepted
    # exa-send.py announces these first, then after 8 seconds sends wrong flags
    prefixes = ["192.168.1.1/32", "192.168.2.1/32"]

    def _bgp_routes_accepted():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        for p in prefixes:
            if p not in routes:
                return "prefix {} not in RIB".format(p)
        return None

    test_func = functools.partial(_bgp_routes_accepted)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, (
        "Routes with correct flags not accepted. Detail: {}".format(result)
    )

    # Phase 2: After exa-send.py withdraws correct routes and announces wrong flags,
    # verify routes are treat-as-withdraw (not in RIB)
    def _bgp_routes_withdrawn():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        for p in prefixes:
            if p in routes:
                return "prefix {} still in RIB".format(p)
        return None

    test_func = functools.partial(_bgp_routes_withdrawn)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "Routes with malformed flags still in RIB. "
        "Expected treat-as-withdraw. Detail: {}".format(result)
    )

    # Final check: BGP session still up
    output = json.loads(r1.vtysh_cmd("show bgp neighbors 10.0.0.2 json"))
    state = output.get("10.0.0.2", {}).get("bgpState")
    assert state == "Established", (
        "BGP session torn down (state={}), expected treat-as-withdraw".format(state)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
