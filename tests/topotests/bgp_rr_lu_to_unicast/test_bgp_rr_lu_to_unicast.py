#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_rr_lu_to_unicast.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Olasupo Okunaiya
#

"""
test_bgp_rr_lu_to_unicast.py: a route reflector that learns a prefix over an
ipv4 labeled-unicast (SAFI 4) session must reflect it to an ipv4 unicast-only
(SAFI 1) client with the mandatory NEXT_HOP path attribute present.

The next hop of a labeled path arrives in the MP_REACH_NLRI, so the legacy
NEXT_HOP (type 3) attribute flag is never set on the stored path. When the
route was reflected out of the ipv4 unicast address-family the serializer
dropped NEXT_HOP entirely, producing an UPDATE that the unicast client
rejected as "Missing well-known attribute NEXT_HOP", so the prefix never
installed.

Topology (single AS 65001, iBGP, loopback reachability via OSPF):

    r1 ---(ipv4 labeled-unicast)--- r2 ---(ipv4 unicast)--- r3
  10.0.0.13                       10.0.0.10               10.0.0.12
  originates                    route reflector        unicast-only client
  10.0.0.13/32
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1 --- s1 --- r2 --- s2 --- r3
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_sessions_up():
    "The two iBGP sessions on the route reflector must reach Established."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _sessions_up():
        out = tgen.gears["r2"].vtysh_cmd("show bgp summary json", isjson=True)
        expected = {
            "ipv4Unicast": {"peers": {"10.0.0.12": {"state": "Established"}}},
            "ipv4LabeledUnicast": {"peers": {"10.0.0.13": {"state": "Established"}}},
        }
        return topotest.json_cmp(out, expected)

    _, result = topotest.run_and_expect(_sessions_up, None, count=60, wait=1)
    assert result is None, "iBGP sessions did not come up: {}".format(result)


def test_rr_advertises_nexthop_to_unicast_client():
    "The RR Adj-RIB-Out for the unicast client must carry the next hop."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _advertised():
        out = tgen.gears["r2"].vtysh_cmd(
            "show bgp ipv4 unicast neighbors 10.0.0.12 advertised-routes json",
            isjson=True,
        )
        expected = {"advertisedRoutes": {"10.0.0.13/32": {"nextHop": "10.0.0.13"}}}
        return topotest.json_cmp(out, expected)

    _, result = topotest.run_and_expect(_advertised, None, count=60, wait=1)
    assert result is None, "RR advertised no next hop: {}".format(result)


def test_unicast_client_installs_route_with_nexthop():
    "The unicast-only client must accept the reflected route with NEXT_HOP set."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _installed():
        out = tgen.gears["r3"].vtysh_cmd(
            "show bgp ipv4 unicast 10.0.0.13/32 json", isjson=True
        )
        expected = {
            "prefix": "10.0.0.13/32",
            "paths": [{"valid": True, "nexthops": [{"ip": "10.0.0.13"}]}],
        }
        return topotest.json_cmp(out, expected)

    _, result = topotest.run_and_expect(_installed, None, count=60, wait=1)
    assert result is None, "unicast client did not install route: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
