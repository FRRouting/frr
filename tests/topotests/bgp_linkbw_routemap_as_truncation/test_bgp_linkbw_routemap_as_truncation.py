#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test that route_set_ecommunity_lb() does not truncate a 4-byte AS to
BGP_AS_TRANS when encoding the extended (4-byte AS) link-bandwidth
extended community via a route-map.

Topology
--------

  r1 (AS 400000) ── eBGP ── r2 (AS 65000)

r1's local AS (400000) exceeds BGP_AS_MAX (65535), so it can only be
represented in the extended (4-byte AS / IPv6 ecommunity) link-bandwidth
encoding, never in the classic 2-byte encoding. r1 advertises 10.10.10.10/32
to r2 with "extended-link-bandwidth" enabled and an outbound route-map
setting link-bandwidth, which exercises route_set_ecommunity_lb().

Before the fix, route_set_ecommunity_lb() truncated any AS above
BGP_AS_MAX to BGP_AS_TRANS (23456) before choosing between the extended
and classic encodings, so r2 would see "LB:23456:..." instead of the
real "LB:400000:...".
"""

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

PREFIX = "10.10.10.10/32"
R1_AS = "400000"
BGP_AS_TRANS = "23456"

_LB_AS_RE = re.compile(r"LB:(\d+):")


def lb_as_from_string(lb_string):
    match = _LB_AS_RE.search(lb_string or "")
    return match.group(1) if match else None


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_linkbw_extended_as_not_truncated():
    """r2 should see the real 4-byte AS (400000), not BGP_AS_TRANS (23456)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    receiver = tgen.gears["r2"]

    def _check_receiver_lb_as():
        output = json.loads(receiver.vtysh_cmd("show ip bgp %s json" % PREFIX))
        paths = output.get("paths", [])
        if not paths:
            return "prefix %s not found on r2" % PREFIX

        for path in paths:
            ec = path.get("extendedIpv6Community")
            got_as = lb_as_from_string(ec.get("string") if ec else None)
            if got_as == R1_AS:
                return None

        got = [
            lb_as_from_string(p.get("extendedIpv6Community", {}).get("string"))
            for p in paths
        ]
        return "expected LB AS %s, got %s" % (R1_AS, got)

    test_func = functools.partial(_check_receiver_lb_as)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "route_set_ecommunity_lb() must not truncate a 4-byte AS (%s) to "
        "BGP_AS_TRANS (%s) in the extended link-bandwidth encoding: %s"
        % (R1_AS, BGP_AS_TRANS, result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
