#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test that bgp_local_as_for_peer() honors "neighbor X local-as Y" when
selecting the AS to encode in a route-map-set link-bandwidth extended
community.

Topology
--------

  r1 (AS 65001, "neighbor r2 local-as 65099") ── eBGP ── r2 (AS 65002)

r1 presents itself to r2 as AS 65099 (the local-as override), not its
real AS 65001. r1 advertises 10.20.20.20/32 to r2 with an outbound
route-map setting link-bandwidth, which calls bgp_local_as_for_peer() to
pick the AS. Before accounting for change_local_as, that function would
return r1's real AS (65001) instead of the local-as override (65099).
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

PREFIX = "10.20.20.20/32"
LOCAL_AS_OVERRIDE = "65099"
REAL_AS = "65001"

_LB_AS_RE = re.compile(r"LB:(\d+):")


def lb_as_from_string(lb_string):
    match = _LB_AS_RE.search(lb_string or "")
    return match.group(1) if match else None


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_linkbw_local_as_override():
    """r2 should see the local-as override (65099), not r1's real AS (65001)."""
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
            ec = path.get("extendedCommunity")
            got_as = lb_as_from_string(ec.get("string") if ec else None)
            if got_as == LOCAL_AS_OVERRIDE:
                return None

        got = [
            lb_as_from_string(p.get("extendedCommunity", {}).get("string"))
            for p in paths
        ]
        return "expected LB AS %s, got %s" % (LOCAL_AS_OVERRIDE, got)

    test_func = functools.partial(_check_receiver_lb_as)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "bgp_local_as_for_peer() must honor 'neighbor X local-as %s' instead "
        "of r1's real AS (%s) in the link-bandwidth encoding: %s"
        % (LOCAL_AS_OVERRIDE, REAL_AS, result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
