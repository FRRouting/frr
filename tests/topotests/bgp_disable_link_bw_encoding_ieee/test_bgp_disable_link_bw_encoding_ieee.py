#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test raw link-bandwidth encoding with disable-link-bw-encoding-ieee.

Topology
--------

  r1 ── iBGP ── r2

Both routers use disable-link-bw-encoding-ieee on the session: r1 for outbound
encode (route-map uses destination peer flags), r2 for inbound decode.

Two prefixes exercise different route_set_ecommunity_lb() paths on r1:

  - 10.10.10.10/32: set extcommunity bandwidth only (old_ecom == NULL)
  - 10.10.10.11/32: set extcommunity rt then bandwidth (old_ecom merge path)

Checks raw LB bytes 1250000000 (10 Gbps) on r1 advertised-routes and r2 RIB.
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

PREFIX_ORIG = "10.10.10.10/32"
PREFIX_MERGE = "10.10.10.11/32"
R2_NEIGHBOR = "192.168.12.2"

# Mbps in r1 frr.conf route-map; FRR converts (Mbps * 1_000_000) / 8 bytes/sec.
BW_MBPS = 10000
LB_BYTES_RAW = (BW_MBPS * 1_000_000) // 8

_LB_BYTES_RE = re.compile(r"LB:\d+:(\d+)")


def lb_bytes_from_string(lb_string):
    match = _LB_BYTES_RE.search(lb_string or "")
    return int(match.group(1)) if match else None


def _paths_for_prefix(output, prefix, key="routes"):
    entry = output.get(key, {}).get(prefix)
    if isinstance(entry, list):
        return entry
    if isinstance(entry, dict):
        return entry.get("paths", [])
    return []


def _check_lb_bytes_in_output(output, prefix, label, routes_key="routes"):
    paths = _paths_for_prefix(output, prefix, key=routes_key)
    if not paths:
        return "%s: prefix %s not found" % (label, prefix)

    for path in paths:
        ec = path.get("extendedCommunity")
        got = lb_bytes_from_string(ec.get("string") if ec else None)
        if got == LB_BYTES_RAW:
            return None

    got = [
        lb_bytes_from_string(p.get("extendedCommunity", {}).get("string"))
        for p in paths
    ]
    return "%s: expected raw LB bytes %d, paths=%d got %s" % (
        label,
        LB_BYTES_RAW,
        len(paths),
        got,
    )


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


def test_bgp_disable_link_bw_encoding_ieee_originator():
    """LB only on originate path (old_ecom == NULL in route_set_ecommunity_lb)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    originator = tgen.gears["r1"]
    receiver = tgen.gears["r2"]

    def _check_originator_advertised_lb():
        output = json.loads(
            originator.vtysh_cmd(
                "show bgp ipv4 unicast neighbor %s advertised-routes detail json"
                % R2_NEIGHBOR
            )
        )
        return _check_lb_bytes_in_output(
            output, PREFIX_ORIG, "r1 advertised", routes_key="advertisedRoutes"
        )

    test_func = functools.partial(_check_originator_advertised_lb)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "originator should retain disable_ieee_floating on outbound route-map attach"
    )

    def _check_receiver_lb():
        output = json.loads(receiver.vtysh_cmd("show bgp ipv4 unicast json detail"))
        return _check_lb_bytes_in_output(output, PREFIX_ORIG, "r2")

    test_func = functools.partial(_check_receiver_lb)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "receiver should decode raw link-bandwidth on ingest"


def test_bgp_disable_link_bw_encoding_ieee_merge_ec():
    """RT then LB on same route-map entry (old_ecom merge path)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    originator = tgen.gears["r1"]
    receiver = tgen.gears["r2"]

    def _check_originator_advertised_lb():
        output = json.loads(
            originator.vtysh_cmd(
                "show bgp ipv4 unicast neighbor %s advertised-routes detail json"
                % R2_NEIGHBOR
            )
        )
        return _check_lb_bytes_in_output(
            output, PREFIX_MERGE, "r1 advertised merge", routes_key="advertisedRoutes"
        )

    test_func = functools.partial(_check_originator_advertised_lb)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "merge path should set disable_ieee_floating from outbound peer after dup"
    )

    def _check_receiver_lb():
        output = json.loads(receiver.vtysh_cmd("show bgp ipv4 unicast json detail"))
        return _check_lb_bytes_in_output(output, PREFIX_MERGE, "r2 merge")

    test_func = functools.partial(_check_receiver_lb)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "receiver should decode merge-path raw link-bandwidth"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
