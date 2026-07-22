#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test cumulative link-bandwidth with disable-link-bw-encoding-ieee on eBGP.

Same topology as bgp_link_bandwidth_cumulative, but r1 exports raw 32-bit LB
encoding to r4. Cumulative bandwidth exceeds UINT32_MAX and must be capped at
0xFFFFFFFF instead of silently truncating the lower 32 bits.
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
R4_NEIGHBOR = "192.168.14.4"

BW_MBPS_FROM_R2 = 30000
BW_MBPS_FROM_R3 = 100000

_LB_BYTES_RE = re.compile(r"LB:\d+:(\d+)")


def mbps_to_bytes_per_sec(mbps):
    return (mbps * 1_000_000) // 8


def lb_bytes_from_string(lb_string):
    match = _LB_BYTES_RE.search(lb_string or "")
    return int(match.group(1)) if match else None


BPS_FROM_R2 = mbps_to_bytes_per_sec(BW_MBPS_FROM_R2)
BPS_FROM_R3 = mbps_to_bytes_per_sec(BW_MBPS_FROM_R3)
LB_BYTES_CUMULATIVE_RAW_SUM = BPS_FROM_R2 + BPS_FROM_R3
LB_BYTES_CUMULATIVE_RAW_CLAMP = 0xFFFFFFFF
LB_BYTES_CUMULATIVE_RAW_TRUNCATED = LB_BYTES_CUMULATIVE_RAW_SUM & 0xFFFFFFFF


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r1", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _paths_for_prefix(output, prefix, key="routes"):
    entry = output.get(key, {}).get(prefix)
    if isinstance(entry, list):
        return entry
    if isinstance(entry, dict):
        return entry.get("paths", [])
    return []


def _any_path_lb_bytes_match(output, routes_key, expected_bytes):
    for path in _paths_for_prefix(output, PREFIX, key=routes_key):
        ec = path.get("extendedCommunity")
        if ec and lb_bytes_from_string(ec.get("string")) == expected_bytes:
            return True
    return False


def test_bgp_link_bandwidth_cumulative_disable_ieee():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = tgen.gears["r1"]

    def _check_dut_advertised_raw_cumulative():
        output = json.loads(
            dut.vtysh_cmd(
                "show bgp ipv4 unicast neighbor %s advertised-routes detail json"
                % R4_NEIGHBOR
            )
        )
        if not _any_path_lb_bytes_match(
            output, "advertisedRoutes", LB_BYTES_CUMULATIVE_RAW_CLAMP
        ):
            paths = _paths_for_prefix(output, PREFIX, key="advertisedRoutes")
            got = [
                lb_bytes_from_string(p.get("extendedCommunity", {}).get("string"))
                for p in paths
            ]
            return (
                "r1 advertised raw cumulative LB bytes %u (not truncated %u), "
                "paths=%d got %s"
                % (
                    LB_BYTES_CUMULATIVE_RAW_CLAMP,
                    LB_BYTES_CUMULATIVE_RAW_TRUNCATED,
                    len(paths),
                    got,
                )
            )
        return None

    test_func = functools.partial(_check_dut_advertised_raw_cumulative)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "DUT should cap cumulative LB at %u for disable-link-bw-encoding-ieee"
        % LB_BYTES_CUMULATIVE_RAW_CLAMP
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
