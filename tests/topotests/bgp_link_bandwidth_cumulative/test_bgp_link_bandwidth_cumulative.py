#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test cumulative link-bandwidth re-advertisement to eBGP.

Topology
--------

          r2  (iBGP, set extcommunity bandwidth 30000)
         /
   DUT r1 ────── r4  (eBGP, expects cumulative LB bytes below)
         \\
          r3  (iBGP, set extcommunity bandwidth 100000)

Prefix: 10.10.10.10/32 (originated on both r2 and r3)
Bandwidth Mbps values above match BW_MBPS_FROM_R2 / BW_MBPS_FROM_R3 in this file.

Link-bandwidth extended communities use classic 8-byte IEEE float32 encoding.
Assertions match only the integer in LB:AS:<bytes> (not the human Gbps suffix),
using the same float32 semantics as bgpd encode/decode helpers.

Checks:
  - r1 RIB: per-peer LB bytes from r2 and r3
  - r1 advertised to r4: cumulative LB bytes on the eBGP UPDATE
  - r4 RIB: same cumulative LB bytes as received from r1
"""

import os
import re
import sys
import json
import struct
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

# Mbps values must match r2/r3 frr.conf: set extcommunity bandwidth <Mbps>
BW_MBPS_FROM_R2 = 30000
BW_MBPS_FROM_R3 = 100000

_LB_BYTES_RE = re.compile(r"LB:\d+:(\d+)")


def mbps_to_bytes_per_sec(mbps):
    """Bytes/sec passed to encode_lb_extcomm (integer Mbps, same as FRR CLI)."""
    return (mbps * 1_000_000) // 8


def frr_lb_ieee_uint32(bytes_per_sec):
    """
    IEEE float32 wire encoding for link-bandwidth EC.

    Matches bgpd uint64_to_ieee_float_uint32(): store (float)bytes_per_sec as
    uint32 bit pattern (union float / uint32_t d).
    """
    return struct.unpack("I", struct.pack("f", float(bytes_per_sec)))[0]


def frr_lb_display_bytes(bytes_per_sec):
    """
    Integer shown in 'LB:AS:<bytes>' after one encode/decode cycle.

    Matches bgpd ieee_float_uint32_to_uint64() / ecommunity_lb_str(): the
    uint32 wire bits reinterpreted as float, cast to uint64 for display.
    """
    wire = frr_lb_ieee_uint32(bytes_per_sec)
    return int(struct.unpack("f", struct.pack("I", wire))[0])


def frr_lb_cumulative_display_bytes(bytes_per_sec_list):
    """
    LB:AS:<bytes> after cumulative replace (sum decoded values, re-encode).

    Matches ecommunity_replace_linkbw(): cum_bw is sum of per-path decoded
    bandwidth, then encode_lb_extcomm() applies another float32 round-trip.
    """
    total = sum(frr_lb_display_bytes(bps) for bps in bytes_per_sec_list)
    return frr_lb_display_bytes(total)


def lb_bytes_from_string(lb_string):
    """Parse the bytes field from LB:AS:<bytes> (...)."""
    match = _LB_BYTES_RE.search(lb_string or "")
    return int(match.group(1)) if match else None


BPS_FROM_R2 = mbps_to_bytes_per_sec(BW_MBPS_FROM_R2)
BPS_FROM_R3 = mbps_to_bytes_per_sec(BW_MBPS_FROM_R3)
LB_BYTES_FROM_R2 = frr_lb_display_bytes(BPS_FROM_R2)
LB_BYTES_FROM_R3 = frr_lb_display_bytes(BPS_FROM_R3)
LB_BYTES_CUMULATIVE_EBGP = frr_lb_cumulative_display_bytes(
    [BPS_FROM_R2, BPS_FROM_R3]
)


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
    """Normalize show bgp json detail vs detail json path layouts."""
    entry = output.get(key, {}).get(prefix)
    if isinstance(entry, list):
        return entry
    if isinstance(entry, dict):
        return entry.get("paths", [])
    return []


def _path_lb_bytes_from_peer(output, peer_hostname, expected_bytes):
    """Return True if path from peer_hostname has LB:AS:expected_bytes."""
    for path in _paths_for_prefix(output, PREFIX):
        peer = path.get("peer", {})
        if peer.get("hostname") != peer_hostname:
            continue
        ec = path.get("extendedCommunity")
        if ec and lb_bytes_from_string(ec.get("string")) == expected_bytes:
            return True
    return False


def _any_path_lb_bytes_match(output, routes_key, expected_bytes):
    """Return True if any path under routes_key carries LB:AS:expected_bytes."""
    for path in _paths_for_prefix(output, PREFIX, key=routes_key):
        ec = path.get("extendedCommunity")
        if ec and lb_bytes_from_string(ec.get("string")) == expected_bytes:
            return True
    return False


def test_bgp_link_bandwidth_cumulative():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = tgen.gears["r1"]
    ebgp = tgen.gears["r4"]

    def _check_dut_ibgp_paths():
        output = json.loads(dut.vtysh_cmd("show bgp ipv4 unicast json detail"))
        if not _path_lb_bytes_from_peer(output, "r2", LB_BYTES_FROM_R2):
            return "r2 path missing LB bytes %u" % LB_BYTES_FROM_R2
        if not _path_lb_bytes_from_peer(output, "r3", LB_BYTES_FROM_R3):
            return "r3 path missing LB bytes %u" % LB_BYTES_FROM_R3
        return None

    test_func = functools.partial(_check_dut_ibgp_paths)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "DUT should receive expected link-bandwidth from r2 and r3"

    def _check_dut_advertised_cumulative():
        output = json.loads(
            dut.vtysh_cmd(
                "show bgp ipv4 unicast neighbor %s advertised-routes detail json"
                % R4_NEIGHBOR
            )
        )
        if not _any_path_lb_bytes_match(
            output, "advertisedRoutes", LB_BYTES_CUMULATIVE_EBGP
        ):
            paths = _paths_for_prefix(output, PREFIX, key="advertisedRoutes")
            got = [
                lb_bytes_from_string(p.get("extendedCommunity", {}).get("string"))
                for p in paths
            ]
            return "r1 advertised cumulative LB bytes %u, paths=%d got %s" % (
                LB_BYTES_CUMULATIVE_EBGP,
                len(paths),
                got,
            )
        return None

    test_func = functools.partial(_check_dut_advertised_cumulative)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "DUT should advertise cumulative LB bytes %u to r4" % LB_BYTES_CUMULATIVE_EBGP

    def _check_ebgp_received_cumulative():
        output = json.loads(ebgp.vtysh_cmd("show bgp ipv4 unicast json detail"))
        paths = _paths_for_prefix(output, PREFIX)
        if len(paths) != 1:
            return "expected one eBGP path, got %d" % len(paths)
        if not _any_path_lb_bytes_match(output, "routes", LB_BYTES_CUMULATIVE_EBGP):
            ec = paths[0].get("extendedCommunity")
            return "r4 received cumulative LB bytes %u, got %s" % (
                LB_BYTES_CUMULATIVE_EBGP,
                ec.get("string") if ec else None,
            )
        return None

    test_func = functools.partial(_check_ebgp_received_cumulative)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "eBGP peer should receive cumulative LB bytes %u" % LB_BYTES_CUMULATIVE_EBGP


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
