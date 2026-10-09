#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (C) 2026 Nexthop Systems
#

"""
A MAC learned from a remote VTEP and then configured locally as sticky (static)
is advertised with a MAC Mobility sequence number above 0. The route must still
carry the sticky flag (RFC 7432 section 7.7), and the remote VTEP must install
the MAC as sticky.
"""

import os
import re
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNI = 100
R1_VTEP = "10.0.0.1"
R2_VTEP = "10.0.0.2"
FRESH_MAC = "00:00:5e:00:53:01"
MOVED_MAC = "00:00:5e:00:53:02"


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for rname, vtep in (("r1", R1_VTEP), ("r2", R2_VTEP)):
        router = tgen.gears[rname]
        router.cmd_raises(f"/bin/bash {CWD}/setup.sh {vtep}")
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_mac(router, mac, expected):
    cmd = f"show evpn mac vni {VNI} mac {mac} json"
    return topotest.router_json_cmp(router, cmd, {mac: expected})


def _wait_mac(router, mac, expected, what):
    test_func = functools.partial(_check_mac, router, mac, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"{router.name}: {what}: {result}"


def _bgp_paths(output):
    if not isinstance(output, dict):
        return
    if "paths" in output:
        for path in output["paths"]:
            yield from path if isinstance(path, list) else [path]
        return
    for value in output.values():
        yield from _bgp_paths(value)


def _bgp_mac_mm(router, mac, nexthop):
    """
    MAC Mobility values of the global table paths for mac from nexthop, as
    (seq, sticky) tuples.
    """
    output = router.vtysh_cmd(
        f"show bgp l2vpn evpn route rd all mac {mac} json", isjson=True
    )
    mm = []
    for p in _bgp_paths(output):
        if not any(nh.get("ip") == nexthop for nh in p.get("nexthops", [])):
            continue
        ecomm = p.get("extendedCommunity", {}).get("string", "")
        match = re.search(r"MM:(\d+)(, sticky MAC)?", ecomm)
        mm.append((int(match.group(1)), bool(match.group(2))) if match else None)
    return mm


def _wait_bgp_mac_mm(router, mac, nexthop, seq, what):
    test_func = functools.partial(_bgp_mac_mm, router, mac, nexthop)
    _, result = topotest.run_and_expect(test_func, [(seq, True)], count=30, wait=1)
    assert result == [(seq, True)], (
        f"{router.name}: {what}: MAC Mobility (seq, sticky) from {nexthop} is {result}, "
        f"want [({seq}, True)]"
    )


def test_evpn_converge():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, peer in (("r1", R2_VTEP), ("r2", R1_VTEP)):
        router = tgen.gears[rname]
        expected = {"numRemoteVteps": 1, "remoteVteps": [{"ip": peer}]}
        test_func = functools.partial(
            topotest.router_json_cmp, router, f"show evpn vni {VNI} json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{rname}: VNI {VNI} has no remote VTEP {peer}: {result}"


def test_evpn_sticky_mac_seq0():
    """A sticky MAC that was never remote is advertised with sequence 0."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.cmd_raises(f"bridge fdb add {FRESH_MAC} dev acc100 master static sticky")
    _wait_mac(
        r1,
        FRESH_MAC,
        {"type": "local", "stickyMac": True, "localSequence": 0},
        "sticky MAC is not local",
    )

    _wait_bgp_mac_mm(r2, FRESH_MAC, R1_VTEP, 0, "sticky MAC with sequence 0")
    _wait_mac(
        r2,
        FRESH_MAC,
        {
            "type": "remote",
            "remoteVtep": R1_VTEP,
            "stickyMac": True,
            "remoteSequence": 0,
        },
        "sticky MAC with sequence 0 is not remote sticky",
    )


def test_evpn_sticky_mac_after_move():
    """
    A MAC learned from r2, then configured on r1 as sticky, is advertised by r1
    with sequence 1 and the sticky flag.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.cmd_raises(f"bridge fdb add {MOVED_MAC} dev acc100 master dynamic")
    _wait_mac(
        r1,
        MOVED_MAC,
        {"type": "remote", "remoteVtep": R2_VTEP, "remoteSequence": 0},
        "MAC from r2 is not remote",
    )

    r1.cmd_raises(f"bridge fdb replace {MOVED_MAC} dev acc100 master static sticky")
    _wait_mac(
        r1,
        MOVED_MAC,
        {"type": "local", "stickyMac": True, "localSequence": 1},
        "MAC moved from r2 is not local sticky with sequence 1",
    )

    _wait_bgp_mac_mm(r2, MOVED_MAC, R1_VTEP, 1, "sticky MAC with sequence 1")
    _wait_mac(
        r2,
        MOVED_MAC,
        {
            "type": "remote",
            "remoteVtep": R1_VTEP,
            "stickyMac": True,
            "remoteSequence": 1,
        },
        "sticky MAC with sequence 1 is not remote sticky",
    )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
