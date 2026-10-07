#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
peer1 sends an AIGP attribute with three AIGP TLVs (10, 20, 30) and an
unknown TLV in between. r1 must use the first AIGP TLV, and pass the
subsequent AIGP TLVs along unchanged when reflecting the route to peer2
(RFC 7311 section 3).
"""

import os
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


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.101", defaultRoute="via 10.0.0.1")
    peer2 = tgen.add_exabgp_peer("peer2", ip="10.0.0.102", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)
    switch.add_link(peer2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    r1.start()

    for pname, peer in tgen.exabgp_peers().items():
        peer.start(os.path.join(CWD, pname), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aigp_tlvs():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peer2 = tgen.gears["peer2"]

    def _bgp_check_aigp_metric():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {"paths": [{"aigpMetric": 10, "valid": True}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_aigp_metric)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 does not use the first AIGP TLV"

    # Flags 0x80, type 26, length 33: AIGP TLVs 10, 20 and 30, without
    # the unknown TLV.
    aigp = (
        "801a21"
        + "01000b000000000000000a"
        + "01000b0000000000000014"
        + "01000b000000000000001e"
    )
    logfile = os.path.join(peer2.gearlogdir, "peer2-received.log")

    def _peer2_check_aigp_tlvs():
        with open(logfile) as f:
            for line in f:
                body = json.loads(line)["neighbor"]["message"].get("body", "")
                if aigp in body.lower():
                    return True
        return False

    test_func = functools.partial(_peer2_check_aigp_tlvs)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "peer2 did not receive subsequent AIGP TLVs unchanged"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
