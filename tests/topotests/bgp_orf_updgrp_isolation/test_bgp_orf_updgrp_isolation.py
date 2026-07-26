#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_orf_updgrp_isolation_bug.py
#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP ORF update-group isolation bug.

Verify that peers are NOT incorrectly isolated when ORF is not fully
negotiated.  With the old (buggy) code, a peer with only SM_RCV
(remote advertised ORF send capability) but no RM_ADV (we did not
advertise ORF receive capability) would be incorrectly isolated into
its own update-group.

Topology:

    r2 (AS 65002) -- r1 (AS 65001) -- r3 (AS 65002)
                           |
                          r4 (AS 65002)

r1 advertises 10.0.0.1/32.

All three peers (r2, r3, r4) are in the same AS 65002:
  - r2: "capability orf prefix-list send" - r1 has NO receive capability
        for r2, so ORF is NOT negotiated.  SM_RCV is set, RM_ADV is NOT.
  - r3: No ORF capability at all - plain BGP peer.
  - r4: No ORF capability at all - plain BGP peer.

Expected behavior (with fix):
  - r2, r3, r4 should all share the same update-group because ORF is NOT
    negotiated for any of them.

Buggy behavior (without fix):
  - r2 would be incorrectly isolated into its own update-group because
    the old code only checked SM_RCV.
"""

import os
import re
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    # r1 -- r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1 -- r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r1 -- r4
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_update_group(router, peer_ip, afi="ipv4 unicast"):
    """
    Return the update-group ID that contains peer_ip, or None if not found.
    """
    output = router.vtysh_cmd("show bgp {} update-group".format(afi))
    current_group = None
    for line in output.splitlines():
        m = re.match(r"\s*Update-group (\d+):", line)
        if m:
            current_group = int(m.group(1))
        if peer_ip in line:
            return current_group
    return None


def test_bgp_orf_updgrp_isolation_bug():
    """
    Verify that r2, r3, r4 all share the same update-group.

    r2 has "capability orf prefix-list send" but r1 did NOT configure
    "capability orf prefix-list receive" for r2, so ORF is NOT negotiated.
    SM_RCV is set on r1 (r2 advertised ORF send), but RM_ADV is NOT set
    (r1 did not advertise ORF receive).

    With the old buggy code, r2 would be isolated because the code only
    checked SM_RCV.  With the fix, r2 is NOT isolated because both
    RM_ADV and SM_RCV must be set for ORF isolation to apply.

    Since all three peers are in the same AS with identical config
    (same flags, same policies), they should share an update-group.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Wait for all sessions to reach Established.
    def _bgp_sessions_established():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.12.2": {"state": "Established"},
                "192.168.13.2": {"state": "Established"},
                "192.168.14.2": {"state": "Established"},
            }
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(
        _bgp_sessions_established, None, count=60, wait=0.5
    )
    assert result is None, "BGP sessions did not reach Established"

    # Verify all three peers share the same update-group.
    def _check_same_update_group():
        grp_r2 = get_update_group(r1, "192.168.12.2")
        grp_r3 = get_update_group(r1, "192.168.13.2")
        grp_r4 = get_update_group(r1, "192.168.14.2")
        if grp_r2 is None:
            return "could not find update-group for r2"
        if grp_r3 is None:
            return "could not find update-group for r3"
        if grp_r4 is None:
            return "could not find update-group for r4"
        if grp_r2 != grp_r3:
            return (
                "BUG: r2 (ORF not negotiated) is in different update-group "
                "than r3.  r2 group={}, r3 group={}.  "
                "This means r2 was incorrectly isolated due to SM_RCV alone.".format(
                    grp_r2, grp_r3
                )
            )
        if grp_r2 != grp_r4:
            return (
                "BUG: r2 is in different update-group than r4.  "
                "r2 group={}, r4 group={}.".format(grp_r2, grp_r4)
            )
        return None

    _, result = topotest.run_and_expect(
        _check_same_update_group, None, count=60, wait=0.5
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
