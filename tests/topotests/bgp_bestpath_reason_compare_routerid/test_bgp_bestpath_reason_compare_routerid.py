#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026
# by Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test BGP bestpath selection reason with compare-routerid.

Topology: R1 has two BGP sessions each to R2 and R3.
R2 and R3 both advertise 192.168.199.0/24.

|        192.16.2.0/24
|   ----------------------   R2          -------- 192.168.199.0/24
|                         RID 0.0.0.2
|        192.16.21.0/24   AS 65024
R1 ----------------------
AS 65001
|        192.16.3.0/24
|   ----------------------   R3          -------- 192.168.199.0/24
|                         RID 0.0.0.3
|        192.16.31.0/24  AS 65003
|   ----------------------

Without `bgp bestpath compare-routerid`, the best path is chosen by "Older
Path" (the path received first among the four equal-quality paths).

After enabling `bgp bestpath compare-routerid`, R1 should select the path via
192.16.2.2 (lower neighbor IP within the winning router-id group 0.0.0.2) and
the bestpath selection reason should be "Router ID", not "Neighbor IP".

The bug was that the multipath eligibility loop was using the reason from the
first path comparison (192.16.21.2 vs 192.16.2.2, an ECMP-equal partner),
which produced "Neighbor IP", instead of the first non-ECMP comparison
(192.16.3.3 vs 192.16.2.2) which correctly yields "Router ID".
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # R1 <-> R2, session 1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1 <-> R2, session 2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1 <-> R3, session 1
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # R1 <-> R3, session 2
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Verify all four BGP sessions on R1 reach Established state."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for all four BGP sessions on R1 to establish")

    def _check_sessions():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))

        if "peers" not in output:
            return "No peers section in BGP summary"

        peers = output["peers"]
        expected = ["192.16.2.2", "192.16.21.2", "192.16.3.3", "192.16.31.3"]

        for peer in expected:
            if peer not in peers:
                return f"Peer {peer} not found"
            if peers[peer]["state"] != "Established":
                return f"Peer {peer} not established: {peers[peer]['state']}"

        return None

    _, result = topotest.run_and_expect(_check_sessions, None, count=60, wait=1)
    assert result is None, f"BGP sessions did not converge: {result}"

    step("All four BGP sessions established")


def test_bgp_four_paths_received():
    """Verify R1 receives all four paths for 192.168.199.0/24."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for R1 to receive all four paths for 192.168.199.0/24")

    def _check_path_count():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

        if "pathCount" not in output:
            return "pathCount not in output"

        if output["pathCount"] != 4:
            return f"Expected 4 paths, got {output['pathCount']}"

        return None

    _, result = topotest.run_and_expect(_check_path_count, None, count=60, wait=1)
    assert result is None, f"Did not receive all four paths: {result}"

    step("R1 has all four paths for 192.168.199.0/24")


def test_bgp_bestpath_reason_router_id():
    """
    Verify that enabling compare-routerid produces 'Router ID' as the bestpath
    selection reason, not 'Neighbor IP'.

    Steps:
    1. Enable 'bgp bestpath compare-routerid' on R1.
    2. Wait for bestpath to settle.
    3. Assert best path is via 192.16.2.2 (lower neighbor IP in the winning
       router-id group 0.0.0.2).
    4. Assert the selection reason contains "Router ID".
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enabling bgp bestpath compare-routerid on R1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        bgp bestpath compare-routerid
        end
        """
    )

    step("Waiting for best path to be 192.16.2.2 with 'Router ID' selection reason")

    def _check_bestpath_reason():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

        if "paths" not in output:
            return "No paths in output"

        best_path = None
        for path in output["paths"]:
            bp = path.get("bestpath", {})
            if bp.get("overall", False):
                best_path = path
                break

        if best_path is None:
            return "No best path found"

        # R1 should select 192.16.2.2: lower neighbor IP in the winning
        # router-id group (0.0.0.2 < 0.0.0.3).
        nexthop = best_path.get("nexthops", [{}])[0].get("ip")
        if nexthop != "192.16.2.2":
            return f"Best path nexthop is {nexthop}, expected 192.16.2.2"

        reason = best_path.get("bestpath", {}).get("selectionReason", "")
        if "Router ID" not in reason:
            return f"Expected 'Router ID' in selection reason, got: '{reason}'"

        return None

    _, result = topotest.run_and_expect(_check_bestpath_reason, None, count=60, wait=1)
    assert result is None, (
        f"Bestpath reason check failed: {result}\n"
        "Bug: compare-routerid should produce 'Router ID' reason, not "
        "'Neighbor IP'. The multipath loop was using the reason from an "
        "ECMP-equal partner comparison instead of the first non-ECMP "
        "comparison."
    )

    step("Verified: best path is via 192.16.2.2 with 'Router ID' selection reason")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
