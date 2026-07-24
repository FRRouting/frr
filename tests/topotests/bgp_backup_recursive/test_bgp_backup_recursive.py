#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test BGP PIC backup paths with a recursively-resolved backup nexthop.

Topology (all in AS 65001, pure iBGP):

                    +--- R4 (lo: 10.255.255.4) --- 10.99.99.0/24
                    |    network, MED 100  (PRIMARY)
                    |
                  R2 (transit, no BGP)
                    |
                    | 10.0.12/24
                    |
   R1 (lo: 10.255.255.1) +
    |
    | 10.0.13/24
    |
                  R3 (transit, no BGP)
                    |
                    +--- R5 (lo: 10.255.255.5) --- 10.99.99.0/24
                         network, MED 200  (BACKUP)

R1 has iBGP loopback-to-loopback sessions with R4 and R5.
R4 advertises 10.99.99.0/24 with MED 100, next-hop-self -> 10.255.255.4.
R5 advertises 10.99.99.0/24 with MED 200, next-hop-self -> 10.255.255.5.

R1 reaches 10.255.255.4 only via R2 (static route 10.255.255.4/32 -> 10.0.12.2).
R1 reaches 10.255.255.5 only via R3 (static route 10.255.255.5/32 -> 10.0.13.3).

So both the primary BGP nexthop (10.255.255.4) and the backup BGP nexthop
(10.255.255.5) require recursive resolution through a static route.

This test exercises the case that the existing bgp_backup and
bgp_backup_ecmp topotests do NOT cover: the backup path computed
by BGP has a non-directly-connected nexthop that zebra must resolve
recursively before installing it as a backup nexthop in the FIB.
"""

import json
import os
import sys

import pytest

from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # R1 <-> R2 (10.0.12.0/24)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1 <-> R3 (10.0.13.0/24)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # R2 <-> R4 (10.0.24.0/24)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    # R3 <-> R5 (10.0.35.0/24)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    # R4's connected prefix (10.99.99.0/24)
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])

    # R5's connected prefix (10.99.99.0/24)
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_backup_recursive_nexthop():
    """
    Verify BGP PIC backup-path computation when the backup nexthop
    needs recursive resolution through an underlay route.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Wait for iBGP sessions to R4 (10.255.255.4) and R5 (10.255.255.5) to come up")

    def _check_bgp_convergence():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        peers = output.get("peers", {})
        for peer in ("10.255.255.4", "10.255.255.5"):
            if peer not in peers:
                return f"peer {peer} missing"
            if peers[peer].get("state") != "Established":
                return f"peer {peer} not Established: {peers[peer].get('state')}"
        return None

    _, result = topotest.run_and_expect(_check_bgp_convergence, None, count=60, wait=1)
    assert result is None, f"BGP convergence failed: {result}"

    step("Wait for R1 to receive both paths for 10.99.99.0/24")

    def _check_paths_count():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))
        if output.get("pathCount") != 2:
            return f"expected 2 paths, got {output.get('pathCount')}"
        return None

    _, result = topotest.run_and_expect(_check_paths_count, None, count=60, wait=1)
    assert result is None, f"path count check failed: {result}"

    step("Verify primary best path is via R4 (nexthop 10.255.255.4, MED 100)")

    def _check_best_is_r4():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))
        for path in output.get("paths", []):
            if path.get("bestpath", {}).get("overall"):
                nh = path.get("nexthops", [{}])[0].get("ip")
                med = path.get("metric")
                if nh != "10.255.255.4":
                    return f"best path nexthop {nh} != 10.255.255.4"
                if med != 100:
                    return f"best path MED {med} != 100"
                return None
        return "no best path marked"

    _, result = topotest.run_and_expect(_check_best_is_r4, None, count=30, wait=1)
    assert result is None, f"best path check failed: {result}"

    step("Verify FIB primary nexthop is recursively resolved through R2 (10.0.12.2)")

    def _check_fib_recursive_primary():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.99.0/24 json"))
        routes = output.get("10.99.99.0/24")
        if not routes:
            return "10.99.99.0/24 not in route table"
        entry = routes[0]
        nexthops = entry.get("nexthops", [])
        if not nexthops:
            return "no primary nexthops"
        # We expect the resolved underlay address (R2's 10.0.12.2) to appear
        # somewhere in the nexthop chain — either directly as "ip" or
        # via a "resolver"/"resolved" record, depending on how zebra
        # renders recursion in this build.
        flat = json.dumps(nexthops)
        if "10.0.12.2" not in flat:
            return f"primary nexthop chain does not reference 10.0.12.2: {flat}"
        return None

    _, result = topotest.run_and_expect(
        _check_fib_recursive_primary, None, count=30, wait=1
    )
    assert result is None, f"primary recursive nexthop check failed: {result}"

    step("Before enabling install backup-path: verify no backup is selected")

    def _check_no_backup_in_bgp():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))
        for path in output.get("paths", []):
            if path.get("backup"):
                nh = path.get("nexthops", [{}])[0].get("ip")
                return f"unexpected backup path before feature enabled: {nh}"
        return None

    _, result = topotest.run_and_expect(_check_no_backup_in_bgp, None, count=15, wait=15)
    assert result is None, f"pre-enable BGP backup check failed: {result}"

    def _check_no_backup_in_fib():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.99.0/24 json"))
        routes = output.get("10.99.99.0/24")
        if not routes:
            return "10.99.99.0/24 not in route table"
        backups = routes[0].get("backupNexthops", [])
        if backups:
            return f"unexpected backupNexthops before feature enabled: {backups}"
        return None

    _, result = topotest.run_and_expect(_check_no_backup_in_fib, None, count=15, wait=15)
    assert result is None, f"pre-enable FIB backup check failed: {result}"

    step("Enable 'install backup-path' on R1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path
        end
    """
    )

    step("Verify R5 (10.255.255.5) is selected as the BGP backup path")

    def _check_backup_is_r5():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))
        backups = []
        for path in output.get("paths", []):
            if path.get("backup"):
                backups.append(path.get("nexthops", [{}])[0].get("ip"))
        if len(backups) != 1:
            return f"expected 1 backup path, got {len(backups)}: {backups}"
        if backups[0] != "10.255.255.5":
            return f"backup BGP nexthop is {backups[0]}, expected 10.255.255.5"
        return None

    _, result = topotest.run_and_expect(_check_backup_is_r5, None, count=30, wait=1)
    assert result is None, f"BGP backup selection failed: {result}"

    step(
        "Verify FIB backupNexthops contains a recursively-resolved entry "
        "pointing at R3 (10.0.35.5 / 10.0.13.3 chain via 10.255.255.5)"
    )

    def _check_fib_recursive_backup():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.99.0/24 json"))
        routes = output.get("10.99.99.0/24")
        if not routes:
            return "10.99.99.0/24 not in route table"
        entry = routes[0]
        backups = entry.get("backupNexthops", [])
        if not backups:
            return "no backupNexthops installed"
        flat = json.dumps(backups)
        # The backup BGP nexthop is 10.255.255.5; zebra should record it,
        # and the underlay resolution should reference R3's interface
        # address 10.0.13.3 (the static route's gateway on R1).
        if "10.255.255.5" not in flat:
            return f"backup nexthop chain missing BGP nexthop 10.255.255.5: {flat}"
        if "10.0.13.3" not in flat:
            return (
                "backup nexthop chain does not reference recursively-resolved "
                f"underlay 10.0.13.3: {flat}"
            )
        return None

    _, result = topotest.run_and_expect(
        _check_fib_recursive_backup, None, count=30, wait=1
    )
    assert result is None, f"backup recursive nexthop check failed: {result}"

    step("Disable 'install backup-path' and verify cleanup")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no install backup-path
        end
    """
    )

    _, result = topotest.run_and_expect(_check_no_backup_in_bgp, None, count=30, wait=1)
    assert result is None, f"BGP backup not cleared after disable: {result}"

    _, result = topotest.run_and_expect(_check_no_backup_in_fib, None, count=30, wait=1)
    assert result is None, f"FIB backup not cleared after disable: {result}"

    step("Re-enable 'install backup-path' to confirm toggle works")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path
        end
    """
    )

    _, result = topotest.run_and_expect(_check_backup_is_r5, None, count=30, wait=1)
    assert result is None, f"backup not restored after re-enable: {result}"

    _, result = topotest.run_and_expect(
        _check_fib_recursive_backup, None, count=30, wait=1
    )
    assert result is None, f"FIB recursive backup not restored: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
