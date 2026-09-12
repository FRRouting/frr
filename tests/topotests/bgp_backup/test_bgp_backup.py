#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test BGP bestpath selection reasoning.

|----------------------     R3          -------- 192.168.199.0/24
|    10.16.3.0/24       RID 10.255.255.3
|                        AS 65003
|                        MED 150
|
|
|    10.16.2.0/24
R1 --------------------    R2          -------- 192.168.199.0/24
AS 65001                 RID 10.255.255.2
|                        AS 65024
|                        MED 200
|
|
|----------------------     R4          -------- 192.168.199.0/24
    10.16.4.0/24        RID 10.255.255.4
                         AS 65024
                         MED 100
"""

from lib.common_config import step
from lib.topolog import logger
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib import topotest
import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    # Create routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # R1 connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # Add switches for the 192.168.199.0/24 networks
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Configure all the routers
    router_list = tgen.routers()

    # Load router configs
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _converge_bgp(router, peer_addrs, count=60, wait=1):
    """
    Verify that BGP sessions are established for a given router with specified peers.

    Parameters:
    -----------
    router : TopoRouter
        The router object to check BGP convergence for
    peer_addrs : list
        List of peer IP addresses that should be in Established state
    count : int, optional
        Maximum number of attempts to check
    wait : int, optional
        Time to wait between attempts in seconds

    Returns:
    --------
    bool
        True if all peer sessions are established, False otherwise
    """
    step(
        f"Checking BGP convergence for {router.name} with peers: {peer_addrs}")

    def _check_bgp_peers():
        output = json.loads(router.vtysh_cmd(
            "show bgp ipv4 unicast summary json"))

        if "peers" not in output:
            return "No peers section found in BGP summary output"

        peers = output["peers"]

        # Check if all expected peers are established
        for peer_addr in peer_addrs:
            if peer_addr not in peers:
                return f"Peer {peer_addr} not found"

            if peers[peer_addr]["state"] != "Established":
                return f"Peer {peer_addr} not established, state: {peers[peer_addr]['state']}"

        return None

    test_func = functools.partial(_check_bgp_peers)
    success, result = topotest.run_and_expect(
        test_func, None, count=count, wait=wait)

    if success:
        logger.info(f"BGP convergence successful for {router.name}")
        return True
    else:
        logger.error(f"BGP convergence failed for {router.name}: {result}")
        return False


def test_bgp_backup_paths():
    """
    Verify that R1 receives all three paths for the 192.168.199.0/24 prefix.

    This test uses run_and_expect to wait until all three paths for the prefix
    are received by R1 from R2, R3, and R4.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Activate the BGP peer on R3
    step("Activating BGP peer on R3")
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        """
        configure terminal
        router bgp 65003
        address-family ipv4 unicast
        neighbor 10.16.3.1 activate
        end
    """
    )

    # Activate the BGP peer on R4
    step("Activating BGP peer on R4")
    r4 = tgen.gears["r4"]
    r4.vtysh_cmd(
        """
        configure terminal
        router bgp 65024
        address-family ipv4 unicast
        neighbor 10.16.4.1 activate
        end
    """
    )
    step("Waiting for R1 to receive all three paths for 192.168.199.0/24")

    def _check_paths_count():
        output = json.loads(r1.vtysh_cmd(
            "show bgp ipv4 unicast 192.168.199.0/24 json"))

        if "pathCount" not in output:
            return "pathCount not found in output"

        if output["pathCount"] != 3:
            return f"Expected 3 paths, got {output['pathCount']}"

        return None

    test_func = functools.partial(_check_paths_count)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, "Did not receive all three paths for 192.168.199.0/24"
    step("Successfully received all three paths for 192.168.199.0/24")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
        address-family ipv4 unicast
        install backup-path
        end
    """
    )

    # Check if path is present in output of show ip route <pfx> json
    def _check_iproute_prefix_json(path, path_should_be_present=True):
        output = json.loads(r1.vtysh_cmd(
            "show ip route 192.168.199.0/24 json"))
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found"

        route = output["192.168.199.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return "Invalid route entry"

        route_entry = route[0]
        nexthops = route_entry.get("nexthops", [])
        if len(nexthops) == 0:
            return "No nexthops found"

        # Check if path is found
        path_found = False
        for nh in nexthops:
            if nh.get("ip") == path:
                path_found = True
                break

        if not path_found:
            if path_should_be_present:
                return f"{path} is not present"
            else:
                return None
        else:
            if path_should_be_present:
                return None
            else:
                return f"{path} is still present"

        return None

    # Check if path is a backup in output of show ip route <pfx> json
    def _check_iproute_backup_prefix_json(path, intf, path_should_be_backup=True):
        output = json.loads(r1.vtysh_cmd(
            "show ip route 192.168.199.0/24 json"))
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found"

        route = output["192.168.199.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return "Invalid route entry"

        route_entry = route[0]
        backup_nexthops = route_entry.get("backupNexthops", [])

        if len(backup_nexthops) == 0:
            return "No backup nexthops found"

        # Check if path is still the backup path
        path_is_backup = False
        for nh in backup_nexthops:
            if nh.get("ip") == path and nh.get("interfaceName") == intf:
                path_is_backup = True
                break

        if not path_is_backup:
            if path_should_be_backup:
                return f"{path} via {intf} is not the backup path"
            else:
                return None
        else:
            if path_should_be_backup:
                return None
            else:
                return f"{path} via {intf} is still the backup path"

        return None

    # Check if path is a backup in output of show ip route json
    def _check_iproute_backup_json(path, intf):
        output = json.loads(r1.vtysh_cmd("show ip route json"))
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found in JSON output"

        route = output["192.168.199.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return "Route entry is not a valid list"

        route_entry = route[0]
        if "backupNexthops" not in route_entry:
            return "backupNexthops field not found in route entry"

        backup_nexthops = route_entry["backupNexthops"]
        if not isinstance(backup_nexthops, list) or len(backup_nexthops) == 0:
            return "backupNexthops is not a valid list or is empty"

        # Verify backup nexthop contains path
        found_backup = False
        for nh in backup_nexthops:
            if nh.get("ip") == path and nh.get("interfaceName") == intf:
                found_backup = True
            break

        if not found_backup:
            return f"Backup nexthop {path} via {intf} not found in backupNexthops"

        return None

    # Check if path is a backup in output of show ip bgp <pfx> json
    def _check_bgp_backup_prefix_json(path, path_should_be_backup=True):
        """Verify path is marked as backup (or not) in BGP table"""
        output = json.loads(r1.vtysh_cmd(
            "show ip bgp 192.168.199.0/24 json"))
        if "paths" not in output:
            return "No paths found in BGP output"

        paths = output["paths"]
        # Find path and verify it's marked as backup
        path_is_backup = False
        found_path = False
        for p in paths:
            nexthops = p.get("nexthops", [])
            for nh in nexthops:
                if nh.get("ip") == path:
                    found_path = True
                if nh.get("ip") == path and p.get("backup") is True:
                    path_is_backup = True
                    break

        if not found_path:
            return f"{path} not found in BGP table"
        if not path_is_backup:
            if path_should_be_backup:
                return f"{path} not marked as backup in BGP table"
            else:
                return None
        else:
            if path_should_be_backup:
                return None
            else:
                return f"{path} still marked as backup in BGP table"

    # Check if path is a backup in output of show ip bgp json
    def _check_bgp_backup_json(path):
        output = json.loads(r1.vtysh_cmd("show ip bgp json"))
        if "routes" not in output:
            return "Routes field not found in BGP table JSON output"

        routes = output["routes"]
        if "192.168.199.0/24" not in routes:
            return "Route 192.168.199.0/24 not found in BGP table JSON"

        route_paths = routes["192.168.199.0/24"]
        if not isinstance(route_paths, list):
            return "Route paths is not a valid list"

        # Find a path with backup: true
        found_backup = False
        for p in route_paths:
            if p.get("backup") is True:
                if p.get("nexthops")[0].get("ip") == path:
                    found_backup = True
                break

        if not found_backup:
            return "No path with 'backup: true' found in BGP table JSON"

        return None

    output = json.loads(r1.vtysh_cmd(
        "show bgp ipv4 unicast 192.168.199.0/24 json"))

    # Verify all three nexthops are present
    nexthops = set()
    for path in output["paths"]:
        nexthop = path.get("nexthops")[0].get("ip")
        nexthops.add(nexthop)

    expected_nexthops = {"10.16.2.2", "10.16.3.3", "10.16.4.4"}
    assert (
        nexthops == expected_nexthops
    ), f"Expected nexthops {expected_nexthops}, got {nexthops}"

    step("Verified paths from all three peers (R2, R3, and R4)")

    step("Starting comprehensive verification of BGP backup paths")

    # 1. Routing table verification (show ip route) - Text output
    step("Verifying routing table text output for backup path mnemonic 'b'")

    def _check_route_text_backup():
        output = r1.vtysh_cmd("show ip route")
        # Check for the backup path marker 'b' in the routing table
        if "b" not in output:
            return "Backup path mnemonic 'b' not found in routing table text output"
        # Verify the route is present
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found in routing table"
        return None

    test_func = functools.partial(_check_route_text_backup)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Routing table text verification failed: {}".format(
        result)
    step("Successfully verified backup path 'b' mnemonic in routing table text output")

    # 2. Routing table verification (show ip route) - JSON output
    step("Verifying routing table JSON output for backupNexthops")

    test_func = functools.partial(
        _check_iproute_backup_json, "10.16.2.2", "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Routing table JSON verification failed: {}".format(
        result)
    step("Successfully verified backupNexthops in routing table JSON output")

    # 3. Specific route verification (show ip route 192.168.199.0/24) - Text output
    step("Verifying specific route text output for backup path prefix 'b'")

    def _check_specific_route_text_backup():
        output = r1.vtysh_cmd("show ip route 192.168.199.0/24")
        # Check for backup path marker 'b' before the backup nexthop
        if "b" not in output:
            return "Backup path prefix 'b' not found in specific route text output"
        # Verify the backup nexthop 10.16.2.2 is present
        if "10.16.2.2" not in output:
            return "Backup nexthop 10.16.2.2 not found in specific route output"
        return None

    test_func = functools.partial(_check_specific_route_text_backup)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Specific route text verification failed: {}".format(
        result)
    step("Successfully verified backup path 'b' prefix in specific route text output")

    # 4. Specific route verification (show ip route 192.168.199.0/24) - JSON output
    step("Verifying specific route JSON output for backupNexthops structure")

    test_func = functools.partial(
        _check_iproute_backup_prefix_json, "10.16.2.2", "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Specific route JSON verification failed: {}".format(
        result)
    step("Successfully verified backupNexthops structure in specific route JSON output")

    # 5. BGP table verification (show ip bgp) - Text output
    step("Verifying BGP table text output for backup path mnemonic 'B'")

    def _check_bgp_table_text_backup():
        output = r1.vtysh_cmd("show ip bgp")
        # Check for the backup path marker 'B' (uppercase) in Status codes
        if "B" not in output:
            return "Backup path mnemonic 'B' not found in BGP table text output"
        # Verify the route is present
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found in BGP table"
        return None

    test_func = functools.partial(_check_bgp_table_text_backup)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP table text verification failed: {}".format(
        result)
    step("Successfully verified backup path 'B' mnemonic in BGP table text output")

    # 6. BGP table verification (show ip bgp) - JSON output
    step("Verifying BGP table JSON output for backup field")

    test_func = functools.partial(_check_bgp_backup_json, "10.16.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP table JSON verification failed: {}".format(
        result)
    step("Successfully verified 'backup: true' field in BGP table JSON output")

    # 7. Specific BGP route verification (show ip bgp 192.168.199.0/24) - Text output
    step("Verifying specific BGP route text output for 'backup' keyword")

    def _check_specific_bgp_text_backup():
        output = r1.vtysh_cmd("show ip bgp 192.168.199.0/24")
        # Check for the 'backup' keyword in the path description
        if "backup" not in output.lower():
            return "'backup' keyword not found in specific BGP route text output"
        # Verify the route is present
        if "192.168.199.0/24" not in output:
            return "Route 192.168.199.0/24 not found in specific BGP route output"
        return None

    test_func = functools.partial(_check_specific_bgp_text_backup)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Specific BGP route text verification failed: {}".format(
        result)
    step("Successfully verified 'backup' keyword in specific BGP route text output")

    # 8. Specific BGP route verification (show ip bgp 192.168.199.0/24) - JSON output
    step("Verifying specific BGP route JSON output for backup field in paths array")

    test_func = functools.partial(_check_bgp_backup_prefix_json, "10.16.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Specific BGP route JSON verification failed: {}".format(
        result)
    step("Successfully verified 'backup: true' field in specific BGP route JSON paths array")

    step("All comprehensive BGP backup path verifications completed successfully")

    # Dynamic backup path selection test
    step("Starting dynamic backup path selection test with interface state changes")

    # 1. Record initial state
    step("Recording initial backup path state")

    def _get_backup_path_info():
        """Get current backup path information from JSON output"""
        output = json.loads(r1.vtysh_cmd(
            "show ip route 192.168.199.0/24 json"))
        if "192.168.199.0/24" not in output:
            return None, "Route not found"

        route = output["192.168.199.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return None, "Invalid route entry"

        route_entry = route[0]
        backup_nexthops = route_entry.get("backupNexthops", [])

        if len(backup_nexthops) == 0:
            return None, "No backup nexthops found"

        # Return the first backup nexthop
        return backup_nexthops[0], None

    initial_backup, error = _get_backup_path_info()
    assert initial_backup is not None, "Failed to get initial backup path: {}".format(
        error)
    assert initial_backup.get(
        "ip") == "10.16.2.2", "Initial backup path should be via 10.16.2.2"
    assert initial_backup.get(
        "interfaceName") == "r1-eth0", "Initial backup path should be via r1-eth0"

    step("Initial backup path confirmed: {} via {}".format(
        initial_backup.get("ip"), initial_backup.get("interfaceName")))

    # Verify the other non-backup path exists (via R3)
    bgp_output = json.loads(r1.vtysh_cmd("show ip bgp 192.168.199.0/24 json"))
    assert "paths" in bgp_output, "No paths found in BGP output"
    paths = bgp_output["paths"]
    assert len(paths) >= 3, "Expected at least 3 paths"

    # Find the path via R3 (10.16.3.3)
    r3_path_exists = False
    for path in paths:
        nexthops = path.get("nexthops", [])
        for nh in nexthops:
            if nh.get("ip") == "10.16.3.3":
                r3_path_exists = True
                break

    assert r3_path_exists, "Path via R3 (10.16.3.3) not found in initial state"
    step("Confirmed path via R3 (10.16.3.3) exists as non-backup path")

    # 2. Simulate interface failure - shutdown r1-eth0 (interface to R2)
    step("Shutting down interface r1-eth0 (to R2) to simulate failure")

    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        shutdown
        end
    """
    )

    step("Interface r1-eth0 shut down, waiting for BGP convergence")

    # 3. Verify backup path failover to R3
    step("Verifying backup path has failed over to R3 (10.16.3.3)")
    test_func = functools.partial(
        _check_iproute_backup_prefix_json, "10.16.3.3", "r1-eth1")
    _, result1 = topotest.run_and_expect(test_func, None, count=60, wait=1)
    test_func = functools.partial(
        _check_iproute_prefix_json, "10.16.2.2", path_should_be_present=False)
    _, result2 = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result1 is None and result2 is None, "Backup path failover verification failed: {}".format(
        result)
    step("Successfully verified backup path failed over to R3 (10.16.3.3) via r1-eth1")

    # Verify in text output
    step("Verifying backup path failover in text output")

    def _check_backup_failover_text():
        """Verify backup path failover in text output"""
        output = r1.vtysh_cmd("show ip route 192.168.199.0/24")
        # Should have backup marker 'b'
        if "b" not in output:
            return "Backup path marker 'b' not found after failover"
        # Should have R3 nexthop
        if "10.16.3.3" not in output:
            return "R3 nexthop (10.16.3.3) not found in routing table after failover"
        # Should NOT have R2 nexthop
        if "10.16.2.2" in output:
            return "R2 nexthop (10.16.2.2) still present after interface shutdown"
        return None

    test_func = functools.partial(_check_backup_failover_text)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Backup path failover text verification failed: {}".format(
        result)
    step("Successfully verified backup path failover in text output")

    # Verify in BGP table
    step("Verifying backup path failover in BGP table")

    # test_func = functools.partial(_check_bgp_backup_failover)
    test_func = functools.partial(_check_bgp_backup_prefix_json, "10.16.3.3")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP backup path failover verification failed: {}".format(
        result)
    step("Successfully verified R3 path marked as backup in BGP table")

    # 4. Restore interface - bring r1-eth0 back up
    step("Bringing interface r1-eth0 back up to restore original backup path")

    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        no shutdown
        end
    """
    )

    step("Interface r1-eth0 brought back up, waiting for BGP convergence")

    # 5. Verify backup path changes to R2 after interface restoration
    step("Verifying backup path changes to R2 (10.16.2.2) after interface restoration")
    test_func = functools.partial(
        _check_iproute_backup_prefix_json, "10.16.2.2", "r1-eth0")
    _, result1 = topotest.run_and_expect(test_func, None, count=60, wait=1)

    test_func = functools.partial(
        _check_iproute_backup_prefix_json, "10.16.3.3", "r1-eth1", path_should_be_backup=False)
    _, result2 = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result1 is None and result2 is None, "Backup path persistence verification failed: {}".format(
        result)

    step("Successfully verified R2 (10.16.2.2) is backup path and R3 is present but not backup")

    step("Verifying backup path changes to R2 in text output")

    def _check_backup_is_r2_text():
        """Verify R2 is backup path in text output"""
        output = r1.vtysh_cmd("show ip route 192.168.199.0/24")
        # Should have backup marker 'b'
        if "b" not in output:
            return "Backup path marker 'b' not found after restoration"
        # Should have R3 nexthop (the backup)
        if "10.16.2.2" not in output:
            return "R2 nexthop (10.16.2.2) not found in routing table after restoration"
        return None

    test_func = functools.partial(_check_backup_is_r2_text)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Backup path persistence text verification failed: {}".format(
        result)
    step("Successfully verified R3 remains as backup in text output with R2 also present")

    # Verify in BGP table
    step("Verifying backup path is restored as R2 in BGP table")
    test_func = functools.partial(_check_bgp_backup_prefix_json, "10.16.2.2")
    _, result1 = topotest.run_and_expect(test_func, None, count=30, wait=1)
    test_func = functools.partial(
        _check_bgp_backup_prefix_json, "10.16.3.3", path_should_be_backup=False)
    _, result2 = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result1 is None and result2 is None, \
        "BGP backup path persistence verification failed: {}".format(result)
    step("Successfully verified R2 path is restored as backup and R3 path exists but is not backup in BGP table")

    step("Verifying backup path does not show up if config is removed")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
        address-family ipv4 unicast
        no install backup-path
        end
    """
    )
    test_func = functools.partial(
        _check_iproute_prefix_json, "10.16.3.3", path_should_be_present=False)
    _, result1 = topotest.run_and_expect(test_func, None, count=60, wait=1)
    test_func = functools.partial(
        _check_iproute_prefix_json, "10.16.2.2", path_should_be_present=False)
    _, result2 = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result1 is None and result2 is None, \
        "Backup path failover verification failed: {}".format(result)

    step("Dynamic backup path selection test completed successfully")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
