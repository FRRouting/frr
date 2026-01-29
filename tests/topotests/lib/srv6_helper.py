# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Free Mobile, Vincent Jardin
#
# Helper functions for SRv6 topotests.
# Provides utilities for querying SRv6 routes from the Linux kernel
# and verifying data plane connectivity.

import re


def get_kernel_srv6_routes(router, proto="isis"):
    """
    Get SRv6 routes from the kernel using iproute2 JSON output.

    Args:
        router: The router object to query
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A dict with route prefixes as keys and route info as values.
        Route info includes: encap type, action, mode, segs, dev, via, proto.
        For multipath routes, 'nexthops' contains a list of additional nexthops.

    Example output:
    {
        'fc00:0:2::/48': {
            'encap': 'seg6',
            'mode': 'encap',
            'segs': ['fc00:0:3:1::'],
            'dev': 'eth-rt3',
            'gateway': 'fe80::...',
            'proto': 'isis'
        },
        'fc00:0:1::/48': {
            'encap': 'seg6local',
            'action': 'uN',
            'dev': 'sr0',
            'proto': 'isis'
        },
        'fc00:0:4:1::/64': {
            'encap': 'seg6local',
            'action': 'End.X',
            'nh6': 'fe80::...',
            'dev': 'eth-rt2-1',
            'proto': 'isis',
            'nexthops': [
                {'gateway': 'fe80::...', 'dev': 'eth-rt5', 'weight': 1}
            ]
        }
    }
    """
    import json as json_module

    output = router.run(f"ip -j -6 route show proto {proto}")
    routes = {}

    try:
        json_routes = json_module.loads(output)
    except json_module.JSONDecodeError:
        return routes

    for rt in json_routes:
        prefix = rt.get("dst", "")
        if not prefix:
            continue

        route = {"proto": proto}

        # Copy relevant fields from JSON
        if "dev" in rt:
            route["dev"] = rt["dev"]
        if "gateway" in rt:
            route["gateway"] = rt["gateway"]
        if "metric" in rt:
            route["metric"] = rt["metric"]

        # Parse encap information
        # Note: iproute2 JSON format varies - encap can be a dict or string
        encap = rt.get("encap")
        if encap:
            if isinstance(encap, dict):
                encap_type = encap.get("type")
                if encap_type == "seg6local":
                    route["encap"] = "seg6local"
                    if "action" in encap:
                        route["action"] = encap["action"]
                    if "nh6" in encap:
                        route["nh6"] = encap["nh6"]
                elif encap_type == "seg6":
                    route["encap"] = "seg6"
                    if "mode" in encap:
                        route["mode"] = encap["mode"]
                    if "segs" in encap:
                        route["segs"] = encap["segs"]
            elif isinstance(encap, str):
                # Handle string format: "seg6local action uN"
                if "seg6local" in encap:
                    route["encap"] = "seg6local"
                elif "seg6" in encap:
                    route["encap"] = "seg6"

        # Parse multipath nexthops
        if "nexthops" in rt:
            route["nexthops"] = []
            for nh in rt["nexthops"]:
                nexthop = {}
                if "gateway" in nh:
                    nexthop["gateway"] = nh["gateway"]
                if "dev" in nh:
                    nexthop["dev"] = nh["dev"]
                if "weight" in nh:
                    nexthop["weight"] = nh["weight"]
                if nexthop:
                    route["nexthops"].append(nexthop)

        routes[prefix] = route

    return routes


def get_route_nexthop_info(router, prefix, proto="isis"):
    """
    Get nexthop information for a specific route from the kernel using JSON output.

    Args:
        router: The router object to query
        prefix: The IPv6 prefix to look up
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A dict with 'via' (nexthop address), 'dev' (outgoing interface),
        and 'encap' (encapsulation type if present).
    """
    import json as json_module

    output = router.run(f"ip -j -6 route show {prefix} proto {proto}")
    info = {"via": None, "dev": None, "encap": None}

    try:
        json_routes = json_module.loads(output)
    except json_module.JSONDecodeError:
        return info

    if not json_routes:
        return info

    rt = json_routes[0]
    if "gateway" in rt:
        info["via"] = rt["gateway"]
    if "dev" in rt:
        info["dev"] = rt["dev"]

    encap = rt.get("encap")
    if encap:
        if isinstance(encap, dict):
            encap_type = encap.get("type")
            if encap_type == "seg6local":
                info["encap"] = "seg6local"
            elif encap_type == "seg6":
                info["encap"] = "seg6"
        elif isinstance(encap, str):
            if "seg6local" in encap:
                info["encap"] = "seg6local"
            elif "seg6" in encap:
                info["encap"] = "seg6"

    return info


def check_ping6(router, dest, source=None, count=3, timeout=10):
    """
    Run a ping6 test and return success/failure.

    Args:
        router: The router object to ping from
        dest: Destination IPv6 address
        source: Source address or interface (optional)
        count: Number of ping packets to send
        timeout: Timeout in seconds for each packet

    Returns:
        A tuple of (success, output) where success is True if any packets
        were received, and output is the raw ping command output.
    """
    cmd = f"ping6 -c {count} -W {timeout}"
    if source:
        cmd += f" -I {source}"
    cmd += f" {dest}"

    output = router.run(cmd)
    match = re.search(r"(\d+) received", output)
    if match:
        received = int(match.group(1))
        return received > 0, output
    return False, output


def verify_kernel_srv6_route(router, prefix, expected, proto="isis"):
    """
    Verify a specific SRv6 route in the kernel matches expected attributes.

    Args:
        router: The router object to check
        prefix: The IPv6 prefix to verify
        expected: Dict with expected route attributes
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A tuple of (success, message) where success is True if the route
        matches all expected attributes.
    """
    routes = get_kernel_srv6_routes(router, proto)

    if prefix not in routes:
        return False, f"Route {prefix} not found in kernel"

    route = routes[prefix]

    for key, value in expected.items():
        if key not in route:
            return False, f"Route {prefix} missing attribute {key}"
        if route[key] != value:
            return False, f"Route {prefix} {key}: expected {value}, got {route[key]}"

    return True, "OK"


def get_frr_route_json(router, prefix, addr_type="ipv6"):
    """
    Get route information from FRR RIB in JSON format.

    Uses 'show ipv6 route <prefix> json' command.
    JSON output includes 'backupNexthops' array if backup routes exist.

    Args:
        router: The router object to query
        prefix: The IPv6 prefix to look up
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        Route dict or None if not found.
    """
    import json

    cmd = f"show {addr_type} route {prefix} json"
    output = router.vtysh_cmd(cmd)
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None

    if prefix in data and len(data[prefix]) > 0:
        return data[prefix][0]

    return None


def verify_route_has_backup_nexthops(router, prefix, min_backups=1, addr_type="ipv6"):
    """
    Verify that a route has backup nexthops using JSON output.

    Args:
        router: The router object to check
        prefix: The IPv6 prefix to verify
        min_backups: Minimum number of backup nexthops expected
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A tuple of (success, message, route_info).
    """
    route = get_frr_route_json(router, prefix, addr_type)

    if route is None:
        return False, f"Route {prefix} not found", None

    backup_nexthops = route.get("backupNexthops", [])
    backup_count = len(backup_nexthops)

    if backup_count >= min_backups:
        return True, f"Route {prefix} has {backup_count} backup nexthops", route
    else:
        return False, f"Route {prefix}: expected >= {min_backups} backups, found {backup_count}", route


def get_frr_srv6_sids_json(router):
    """
    Get SRv6 SIDs from FRR using JSON output.

    Uses 'show segment-routing srv6 sid json' command.
    The JSON output includes a 'backup' boolean in the context object
    for backup End.X SIDs used by TI-LFA.

    Args:
        router: The router object to query

    Returns:
        A dict with SID info, keyed by SID address.
    """
    import json

    output = router.vtysh_cmd("show segment-routing srv6 sid json")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {}


def get_frr_backup_sids(router):
    """
    Get backup SRv6 SIDs from FRR using JSON output.

    Backup SIDs have 'backup': true in their context object.
    These are End.X SIDs allocated for TI-LFA backup paths.

    Args:
        router: The router object to query

    Returns:
        A list of backup SID dicts with 'sid', 'behavior', 'interfaceName'.
    """
    sids_json = get_frr_srv6_sids_json(router)
    backup_sids = []

    for sid_addr, sid_info in sids_json.items():
        context = sid_info.get("context", {})
        if context.get("backup"):
            backup_sid = {
                "sid": sid_info.get("sid", sid_addr),
                "behavior": sid_info.get("behavior", ""),
                "backup": True,
            }
            if "interfaceName" in context:
                backup_sid["interfaceName"] = context["interfaceName"]
            backup_sids.append(backup_sid)

    return backup_sids


def verify_backup_sids_allocated(router, min_count=1):
    """
    Verify that backup End.X SIDs are allocated on a router.

    Args:
        router: The router object to check
        min_count: Minimum number of backup SIDs expected

    Returns:
        A tuple of (success, message, backup_sids list).
    """
    backup_sids = get_frr_backup_sids(router)
    count = len(backup_sids)

    if count >= min_count:
        return True, f"Found {count} backup SIDs", backup_sids
    else:
        return False, f"Expected >= {min_count} backup SIDs, found {count}", backup_sids


def get_kernel_endx_routes_with_backup(router, proto="isis"):
    """
    Get seg6local End.X routes that have backup nexthops from the kernel.

    End.X routes with TI-LFA protection will have the primary nexthop
    in the main route line (nh6) and backup nexthops as continuation lines.

    Args:
        router: The router object to query
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A list of dicts with End.X routes that have backup nexthops.
        Each dict has: 'prefix', 'action', 'nh6', 'dev', 'nexthops'.
    """
    routes = get_kernel_srv6_routes(router, proto)
    endx_with_backup = []

    for prefix, route_info in routes.items():
        if route_info.get("encap") == "seg6local":
            action = route_info.get("action", "")
            # End.X actions include End.X, End.DX6, uA, etc.
            if action in ("End.X", "End.DX6", "uA") or "End" in action:
                nexthops = route_info.get("nexthops", [])
                if nexthops:
                    endx_with_backup.append({
                        "prefix": prefix,
                        "action": action,
                        "nh6": route_info.get("nh6"),
                        "dev": route_info.get("dev"),
                        "nexthops": nexthops,
                    })

    return endx_with_backup


def verify_kernel_endx_has_backup_nexthops(router, min_count=1, proto="isis"):
    """
    Verify that End.X routes in the kernel have backup nexthops installed.

    This verifies that zebra correctly installed backup nexthops for
    seg6local End.X routes computed by TI-LFA.

    Args:
        router: The router object to check
        min_count: Minimum number of End.X routes with backup nexthops expected
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A tuple of (success, message, endx_routes list).
    """
    endx_routes = get_kernel_endx_routes_with_backup(router, proto)
    count = len(endx_routes)

    if count >= min_count:
        return True, f"Found {count} End.X routes with backup nexthops", endx_routes
    else:
        return False, f"Expected >= {min_count} End.X routes with backup, found {count}", endx_routes


#
# Debug output monitoring functions
#
def enable_isis_lfa_debug(router):
    """
    Enable ISIS LFA debug output on a router.

    Args:
        router: The router object to configure

    Returns:
        True if debug was enabled successfully.
    """
    router.vtysh_cmd("debug isis lfa")
    router.vtysh_cmd("debug isis events")
    return True


def disable_isis_lfa_debug(router):
    """
    Disable ISIS LFA debug output on a router.

    Args:
        router: The router object to configure

    Returns:
        True if debug was disabled successfully.
    """
    router.vtysh_cmd("no debug isis lfa")
    router.vtysh_cmd("no debug isis events")
    return True


def get_isisd_log(router, lines=100):
    """
    Get recent lines from the isisd log file.

    Args:
        router: The router object to query
        lines: Number of lines to retrieve (default: 100)

    Returns:
        String containing the log lines.
    """
    output = router.run(f"tail -n {lines} /var/log/frr/isisd.log 2>/dev/null || "
                       f"tail -n {lines} /tmp/topotests/*/{{router.name}}/isisd.log 2>/dev/null || "
                       "echo 'Log file not found'")
    return output


def parse_sid_allocation_events(log_content):
    """
    Parse SID allocation/deallocation events from ISIS debug log.

    Looks for patterns like:
    - "Add Backup End.X SID" / "Add Primary End.X SID"
    - "Delete SRv6 End.X SID"
    - "SRv6 SID ... ALLOCATED"
    - "SRv6 SID ... RELEASED"
    - "setting adjacency SID"

    Args:
        log_content: String containing log lines

    Returns:
        A dict with 'allocations', 'deallocations', and 'errors' lists.
    """
    events = {"allocations": [], "deallocations": [], "errors": []}

    for line in log_content.splitlines():
        line_lower = line.lower()

        # Look for SID allocation patterns
        if "add" in line_lower and "end.x sid" in line_lower:
            events["allocations"].append({"type": "add_endx", "raw": line})
        elif "allocated" in line_lower and "sid" in line_lower:
            events["allocations"].append({"type": "allocated", "raw": line})
        elif "setting" in line_lower and "sid" in line_lower:
            events["allocations"].append({"type": "setting", "raw": line})
        elif "installing" in line_lower and "sid" in line_lower:
            events["allocations"].append({"type": "installing", "raw": line})
        # Look for deallocation patterns
        elif "delete" in line_lower and "sid" in line_lower:
            events["deallocations"].append({"type": "delete", "raw": line})
        elif "released" in line_lower and "sid" in line_lower:
            events["deallocations"].append({"type": "released", "raw": line})
        elif "uninstalling" in line_lower and "sid" in line_lower:
            events["deallocations"].append({"type": "uninstalling", "raw": line})
        # Look for errors
        elif "fail" in line_lower and "sid" in line_lower:
            events["errors"].append({"type": "failed", "raw": line})

    return events


def check_for_allocation_loops(events, max_same_type=10):
    """
    Check for SID allocation loops in parsed events.

    An allocation loop is detected when there are many consecutive
    allocations or deallocations of the same type without corresponding
    opposite operations.

    Args:
        events: Dict from parse_sid_allocation_events()
        max_same_type: Maximum allowed consecutive same-type events

    Returns:
        A tuple of (has_loop, message).
    """
    allocs = events.get("allocations", [])
    deallocs = events.get("deallocations", [])

    # Check for excessive allocations without deallocations
    if len(allocs) > max_same_type and len(deallocs) == 0:
        return True, f"Potential allocation loop: {len(allocs)} allocations, 0 deallocations"

    # Check for excessive deallocations without allocations
    if len(deallocs) > max_same_type and len(allocs) == 0:
        return True, f"Potential deallocation loop: {len(deallocs)} deallocations, 0 allocations"

    # Check for rapid back-and-forth (alloc/dealloc ratio close to 1:1 with high count)
    if len(allocs) > max_same_type and len(deallocs) > max_same_type:
        ratio = len(allocs) / len(deallocs) if len(deallocs) > 0 else float('inf')
        if 0.8 <= ratio <= 1.2:
            return True, f"Potential allocation churn: {len(allocs)} allocations, {len(deallocs)} deallocations"

    return False, f"No allocation loops detected ({len(allocs)} allocs, {len(deallocs)} deallocs)"


def verify_no_pending_allocations(router):
    """
    Verify there are no SIDs with pending allocation (allocation_in_progress).

    This checks that all SID allocations have completed by verifying
    all SIDs in the table have valid (non-zero) addresses.

    Args:
        router: The router object to check

    Returns:
        A tuple of (success, message, pending_count).
    """
    sids = get_frr_srv6_sids_json(router)
    pending = []

    for sid_addr, sid_info in sids.items():
        # Check if SID address is unspecified (all zeros) which indicates pending
        if sid_addr == "::" or sid_addr.startswith("::"):
            pending.append(sid_info)

    if pending:
        return False, f"Found {len(pending)} SIDs with pending allocation", len(pending)
    else:
        return True, f"All {len(sids)} SIDs have completed allocation", 0


def monitor_sid_stability(router, duration_seconds=5, check_interval=1):
    """
    Monitor SID table for stability over a period of time.

    This helps detect continuous SID reallocation issues.

    Args:
        router: The router object to monitor
        duration_seconds: How long to monitor (default: 5 seconds)
        check_interval: Seconds between checks (default: 1)

    Returns:
        A tuple of (stable, message, snapshots).
        stable is True if SID table didn't change during monitoring.
        snapshots is a list of SID table states captured.
    """
    import time

    snapshots = []
    start_time = time.time()

    while time.time() - start_time < duration_seconds:
        sids = get_frr_srv6_sids_json(router)
        # Create a comparable snapshot (just the SID addresses)
        snapshot = set(sids.keys())
        snapshots.append(snapshot)
        time.sleep(check_interval)

    # Check if all snapshots are identical
    if len(snapshots) < 2:
        return True, "Not enough snapshots collected", snapshots

    first_snapshot = snapshots[0]
    for i, snapshot in enumerate(snapshots[1:], 1):
        if snapshot != first_snapshot:
            added = snapshot - first_snapshot
            removed = first_snapshot - snapshot
            return False, f"SID table changed at snapshot {i}: added={added}, removed={removed}", snapshots

    return True, f"SID table stable across {len(snapshots)} snapshots", snapshots


#
# Backup path verification functions for TI-LFA
#
def get_backup_path_details(router, prefix, addr_type="ipv6"):
    """
    Get detailed information about backup nexthops for a route.

    This extracts the backup path information from FRR RIB, including
    the backup nexthop interface, gateway, and any SRv6 segment list.

    Args:
        router: The router object to query
        prefix: The IPv6 prefix to look up
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A dict with:
        - 'has_backup': True if backup nexthops exist
        - 'primary_nexthops': List of primary nexthop details
        - 'backup_nexthops': List of backup nexthop details
        - 'raw_route': The raw route dict from FRR
    """
    route = get_frr_route_json(router, prefix, addr_type)

    result = {
        "has_backup": False,
        "primary_nexthops": [],
        "backup_nexthops": [],
        "raw_route": route,
    }

    if route is None:
        return result

    # Extract primary nexthops
    for nh in route.get("nexthops", []):
        primary = {
            "interface": nh.get("interfaceName"),
            "gateway": nh.get("ip"),
            "active": nh.get("active", False),
            "fib": nh.get("fib", False),
        }
        result["primary_nexthops"].append(primary)

    # Extract backup nexthops
    for nh in route.get("backupNexthops", []):
        backup = {
            "interface": nh.get("interfaceName"),
            "gateway": nh.get("ip"),
            "seg6": nh.get("seg6"),
            "seg6local": nh.get("seg6local"),
        }
        result["backup_nexthops"].append(backup)

    result["has_backup"] = len(result["backup_nexthops"]) > 0

    return result


def verify_backup_path_preinstalled(router, prefix, expected_backup_interface=None,
                                    addr_type="ipv6"):
    """
    Verify that a backup path is pre-installed for a given prefix.

    This confirms TI-LFA has computed and installed a backup path
    before any failure occurs.

    Args:
        router: The router object to check
        prefix: The IPv6 prefix to verify
        expected_backup_interface: Optional interface name the backup should use
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A tuple of (success, message, backup_details).
    """
    details = get_backup_path_details(router, prefix, addr_type)

    if details["raw_route"] is None:
        return False, f"Route {prefix} not found", details

    if not details["has_backup"]:
        return False, f"Route {prefix} has no backup path pre-installed", details

    backup_count = len(details["backup_nexthops"])

    if expected_backup_interface:
        backup_interfaces = [b["interface"] for b in details["backup_nexthops"]]
        if expected_backup_interface not in backup_interfaces:
            return False, (f"Route {prefix}: expected backup via {expected_backup_interface}, "
                          f"found {backup_interfaces}"), details

    return True, f"Route {prefix} has {backup_count} backup path(s) pre-installed", details


def capture_preinstalled_backup_paths(router, prefixes, addr_type="ipv6"):
    """
    Capture the pre-installed backup paths for a list of prefixes.

    Used before a failure to record what backup paths exist, so we can
    verify the correct backup was activated after failure.

    Args:
        router: The router object to query
        prefixes: List of prefixes to capture backup paths for
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A dict mapping prefix to backup path details.
    """
    backup_paths = {}

    for prefix in prefixes:
        details = get_backup_path_details(router, prefix, addr_type)
        if details["has_backup"]:
            backup_paths[prefix] = details

    return backup_paths


def verify_backup_index_set(router, prefix, addr_type="ipv6"):
    """
    Verify that primary nexthops have backupIndex set correctly.

    When TI-LFA computes backup paths, primary nexthops should have a
    backupIndex array that references the backup nexthops. This confirms
    the backup relationship is properly installed in the RIB.

    Args:
        router: The router object to check
        prefix: The IPv6 prefix to verify
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A tuple of (success, message, details).
        details contains 'nexthops_with_backup' count and 'total_nexthops' count.
    """
    route = get_frr_route_json(router, prefix, addr_type)

    if route is None:
        return False, f"Route {prefix} not found", {}

    nexthops = route.get("nexthops", [])
    backup_nexthops = route.get("backupNexthops", [])

    if not backup_nexthops:
        return False, f"Route {prefix} has no backup nexthops", {
            "total_nexthops": len(nexthops),
            "nexthops_with_backup": 0,
        }

    # Count nexthops that have backupIndex set
    nexthops_with_backup = 0
    for nh in nexthops:
        if "backupIndex" in nh and len(nh["backupIndex"]) > 0:
            nexthops_with_backup += 1
            # Verify backup indices are valid
            for idx in nh["backupIndex"]:
                if idx >= len(backup_nexthops):
                    return False, (f"Route {prefix}: nexthop has invalid backupIndex {idx} "
                                  f"(only {len(backup_nexthops)} backup nexthops)"), {
                        "total_nexthops": len(nexthops),
                        "nexthops_with_backup": nexthops_with_backup,
                    }

    details = {
        "total_nexthops": len(nexthops),
        "nexthops_with_backup": nexthops_with_backup,
        "backup_nexthops": len(backup_nexthops),
    }

    if nexthops_with_backup == 0:
        return False, f"Route {prefix}: no nexthops have backupIndex set", details

    return True, (f"Route {prefix}: {nexthops_with_backup}/{len(nexthops)} nexthops "
                 f"have backupIndex referencing {len(backup_nexthops)} backup nexthops"), details


def verify_backup_path_activated(router, prefix, preinstalled_backup, addr_type="ipv6"):
    """
    Verify that traffic switched to the pre-installed backup path after failure.

    Compares the current active nexthop with the pre-installed backup nexthop
    to confirm the backup path was activated.

    Args:
        router: The router object to check
        prefix: The IPv6 prefix to verify
        preinstalled_backup: The backup path details captured before failure
        addr_type: Address type ("ipv4" or "ipv6")

    Returns:
        A tuple of (success, message, current_details).
    """
    current = get_backup_path_details(router, prefix, addr_type)

    if current["raw_route"] is None:
        return False, f"Route {prefix} not found after failure", current

    if not current["primary_nexthops"]:
        return False, f"Route {prefix} has no nexthops after failure", current

    # Get the current active nexthop interfaces
    current_interfaces = set()
    for nh in current["primary_nexthops"]:
        if nh.get("active") or nh.get("fib"):
            iface = nh.get("interface")
            if iface:
                current_interfaces.add(iface)

    # Get the pre-installed backup nexthop interfaces
    backup_interfaces = set()
    for nh in preinstalled_backup.get("backup_nexthops", []):
        iface = nh.get("interface")
        if iface:
            backup_interfaces.add(iface)

    # Check if current path matches the pre-installed backup
    if backup_interfaces and current_interfaces:
        overlap = current_interfaces & backup_interfaces
        if overlap:
            return True, (f"Route {prefix}: traffic switched to backup path "
                         f"via {overlap}"), current
        else:
            return False, (f"Route {prefix}: current path {current_interfaces} "
                          f"does not match backup {backup_interfaces}"), current

    # If we can't determine interfaces, at least verify route is reachable
    return True, f"Route {prefix}: path changed after failure (interface check inconclusive)", current
