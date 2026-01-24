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
    Get SRv6 routes from the kernel using iproute2.

    Args:
        router: The router object to query
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A dict with route prefixes as keys and route info as values.
        Route info includes: encap type, action, mode, segs, dev, via, proto.

    Example output:
    {
        'fc00:0:2::/48': {
            'encap': 'seg6',
            'mode': 'encap',
            'segs': ['fc00:0:3:1::'],
            'dev': 'eth-rt3',
            'via': 'fe80::...',
            'proto': 'isis'
        },
        'fc00:0:1::/48': {
            'encap': 'seg6local',
            'action': 'uN',
            'dev': 'sr0',
            'proto': 'isis'
        }
    }
    """
    output = router.run(f"ip -6 route show proto {proto}")
    routes = {}

    for line in output.strip().splitlines():
        if not line:
            continue

        parts = line.split()
        if not parts:
            continue

        prefix = parts[0]
        route = {}

        if "encap seg6local" in line:
            route["encap"] = "seg6local"
            action_match = re.search(r"action (\S+)", line)
            if action_match:
                route["action"] = action_match.group(1)
        elif "encap seg6" in line:
            route["encap"] = "seg6"
            mode_match = re.search(r"mode (\S+)", line)
            if mode_match:
                route["mode"] = mode_match.group(1)
            segs_match = re.search(r"segs \d+ \[ ([^\]]+) \]", line)
            if segs_match:
                route["segs"] = segs_match.group(1).split()

        dev_match = re.search(r"dev (\S+)", line)
        if dev_match:
            route["dev"] = dev_match.group(1)

        via_match = re.search(r"via (\S+)", line)
        if via_match:
            route["via"] = via_match.group(1)

        metric_match = re.search(r"metric (\d+)", line)
        if metric_match:
            route["metric"] = metric_match.group(1)

        route["proto"] = proto
        routes[prefix] = route

    return routes


def get_route_nexthop_info(router, prefix, proto="isis"):
    """
    Get nexthop information for a specific route from the kernel.

    Args:
        router: The router object to query
        prefix: The IPv6 prefix to look up
        proto: The protocol to filter routes by (default: "isis")

    Returns:
        A dict with 'via' (nexthop address), 'dev' (outgoing interface),
        and 'encap' (encapsulation type if present).
    """
    output = router.run(f"ip -6 route show {prefix} proto {proto}")
    info = {"via": None, "dev": None, "encap": None}

    for line in output.strip().splitlines():
        if not line or line.startswith(" "):
            continue

        via_match = re.search(r"via (\S+)", line)
        if via_match:
            info["via"] = via_match.group(1)

        dev_match = re.search(r"dev (\S+)", line)
        if dev_match:
            info["dev"] = dev_match.group(1)

        if "encap seg6local" in line:
            info["encap"] = "seg6local"
        elif "encap seg6" in line:
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
