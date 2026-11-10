#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test features that ride on IS-IS IPv4 routes with IPv6 link-local nexthops
(isis ipv4-over-ipv6-nexthop), on a ring where no link has IPv4:

     +----+   s1   +----+   s2   +----+
     | r1 |--------| r2 |--------| r3 |
     +----+        +----+        +----+
       |                           |
       | s5 (affinity red)         | s3
       |                           |
     +----+          s4          +----+
     | r5 |----------------------| r4 |
     +----+                      +----+

- Segment Routing prefix SIDs and flex-algo labels forward IPv4 over the
  link-local nexthops; flex-algo 128 excludes the red link.
- PIM routes IPv4 multicast over them.
- LDP gives IPv4 FECs no labels over them: remote LFA leaves prefixes
  unprotected, and LDP-IGP sync needs LDP over IPv6.

The routers are level-1 because flex-algo elects its definition from the
level-1 database only.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import required_linux_kernel_version, step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd, pytest.mark.ldpd, pytest.mark.pimd]

ROUTERS = ("r1", "r2", "r3", "r4", "r5")

# Link-state metric that LDP-IGP sync advertises until sync is achieved.
LDP_SYNC_MAX_METRIC = 16777214


def lo4(router):
    return "10.255.0.{}".format(router[1:])


def host4(router):
    return "{}/32".format(lo4(router))


def build_topo(tgen):
    for router in ROUTERS:
        tgen.add_router(router)

    # Link i joins r<i> and r<i+1>; r<n>-eth0 faces r<n-1>, except on r1.
    for i in range(1, 6):
        switch = tgen.add_switch("s{}".format(i))
        switch.add_link(tgen.gears["r{}".format(i)])
        switch.add_link(tgen.gears["r{}".format(i % 5 + 1)])


def setup_module(mod):
    # IPv4 routes with IPv6 gateways (RTA_VIA) need Linux 5.2.
    if required_linux_kernel_version("5.2") is not True:
        pytest.skip("Linux kernel >= 5.2 is required")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def _expect(func, *args, count=60, wait=0.5):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, result


def _config(router, *lines):
    router.vtysh_cmd("configure terminal\n" + "\n".join(lines))


def _isis_route(router, prefix):
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    for route in routes.get(prefix, []):
        if route.get("protocol") == "isis" and route.get("installed"):
            return route
    return None


def _check_labelled_route(router, prefix, intf, label):
    route = _isis_route(router, prefix)
    if route is None:
        return "{}: no installed IS-IS route on {}".format(prefix, router.name)
    nexthops = [nh for nh in route["nexthops"] if nh.get("active")]
    if [
        (nh.get("interfaceName"), nh.get("ip", "")[:5], nh.get("labels"))
        for nh in nexthops
    ] != [(intf, "fe80:", [label])]:
        return "{} on {}: nexthops {}".format(prefix, router.name, nexthops)
    kernel = router.run("ip -4 route show {}".format(prefix.split("/")[0]))
    if not re.search(r"encap mpls\s+{} via inet6 fe80:".format(label), kernel):
        return "{} on {}: kernel route {}".format(prefix, router.name, kernel)
    return None


def _check_lfib(router, label, intf, out_label):
    """An SR LFIB entry for label, forwarding to a link-local nexthop."""
    table = json.loads(router.vtysh_cmd("show mpls table json"))
    entry = table.get(str(label))
    if entry is None:
        return "{}: no label {}".format(router.name, label)
    nexthops = [
        (nh.get("interface"), nh.get("nexthop", "")[:5], nh.get("outLabel"))
        for nh in entry["nexthops"]
    ]
    if nexthops != [(intf, "fe80:", out_label)]:
        return "{} label {}: nexthops {}".format(router.name, label, entry["nexthops"])
    return None


def _check_ping(src, dst):
    output = src.run("ping -c 3 -i 0.2 -W 1 -I {} {}".format(lo4(src.name), dst))
    if " 0% packet loss" not in output:
        return "ping {} -> {} failed: {}".format(src.name, dst, output)
    return None


def test_sr_prefix_sids():
    """IPv4 prefix SIDs are pushed onto link-local nexthops, swapped and
    popped by transit routers over them, and the traffic gets through."""
    tgen = _skip_on_failure()
    r1, r4, r5 = (tgen.gears[r] for r in ("r1", "r4", "r5"))

    step("r1 pushes the prefix SIDs of r3 and r4 onto link-local nexthops")
    _expect(_check_labelled_route, r1, host4("r3"), "r1-eth0", 16003)
    _expect(_check_labelled_route, r1, host4("r4"), "r1-eth1", 16004)

    step("r5 pops r4's SID and swaps r3's towards r4, over link-local nexthops")
    _expect(_check_lfib, r5, 16004, "r5-eth0", 3)
    _expect(_check_lfib, r5, 16003, "r5-eth0", 16003)

    step("IPv4 crosses the labelled paths both ways")
    _expect(_check_ping, r1, lo4("r4"), count=10)
    _expect(_check_ping, r4, lo4("r1"), count=10)
    _expect(_check_ping, r1, lo4("r3"), count=10)


def test_flex_algo():
    """Flex-algo 128 computes its own paths over the link-local adjacencies,
    avoiding the red link, and its labels forward IPv4."""
    tgen = _skip_on_failure()
    r1, r5 = tgen.gears["r1"], tgen.gears["r5"]

    step("Algorithm 0 reaches r5 over the red link, algorithm 128 around it")
    _expect(_check_lfib, r1, 16005, "r1-eth1", 3)
    _expect(_check_lfib, r1, 16205, "r1-eth0", 16205)
    _expect(_check_lfib, r1, 16204, "r1-eth0", 16204)

    step("Forward to an address on r5 outside IS-IS through the algo 128 label")
    r5.run("ip link add fa0 type dummy && ip link set fa0 up")
    r5.run("ip addr add 192.0.2.5/32 dev fa0")
    nexthop = json.loads(r1.vtysh_cmd("show mpls table json"))["16205"]["nexthops"][0]
    r1.run(
        "ip route add 192.0.2.5/32 encap mpls 16205 via inet6 {} dev r1-eth0 src {}".format(
            nexthop["nexthop"], lo4("r1")
        )
    )
    try:
        _expect(_check_ping, r1, "192.0.2.5", count=10)
    finally:
        r1.run("ip route del 192.0.2.5/32")
        r5.run("ip link del fa0")


def test_pim():
    """IPv4 multicast follows RPF over the link-local nexthops."""
    tgen = _skip_on_failure()
    r1, r4, r5 = (tgen.gears[r] for r in ("r1", "r4", "r5"))

    step("A receiver on r1 and a source on r4, behind dummy interfaces")
    r1.run("ip link add rcv0 type dummy && ip link set rcv0 up multicast on")
    r1.run("ip addr add 198.51.100.1/24 dev rcv0")
    _config(r1, "interface rcv0", "ip pim", "ip igmp", "ip igmp join-group 239.1.1.1")
    r4.run("ip link add src0 type dummy && ip link set src0 up multicast on")
    r4.run("ip addr add 192.0.2.4/24 dev src0")
    _config(r4, "interface src0", "ip pim", "ip router isis TEST", "isis passive")

    sender = (
        "import socket, time\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 16)\n"
        "s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, "
        "socket.inet_aton('192.0.2.4'))\n"
        "s.bind(('192.0.2.4', 0))\n"
        "for _ in range(100):\n"
        "    s.sendto(b'x' * 100, ('239.1.1.1', 5000))\n"
        "    time.sleep(0.05)\n"
    )
    r4.run("cat > /tmp/mcast_send.py << 'EOF'\n{}EOF".format(sender))

    def _sg_on_spt():
        r4.run("python3 /tmp/mcast_send.py")
        mroute = json.loads(r1.vtysh_cmd("show ip mroute json"))
        sg = mroute.get("239.1.1.1", {}).get("192.0.2.4")
        if not sg or sg.get("iif") != "r1-eth1" or "rcv0" not in sg.get("oil", {}):
            return "r1 (S,G): {}".format(sg)
        mroute = json.loads(r5.vtysh_cmd("show ip mroute json"))
        sg = mroute.get("239.1.1.1", {}).get("192.0.2.4")
        if not sg or sg.get("iif") != "r5-eth0" or "r5-eth1" not in sg.get("oil", {}):
            return "r5 (S,G): {}".format(sg)
        return None

    step("The shortest-path tree runs r4 -> r5 -> r1 over link-local links")
    _expect(_sg_on_spt, count=10, wait=1)

    def _packets():
        count = json.loads(r1.vtysh_cmd("show ip mroute count json"))
        return count["239.1.1.1"]["192.0.2.4"]["packets"]

    step("r1 forwards the source's packets to the receiver")
    before = _packets()
    r4.run("python3 /tmp/mcast_send.py")
    assert _packets() >= before + 100, "r1 forwarded {} packets".format(
        _packets() - before
    )


def test_ldp_remote_lfa():
    """LDP labels no IPv4 FEC over link-local nexthops, so remote LFA cannot
    protect over them; classic LFA still does, and routes stay installed."""
    tgen = _skip_on_failure()
    r1 = tgen.gears["r1"]

    step("Turn segment routing off and run LDP for both address families")
    for router in tgen.routers().values():
        n = router.name[1:]
        _config(router, "router isis TEST", "no segment-routing on")
        _config(
            router,
            "mpls ldp",
            "address-family ipv4",
            "label local allocate host-routes",
            "discovery targeted-hello accept",
            "discovery transport-address 10.255.0.{}".format(n),
            "interface {}-eth0".format(router.name),
            "exit",
            "interface {}-eth1".format(router.name),
            "exit",
            "exit-address-family",
            "address-family ipv6",
            "label local allocate host-routes",
            "discovery transport-address 2001:db8::{}".format(n),
            "interface {}-eth0".format(router.name),
            "exit",
            "interface {}-eth1".format(router.name),
            "exit",
            "exit-address-family",
        )

    def _ldp_sessions():
        output = json.loads(r1.vtysh_cmd("show mpls ldp neighbor json"))
        neighbors = output.get("neighbors", [])
        up = sorted(
            (n["addressFamily"], n["neighborId"])
            for n in neighbors
            if n["state"] == "OPERATIONAL"
        )
        if up != [("ipv6", "10.255.0.2"), ("ipv6", "10.255.0.5")]:
            return "r1 LDP sessions: {}".format(neighbors)
        return None

    step("Only IPv6 LDP forms over the links")
    _expect(_ldp_sessions)

    step("Enable remote LFA on r1 for the loopbacks")
    _config(
        r1,
        "ip prefix-list PLIST seq 5 permit 10.255.0.0/24 le 32",
        "router isis TEST",
        "fast-reroute remote-lfa prefix-list PLIST",
    )
    for intf in ("r1-eth0", "r1-eth1"):
        _config(
            r1,
            "interface " + intf,
            "isis fast-reroute lfa",
            "isis fast-reroute remote-lfa tunnel mpls-ldp",
        )

    def _protection():
        for router, backup in (
            ("r2", False),
            ("r3", True),
            ("r4", True),
            ("r5", False),
        ):
            route = _isis_route(r1, host4(router))
            if route is None:
                return "no route to {}".format(router)
            if bool(route.get("backupNexthops")) != backup:
                return "{}: backup nexthops {}".format(
                    router, route.get("backupNexthops")
                )
        return None

    # r2 and r5 would need remote LFA (PQ node r4 resp. r3); classic LFA
    # protects r3 and r4.
    step("Classic LFA protects r3 and r4; r2 and r5 stay unprotected")
    _expect(_protection)
    _expect(_check_ping, r1, lo4("r3"), count=10)


def test_ldp_sync():
    """LDP-IGP sync completes over IPv6 LDP; with IPv4-only LDP the links
    stay at the maximum metric."""
    tgen = _skip_on_failure()
    r1 = tgen.gears["r1"]

    def _metric(expected_max):
        route = _isis_route(r1, host4("r2"))
        if route is None:
            return "no route to r2"
        if (route["metric"] >= LDP_SYNC_MAX_METRIC) != expected_max:
            return "metric to r2: {}".format(route["metric"])
        return None

    def _synced():
        output = r1.vtysh_cmd("show isis mpls ldp-sync")
        if output.count("State: Sync achieved") != 2:
            return "r1 ldp-sync: {}".format(output)
        return None

    step("mpls ldp-sync with IPv6 LDP sessions: sync achieved, normal metrics")
    for router in tgen.routers().values():
        _config(router, "router isis TEST", "mpls ldp-sync")
    _expect(_synced)
    _expect(_metric, False)

    step("IPv4-only LDP: no session over the links, so the maximum metric")
    for router in tgen.routers().values():
        _config(router, "mpls ldp", "no address-family ipv6")
    _expect(_metric, True)
    _expect(_check_ping, r1, lo4("r3"), count=10)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
