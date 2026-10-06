#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test IS-IS IPv4 routing over IPv6 link-local nexthops (ipv4-over-ipv6-nexthop).

            s1 p2p, no IPv4
       +----------------------+
       |                      |
     +----+  s4 p2p, IPv4   +----+
     | r1 |-----------------| r2 |
     +----+ 10.0.14.0/24    +----+
       |                      |
       | s3 p2p, no IPv4      | s2 LAN, no IPv4
       |                      |
     +----+-------------------+------+----+  s5 p2p, no IPv4  +----+
     | r3 |                          | r4 |-------------------| r5 |
     +----+                          +----+                   +----+

Every router has an IPv4 /32 and an IPv6 /128 on its loopback; the only IPv4
link is s4. IPv4 is routed over the other links through the neighbors' IPv6
link-local addresses, while s4 keeps its IPv4 nexthop.
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
from lib.common_config import (
    kill_router_daemons,
    required_linux_kernel_version,
    start_router_daemons,
    step,
)
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd, pytest.mark.isisd]

ROUTERS = ("r1", "r2", "r3", "r4", "r5")


def lo4(router):
    return "10.255.0.{}".format(router[1:])


def host4(router):
    return "{}/32".format(lo4(router))


def host6(router):
    return "2001:db8::{}/128".format(router[1:])


def build_topo(tgen):
    for router in ROUTERS:
        tgen.add_router(router)

    # The link order fixes the interface names used throughout.
    for switch, members in (
        ("s1", ("r1", "r2")),
        ("s4", ("r1", "r2")),
        ("s3", ("r1", "r3")),
        ("s2", ("r2", "r3", "r4")),
        ("s5", ("r4", "r5")),
    ):
        sw = tgen.add_switch(switch)
        for member in members:
            sw.add_link(tgen.gears[member])


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


def _isis_route(router, prefix):
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    for route in routes.get(prefix, []):
        if route.get("protocol") == "isis" and route.get("installed"):
            return route
    return None


def _nexthops(router, prefix):
    """The route's active nexthops as {(interface, "v4"|"ll")}, or an error string."""
    route = _isis_route(router, prefix)
    if route is None:
        return "{}: no installed IS-IS route on {}".format(prefix, router.name)
    found = set()
    for nexthop in route.get("nexthops", []):
        if not nexthop.get("active"):
            continue
        address = nexthop.get("ip", "")
        if address.startswith("fe80:"):
            kind = "ll"
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
            kind = "v4"
        else:
            return "{}: unexpected nexthop {}".format(prefix, nexthop)
        found.add((nexthop.get("interfaceName"), kind))
    return found


def _check_nexthops(router, prefix, expected):
    found = _nexthops(router, prefix)
    if isinstance(found, str):
        return found
    if found != set(expected):
        return "{} on {}: nexthops {} != expected {}".format(
            prefix, router.name, sorted(found), sorted(expected)
        )
    return None


def _check_no_route(router, prefix):
    if _isis_route(router, prefix) is not None:
        return "{} on {}: unexpected IS-IS route".format(prefix, router.name)
    return None


def _check_route6(router, prefix):
    routes = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(prefix)))
    if not any(r.get("protocol") == "isis" for r in routes.get(prefix, [])):
        return "{} on {}: no IS-IS IPv6 route".format(prefix, router.name)
    return None


def _kernel_gateways(router, prefix):
    """The kernel route's gateways as a sorted list of 'inet6 fe80' / 'inet'."""
    out = router.run("ip -4 route show {}".format(prefix.split("/")[0]))
    if not out.strip():
        return "{} on {}: no kernel route".format(prefix, router.name)
    kinds = sorted(re.findall(r"via (inet6 fe80|\d+\.\d+\.\d+\.\d+)", out))
    return ["inet6" if k.startswith("inet6") else "inet" for k in kinds]


def _check_kernel(router, prefix, expected):
    kinds = _kernel_gateways(router, prefix)
    if isinstance(kinds, str):
        return kinds
    if kinds != sorted(expected):
        return "{} on {}: kernel gateways {} != {}: {}".format(
            prefix,
            router.name,
            kinds,
            sorted(expected),
            router.run("ip -4 route show {}".format(prefix.split("/")[0])),
        )
    return None


def _ping(src, dst):
    output = src.run("ping -c 3 -i 0.2 -W 1 -I {} {}".format(lo4(src.name), lo4(dst)))
    return " 0% packet loss" in output, output


def _check_ping(src, dst):
    ok, output = _ping(src, dst)
    return None if ok else "ping {} -> {} failed: {}".format(src.name, dst, output)


def _config(router, *lines):
    router.vtysh_cmd("configure terminal\n" + "\n".join(lines))


def _steady_state(tgen):
    r1, r2, r3, r4, r5 = (tgen.gears[r] for r in ROUTERS)

    step("Mixed-family ECMP: r2 via the IPv4 link and the link-local link")
    _expect(_check_nexthops, r1, host4("r2"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_nexthops, r2, host4("r1"), {("r2-eth0", "ll"), ("r2-eth1", "v4")})

    step("Link-local only paths: p2p and across the LAN")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})
    _expect(
        _check_nexthops,
        r1,
        host4("r4"),
        {("r1-eth0", "ll"), ("r1-eth1", "v4"), ("r1-eth2", "ll")},
    )
    _expect(_check_nexthops, r4, host4("r1"), {("r4-eth0", "ll")})
    _expect(_check_nexthops, r5, host4("r1"), {("r5-eth0", "ll")})
    _expect(_check_nexthops, r2, host4("r5"), {("r2-eth2", "ll")})

    step("The kernel holds the same nexthops, IPv6 gateways as RTA_VIA")
    _expect(_check_kernel, r1, host4("r2"), ["inet", "inet6"])
    _expect(_check_kernel, r1, host4("r4"), ["inet", "inet6", "inet6"])
    _expect(_check_kernel, r5, host4("r1"), ["inet6"])

    step("IPv4 traffic crosses p2p, LAN and mixed ECMP hops")
    _expect(_check_ping, r1, "r5", count=10)
    _expect(_check_ping, r5, "r2", count=10)
    _expect(_check_ping, r3, "r1", count=10)


def test_steady_state():
    tgen = _skip_on_failure()
    _steady_state(tgen)


def test_ttl_expiry():
    """IPv4 arriving on an interface without IPv4 still gets Time Exceeded."""
    tgen = _skip_on_failure()
    r5 = tgen.gears["r5"]

    step("Each hop from r5 towards r1 answers from its only IPv4, its loopback")
    for ttl, hop in ((1, "r4"), (2, None)):
        output = r5.run(
            "ping -n -c 1 -W 1 -t {} -I {} {} || true".format(ttl, lo4("r5"), lo4("r1"))
        )
        match = re.search(r"From (\S+) icmp_seq=\d+ Time to live exceeded", output)
        assert match, output
        if hop:
            assert match.group(1) == lo4(hop), output
        else:
            assert match.group(1) in (lo4("r2"), lo4("r3")), output


def test_strict_rp_filter():
    """Strict reverse-path filtering accepts traffic over link-local nexthops."""
    tgen = _skip_on_failure()

    step("Enable rp_filter=1 everywhere")
    for router in tgen.routers().values():
        router.run(
            "sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"
        )
        router.run("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $f; done")

    try:
        _expect(_check_ping, tgen.gears["r1"], "r5", count=10)
        _expect(_check_ping, tgen.gears["r5"], "r3", count=10)
    finally:
        for router in tgen.routers().values():
            router.run(
                "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done"
            )


def test_address_changes():
    """Adding IPv4 to a link switches it to IPv4 nexthops; removing it switches back."""
    tgen = _skip_on_failure()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("IPv4 on r1's end of s1 only: still link-local in both directions")
    r1.run("ip addr add 10.0.12.1/24 dev r1-eth0")
    _expect(_check_nexthops, r1, host4("r2"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_nexthops, r2, host4("r1"), {("r2-eth0", "ll"), ("r2-eth1", "v4")})

    step("IPv4 on both ends of s1: native IPv4 nexthops")
    r2.run("ip addr add 10.0.12.2/24 dev r2-eth0")
    _expect(_check_nexthops, r1, host4("r2"), {("r1-eth0", "v4"), ("r1-eth1", "v4")})
    _expect(_check_nexthops, r2, host4("r1"), {("r2-eth0", "v4"), ("r2-eth1", "v4")})
    _expect(_check_kernel, r1, host4("r2"), ["inet", "inet"])

    step("Remove both addresses: back to link-local")
    r1.run("ip addr del 10.0.12.1/24 dev r1-eth0")
    r2.run("ip addr del 10.0.12.2/24 dev r2-eth0")
    _expect(_check_nexthops, r1, host4("r2"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_nexthops, r2, host4("r1"), {("r2-eth0", "ll"), ("r2-eth1", "v4")})
    _expect(_check_kernel, r1, host4("r2"), ["inet", "inet6"])
    _expect(_check_ping, r1, "r2", count=10)


def test_link_down_up():
    """Losing a link-local-only link reroutes IPv4; restoring it brings it back."""
    tgen = _skip_on_failure()
    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    step("Shut s3 (r1-r3): r3 is reached through r2 and the LAN")
    r1.run("ip link set r1-eth2 down")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_nexthops, r3, host4("r1"), {("r3-eth1", "ll")})
    _expect(_check_kernel, r1, host4("r3"), ["inet", "inet6"])
    _expect(_check_ping, r1, "r3", count=10)

    step("Restore s3")
    r1.run("ip link set r1-eth2 up")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})
    _expect(_check_ping, r1, "r3", count=10)


def test_link_local_change():
    """A neighbor's link-local address changing on a live adjacency moves the nexthop."""
    tgen = _skip_on_failure()
    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    old_ll = re.search(
        r"inet6 (fe80::\S+)/64", r3.run("ip -6 addr show dev r3-eth0 scope link")
    )
    assert old_ll, r3.run("ip -6 addr show dev r3-eth0")
    new_ll = "fe80::3:99"

    step("Replace r3-eth0's link-local address without taking the link down")
    r3.run("ip -6 addr add {}/64 dev r3-eth0 nodad".format(new_ll))
    r3.run("ip -6 addr del {}/64 dev r3-eth0".format(old_ll.group(1)))

    def _uses_new_ll():
        out = r1.run("ip -4 route show {}".format(lo4("r3")))
        if "via inet6 {} ".format(new_ll) not in out:
            return "kernel route does not use {}: {}".format(new_ll, out)
        return None

    _expect(_uses_new_ll)
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})
    _expect(_check_ping, r1, "r3", count=10)


def test_ipv6_removed_from_link():
    """Without IPv6 on a link there is no link-local nexthop, so no IPv4 either."""
    tgen = _skip_on_failure()
    r1 = tgen.gears["r1"]

    step("no ipv6 router isis on r1-eth2: IPv4 to r3 moves off s3")
    _config(r1, "interface r1-eth2", "no ipv6 router isis TEST")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_ping, r1, "r3", count=10)

    step("Restore it")
    _config(r1, "interface r1-eth2", "ipv6 router isis TEST")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})

    step("Disable IPv6 on r1-eth2 altogether: the link-local address goes away")
    r1.run("sysctl -qw net.ipv6.conf.r1-eth2.disable_ipv6=1")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth0", "ll"), ("r1-eth1", "v4")})
    _expect(_check_ping, r1, "r3", count=10)

    step("Re-enable IPv6: the link-local nexthop returns")
    r1.run("sysctl -qw net.ipv6.conf.r1-eth2.disable_ipv6=0")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")}, count=120)
    _expect(_check_ping, r1, "r3", count=10)


def test_bfd():
    """BFD over link-local tears down the adjacency, and its IPv4 routes, fast."""
    tgen = _skip_on_failure()
    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    step("Enable BFD on s3 and slow the hellos so that only BFD detects fast")
    for router, intf in ((r1, "r1-eth2"), (r3, "r3-eth0")):
        _config(router, "interface " + intf, "isis bfd", "isis hello-multiplier 30")

    def _bfd_up():
        peers = json.loads(r1.vtysh_cmd("show bfd peers json"))
        if not any(p.get("status") == "up" for p in peers):
            return "no BFD session up: {}".format(peers)
        return None

    _expect(_bfd_up)
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})

    step("Silence s3 (carrier stays up): BFD, not the 30s hold, moves IPv4")
    r1.run("modprobe sch_netem || true")
    silence = "tc qdisc {} dev {} root netem loss 100%"
    for router, intf in ((r1, "r1-eth2"), (r3, "r3-eth0")):
        router.run(silence.format("add", intf) + " || true")
        if "netem" not in router.run("tc qdisc show dev {}".format(intf)):
            for router_, intf_ in ((r1, "r1-eth2"), (r3, "r3-eth0")):
                router_.run(silence.format("del", intf_) + " 2>/dev/null || true")
                _config(
                    router_,
                    "interface " + intf_,
                    "no isis bfd",
                    "no isis hello-multiplier",
                )
            pytest.skip("sch_netem is not available")
    try:
        _expect(
            _check_nexthops,
            r1,
            host4("r3"),
            {("r1-eth0", "ll"), ("r1-eth1", "v4")},
            count=20,
        )
    finally:
        for router, intf in ((r1, "r1-eth2"), (r3, "r3-eth0")):
            router.run(silence.format("del", intf))

    step("Restore BFD: the s3 path comes back")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")}, count=120)
    for router, intf in ((r1, "r1-eth2"), (r3, "r3-eth0")):
        _config(router, "interface " + intf, "no isis bfd", "no isis hello-multiplier")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")})


def test_lfa():
    """When an adjacency is lost while the interface stays up, IPv4 routes on
    link-local nexthops switch to their LFA backups without waiting for SPF."""
    tgen = _skip_on_failure()
    r1, r3, r5 = (tgen.gears[r] for r in ("r1", "r3", "r5"))

    step("Enable LFA on r1-eth2")
    _config(r1, "interface r1-eth2", "isis fast-reroute lfa")

    def _has_backup():
        route = _isis_route(r1, host4("r3"))
        if route is None or not route.get("backupNexthops"):
            return "no backup nexthops for r3: {}".format(route)
        return None

    _expect(_has_backup)

    step("Let r1 run SPF for a change at r5, then hold SPF back for 60s")
    _config(r5, "interface lo", "ip address 10.255.5.5/32")
    _expect(
        _check_nexthops,
        r1,
        "10.255.5.5/32",
        {("r1-eth0", "ll"), ("r1-eth1", "v4"), ("r1-eth2", "ll")},
    )
    _config(r1, "router isis TEST", "spf-interval 60")

    # r1-eth2 stays up, so zebra sees no failure: only isisd's fast-reroute
    # switchover on adjacency loss (10s hold) can move IPv4 before SPF runs.
    step("Take r3's end of s3 down: IPv4 to r3 moves when the adjacency expires")
    r3.run("ip link set r3-eth0 down")
    try:
        _expect(
            _check_nexthops,
            r1,
            host4("r3"),
            {("r1-eth0", "ll"), ("r1-eth1", "v4")},
            count=30,
        )
    finally:
        r3.run("ip link set r3-eth0 up")
        _config(r5, "interface lo", "no ip address 10.255.5.5/32")
        _config(r1, "router isis TEST", "spf-interval 1")
        _config(r1, "interface r1-eth2", "no isis fast-reroute lfa")
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth2", "ll")}, count=120)
    _expect(_check_ping, r1, "r3", count=10)


def test_isisd_restart():
    """A restarted isisd reinstalls the link-local IPv4 nexthops."""
    tgen = _skip_on_failure()

    step("Kill isisd on r2: its neighbors withdraw the paths through it")
    kill_router_daemons(tgen, "r2", ["isisd"])
    _expect(_check_nexthops, tgen.gears["r1"], host4("r4"), {("r1-eth2", "ll")})

    step("Start it again")
    start_router_daemons(tgen, "r2", ["isisd"])

    _steady_state(tgen)


def test_multi_topology():
    """The IPv4 topology forms over link-local only links with MT as well."""
    tgen = _skip_on_failure()

    step("Enable the IPv6 unicast topology everywhere")
    for router in tgen.routers().values():
        _config(router, "router isis TEST", "topology ipv6-unicast")
    _steady_state(tgen)
    _expect(_check_route6, tgen.gears["r1"], host6("r5"))


def test_mixed_neighbor():
    """A router without the option routes no IPv4 over link-local only links.

    Its neighbors cannot tell (nothing in IS-IS signals it), so they keep the
    link: every router computes on the same graph, which avoids loops."""
    tgen = _skip_on_failure()
    r1, r4, r5 = (tgen.gears[r] for r in ("r1", "r4", "r5"))

    step("no ipv4-over-ipv6-nexthop on r5, whose only link is link-local")
    _config(r5, "router isis TEST", "no ipv4-over-ipv6-nexthop")
    _expect(_check_no_route, r5, host4("r4"))
    _expect(_check_no_route, r5, host4("r1"))

    step("r4 and r1 still compute IPv4 paths to r5")
    _expect(_check_nexthops, r4, host4("r5"), {("r4-eth1", "ll")})
    _expect(
        _check_nexthops,
        r1,
        host4("r4"),
        {("r1-eth0", "ll"), ("r1-eth1", "v4"), ("r1-eth2", "ll")},
    )

    step("IPv6 to r5 is unaffected")
    _expect(_check_route6, r1, host6("r5"))

    step("Re-enable it on r5, then return to the standard topology")
    _config(r5, "router isis TEST", "ipv4-over-ipv6-nexthop")
    _steady_state(tgen)
    for router in tgen.routers().values():
        _config(router, "router isis TEST", "no topology ipv6-unicast")
    _steady_state(tgen)


def test_disable_enable():
    """Off, IPv4 uses only the IPv4 link; on again, the link-local links return."""
    tgen = _skip_on_failure()
    r1 = tgen.gears["r1"]

    step("no ipv4-over-ipv6-nexthop on r1: only s4 remains for IPv4")
    _config(r1, "router isis TEST", "no ipv4-over-ipv6-nexthop")
    assert "ipv4-over-ipv6-nexthop" not in r1.vtysh_cmd("show running-config")
    _expect(_check_nexthops, r1, host4("r2"), {("r1-eth1", "v4")})
    _expect(_check_nexthops, r1, host4("r3"), {("r1-eth1", "v4")})
    _expect(_check_route6, r1, host6("r3"))

    step("Re-enable it")
    _config(r1, "router isis TEST", "ipv4-over-ipv6-nexthop")
    assert " ipv4-over-ipv6-nexthop" in r1.vtysh_cmd("show running-config")
    _steady_state(tgen)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
