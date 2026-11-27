#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test IS-IS unnumbered interfaces and IPv4 over IPv6 link-local nexthops on
the same router.

     +----+  s1 p2p, IPv6 link-local only  +----+  s2 p2p, IPv4 only, no addresses  +----+
     | r2 |--------------------------------| r1 |-----------------------------------| r3 |
     +----+  isis ipv4-over-ipv6-nexthop   +----+  isis unnumbered                  +----+

No link has an IPv4 address. s1 routes IPv4 through the neighbors' IPv6
link-local addresses; s2 has no IPv6 at all, so r1 and r3 borrow their
loopback IPv4 addresses and install onlink nexthops. The two options cannot
be enabled on the same interface.
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

pytestmark = [pytest.mark.isisd]


def lo4(router):
    return "10.255.0.{}".format(router[1:])


def host4(router):
    return "{}/32".format(lo4(router))


def build_topo(tgen):
    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    # The link order fixes the interface names used throughout.
    for switch, members in (("s1", ("r1", "r2")), ("s2", ("r1", "r3"))):
        sw = tgen.add_switch(switch)
        for member in members:
            sw.add_link(tgen.gears[member])


def setup_module(mod):
    # IPv4 routes with IPv6 gateways (RTA_VIA) need Linux 5.2.
    if required_linux_kernel_version("5.2") is not True:
        pytest.skip("Linux kernel >= 5.2 is required")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # s2 carries no IPv6 at all, not even link-local addresses.
    for router, intf in (("r1", "r1-eth1"), ("r3", "r3-eth0")):
        tgen.gears[router].run(
            "sysctl -qw net.ipv6.conf.{}.disable_ipv6=1".format(intf)
        )

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _expect(func, *args, count=60, wait=0.5):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, result


def _check_nexthop(router, prefix, intf, kind):
    """The installed IS-IS route has one active nexthop on intf: "ll" for an
    IPv6 link-local gateway, or an IPv4 gateway address (installed onlink)."""
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    route = next(
        (
            r
            for r in routes.get(prefix, [])
            if r.get("protocol") == "isis" and r.get("installed")
        ),
        None,
    )
    if route is None:
        return "{}: no installed IS-IS route on {}".format(prefix, router.name)
    nexthops = [nh for nh in route.get("nexthops", []) if nh.get("active")]
    if len(nexthops) != 1 or nexthops[0].get("interfaceName") != intf:
        return "{} on {}: nexthops {}".format(prefix, router.name, nexthops)
    address = nexthops[0].get("ip", "")
    if kind == "ll" and not address.startswith("fe80:"):
        return "{} on {}: {} is not link-local".format(prefix, router.name, address)
    if kind != "ll" and address != kind:
        return "{} on {}: {} != {}".format(prefix, router.name, address, kind)

    kernel = router.run("ip -4 route show {}".format(prefix.split("/")[0]))
    if kind == "ll" and "via inet6 fe80:" not in kernel:
        return "{} on {}: kernel route {}".format(prefix, router.name, kernel)
    if kind != "ll" and not re.search(
        r"via {} .*onlink".format(re.escape(kind)), kernel
    ):
        return "{} on {}: kernel route {}".format(prefix, router.name, kernel)
    return None


def _check_ping(src, dst):
    output = src.run("ping -c 3 -i 0.2 -W 1 -I {} {}".format(lo4(src.name), lo4(dst)))
    if " 0% packet loss" not in output:
        return "ping {} -> {} failed: {}".format(src.name, dst, output)
    return None


def _config(router, *lines):
    router.vtysh_cmd("configure terminal\n" + "\n".join(lines))


def _link_local_on_s1(tgen):
    r1, r2, r3 = (tgen.gears[r] for r in ("r1", "r2", "r3"))

    step("s1: link-local nexthops, s2: borrowed loopback addresses, onlink")
    _expect(_check_nexthop, r1, host4("r2"), "r1-eth0", "ll")
    _expect(_check_nexthop, r2, host4("r1"), "r2-eth0", "ll")
    _expect(_check_nexthop, r1, host4("r3"), "r1-eth1", lo4("r3"))
    _expect(_check_nexthop, r3, host4("r1"), "r3-eth0", lo4("r1"))

    step("Transit traffic crosses both kinds of link")
    _expect(_check_nexthop, r2, host4("r3"), "r2-eth0", "ll")
    _expect(_check_nexthop, r3, host4("r2"), "r3-eth0", lo4("r1"))
    _expect(_check_ping, r2, "r3", count=10)
    _expect(_check_ping, r3, "r2", count=10)


def test_both_methods():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _link_local_on_s1(tgen)


def test_both_options_rejected():
    """An interface cannot route IPv4 over link-local nexthops and be
    unnumbered at the same time."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("isis unnumbered on r1-eth0, which has isis ipv4-over-ipv6-nexthop")
    output = r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nisis unnumbered")
    assert "Can't route IPv4 over IPv6 link-local nexthops" in output, output
    config = r1.vtysh_cmd("show running-config")
    block = re.search(r"^interface r1-eth0\n((?: .*\n)*)", config, re.M)
    assert block and "isis unnumbered" not in block.group(1), config

    step("The reverse is rejected too, on r1-eth1, which is unnumbered")
    output = r1.vtysh_cmd(
        "configure terminal\ninterface r1-eth1\nisis ipv4-over-ipv6-nexthop"
    )
    assert "Can't route IPv4 over IPv6 link-local nexthops" in output, output
    _link_local_on_s1(tgen)


def test_switch_to_unnumbered():
    """s1 switches from link-local nexthops to unnumbered and back."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("isis unnumbered instead of ipv4-over-ipv6-nexthop on both ends of s1")
    for router, intf in ((r1, "r1-eth0"), (r2, "r2-eth0")):
        _config(
            router,
            "interface " + intf,
            "no isis ipv4-over-ipv6-nexthop",
            "isis unnumbered",
        )
    _expect(_check_nexthop, r1, host4("r2"), "r1-eth0", lo4("r2"))
    _expect(_check_nexthop, r2, host4("r1"), "r2-eth0", lo4("r1"))
    _expect(_check_ping, r2, "r3", count=10)

    step("Back to link-local nexthops")
    for router, intf in ((r1, "r1-eth0"), (r2, "r2-eth0")):
        _config(
            router,
            "interface " + intf,
            "no isis unnumbered",
            "isis ipv4-over-ipv6-nexthop",
        )
    _link_local_on_s1(tgen)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
