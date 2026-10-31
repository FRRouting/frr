#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_ipv6_linklocal_nexthop.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Nvidia, Inc.
# Sougata Barik
#

"""
test_static_ipv6_linklocal_nexthop.py:

An IPv6 link-local address is only meaningful together with the link it
belongs to (RFC 4007).  Every IPv6 interface owns a connected fe80::/64, so
a link-local nexthop without an interface cannot be resolved through the
RIB: doing so picks whichever fe80::/64 happens to be selected and installs
the route via an arbitrary interface, black-holing the traffic.  The kernel
rejects such a route ("Egress device not specified").

Verify that:
  - staticd rejects an IPv6 static route with a link-local gateway and no
    interface.
  - the same route with an interface is installed via that interface and
    forwards traffic.
  - zebra does not resolve a link-local nexthop without an interface that
    is received from a client (sharpd), and keeps the route inactive.

Topology:

          r1-eth0     s1     r2-eth0
    r1 ------------------------------ r2   (fe80::2, lo 2001:db8:5c1::1)
    |  fe80::1
    |  r1-eth1        s2     r3-eth0
    +-------------------------------- r3   (decoy link)

r1 lo: 2001:db8:ffff::1/128
"""

import os
import sys
import functools
import pytest

pytestmark = [pytest.mark.staticd, pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

LL_ERR = "Interface has to be specified for a link-local nexthop"
STATIC_PREFIX = "2001:db8:5c1::/48"
SHARP_PREFIX = "2001:db8:5c2::/128"


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    link_locals = {
        "r1": ("r1-eth0", "fe80::1/64"),
        "r2": ("r2-eth0", "fe80::2/64"),
        "r3": ("r3-eth0", "fe80::3/64"),
    }
    for rname, (ifname, addr) in link_locals.items():
        tgen.gears[rname].cmd_raises(
            "ip -6 addr add {} dev {} nodad".format(addr, ifname)
        )

    daemons = ["zebra", "staticd"]
    for rname, router in tgen.routers().items():
        if rname == "r1":
            router.load_frr_config(daemons=daemons + ["sharpd"])
        else:
            router.load_frr_config(daemons=daemons)

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_json(router, prefix):
    output = router.vtysh_cmd("show ipv6 route {} json".format(prefix), isjson=True)
    return output.get(prefix, [])


def _check_route_via(router, prefix, protocol, gateway, ifname):
    for entry in _route_json(router, prefix):
        if entry.get("protocol") != protocol:
            continue
        if not entry.get("selected") or not entry.get("installed"):
            return "{} route {} not selected/installed: {}".format(
                protocol, prefix, entry
            )
        for nh in entry.get("nexthops", []):
            if (
                nh.get("ip") == gateway
                and nh.get("interfaceName") == ifname
                and nh.get("active")
            ):
                return None
        return "{} route {} not active via {} {}: {}".format(
            protocol, prefix, gateway, ifname, entry
        )
    return "{} route {} not found".format(protocol, prefix)


def _check_route_inactive(router, prefix, protocol, gateway):
    for entry in _route_json(router, prefix):
        if entry.get("protocol") != protocol:
            continue
        if entry.get("selected") or entry.get("installed"):
            return "{} route {} must not be selected/installed: {}".format(
                protocol, prefix, entry
            )
        for nh in entry.get("nexthops", []):
            if nh.get("ip") == gateway and nh.get("active"):
                return "{} nexthop {} must not be active: {}".format(
                    protocol, gateway, entry
                )
        return None
    return "{} route {} not found".format(protocol, prefix)


def test_static_ll_nexthop_without_interface_rejected():
    "staticd must reject a link-local gateway without an interface."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure {} via fe80::2 without an interface".format(STATIC_PREFIX))
    output = r1.vtysh_cmd(
        "configure terminal\nipv6 route {} fe80::2\n".format(STATIC_PREFIX)
    )
    logger.info("vtysh output: %s", output)
    assert LL_ERR in output, "expected '{}' in output, got: {}".format(LL_ERR, output)

    step("Verify the route is neither in the running config nor in the RIB")
    running = r1.vtysh_cmd("show running-config")
    assert "ipv6 route {} fe80::2\n".format(STATIC_PREFIX) not in running
    assert _route_json(r1, STATIC_PREFIX) == []

    output = r1.cmd("ip -6 route show {}".format(STATIC_PREFIX)).strip()
    assert output == "", "unexpected kernel route: {}".format(output)


def test_static_ll_nexthop_with_interface():
    "A link-local gateway with an interface is installed via that interface."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure {} via fe80::2 r1-eth0".format(STATIC_PREFIX))
    output = r1.vtysh_cmd(
        "configure terminal\nipv6 route {} fe80::2 r1-eth0\n".format(STATIC_PREFIX)
    )
    assert LL_ERR not in output, output

    test_func = functools.partial(
        _check_route_via, r1, STATIC_PREFIX, "static", "fe80::2", "r1-eth0"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    output = r1.cmd("ip -6 route show {}".format(STATIC_PREFIX))
    assert "via fe80::2 dev r1-eth0" in output, output

    step("Verify traffic is forwarded to r2")
    output = r1.cmd("ping -6 -c 3 -W 1 -I 2001:db8:ffff::1 2001:db8:5c1::1")
    assert " 0% packet loss" in output, output

    r1.vtysh_cmd(
        "configure terminal\nno ipv6 route {} fe80::2 r1-eth0\n".format(STATIC_PREFIX)
    )


def test_zebra_ll_nexthop_without_interface_not_resolved():
    "zebra must not resolve a client link-local nexthop without an interface."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Install {} from sharpd via fe80::2 without an interface".format(SHARP_PREFIX))
    r1.vtysh_cmd("sharp install routes 2001:db8:5c2:: nexthop fe80::2 1")

    test_func = functools.partial(
        _check_route_inactive, r1, SHARP_PREFIX, "sharp", "fe80::2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    output = r1.cmd("ip -6 route show {}".format(SHARP_PREFIX)).strip()
    assert output == "", "unexpected kernel route: {}".format(output)

    r1.vtysh_cmd("sharp remove routes 2001:db8:5c2:: 1")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
