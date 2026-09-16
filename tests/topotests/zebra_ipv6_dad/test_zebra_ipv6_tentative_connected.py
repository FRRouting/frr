#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nvidia Inc.
#                       Donald Sharp
#

"""
Zebra must not install a connected/local IPv6 route while the kernel
address is still tentative (DAD in progress).

Linux keeps an address tentative on a down interface because DAD cannot
run.  Zebra records that address, then on if_up installs connected
routes without re-checking tentative.  Stretch DAD with dad_transmits=60
so the mismatch is visible after the link comes up.
"""

import json
import os
import sys
import pytest
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

IFNAME = "dad0"
PEER = "dad1"
ADDR = "2001:db8:1111::1"
PREFIX = "2001:db8:1111::/64"
HOST = "2001:db8:1111::1/128"


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_config(TopoRouter.RD_ZEBRA, "/dev/null")

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _kernel_addr_info(router):
    output = json.loads(router.run("ip -6 -j addr show dev {}".format(IFNAME)))
    if not output:
        return None
    for info in output[0].get("addr_info", []):
        if info.get("local") == ADDR and info.get("prefixlen") == 64:
            return info
    return None


def _kernel_addr_flag(info, name):
    # iproute2 reports address flags either as top level booleans
    # ("tentative": true) or as a "flags" list, depending on version.
    if info.get(name) is True:
        return True
    return name in info.get("flags", [])


def _kernel_addr_tentative(router):
    info = _kernel_addr_info(router)
    if info is None:
        return "{} {}/64 not present in kernel".format(IFNAME, ADDR)
    if _kernel_addr_flag(info, "tentative"):
        return None
    return "{} {}/64 is not tentative (addr_info={})".format(IFNAME, ADDR, info)


def _connected_route_present(router):
    """Is PREFIX present on IFNAME in 'show ipv6 route connected json'?"""
    routes = json.loads(router.vtysh_cmd("show ipv6 route connected json"))
    for entry in routes.get(PREFIX, []):
        for nexthop in entry.get("nexthops", []):
            if nexthop.get("interfaceName") == IFNAME:
                return True
    return False


def _zebra_has_connected_or_local(router):
    try:
        routes = json.loads(router.vtysh_cmd("show ipv6 route json"))
    except (json.JSONDecodeError, TypeError) as err:
        return "failed to parse ipv6 routes: {}".format(err)

    found = []
    for prefix, proto in ((PREFIX, "connected"), (HOST, "local")):
        for entry in routes.get(prefix, []):
            if entry.get("protocol") == proto:
                found.append("{} ({})".format(prefix, proto))
                break
    return found


def test_zebra_ipv6_tentative_not_in_rib():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Create a veth pair so DAD actually runs (dummy is NOARP and skips DAD)")
    r1.run("ip link del {} >/dev/null 2>&1 || true".format(IFNAME))
    r1.run("ip link add {} type veth peer name {}".format(IFNAME, PEER))
    r1.run("ip link set {} up".format(PEER))
    r1.run("ip link set {} down".format(IFNAME))

    step("Stretch DAD to 60 NS transmissions (~60s)")
    r1.run("echo 1 > /proc/sys/net/ipv6/conf/{}/accept_dad".format(IFNAME))
    r1.run("echo 60 > /proc/sys/net/ipv6/conf/{}/dad_transmits".format(IFNAME))

    step("Add the IPv6 address while the interface is down")
    r1.run("ip -6 addr add {}/64 dev {}".format(ADDR, IFNAME))

    def _down_iface_and_tentative():
        try:
            ifaces = json.loads(r1.vtysh_cmd("show interface {} json".format(IFNAME)))
        except (json.JSONDecodeError, TypeError) as err:
            return "failed to parse show interface: {}".format(err)
        if IFNAME not in ifaces:
            return "{} not in zebra yet".format(IFNAME)
        err = _kernel_addr_tentative(r1)
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        _down_iface_and_tentative, None, count=20, wait=1
    )
    assert result is None, result

    step("While down, zebra must not install connected/local into the RIB")
    found = _zebra_has_connected_or_local(r1)
    assert (
        not found
    ), "Zebra already has {} in the RIB while {} is down and the address is tentative".format(
        found, IFNAME
    )

    step("Bring the interface up; kernel DAD is still in progress")
    r1.run("ip link set {} up".format(IFNAME))

    def _iface_operative():
        try:
            ifaces = json.loads(r1.vtysh_cmd("show interface {} json".format(IFNAME)))
        except (json.JSONDecodeError, TypeError) as err:
            return "failed to parse show interface: {}".format(err)
        iface = ifaces.get(IFNAME)
        if not iface:
            return "{} missing from zebra".format(IFNAME)
        if iface.get("operationalStatus") != "up":
            return "{} operationalStatus={} (waiting for up)".format(
                IFNAME, iface.get("operationalStatus")
            )
        return None

    _, result = topotest.run_and_expect(_iface_operative, None, count=20, wait=1)
    assert result is None, result

    err = _kernel_addr_tentative(r1)
    assert (
        err is None
    ), "Expected kernel address to still be tentative after if_up: {}".format(err)

    step("Zebra must not have connected/local routes while the address is tentative")
    found = _zebra_has_connected_or_local(r1)
    logger.info("kernel addr: %s", r1.run("ip -6 addr show dev {}".format(IFNAME)))
    logger.info("zebra ipv6 route json: %s", r1.vtysh_cmd("show ipv6 route json"))
    assert not found, (
        "Zebra installed {} for a tentative IPv6 address on {} "
        "(kernel DAD still in progress)".format(found, IFNAME)
    )

    step("'show ipv6 route connected' must not show the prefix while it is tentative")
    # Hold the invariant for a while: the interface is operative now, so a
    # missing tentative re-check shows up as the connected route appearing.
    for _ in range(10):
        err = _kernel_addr_tentative(r1)
        assert err is None, "DAD finished sooner than expected: {}".format(err)
        assert not _connected_route_present(r1), (
            "Zebra installed connected {} on {} while the kernel address is "
            "still tentative".format(PREFIX, IFNAME)
        )
        sleep(1)

    step("Once DAD completes the tentative flag drops and the route is installed")

    def _dad_done_and_route_installed():
        info = _kernel_addr_info(r1)
        if info is None:
            return "{} {}/64 disappeared from the kernel".format(IFNAME, ADDR)
        if _kernel_addr_flag(info, "dadfailed"):
            return "{} {}/64 failed DAD (addr_info={})".format(IFNAME, ADDR, info)
        if _kernel_addr_flag(info, "tentative"):
            return "{} {}/64 still tentative".format(IFNAME, ADDR)
        if not _connected_route_present(r1):
            return "connected {} not installed on {} after DAD completed".format(
                PREFIX, IFNAME
            )
        return None

    # dad_transmits=60 with the default 1s RetransTimer, so DAD needs ~60s.
    _, result = topotest.run_and_expect(
        _dad_done_and_route_installed, None, count=120, wait=1
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
