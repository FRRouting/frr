#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Same local IPv4 address with different prefix lengths on one interface.

1. zebra has 192.0.2.1/28 configured. Outside of zebra, the address is
   flushed and replaced with 192.0.2.1/27 while the link is down. When
   the link comes back up, zebra must not put the stale /28 back.
   "no ip address 192.0.2.1/28" must then leave the kernel /27 alone.
2. zebra has 198.51.100.1/27 and 198.51.100.1/28 configured.
   "no ip address 198.51.100.1/28" must delete the /28, not the /27.
3. A configured IPv6 link-local address is restored after a link
   down/up (regression check for the IPv4/IPv6 wakeup on link-up).
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    step,
    create_address_on_interface,
    flush_addresses_on_interface,
    get_addresses_on_interface,
    shutdown_bringup_interface_in_kernel,
)


def setup_module(mod):
    topodef = {"s1": ("r1",), "s2": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _kernel_v4(router, ifname):
    return get_addresses_on_interface(get_topogen(), router.name, ifname, "ipv4")


def _zebra_v4(router, ifname):
    output = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
    return sorted(
        a["address"]
        for a in output.get(ifname, {}).get("ipAddresses", [])
        if "." in a["address"]
    )


def _expect_v4(router, ifname, expected):
    def _check():
        kernel = _kernel_v4(router, ifname)
        zebra = _zebra_v4(router, ifname)
        if kernel == expected and zebra == expected:
            return None
        return "kernel {} zebra {}, expected {}".format(kernel, zebra, expected)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    return result


def _link_ups(router, ifname):
    output = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
    return output[ifname]["linkUps"]


def _has_ll(router, ifname):
    addrs = get_addresses_on_interface(get_topogen(), router.name, ifname, "ipv6")
    return None if "fe80::1/64" in addrs else addrs


def test_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    result = _expect_v4(r1, "r1-eth0", ["192.0.2.1/28"])
    assert result is None, result
    result = _expect_v4(r1, "r1-eth1", ["198.51.100.1/27", "198.51.100.1/28"])
    assert result is None, result


def test_no_readd_of_stale_mask_on_link_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Replace 192.0.2.1/28 with 192.0.2.1/27 outside of zebra, link down")
    flush_addresses_on_interface(tgen, "r1", "r1-eth0")
    shutdown_bringup_interface_in_kernel(tgen, "r1", "r1-eth0", False)
    create_address_on_interface(tgen, "r1", "r1-eth0", "192.0.2.1/27")
    result = _expect_v4(r1, "r1-eth0", ["192.0.2.1/27"])
    assert result is None, result

    step("Link up: zebra must not re-add the stale 192.0.2.1/28")
    link_ups = _link_ups(r1, "r1-eth0")
    shutdown_bringup_interface_in_kernel(tgen, "r1", "r1-eth0", True)

    # Wait until zebra has handled the link-up and the addresses it
    # installs on link-up are in the kernel, so that the check below
    # cannot pass before zebra had the chance to re-add the /28.
    def _link_up_done():
        if _link_ups(r1, "r1-eth0") <= link_ups:
            return "zebra has not seen the link-up yet"
        return _has_ll(r1, "r1-eth0")

    _, result = topotest.run_and_expect(_link_up_done, None, count=30, wait=1)
    assert result is None, "link-up not handled: {}".format(result)
    result = _expect_v4(r1, "r1-eth0", ["192.0.2.1/27"])
    assert result is None, "after link up: {}".format(result)

    step("Remove the stale /28 from the config, the /27 must stay")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nno ip address 192.0.2.1/28\n")
    result = _expect_v4(r1, "r1-eth0", ["192.0.2.1/27"])
    assert result is None, "after no ip address: {}".format(result)


def test_delete_exact_prefix():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("no ip address 198.51.100.1/28 must keep 198.51.100.1/27")
    r1.vtysh_cmd(
        "configure terminal\ninterface r1-eth1\nno ip address 198.51.100.1/28\n"
    )
    result = _expect_v4(r1, "r1-eth1", ["198.51.100.1/27"])
    assert result is None, result


def test_ipv6_link_local_restored_on_link_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _has_ll_r1():
        return _has_ll(r1, "r1-eth0")

    _, result = topotest.run_and_expect(_has_ll_r1, None, count=30, wait=1)
    assert result is None, "fe80::1/64 missing initially"

    step("Link down/up, zebra must restore fe80::1/64")
    shutdown_bringup_interface_in_kernel(tgen, "r1", "r1-eth0", False)
    shutdown_bringup_interface_in_kernel(tgen, "r1", "r1-eth0", True)
    _, result = topotest.run_and_expect(_has_ll_r1, None, count=30, wait=1)
    assert result is None, "fe80::1/64 not restored after link up"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
