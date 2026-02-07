#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_ipv6_ra_simple.py
#
# Copyright (c) 2026 by Nvidia Corporation
#                       Donald Sharp

"""
Test IPv6 RA default routes being properly handled by zebra.
Have an additional test that shows the old behavior still works
as well.

The topology is r1 ----- r2 ----- r3
Both r1 and r3 are sending the default route to
r2.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    sw1 = tgen.add_switch("s1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("s2")
    sw2.add_link(tgen.gears["r2"])
    sw2.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # R2 is a router, so accept RA explicitly on both links.
    topotest.sysctl_assure(tgen.net["r2"], "net.ipv6.conf.all.accept_ra", 2)
    topotest.sysctl_assure(tgen.net["r2"], "net.ipv6.conf.default.accept_ra", 2)
    topotest.sysctl_assure(tgen.net["r2"], "net.ipv6.conf.r2-eth0.accept_ra", 2)
    topotest.sysctl_assure(tgen.net["r2"], "net.ipv6.conf.r2-eth1.accept_ra", 2)

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _kernel_default_routes_present(router):
    out = router.cmd("ip -6 route show default")
    found = {"r2-eth0": False, "r2-eth1": False}
    for line in out.splitlines():
        if "default" not in line or "proto ra" not in line:
            continue
        for dev in found:
            if "dev {}".format(dev) in line:
                found[dev] = True
    return all(found.values())


def _vtysh_default_routes_present(router):
    out = router.vtysh_cmd("show ipv6 route")
    found = {"r2-eth0": False, "r2-eth1": False}
    for line in out.splitlines():
        if "::/0" not in line:
            continue
        for dev in found:
            if ", {}".format(dev) in line:
                found[dev] = True
    return all(found.values())


def _vtysh_default_table_route_ok(router):
    out = router.vtysh_cmd("show ipv6 route")
    want = "K>* 3::2/128 [0/1034] via fe80::202:ff:fe00:12, r2-eth1"
    return want in out


def _kernel_default_route_missing(router, dev):
    out = router.cmd("ip -6 route show default dev {}".format(dev))
    return out.strip() == ""


def _vtysh_default_route_missing(router, dev):
    out = router.vtysh_cmd("show ipv6 route")
    for line in out.splitlines():
        if "::/0" in line and ", {}".format(dev) in line:
            return False
    return True


def test_ipv6_ra_default_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = partial(_kernel_default_routes_present, r2)
    _, result = topotest.run_and_expect(test_func, True, count=40, wait=1)
    assert result is True, "Missing kernel RA default routes on r2"

    test_func = partial(_vtysh_default_routes_present, r2)
    _, result = topotest.run_and_expect(test_func, True, count=40, wait=1)
    assert result is True, "Missing vtysh default routes on r2"


def test_kernel_route_replace():
    tgen = get_topogen()
    # if tgen.routers_have_failure():
    #    pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.cmd_raises(
        "ip -6 route add 3::2/128 via fe80::202:ff:fe00:11 dev r2-eth0 "
        "proto ra metric 1034 hoplimit 64 pref high"
    )
    r2.cmd_raises(
        "ip -6 route replace 3::2/128 via fe80::202:ff:fe00:12 dev r2-eth1 "
        "proto ra metric 1034 hoplimit 64 pref high"
    )

    test_func = partial(_vtysh_default_table_route_ok, r2)
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert result is True, "FRR did not track route replacement in default table"


def test_stop_r3_ra_default_removed():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    r3.cmd_raises(
        'vtysh -c "conf t" -c "interface r3-eth0" -c "ipv6 nd suppress-ra" -c "exit" -c "exit"'
    )

    test_func = partial(_kernel_default_route_missing, r2, "r2-eth1")
    _, result = topotest.run_and_expect(test_func, True, count=40, wait=1)
    assert result is True, "Kernel default route via r2-eth1 not removed"

    test_func = partial(_vtysh_default_route_missing, r2, "r2-eth1")
    _, result = topotest.run_and_expect(test_func, True, count=40, wait=1)
    assert result is True, "Zebra default route via r2-eth1 not removed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
