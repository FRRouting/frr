#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test that the MPLS-TE local interface address sub-TLVs follow the
addresses of the interface, including when an address is removed.

    +----+  10.0.12.0/24, 2001:db8:12::/64  +----+
    | r1 |----------------------------------| r2 |
    +----+                                  +----+
"""

import functools
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    for router in ("r1", "r2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _check_local_addrs(router, ipv4, ipv6):
    """The local interface addresses that router's LSP advertises, as seen by
    r2, are exactly ipv4 and ipv6 (None for neither)."""
    lsp = (
        get_topogen()
        .gears["r2"]
        .vtysh_cmd("show isis database detail {}.00-00".format(router.name))
    )
    # The link to r2 must be advertised, so that a missing LSP or link cannot
    # pass for withdrawn addresses.
    if not re.search(r"Extended Reachability: (?:r2|0000\.0000\.0002)\.00", lsp):
        return "{}'s LSP has no link to r2: {}".format(router.name, lsp)
    found = (
        re.findall(r"Local Interface IP Address\(es\): (\S+)", lsp),
        re.findall(r"Local Interface IPv6 Address\(es\): (\S+)", lsp),
    )
    expected = ([ipv4] if ipv4 else [], [ipv6] if ipv6 else [])
    if found != expected:
        return "{} advertises local addresses {}, expected {}".format(
            router.name, found, expected
        )
    return None


def _expect(router, ipv4, ipv6):
    test_func = functools.partial(_check_local_addrs, router, ipv4, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_address_changes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("r1 advertises its configured addresses")
    _expect(r1, "10.0.12.1", "2001:db8:12::1")

    step("Renumber r1-eth0: the new addresses replace the old ones")
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth0\n"
        "ip address 10.0.13.1/24\n"
        "ipv6 address 2001:db8:13::1/64\n"
        "no ip address 10.0.12.1/24\n"
        "no ipv6 address 2001:db8:12::1/64"
    )
    _expect(r1, "10.0.13.1", "2001:db8:13::1")

    step("Remove the remaining addresses: no local address is advertised")
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth0\n"
        "no ip address 10.0.13.1/24\n"
        "no ipv6 address 2001:db8:13::1/64"
    )
    _expect(r1, None, None)

    step("Add an address back")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nip address 10.0.12.1/24")
    _expect(r1, "10.0.12.1", None)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
