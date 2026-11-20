#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_interface_neighbour_lifetime.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_babel_interface_neighbour_lifetime.py
==========================================

Regression for babeld keeping a dangling neigh->ifp after a real local
interface deletion.

When zebra reports an interface deletion (ZEBRA_INTERFACE_DELETE),
lib/if.c::if_destroy_via_zapi() runs the daemon's if_unreal hook and then
frees the struct interface unless it is retained in the configuration.
babeld's hook (babel_ifp_destroy) only reset the interface (routes,
sendbuf, multicast group); neighbours in the global `neighs` list were
left behind with their borrowed ifp pointer dangling.  Every later
consumer of neigh->ifp then reads freed memory, e.g. `show babel
neighbor` (show_babel_neighbour_sub reads neigh->ifp->name and calls
neighbour_rxcost()/if_up() on it).

The deletion must hit an interface that is NOT present in babeld's own
configuration: r1's babeld.conf enables babel with `network` statements
only and has no `interface r1-eth1` stanza, so ifp->configured stays
false and lib frees the struct.  A configured interface is retained and
the same event is harmless (covered by the link-down/up control, which
exercises the retained/down path without freeing).

Topology
--------

    r3 ---- sw1 ---- r1 ---- sw2 ---- r2

r1-eth1 (towards r2) is deleted with `ip link del` while a babel
neighbour and an installed route are bound to it.  r1-eth0 (towards r3)
carries the control neighbour and control route, which must survive.

Checks after the deletion:
  - `show babel neighbor` still works and lists only the r3 neighbour
    (on the unpatched build babeld is already dead here);
  - the route via r2 is gone, the route via r3 is still installed;
  - r3 still sees r1 as a neighbour (babeld keeps running and talking).
"""

import os
import re
import sys

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.babeld]

P_R2 = "10.99.1.1/32"  # loopback redistributed by r2, via r1-eth1
P_R3 = "10.99.3.1/32"  # loopback redistributed by r3, via r1-eth0
NEIGH_RE = re.compile(r"^Neighbour (\S+) dev (\S+) reach ([0-9a-f]{4})")


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(r1)
    sw1.add_link(r3)

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _neighbours(router):
    """Parse 'show babel neighbor' into [(addr, dev, reach), ...]."""
    out = router.vtysh_cmd("show babel neighbor")
    neighs = []
    for ln in out.splitlines():
        m = NEIGH_RE.match(ln.strip())
        if m:
            neighs.append((m.group(1), m.group(2), m.group(3)))
    return neighs


def _route_installed(router, pfx):
    out = router.vtysh_cmd("show babel route {}".format(pfx))
    return "installed" in out


def _babeld_alive(router):
    return bool(router.cmd("pgrep -x babeld").strip())


def _expect_neighbour(router, addr, dev, count=90, wait=1):
    def check():
        if not any(n[0] == addr and n[1] == dev for n in _neighbours(router)):
            return "neighbour {} on {} not present".format(addr, dev)
        return None

    _, result = topotest.run_and_expect(check, None, count=count, wait=wait)
    return result


def _expect_route(router, pfx, installed=True, count=60, wait=1):
    def check():
        got = _route_installed(router, pfx)
        if got != installed:
            return "route {} installed={} (expected {})".format(pfx, got, installed)
        return None

    _, result = topotest.run_and_expect(check, None, count=count, wait=wait)
    return result


def test_converge():
    "Baseline: two neighbours and two installed routes on r1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    result = _expect_neighbour(r1, "fe80::2", "r1-eth1")
    assert result is None, "r2 neighbour missing: {}".format(result)
    result = _expect_neighbour(r1, "fe80::3", "r1-eth0")
    assert result is None, "r3 neighbour missing: {}".format(result)
    result = _expect_route(r1, P_R2)
    assert result is None, "route via r2 not installed: {}".format(result)
    result = _expect_route(r1, P_R3)
    assert result is None, "route via r3 not installed: {}".format(result)


def test_link_down_up_control():
    "A mere link down/up keeps the interface: no crash, adjacency recovers"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.cmd("ip link set r1-eth1 down")
    # the interface is retained; the neighbour entry may linger showing
    # (down), but the daemon must stay up and answer
    try:
        _neighbours(r1)
    except Exception as exc:
        pytest.fail("show babel neighbor failed after link down: {}".format(exc))
    assert _babeld_alive(r1), "babeld died after link down"

    r1.cmd("ip link set r1-eth1 up")
    result = _expect_neighbour(r1, "fe80::2", "r1-eth1")
    assert result is None, "r2 neighbour did not recover: {}".format(result)
    result = _expect_route(r1, P_R2)
    assert result is None, "route via r2 did not recover: {}".format(result)


def test_interface_delete_unconfigured():
    "Deleting an unconfigured interface must not leave a dangling neigh->ifp"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    r1.cmd("ip link del r1-eth1")

    # Wait for babeld to process the deletion.  With the fix, the
    # neighbour bound to the deleted interface is flushed and the poll
    # succeeds; on the unpatched build the poll itself dereferences the
    # freed ifp and kills babeld, so this is also the bug check.
    def neigh_gone():
        try:
            out = r1.vtysh_cmd("show babel neighbor")
        except Exception as exc:
            return "show babel neighbor failed: {}".format(exc)
        if "dev r1-eth1" in out:
            return "neighbour on deleted interface still present"
        return None

    _, result = topotest.run_and_expect(neigh_gone, None, count=30, wait=0.5)
    assert result is None, "neighbour outlived the interface delete: {}".format(
        result
    )

    neighs = _neighbours(r1)
    logger.info("neighbours after delete: %s", neighs)

    assert _babeld_alive(r1), "babeld died after interface delete"
    assert not any(n[1] == "r1-eth1" for n in neighs), (
        "neighbour on the deleted interface still listed: {}".format(neighs)
    )
    assert any(n[0] == "fe80::3" and n[1] == "r1-eth0" for n in neighs), (
        "control neighbour lost: {}".format(neighs)
    )

    result = _expect_route(r1, P_R2, installed=False, count=10, wait=0.5)
    assert result is None, "route via r2 survived the delete: {}".format(result)
    result = _expect_route(r1, P_R3, installed=True, count=10, wait=0.5)
    assert result is None, "route via r3 lost: {}".format(result)

    # control plane keeps running: r3 must still see r1
    result = _expect_neighbour(r3, "fe80::1", "r3-eth0", count=30, wait=1)
    assert result is None, "r3 lost r1 after the delete: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
