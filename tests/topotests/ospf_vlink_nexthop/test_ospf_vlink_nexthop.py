#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_ospf_vlink_nexthop.py: Regression test for inter-area routes installed
with a wrong/inactive next-hop interface in an OSPF virtual-link environment.

Topology (inter-router links use the default broadcast network type):

                area 0            area 10
   +----+   10.0.1.0/24   +----+   10.0.2.0/24   +----+   area 20
   | r1 |----------------| r2 |----------------| r3 |---- 192.168.21.0/24
   +----+ eth0      eth0 +----+ eth1      eth0 +----+ eth1
   1.1.1.1            2.2.2.2                3.3.3.3 eth2  192.168.22.0/24

 * r2 is an ABR between the backbone (area 0) and the transit area (area 10).
 * r3 is an ABR between area 10 and area 20; it reaches the backbone only
   through an area 10 virtual link to r2.

The virtual link is configured at RUNTIME (vtysh), after the physical
adjacencies are full. This mirrors how the issue is hit in practice (an
operator configures the virtual link on a running system) and is required to
reproduce it: the wrong next-hop only occurs when the real backbone interface
occupies the first link position(s) of the backbone router-LSA, i.e. when the
VLINK pseudo interface is created after the backbone interface. With the
virtual link in the boot configuration the VLINK interface grabs position 0
instead and the stale position resolves to the (harmless) VLINK interface.

Mechanism: the virtual-link next-hop carries an LSA position that is relative
to the *transit* area (area 10, r2-eth1 = position 0), but the backbone
router-route to r3 resolves that position against the *backbone* router-LSA,
where position 0 is the unrelated backbone interface (r2-eth0, toward r1). The
bogus next-hop is then inherited by every inter-area route via r3 and shows up
as e.g.:

  192.168.21.0/24 [110/x] via 10.0.2.2, r2-eth1
                          via 10.0.2.2, r2-eth0 inactive   <-- must NOT appear

This test fails on an unfixed daemon and passes once the next-hop interface is
resolved correctly.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

# Networks advertised from area 20 behind r3.
AREA20_PREFIXES = ["192.168.21.0/24", "192.168.22.0/24"]

# Interface on r2 that legitimately reaches r3 (transit area 10).
GOOD_IF = "r2-eth1"
# Backbone interface on r2 (toward r1); r3's transit address is NOT on it.
BAD_IF = "r2-eth0"


def build_topo(tgen):
    "Build function"

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # area 0: r1 <-> r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # area 10 (transit): r2 <-> r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # area 20 downlinks on r3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _expect_neighbor_full(router, neighbor):
    "Wait until OSPFv2 neighbor `neighbor` is Full on `router`."
    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf neighbor json",
        {"neighbors": {neighbor: [{"converged": "Full"}]}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, '"{}" OSPF neighbor {} not Full'.format(router, neighbor)


def test_ospf_convergence():
    "Wait for the physical adjacencies to come up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for OSPF adjacencies to converge")
    _expect_neighbor_full("r1", "2.2.2.2")
    _expect_neighbor_full("r2", "1.1.1.1")
    _expect_neighbor_full("r2", "3.3.3.3")
    _expect_neighbor_full("r3", "2.2.2.2")


def test_ospf_vlink_configure_runtime():
    """
    Configure the virtual link at runtime, after the physical adjacencies and
    router-LSAs exist (see module docstring for why this ordering is essential
    to reproduce the bug).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("configuring the area 10 virtual link via vtysh")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter ospf\narea 10 virtual-link 3.3.3.3"
    )
    tgen.gears["r3"].vtysh_cmd(
        "configure terminal\nrouter ospf\narea 10 virtual-link 2.2.2.2"
    )


def _check_route_nexthops(rname, prefix):
    """
    Return None if `prefix` on `rname` is installed with at least one active
    next-hop via GOOD_IF and no next-hop at all via BAD_IF; otherwise return a
    diagnostic string (so it can be driven by run_and_expect()).
    """
    tgen = get_topogen()
    output = tgen.gears[rname].vtysh_cmd(
        "show ip route {} json".format(prefix), isjson=True
    )

    entries = output.get(prefix)
    if not entries:
        return "{}: route {} is not installed yet".format(rname, prefix)

    # Use the OSPF entry (there is only one in this topology).
    entry = entries[0]
    nexthops = entry.get("nexthops", [])

    bogus = [nh for nh in nexthops if nh.get("interfaceName") == BAD_IF]
    if bogus:
        return "{}: route {} has a bogus next-hop via {} (bug present): {}".format(
            rname, prefix, BAD_IF, bogus
        )

    good = [
        nh
        for nh in nexthops
        if nh.get("interfaceName") == GOOD_IF and nh.get("active")
    ]
    if not good:
        return "{}: route {} has no active next-hop via {}".format(
            rname, prefix, GOOD_IF
        )

    return None


def test_ospf_vlink_route_nexthop():
    "Inter-area routes via the virtual link must not carry a bogus next-hop."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for prefix in AREA20_PREFIXES:
        test_func = partial(_check_route_nexthops, "r2", prefix)
        _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
        assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
