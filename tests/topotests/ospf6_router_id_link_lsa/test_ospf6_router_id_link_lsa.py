#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_router_id_link_lsa.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Olasupo Okunaiya
#

"""
test_ospf6_router_id_link_lsa.py: Test that OSPFv3 re-originates its
Link-LSAs when zebra hands it a new router-id.

An explicit "ospf6 router-id" restarts the process, so the self-originated
LSAs are flushed and originated again under the new router-id. A router-id
learnt from zebra did neither: ospf6d simply adopted the new value.

Router-LSAs and Intra-Area-Prefix-LSAs survive that, because later area and
interface events originate them again anyway. A Link-LSA does not. It is
originated when the interface comes up and nothing schedules it afterwards,
so it keeps the old advertising router. The neighbour's link-scoped lookup
is keyed on advertising router and link state id, so it never finds a
Link-LSA for the correct router-id and IPv6 nexthop resolution over that
link fails until the stale LSA reaches MaxAge.

This test drives the same code path deterministically: the router-id is
changed while r1 has no adjacency, which is the window in which ospf6d
accepts a router-id change at all.

Topology:

   r1 ------------- r2

r2 starts with OSPFv3 not enabled on the link, so r1 has no neighbour while
its router-id changes. OSPFv3 is enabled on r2 afterwards, and r2's view of
the link-scoped database is what gets checked.
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

pytestmark = [pytest.mark.ospf6d]

OLD_ROUTER_ID = "10.0.0.1"
NEW_ROUTER_ID = "10.0.0.9"


def build_topo(tgen):
    "Build function"

    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    tgen.gears["r1"].add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _link_lsa_adv_routers(router):
    """Return the advertising routers of the Link-LSAs in `router`'s
    link-scoped database, without duplicates.

    A Link-LSA is listed once per payload item (its link-local address and
    then each prefix), so the same advertising router appears on several
    rows of the table."""
    tgen = get_topogen()
    output = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 database link")
    adv_routers = []
    for line in output.splitlines():
        fields = line.split()
        # Type LSId AdvRouter Age SeqNum Payload
        # Lnk  0.0.0.2  10.0.0.9  9  80000001 ...
        if len(fields) >= 5 and fields[0] == "Lnk":
            if fields[2] not in adv_routers:
                adv_routers.append(fields[2])
    return adv_routers


def _expect_link_lsa(router, router_id):
    "Return None once `router` holds a Link-LSA advertised by `router_id`."
    adv_routers = _link_lsa_adv_routers(router)
    if router_id in adv_routers:
        return None
    return "Link-LSAs present: {}".format(adv_routers or "none")


def _r1_has_full_neighbor():
    "Return None once r1 has an adjacency in Full state."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)
    for neighbor in output.get("neighbors", []):
        if neighbor.get("state") == "Full":
            return None
    return "no Full adjacency"


def test_ospf6_link_lsa_originated():
    "r1 must originate a Link-LSA under the router-id zebra gave it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for r1 to originate its Link-LSA as %s", OLD_ROUTER_ID)
    test_func = partial(_expect_link_lsa, "r1", OLD_ROUTER_ID)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not originate a Link-LSA as {}: {}".format(
        OLD_ROUTER_ID, result
    )


def test_ospf6_link_lsa_reoriginated_on_router_id_change():
    "Changing the zebra router-id must re-originate r1's Link-LSA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # r1 has no neighbour yet, so ospf6d accepts the router-id change.
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nip router-id {}\n".format(NEW_ROUTER_ID)
    )

    logger.info("waiting for r1 to re-originate its Link-LSA as %s", NEW_ROUTER_ID)
    test_func = partial(_expect_link_lsa, "r1", NEW_ROUTER_ID)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "r1 did not re-originate its Link-LSA after the router-id changed "
        "to {}: {}".format(NEW_ROUTER_ID, result)
    )

    # The Link-LSA advertised under the old router-id must be gone, not left
    # behind for the neighbours to trip over.
    adv_routers = _link_lsa_adv_routers("r1")
    assert OLD_ROUTER_ID not in adv_routers, (
        "r1 still holds a Link-LSA advertised by the old router-id {}: "
        "{}".format(OLD_ROUTER_ID, adv_routers)
    )


def test_ospf6_neighbor_sees_new_link_lsa():
    "The neighbour must learn the Link-LSA of the new router-id only."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Bring OSPFv3 up on r2 now that r1's router-id has settled.
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\ninterface r2-eth0\nipv6 ospf6 area 0\n"
    )

    _, result = topotest.run_and_expect(_r1_has_full_neighbor, None, count=60, wait=1)
    assert result is None, "OSPFv3 adjacency did not come up: {}".format(result)

    logger.info("checking r2 learns r1's Link-LSA as %s", NEW_ROUTER_ID)
    test_func = partial(_expect_link_lsa, "r2", NEW_ROUTER_ID)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "r2 never learnt a Link-LSA from r1 under its current router-id "
        "{}: {}".format(NEW_ROUTER_ID, result)
    )

    adv_routers = _link_lsa_adv_routers("r2")
    assert OLD_ROUTER_ID not in adv_routers, (
        "r2 holds a stale Link-LSA advertised by r1's old router-id {}: "
        "{}".format(OLD_ROUTER_ID, adv_routers)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
