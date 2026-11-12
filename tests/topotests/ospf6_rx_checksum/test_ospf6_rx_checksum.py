#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Check that ospf6d verifies the checksum of the packets it receives.

      r2 --- r1 --- r3   (r1-r3 uses an Authentication Trailer)
              |
              h1         (sends crafted Hellos, runs no OSPF)

RFC 5340 section 4.2.2 requires the verification. RFC 7166 section 4.2 omits it
for a packet that has an Authentication Trailer, whose checksum field is 0.
"""

import os

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = pytest.mark.ospf6d
CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    for name in ("r1", "r2", "r3"):
        tgen.add_router(name)
    tgen.add_host("h1", "2001:db8:ff::2/64", "via 2001:db8:ff::1")

    for name, peer in [("s1", "r2"), ("s2", "r3"), ("s3", "h1")]:
        switch = tgen.add_switch(name)
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears[peer])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _r1_neighbors():
    output = (
        get_topogen()
        .gears["r1"]
        .vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)
    )
    return {n["neighborId"]: n["state"] for n in output["neighbors"]}


def _send_hello(router_id, *options):
    get_topogen().gears["h1"].cmd_raises(
        "python3 {} h1-eth0 {} {}".format(
            os.path.join(CWD, "send_hello.py"), router_id, " ".join(options)
        )
    )


def _expect_dropped_then_accepted(dropped_id, accepted_id, *options):
    """
    Hellos reach r1 in order, so once the valid one has made a neighbor the
    one with the wrong checksum has been processed too.
    """
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors

    _send_hello(dropped_id, "--bad-checksum", *options)
    _send_hello(accepted_id, *options)

    def _accepted():
        return accepted_id in _r1_neighbors()

    _, result = topotest.run_and_expect(_accepted, True, count=30, wait=0.5)
    assert result, "the Hello with a correct checksum was not accepted"

    neighbors = _r1_neighbors()
    assert (
        dropped_id not in neighbors
    ), "the Hello with a wrong checksum made a neighbor: {}".format(neighbors)
    assert not tgen.gears["r1"].check_router_running()


def test_valid_packets_are_accepted():
    "Both adjacencies reach Full and the routes come through, with and without trailer."
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors

    def _converged():
        neighbors = _r1_neighbors()
        if neighbors.get("10.0.0.2") != "Full" or neighbors.get("10.0.0.3") != "Full":
            return "r1 neighbors: {}".format(neighbors)
        routes = tgen.gears["r1"].vtysh_cmd(
            "show ipv6 ospf6 route detail json", isjson=True
        )["routes"]
        for prefix in ("2001:db8:2::2/128", "2001:db8:3::3/128"):
            if prefix not in routes:
                return "r1 has no route to {}".format(prefix)
        return None

    _, error = topotest.run_and_expect(_converged, None, count=60, wait=1)
    assert error is None, error


def test_wrong_checksum_is_dropped():
    _expect_dropped_then_accepted("10.9.0.1", "10.9.0.2")


def test_checksum_does_not_cover_lls_block():
    "A valid checksum leaves out the LLS block, and it is still checked with one."
    _expect_dropped_then_accepted("10.9.0.3", "10.9.0.4", "--lls")


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
