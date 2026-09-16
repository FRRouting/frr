#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check that a dynamic neighbor with `neighbor X bfd strict` converges when BFD is
available on both sides from the start.

R1 runs plain `bfd`, not `bfd strict`. With `bfd strict` on R1 too the bootstrap
deadlocks, which is a separate pre-existing problem in the outgoing direction:
peer_active() returns BGP_PEER_BFD_DOWN, bgp_timer_set() cancels the start timer
and R1 never connects, so R2 never creates the peer that would register BFD.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config("frr_up.conf")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neighbor)))
    expected = {
        neighbor: {
            "bgpState": "Established",
            "peerBfdInfo": {"status": "Up"},
        }
    }
    return topotest.json_cmp(output, expected)


def _bfd_peer_up(router):
    output = json.loads(router.vtysh_cmd("show bfd peers json"))
    if not output:
        return "no BFD sessions"
    for session in output:
        if session.get("status") != "up":
            return "BFD session {} is {}".format(
                session.get("peer"), session.get("status")
            )
    return None


def test_bgp_bfd_strict_dynamic_neighbor_converges():
    """The dynamic neighbor must converge with BFD strict on both sides."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Check that the BFD session comes up on both sides")
    for router in (r1, r2):
        test_func = functools.partial(_bfd_peer_up, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "BFD session did not come up on {}".format(router.name)

    step("Check that the dynamic neighbor is established on both sides")
    test_func = functools.partial(_bgp_established, r2, "192.0.2.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not establish the dynamic neighbor"

    test_func = functools.partial(_bgp_established, r1, "192.0.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not establish the session"

    step("Check that R2 is not left holding the connection")
    output = json.loads(r2.vtysh_cmd("show bgp neighbor 192.0.2.1 json"))
    assert not output["192.0.2.1"].get(
        "bfdStrictHold"
    ), "R2 still reports the connection as held by BFD strict mode"


def test_bgp_bfd_strict_dynamic_neighbor_reconverges():
    """The dynamic neighbor must come back after being cleared."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Clear the session on R2 to drop the dynamic neighbor")
    r2.vtysh_cmd("clear bgp 192.0.2.1")

    step("Check that the dynamic neighbor converges again on both sides")
    test_func = functools.partial(_bgp_established, r2, "192.0.2.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not re-establish the dynamic neighbor"

    test_func = functools.partial(_bgp_established, r1, "192.0.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not re-establish the session"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
