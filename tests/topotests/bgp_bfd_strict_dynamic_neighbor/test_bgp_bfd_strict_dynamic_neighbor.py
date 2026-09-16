#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check that `neighbor X bfd strict` gates dynamic neighbors as well.

R1 starts without `neighbor X bfd`, so BFD cannot come up and the hold is
observable. BFD is enabled on R1 later in the test.
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
        # r1 has no BFD session configured yet, force bfdd anyway.
        router.load_frr_config("frr.conf", extra_daemons=["bfdd"])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_dynamic_neighbor_held(r2):
    output = json.loads(r2.vtysh_cmd("show bgp neighbor 192.0.2.1 json"))
    expected = {
        "192.0.2.1": {
            "bgpState": "Active",
            "bfdStrictHold": True,
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_dynamic_neighbor_gone(r2):
    try:
        output = json.loads(r2.vtysh_cmd("show bgp neighbor 192.0.2.1 json"))
    except ValueError:
        # No such neighbor, the reply is not JSON.
        return None
    if "192.0.2.1" in output:
        return "dynamic neighbor 192.0.2.1 is still present"
    return None


def _bgp_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neighbor)))
    expected = {
        neighbor: {
            "bgpState": "Established",
            "peerBfdInfo": {"status": "Up"},
        }
    }
    return topotest.json_cmp(output, expected)


def test_bgp_bfd_strict_dynamic_neighbor_held():
    """The incoming connection must not be established before BFD is up."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # The first attempt may be bounced by the config-pending hold, R1 retries.
    step("Check that R2 holds the incoming connection while BFD is not up")
    test_func = functools.partial(_bgp_dynamic_neighbor_held, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not hold the dynamic neighbor connection"

    step("Check that neither side establishes the session while BFD is not up")
    test_func = functools.partial(_bgp_established, r2, "192.0.2.1")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is not None, "R2 established the session before BFD came up"

    test_func = functools.partial(_bgp_established, r1, "192.0.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is not None, "R1 established the session before BFD came up"


def test_bgp_bfd_strict_dynamic_neighbor_hold_time():
    """A held connection whose BFD never comes up must be torn down."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Wait for R2 to hold an incoming connection")
    test_func = functools.partial(_bgp_dynamic_neighbor_held, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not hold the dynamic neighbor connection"

    step("Check that R2 drops the held dynamic neighbor once the hold time expires")
    test_func = functools.partial(_bgp_dynamic_neighbor_gone, r2)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assert result is None, "R2 did not drop the held dynamic neighbor"


def test_bgp_bfd_strict_dynamic_neighbor_established():
    """Once BFD comes up the held connection is released."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Enable BFD on R1 to let the BFD session come up")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
         neighbor 192.0.2.2 bfd
        exit
        """
    )

    step("Check that both sides establish the session once BFD is up")
    test_func = functools.partial(_bgp_established, r2, "192.0.2.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not establish the session after BFD came up"

    test_func = functools.partial(_bgp_established, r1, "192.0.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not establish the session after BFD came up"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
