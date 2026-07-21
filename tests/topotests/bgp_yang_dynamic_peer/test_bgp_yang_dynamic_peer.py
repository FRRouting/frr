#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_dynamic_peer.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
A neighbor learned from "bgp listen range" must not be adopted when the
operator configures that address as a static neighbor.
"""

import os
import sys
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

DYN_ADDR = "192.0.2.2"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _dynamic_neighbor_up(router):
    output = router.vtysh_cmd("show bgp summary")
    return "*%s" % DYN_ADDR in output


def test_dynamic_peer_is_not_adopted():
    "Configuring a live dynamic neighbor address must be rejected"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = lambda: _dynamic_neighbor_up(r1)
    _, result = topotest.run_and_expect(test_func, True, count=40, wait=1)
    assert result, "Dynamic neighbor %s did not come up" % DYN_ADDR

    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65001
 neighbor %s remote-as 65002
"""
            % DYN_ADDR,
            pretty_output=False,
            raises=True,
        )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor %s remote-as" % DYN_ADDR not in running

    test_func = lambda: _dynamic_neighbor_up(r1)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert result, "Dynamic neighbor %s changed after the rejected command" % DYN_ADDR

    detail = r1.vtysh_cmd("show bgp neighbors %s" % DYN_ADDR)
    assert "BGP neighbor is *%s" % DYN_ADDR in detail


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
