#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_default_originate.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Removing default-originate that is filtered by a deny route-map must
not advertise an unfiltered default.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for name in ("r1", "r2"):
        tgen.add_router(name)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _established(router, peer):
    out = router.vtysh_cmd("show bgp neighbors %s" % peer)
    return "BGP state = Established" in out


def _has_default(router):
    out = router.vtysh_cmd("show bgp ipv4 unicast")
    return "0.0.0.0/0" in out


def test_removing_filtered_default_originate_does_not_leak():
    "A deny route-map stays in force until default-originate is gone"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    ok, result = topotest.run_and_expect(
        lambda: _established(r1, "192.0.2.2"), True, count=20, wait=1
    )
    assert ok, result

    ok, result = topotest.run_and_expect(lambda: _has_default(r2), False, count=10, wait=1)
    assert ok, "deny route-map did not suppress the default: %s" % result

    r1.vtysh_multicmd(
        """
router bgp 65001
 address-family ipv4 unicast
  no neighbor 192.0.2.2 default-originate
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )

    detail = r1.vtysh_cmd("show bgp neighbors 192.0.2.2")
    assert "Default information originate" not in detail

    for _ in range(5):
        assert not _has_default(r2), "unfiltered default was advertised"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
