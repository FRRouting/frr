#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_cli_values.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Commands that enqueue several numeric leaves must keep each value.
nb_cli_enqueue_change() stores the value pointer.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_dampening_and_maximum_prefix_keep_each_number():
    "Dampening and maximum-prefix store every number, not the last one"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  bgp dampening 10 750 2000 60
  neighbor 192.0.2.2 maximum-prefix 1000 75 restart 12
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )

    running = r1.vtysh_cmd("show running-config")
    assert "bgp dampening 10 750 2000 60" in running
    assert "neighbor 192.0.2.2 maximum-prefix 1000 75 restart 12" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
