#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_filter_conflict.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
A prefix-list and a distribute-list in the same direction cannot
both be configured. The second command must fail the commit.
"""

import os
import sys
import subprocess
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


def test_distribute_list_rejected_when_prefix_list_set():
    "Same-direction distribute-list does not replace the prefix-list"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65000
 address-family ipv4 unicast
  neighbor 192.0.2.2 distribute-list AL in
 exit-address-family
""",
            pretty_output=False,
            raises=True,
        )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 prefix-list PL in" in running
    assert "neighbor 192.0.2.2 distribute-list" not in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
