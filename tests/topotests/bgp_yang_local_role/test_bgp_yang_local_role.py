#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_local_role.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
local-role is only valid on an eBGP session. An iBGP neighbor must
reject the command instead of storing it.
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


def test_local_role_ibgp_rejected_ebgp_accepted():
    "iBGP local-role is rejected; eBGP local-role is kept"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65000
 neighbor 192.0.2.2 local-role peer
""",
            pretty_output=False,
            raises=True,
        )

    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor 192.0.2.3 local-role customer
""",
        pretty_output=False,
        raises=True,
    )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 local-role" not in running
    assert "neighbor 192.0.2.3 local-role customer" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
