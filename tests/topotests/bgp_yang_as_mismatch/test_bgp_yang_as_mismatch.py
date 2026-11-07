#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_as_mismatch.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
"router bgp" with a different AS must not renumber the running instance.
Entering the same AS again must still reach the node.
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


def test_router_bgp_does_not_renumber():
    "A second AS is rejected and the original neighbor remains"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65001
""",
            pretty_output=False,
            raises=True,
        )

    running = r1.vtysh_cmd("show running-config")
    assert "router bgp 65000" in running
    assert "router bgp 65001" not in running
    assert "neighbor 192.0.2.2 remote-as 65001" in running

    summary = r1.vtysh_cmd("show bgp summary")
    assert "192.0.2.2" in summary

    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor 192.0.2.2 description still-here
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "router bgp 65000" in running
    assert "neighbor 192.0.2.2 description still-here" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
