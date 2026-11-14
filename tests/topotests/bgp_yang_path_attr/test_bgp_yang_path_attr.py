#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_path_attr.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
path-attribute discard must reject OTC (35) and ORIGIN (1), both as an
interactive command and inside one loaded configuration.
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


def _reject(router, commands):
    with pytest.raises(subprocess.CalledProcessError):
        router.vtysh_multicmd(commands, pretty_output=False, raises=True)


def test_discard_otc_and_origin_interactive():
    "Interactive discard of OTC and ORIGIN is rejected"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.2 path-attribute discard 35
""",
    )
    _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.2 path-attribute discard 1
""",
    )

    running = r1.vtysh_cmd("show running-config")
    assert "path-attribute discard" not in running


def test_discard_rejected_in_one_config():
    "A config file that discards OTC or ORIGIN is rejected"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.4 remote-as 65002
 neighbor 192.0.2.4 path-attribute discard 35
""",
    )
    _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.5 remote-as 65002
 neighbor 192.0.2.5 path-attribute discard 1
""",
    )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.4" not in running
    assert "neighbor 192.0.2.5" not in running
    assert "path-attribute discard" not in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
