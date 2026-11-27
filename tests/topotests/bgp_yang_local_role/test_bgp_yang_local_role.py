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


def test_candidate_peer_sort_local_as_and_groups():
    """Verify candidate peer sort honors local-as, oad, and peer-group members (B004)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # local-as makes remote-as 65000 an eBGP peer; as-override & oad succeed.
    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor 192.0.2.10 remote-as 65000
 neighbor 192.0.2.10 local-as 65100
 neighbor 192.0.2.10 oad
 address-family ipv4 unicast
  neighbor 192.0.2.10 as-override
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.10 oad" in running
    assert "neighbor 192.0.2.10 as-override" in running

    # Inverse: local-as matching remote-as makes peer iBGP; as-override fails,
    # oad is accepted as a no-op (as classic does) and not shown.
    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor 192.0.2.11 remote-as 65200
 neighbor 192.0.2.11 local-as 65200
""",
        pretty_output=False,
        raises=True,
    )
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            "router bgp 65000\n address-family ipv4 unicast\n"
            "  neighbor 192.0.2.11 as-override\n exit-address-family\n",
            pretty_output=False,
            raises=True,
        )
    r1.vtysh_multicmd(
        "router bgp 65000\n neighbor 192.0.2.11 oad\n",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.11 as-override" not in running
    assert "neighbor 192.0.2.11 oad" not in running

    # Untyped peer-group with no members must reject route-reflector-client.
    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor PG_EMPTY peer-group
""",
        pretty_output=False,
        raises=True,
    )
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65000
 address-family ipv4 unicast
  neighbor PG_EMPTY route-reflector-client
 exit-address-family
""",
            pretty_output=False,
            raises=True,
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
