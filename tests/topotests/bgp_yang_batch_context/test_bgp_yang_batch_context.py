#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test P1-04 (B4-03, RC-B) & P2-D2 (B2-02): multi-block vtysh -f batch loads
must never evaluate commands against a stale VTY qobj_index from an earlier
router bgp block, and redistribute table-direct must validate unconditionally
against the candidate instance key.
"""

import os
import subprocess
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_multiblock_batch_no_stale_context():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_multicmd(
        """
router bgp 65001
!
router bgp 65002 vrf vrf1
 no bgp log-neighbor-changes
 segment-routing srv6
  no locator LOC1
 exit
 address-family ipv4 unicast
  import vrf default
 exit-address-family
 address-family l2vpn evpn
  rd 65002:1
  no rd 65002:1
  rd 65002:2
 exit-address-family
!
router bgp 65003 vrf vrf2
 address-family ipv4 unicast
  import vrf vrf1
 exit-address-family
!
""",
        pretty_output=False,
        raises=True,
    )

    run = r1.vtysh_cmd("show running-config")
    assert "import vrf default" in run
    assert "import vrf vrf1" in run
    assert "rd 65002:2" in run


def test_redistribute_table_direct_vrf_rejected_in_batch():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65001
!
router bgp 65004 vrf vrf3
 address-family ipv6 unicast
  redistribute table-direct 100
 exit-address-family
!
""",
            pretty_output=False,
            raises=True,
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
