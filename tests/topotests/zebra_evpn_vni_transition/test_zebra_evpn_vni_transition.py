#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Nexthop AI
#               Brad House
#
"""
Remove an L3-VNI from a VRF and then delete its VxLAN interface while EVPN is
not enabled, then enable EVPN. Zebra must keep running and must not hold an
entry for the VNI of the deleted interface.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd_raises(f"/bin/bash {CWD}/r1/setup.sh")
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _vrf_vnis(r1):
    output = json.loads(r1.vtysh_cmd("show vrf vni json"))
    return {vrf["vrf"]: vrf for vrf in output.get("vrfs", [])}


def _evpn_vnis(r1):
    try:
        return json.loads(r1.vtysh_cmd("show evpn vni json"))
    except ValueError:
        return None


def test_zebra_evpn_vni_transition_evpn_disabled():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # L3-VNI 100 on vrf-red, while EVPN is not enabled.
    r1.vtysh_cmd(
        """
        configure terminal
         vrf vrf-red
          vni 100
        """
    )

    def _l3vni_added():
        vrf = _vrf_vnis(r1).get("vrf-red", {})
        return vrf.get("vni") == 100 and vrf.get("vxlanIntf") == "vxlan100"

    _, result = topotest.run_and_expect(_l3vni_added, True, count=30, wait=1)
    assert result, "L3-VNI 100 is not associated with vxlan100"

    # Remove the L3-VNI; its VxLAN interface is still there.
    r1.vtysh_cmd(
        """
        configure terminal
         vrf vrf-red
          no vni 100
        """
    )

    def _l3vni_removed():
        return "vrf-red" not in _vrf_vnis(r1)

    _, result = topotest.run_and_expect(_l3vni_removed, True, count=30, wait=1)
    assert result, "L3-VNI 100 is still present"

    # Delete the VxLAN interface and wait for zebra to drop it.
    r1.cmd_raises("ip link del vxlan100")

    def _vxlan_if_removed():
        return "vxlan100" not in r1.vtysh_cmd("show interface brief")

    _, result = topotest.run_and_expect(_vxlan_if_removed, True, count=30, wait=1)
    assert result, "vxlan100 is still known to zebra"

    # Enable EVPN. VNI 200 shows that zebra has built its VNI table.
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65000
          address-family l2vpn evpn
           advertise-all-vni
        """
    )

    def _evpn_enabled():
        vnis = _evpn_vnis(r1)
        return vnis is not None and "200" in vnis

    _, result = topotest.run_and_expect(_evpn_enabled, True, count=30, wait=1)
    assert tgen.routers_have_failure() is False, tgen.errors
    assert result, "VNI 200 was not added after enabling EVPN"

    vnis = _evpn_vnis(r1)
    assert vnis is not None and "100" not in vnis, (
        "VNI 100 is present without a VxLAN interface: {}".format(vnis)
    )

    # Disabling EVPN cleans the VNI table up.
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65000
          address-family l2vpn evpn
           no advertise-all-vni
        """
    )

    def _zebra_running():
        return "vxlan200" in r1.vtysh_cmd("show interface brief")

    _, result = topotest.run_and_expect(_zebra_running, True, count=10, wait=1)
    assert result, "zebra is not answering"
    assert tgen.routers_have_failure() is False, tgen.errors


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
