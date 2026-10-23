#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_evpn_l3vni_svi_resolve.py
#
# Copyright (c) 2026 by the FRRouting project
#
"""
An L3VNI's SVI must be resolved from the VLAN-VNI map of a VLAN-aware bridge,
not from an unrelated SVI that happens to sit on the same bridge.

zl3vni_from_svi() looks the SVI's VLAN up in the bridge's VLAN-VNI map. On a
miss it falls through to zl3vni_from_svi_ns(), a walk that matches on
"is a VXLAN interface, is operative, same bridge" and ignores the VLAN
entirely. So bringing up any SVI on the bridge -- including one with no VNI
mapping at all -- rebinds the L3VNI to it.

Topology (single VTEP, no peering required; `advertise-all-vni` alone is
enough to enable EVPN in zebra):

    bridge (VLAN-aware)
      +-- vxlan5000   VNI 5000, access VLAN 3745
      +-- Vlan3745    SVI in vrf-red   <- the correct L3VNI SVI
      +-- Vlan12      SVI in vrf-red   <- NO VNI mapping

Flapping Vlan12 must not move the L3VNI's SVI off Vlan3745.
"""

import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()
    tgen.gears["r1"].run(f"/bin/bash {CWD}/r1/setup.sh")


def teardown_module(mod):
    get_topogen().stop_topology()


def _svi_of_l3vni(r1):
    """Return the L3-SVI zebra currently has bound to VNI 5000, or None."""
    out = r1.vtysh_cmd("show vrf vni json", isjson=True)
    for vrf in out.get("vrfs", []):
        if str(vrf.get("vni")) == "5000":
            return vrf.get("sviIntf")
    return None


def test_l3vni_svi_is_vlan3745():
    """Baseline: the L3VNI must resolve to Vlan3745, the SVI of its own VLAN."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _check():
        svi = _svi_of_l3vni(r1)
        return None if svi == "Vlan3745" else f"L3-SVI is {svi}, expected Vlan3745"

    _, result = topotest.run_and_expect(functools.partial(_check), None, count=30, wait=2)
    assert result is None, f"L3VNI 5000 did not come up on Vlan3745: {result}"


def test_unrelated_svi_flap_does_not_steal_l3vni():
    """Flapping Vlan12 -- which has no VNI mapping -- must not rebind the L3VNI."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _link_ups(ifname):
        """zebra's own count of up-events it has processed for this interface."""
        out = r1.vtysh_cmd(f"show interface {ifname} json", isjson=True)
        return out.get(ifname, {}).get("linkUps", 0)

    before = _link_ups("Vlan12")

    r1.run("ip link set dev Vlan12 down")
    r1.run("ip link set dev Vlan12 up")

    # Wait for zebra to have actually processed the up-event rather than for a
    # fixed interval. A fixed sleep lets a slow machine finish the check before
    # zebra runs the resolution, so the test would pass against the unchanged
    # pre-flap binding without ever exercising the regression.
    def _flap_processed():
        now = _link_ups("Vlan12")
        return None if now > before else f"linkUps still {now}, expected > {before}"

    _, result = topotest.run_and_expect(
        functools.partial(_flap_processed), None, count=30, wait=1
    )
    assert result is None, f"zebra never processed the Vlan12 up-event: {result}"

    svi = _svi_of_l3vni(r1)
    assert svi == "Vlan3745", (
        f"L3VNI 5000 SVI moved to {svi} after flapping unrelated SVI Vlan12; "
        "expected it to stay on Vlan3745"
    )


def test_l3vni_svi_recovers_after_own_svi_flap():
    """Flapping the L3VNI's own SVI must still resolve back to Vlan3745."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.run("ip link set dev Vlan3745 down")
    topotest.sleep(2, "waiting for Vlan3745 down to be processed")
    r1.run("ip link set dev Vlan3745 up")

    def _check():
        svi = _svi_of_l3vni(r1)
        return None if svi == "Vlan3745" else f"L3-SVI is {svi}, expected Vlan3745"

    _, result = topotest.run_and_expect(functools.partial(_check), None, count=30, wait=2)
    assert result is None, f"L3VNI 5000 did not recover onto Vlan3745: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
