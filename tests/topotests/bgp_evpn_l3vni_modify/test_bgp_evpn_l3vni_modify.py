#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 NVIDIA Corporation
#
# Test: L3VNI value change via NB MODIFY must tear down old VNI
#
# When a VRF's L3VNI value is changed with a single "vni <new>" command
# (without first doing "no vni <old>"), the northbound system generates
# a single NB_CB_MODIFY callback. The modify handler must tear down the
# old L3VNI before adding the new one. If it does not, the old L3VNI is
# orphaned in zrouter.l3vni_table and bgpd is never notified of its
# deletion.
#
# Reproduction sequence (matches HBN field bug):
#   1. Start with correct VNI 3109 (working state)
#   2. Change to wrong VNI 60810 via vtysh
#   3. Restart FRR (now running with VNI 60810 fully established)
#   4. Change back to correct VNI 3109 via vtysh (BUG TRIGGER)
#   5. Assert old VNI 60810 is gone from zebra and bgpd
#
# Topology:
#   PE1 ---[s1]--- P1 ---[s2]--- PE2
#
#   P1:  spine / iBGP route reflector (OSPF + BGP EVPN)
#   PE1, PE2:  VTEP leaves with VRF vrf-blue, L3VNI initially 3109
#

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("PE1", "P1"),
        "s2": ("P1", "PE2"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    for pe in ("PE1", "PE2"):
        tgen.gears[pe].run(f"/bin/bash {CWD}/{pe}/setup.sh")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_step1_initial_l3vni_3109():
    """Verify L3VNI 3109 is established on PE1 and BGP EVPN peers are up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    def _check_l3vni_3109():
        output = pe1.vtysh_cmd("show evpn vni 3109", isjson=False)
        if "Type: L3" not in output:
            return "L3VNI 3109 not yet showing Type: L3"
        if "vrf-blue" not in output:
            return "L3VNI 3109 not associated with vrf-blue"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_l3vni_3109), None, count=30, wait=2
    )
    assert result is None, f"L3VNI 3109 not established on PE1: {result}"

    def _check_bgp_evpn_peer():
        output = pe1.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
        peers = output.get("peers", {})
        for _, pdata in peers.items():
            if pdata.get("state") == "Established":
                return None
        return "No established BGP EVPN peer"

    _, result = topotest.run_and_expect(
        functools.partial(_check_bgp_evpn_peer), None, count=30, wait=2
    )
    assert result is None, f"BGP EVPN peering not established on PE1: {result}"


def test_step2_change_to_wrong_vni_60810():
    """Change VNI from 3109 to 60810 via vtysh (simulates wrong nv config apply)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    pe1.vtysh_cmd(
        """
        configure terminal
        vrf vrf-blue
         vni 60810
        end
        """
    )

    def _check_vni_60810():
        output = pe1.vtysh_cmd("show vrf vni json", isjson=True)
        raw = json.dumps(output)
        if "60810" in raw:
            return None
        return "VRF vrf-blue not yet showing VNI 60810"

    _, result = topotest.run_and_expect(
        functools.partial(_check_vni_60810), None, count=20, wait=3
    )
    assert result is None, f"VNI change to 60810 not reflected: {result}"


def test_step3_restart_frr_with_wrong_vni():
    """Restart FRR on PE1 with VNI 60810 to fully establish it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    wrong_conf = os.path.join(CWD, "PE1/frr.conf").replace("3109", "unused")
    wrong_conf_path = os.path.join(tgen.logdir, "PE1", "frr_wrong_vni.conf")
    with open(os.path.join(CWD, "PE1/frr.conf"), "r") as f:
        conf = f.read()
    conf = conf.replace("vni 3109", "vni 60810")
    with open(wrong_conf_path, "w") as f:
        f.write(conf)

    pe1.stop()
    pe1.load_frr_config(wrong_conf_path)
    pe1.start()

    def _check_l3vni_60810():
        output = pe1.vtysh_cmd("show evpn vni 60810", isjson=False)
        if "Type: L3" not in output:
            return "L3VNI 60810 not yet showing Type: L3"
        if "vrf-blue" not in output:
            return "L3VNI 60810 not associated with vrf-blue"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_l3vni_60810), None, count=30, wait=2
    )
    assert result is None, f"L3VNI 60810 not established after restart: {result}"


def test_step4_change_back_to_correct_vni_3109():
    """Change VNI back to 3109 without restart (NB MODIFY bug trigger)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    pe1.vtysh_cmd(
        """
        configure terminal
        vrf vrf-blue
         vni 3109
        end
        """
    )

    def _check_vni_3109():
        output = pe1.vtysh_cmd("show vrf vni json", isjson=True)
        raw = json.dumps(output)
        if "3109" in raw:
            return None
        return "VRF vrf-blue not yet showing VNI 3109"

    _, result = topotest.run_and_expect(
        functools.partial(_check_vni_3109), None, count=20, wait=3
    )
    assert result is None, f"VNI change to 3109 not reflected: {result}"


def test_step5_old_vni_must_not_exist():
    """Assert old L3VNI 60810 is no longer present in zebra.

    BUG: lib_vrf_zebra_l3vni_id_modify calls zebra_vxlan_process_vrf_vni_cmd
    with add=1 for the new VNI without first calling the destroy path for
    the old VNI. The old zl3vni entry stays orphaned in zrouter.l3vni_table.

    This assertion FAILS on unfixed code.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    def _check_old_vni_gone():
        output = pe1.vtysh_cmd("show evpn vni json", isjson=True)
        raw = json.dumps(output)
        if "60810" in raw:
            return "old L3VNI 60810 still present in 'show evpn vni json' (orphaned)"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_old_vni_gone), None, count=20, wait=3
    )
    assert result is None, result


def test_step6_bgp_old_vni_gone():
    """Verify bgpd no longer holds the old L3VNI 60810.

    BUG: Because zebra never sent ZEBRA_L3VNI_DEL for VNI 60810, bgpd
    still has stale L3VNI state.

    This assertion FAILS on unfixed code.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    def _check_bgp_old_vni():
        output = pe1.vtysh_cmd("show bgp l2vpn evpn vni json", isjson=True)
        raw = json.dumps(output)
        if "60810" in raw:
            return "old L3VNI 60810 still in bgpd 'show bgp l2vpn evpn vni json'"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_bgp_old_vni), None, count=20, wait=3
    )
    assert result is None, result


def test_step7_new_vni_state():
    """Verify the new L3VNI 3109 is properly associated with vrf-blue."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    def _check_new_vni():
        output = pe1.vtysh_cmd("show vrf vni json", isjson=True)
        raw = json.dumps(output)
        if "3109" not in raw:
            return "VNI 3109 not found in 'show vrf vni json'"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_new_vni), None, count=20, wait=3
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
