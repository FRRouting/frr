#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nageswara Soma
#

"""
Regression test for EVPN instance designation after reviving a hidden
default BGP instance.

When "no router bgp" deletes the default instance while its MPLS-VPN RIB is
non-empty, bgp_delete() keeps the instance alive as a hidden tombstone and
clears bm->bgp_evpn. Reviving it with "router bgp <AS>" reuses the same
struct bgp via the hidden path of bgp_create(), which skips the fresh-
instance setup that re-designates the default as the EVPN instance. As a
result bgp_get_evpn() stays NULL and EVPN stops working on the revived
default ("show bgp l2vpn evpn" collapses to "{}").

A non-empty MPLS-VPN RIB is guaranteed with an explicit "export vpn" vrf
instance. EVPN uses "advertise ipv4 unicast" (not "advertise-all-vni")
on purpose: advertise-all-vni would itself re-assign bm->bgp_evpn and hide
the bug.

Both revival control paths are exercised, since they clear the hidden
flags in different places but share the same bgp_create(hidden=true)
reuse:
  - P1, AS-change revival: flags cleared inline in
    bgp_lookup_by_as_name_type().
  - P2, same-AS revival (the common operator flow): finalized in the
    "router bgp" handler (bgp_vty.c).
"""

import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

AS_INIT = 65001
AS_NEW = 65003
AS_VNI = 65004
VNI = 100
VNI2 = 200
# Type-3 ESIs derived from "evpn mh es-sys-mac" and "evpn mh es-id"
ESI = "03:00:11:22:33:44:55:00:00:01"
ESI2 = "03:00:11:22:33:44:66:00:00:02"


def build_topo(tgen):
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.run(
        "ip link add vrf1 type vrf table 101 && "
        "ip link add dummy1 type dummy && "
        "ip link set dummy1 master vrf1 && "
        "ip addr add 10.10.1.1/24 dev dummy1 && "
        "ip link set dummy1 up && "
        "ip link set vrf1 up && "
        "ip addr add 10.20.0.1/32 dev lo && "
        "ip link add br100 type bridge && "
        "ip link add vxlan100 type vxlan id {0} dstport 4789 "
        "local 10.20.0.1 nolearning && "
        "ip link set vxlan100 master br100 && "
        "ip link set vxlan100 up && "
        "ip link add bond0 type bond mode 802.3ad && "
        "ip link add dummy2 type dummy && "
        "ip link set dummy2 master bond0 && "
        "ip link set bond0 master br100 && "
        "ip link set dummy2 up && "
        "ip link set bond0 up && "
        "ip link add bond1 type bond mode 802.3ad && "
        "ip link add dummy3 type dummy && "
        "ip link set dummy3 master bond1 && "
        "ip link set bond1 master br100 && "
        "ip link set dummy3 up && "
        "ip link set bond1 up && "
        "ip link set br100 up".format(VNI)
    )

    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _evpn_served_by_default(router):
    """bgp_get_evpn()==NULL makes the handler emit "{}"; a live EVPN default
    emits a dict containing the "numPrefix" key (even when the table is
    empty)."""
    output = router.vtysh_cmd("show bgp l2vpn evpn json", isjson=True)
    if not isinstance(output, dict) or "numPrefix" not in output:
        return "default instance is not the EVPN instance: {}".format(output)
    return None


def _vpn_populated(router):
    output = router.vtysh_cmd("show bgp ipv4 vpn json", isjson=True)
    if output.get("totalRoutes", 0) < 1:
        return "default MPLS-VPN RIB is empty"
    return None


def _running_config_has_revived_bgp(router, as_num):
    """Check the default instance block of "show running-config": it must be
    there and carry the l2vpn evpn address-family (written by
    bgp_config_write_evpn_info() from the instance's EVPN state)."""
    output = router.vtysh_cmd("show running-config")
    header = "router bgp {0}\n".format(as_num)
    start = output.find(header)
    if start < 0:
        return "running-config lacks router bgp {0}".format(as_num)
    block = output[start + len(header) :]
    end = block.find("\nexit\n")
    if end >= 0:
        block = block[:end]
    if " address-family l2vpn evpn" not in block:
        return "default instance block lacks the l2vpn evpn address-family"
    return None


def _hidden_tombstone(router):
    output = router.vtysh_cmd("show bgp router json", isjson=True)
    if output.get("bgpInstanceCount") != 1:
        return "expected bgpInstanceCount 1, got {}".format(
            output.get("bgpInstanceCount")
        )
    if "router bgp" in router.vtysh_cmd("show running-config"):
        return "running-config still contains router bgp"
    return None


def _delete_instances(router, as_num):
    router.vtysh_cmd(
        "configure terminal\n"
        "no router bgp {0} vrf vrf1\n"
        "no router bgp {0}\n".format(as_num)
    )


def _revive_and_check(router, delete_as, revive_as, label):
    step("[{0}] delete AS {1}, tombstone default".format(label, delete_as))
    _delete_instances(router, delete_as)
    test_func = functools.partial(_hidden_tombstone, router)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "[{0}] no hidden tombstone".format(label)

    step("[{0}] revive default (router bgp {1})".format(label, revive_as))
    router.vtysh_cmd(_revive_config(revive_as))
    test_func = functools.partial(_evpn_served_by_default, router)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, "[{0}] revived default lost EVPN instance".format(label)

    # The revived instance must still own its EVPN state: bgp_delete() used
    # to run the EVPN-owner teardown on the tombstone, and writing the l2vpn
    # evpn address-family of the revived instance then crashed bgpd in
    # bgp_config_write_evpn_info() (vnihash == NULL).
    step("[{0}] show running-config on the revived default".format(label))
    router.vtysh_cmd("show running-config")
    status = router.check_router_running()
    assert status == "", "[{0}] daemon died after show running-config: {1}".format(
        label, status
    )
    test_func = functools.partial(_running_config_has_revived_bgp, router, revive_as)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "[{0}] {1}".format(label, res)


def _revive_config(as_num, advertise_all_vni=False):
    return """configure terminal
router bgp {0}
 bgp router-id 10.200.200.200
 no bgp ebgp-requires-policy
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
{1} exit-address-family
exit
router bgp {0} vrf vrf1
 bgp router-id 10.200.200.200
 no bgp ebgp-requires-policy
 address-family ipv4 unicast
  redistribute connected
  rd vpn export {0}:1
  rt vpn both {0}:1
  export vpn
 exit-address-family
exit
""".format(
        as_num, "  advertise-all-vni\n" if advertise_all_vni else ""
    )


def test_bgp_hidden_evpn_revival():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Confirm VPNv4 export populated the default MPLS-VPN RIB")
    test_func = functools.partial(_vpn_populated, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "MPLS-VPN RIB not populated before delete"

    step("Confirm the default instance is the EVPN instance")
    test_func = functools.partial(_evpn_served_by_default, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "default is not the EVPN instance before delete"

    # P1: revive with an AS change (65001 -> 65003); the hidden flags are
    # cleared inline in bgp_lookup_by_as_name_type().
    _revive_and_check(r1, AS_INIT, AS_NEW, "P1 AS-change")

    step("Confirm VPNv4 RIB re-populated after P1 revival")
    test_func = functools.partial(_vpn_populated, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "MPLS-VPN RIB not populated after P1 revival"

    # P2: revive with the same AS (65003 -> 65003); finalized in the
    # "router bgp" handler (bgp_vty.c). This is the common operator flow.
    _revive_and_check(r1, AS_NEW, AS_NEW, "P2 same-AS")


def _vni_export_rt(router, as_num):
    """The L2VNI learned from zebra must be known to the default instance
    with an automatic export route target derived from its current AS."""
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {0} json".format(VNI), isjson=True
    )
    if not isinstance(output, dict) or output.get("vni") != str(VNI):
        return "VNI {0} not known to bgpd: {1}".format(VNI, output)
    want = "{0}:{1}".format(as_num, VNI)
    if output.get("exportRts") != [want]:
        return "VNI {0} export RTs {1}, want [{2}]".format(
            VNI, output.get("exportRts"), want
        )
    return None


def _local_es_state(router, up, esi=ESI):
    """bond0 carries an Ethernet Segment (r1/frr.conf); with VNI {0} on the
    same bridge bgpd must know it as a local ES, and its "up" flag must
    follow the bond's oper state (bgpd processes the oper change in
    bgp_evpn_local_es_add()).""".format(
        VNI
    )
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn es {0} json".format(esi), isjson=True
    )
    if not isinstance(output, dict) or output.get("esi") != esi:
        return "ES {0} not known to bgpd: {1}".format(esi, output)
    if "local" not in output.get("type", []):
        return "ES {0} is not local: {1}".format(esi, output.get("type"))
    if ("up" in output.get("flags", [])) != up:
        return "ES {0} flags {1}, want up={2}".format(esi, output.get("flags"), up)
    return None


def _es_evi_present(router, present):
    """ES-EVI of the ESI on VNI {0}, i.e. bond0 attached to br100.""".format(VNI)
    output = router.vtysh_cmd("show bgp l2vpn evpn es-evi json", isjson=True)
    found = isinstance(output, list) and any(
        e.get("esi") == ESI and e.get("vni") == VNI for e in output
    )
    if found != present:
        return "ES-EVI {0}/{1} present={2}, want {3}".format(ESI, VNI, found, present)
    return None


def _ead_evi_route_present(router, present):
    """Type-1 EAD-EVI route (eth tag 0) for the ESI in the default instance."""
    output = router.vtysh_cmd("show bgp l2vpn evpn route type ead json", isjson=True)
    prefix = "[1]:[0]:[{0}]".format(ESI)
    found = False
    if isinstance(output, dict):
        for rd in output.values():
            if isinstance(rd, dict) and any(k.startswith(prefix) for k in rd):
                found = True
    if found != present:
        return "EAD-EVI route for {0} present={1}, want {2}".format(ESI, found, present)
    return None


def _vni_known(router, vni):
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {0} json".format(vni), isjson=True
    )
    if not isinstance(output, dict) or output.get("vni") != str(vni):
        return "VNI {0} not known to bgpd: {1}".format(vni, output)
    return None


def test_bgp_hidden_evpn_revival_vni_rt():
    """A tombstoned default keeps its VNIs and Ethernet Segments. ES and VNI
    events while hidden must not kill bgpd, must leave consistent state
    behind, and reviving with a different AS must re-derive the automatic
    route targets for the new AS."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enable advertise-all-vni on AS {0}, learn VNI {1}".format(AS_NEW, VNI))
    r1.vtysh_cmd(_revive_config(AS_NEW, advertise_all_vni=True))
    test_func = functools.partial(_vni_export_rt, r1, AS_NEW)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_ead_evi_route_present, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res

    step("Delete AS {0}, tombstone default".format(AS_NEW))
    _delete_instances(r1, AS_NEW)
    test_func = functools.partial(_hidden_tombstone, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "no hidden tombstone"

    # zebra keeps delivering ES events to the tombstone through the VRF
    # lookup while there is no EVPN instance; this used to trip the
    # bgp_get_evpn() assert in bgp_evpn_mac_update_on_es_oper_chg().
    step("ES link-down and link-up while the default is hidden")
    r1.run("ip link set bond0 down")
    test_func = functools.partial(_local_es_state, r1, False)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "ES link-down while hidden: {0}".format(res)
    status = r1.check_router_running()
    assert status == "", "daemon died on ES link-down while hidden: {0}".format(status)
    r1.run("ip link set bond0 up")
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "ES link-up while hidden: {0}".format(res)
    status = r1.check_router_running()
    assert status == "", "daemon died on ES link-up while hidden: {0}".format(status)

    # An ES-EVI delete while hidden must withdraw the EAD-EVI route from the
    # tombstone's RIB (there is no EVPN instance to resolve, the ES route
    # table owner is used), and a VNI learnt while hidden must not make the
    # remote-route retry timer spin.
    step(
        "ES-EVI delete, new ES on bond1 and new VNI {0} while the default is hidden".format(
            VNI2
        )
    )
    r1.run("ip link set bond0 nomaster")
    # a new local ES creates its fragment RD from the EVPN instance's
    # router-id; without one, the default's is used
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface bond1\n"
        " evpn mh es-id 2\n"
        " evpn mh es-sys-mac 00:11:22:33:44:66\n"
    )
    r1.run(
        "ip link add br200 type bridge && "
        "ip link add vxlan200 type vxlan id {0} dstport 4789 "
        "local 10.20.0.1 nolearning && "
        "ip link set vxlan200 master br200 && "
        "ip link set vxlan200 up && "
        "ip link set br200 up".format(VNI2)
    )
    topotest.sleep(2, "let zebra report the ES-EVI delete and the new VNI")
    status = r1.check_router_running()
    assert status == "", "daemon died on ES-EVI/VNI change while hidden: {0}".format(
        status
    )

    step("Revive default as AS {0}".format(AS_VNI))
    r1.vtysh_cmd(_revive_config(AS_VNI, advertise_all_vni=True))
    status = r1.check_router_running()
    assert status == "", "daemon died on revival: {0}".format(status)
    test_func = functools.partial(_vni_export_rt, r1, AS_VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_ead_evi_route_present, r1, False)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        res is None
    ), "stale EAD-EVI route after ES-EVI delete while hidden: {0}".format(res)
    test_func = functools.partial(_vni_known, r1, VNI2)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_local_es_state, r1, True, ESI2)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "ES configured while hidden: {0}".format(res)
    warnings = int(r1.cmd("grep -c 'No BGP EVPN instance found' bgpd.log || true"))
    assert warnings <= 5, "remote-route retry spun while hidden: {0} warnings".format(
        warnings
    )

    step("Re-attach bond0 to br100: ES-EVI and EAD-EVI route come back")
    r1.run("ip link set bond0 master br100")
    test_func = functools.partial(_es_evi_present, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_ead_evi_route_present, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res


def test_bgp_hidden_evpn_shutdown_with_tombstone():
    """bgpd must shut down cleanly while the default is a hidden tombstone
    that still holds a VNI and a local ES: bgp_delete() re-adopts it as the
    EVPN instance for the final teardown. Runs last, it stops the router."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Delete AS {0}, tombstone default with its VNI and ES".format(AS_VNI))
    _delete_instances(r1, AS_VNI)
    test_func = functools.partial(_hidden_tombstone, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "no hidden tombstone"
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "tombstone lost its ES: {0}".format(res)

    step("Stop the router with the tombstone in place")
    # SIGTERM to the daemons. stop() returns the core report of the daemons,
    # which is what this test is about; leaked allocations at exit are only
    # logged by the framework, as for every other test.
    errors = r1.stop()
    assert "CORE FOUND" not in errors, "daemon crashed on shutdown: {0}".format(errors)


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
