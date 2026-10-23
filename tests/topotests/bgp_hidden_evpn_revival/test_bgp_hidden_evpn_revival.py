#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nageswara Soma
#

"""
Regression test for EVPN instance designation after reviving a hidden
default BGP instance.

When "no router bgp" deletes the default instance while its MPLS-VPN RIB is
non-empty, bgp_delete() keeps the instance alive as a hidden instance and
clears bm->bgp_evpn. Reviving it with "router bgp <AS>" reuses the same
struct bgp via the hidden path of bgp_create(), which skips the fresh-
instance setup that re-designates the default as the EVPN instance. As a
result bgp_get_evpn() stays NULL and EVPN stops working on the revived
default ("show bgp l2vpn evpn" collapses to "{}").

A non-empty MPLS-VPN RIB is guaranteed with an explicit "export vpn" vrf
instance. The first test uses "advertise ipv4 unicast" (not
"advertise-all-vni") on purpose: advertise-all-vni would itself re-assign
bm->bgp_evpn and hide the bug. The following tests cover the EVPN state
(VNIs, ESs, routes, configuration) across the hidden instance and its revival.

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
L3VNI = 901
VTEP_IP = "10.20.0.1"
VNI_RD = "10.200.200.200:999"
DEFAULT_RD = "10.200.200.200:777"
MACVRF_SOO = "64999:1"
# Type-3 ESIs derived from "evpn mh es-sys-mac" and "evpn mh es-id"
ESI = "03:00:11:22:33:44:55:00:00:01"
ESI2 = "03:00:11:22:33:44:66:00:00:02"


def build_topo(tgen):
    # r2 is an eBGP EVPN peer of r1's vrf1 instance: what vrf1 advertises
    # (and withdraws) is observed there
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd_raises(
        "ip link add vrf1 type vrf table 101 && "
        "ip link set r1-eth0 master vrf1 && "
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
    tgen.gears["r2"].load_frr_config(os.path.join(CWD, "r2/frr.conf"))

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


def _hidden_default(router):
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
    step("[{0}] delete AS {1}, hide the default".format(label, delete_as))
    _delete_instances(router, delete_as)
    test_func = functools.partial(_hidden_default, router)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "[{0}] no hidden instance".format(label)

    step("[{0}] revive default (router bgp {1})".format(label, revive_as))
    router.vtysh_cmd(_revive_config(revive_as))
    test_func = functools.partial(_evpn_served_by_default, router)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, "[{0}] revived default lost EVPN instance".format(label)

    # bgp_delete() used to free the EVPN containers of the hidden instance, and
    # writing the l2vpn evpn address-family of the revived instance then
    # crashed bgpd in bgp_config_write_evpn_info() (vnihash == NULL).
    step("[{0}] show running-config on the revived default".format(label))
    router.vtysh_cmd("show running-config")
    status = router.check_router_running()
    assert status == "", "[{0}] daemon died after show running-config: {1}".format(
        label, status
    )
    test_func = functools.partial(_running_config_has_revived_bgp, router, revive_as)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "[{0}] {1}".format(label, res)


def _vrf1_config(as_num):
    """The vrf1 instance: VPN export (keeps the default's MPLS-VPN RIB
    non-empty) and the EVPN session with r2."""
    config = """router bgp {0} vrf vrf1
 bgp router-id 10.200.200.200
 no bgp ebgp-requires-policy
 neighbor 10.10.1.2 remote-as external
 neighbor 10.10.1.2 timers 3 10
 neighbor 10.10.1.2 timers connect 1
 address-family ipv4 unicast
  redistribute connected
  rd vpn export {0}:1
  rt vpn both {0}:1
  export vpn
 exit-address-family
 address-family l2vpn evpn
  neighbor 10.10.1.2 activate
 exit-address-family
exit
"""
    return config.format(as_num)


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
{2}""".format(
        as_num,
        "  advertise-all-vni\n" if advertise_all_vni else "",
        _vrf1_config(as_num),
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
    """bond0 carries an Ethernet Segment (r1/frr.conf); with the VNI on the
    same bridge bgpd must know it as a local ES, and its "up" flag must
    follow the bond's oper state (bgpd processes the oper change in
    bgp_evpn_local_es_add())."""
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
    """ES-EVI of the ESI on the VNI, i.e. bond0 attached to br100."""
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


def _no_vnis(router):
    """No VNI is known to bgpd: either there is no EVPN instance ("{}") or
    its VNI count is zero."""
    output = router.vtysh_cmd("show bgp l2vpn evpn vni json", isjson=True)
    if isinstance(output, dict) and output.get("numVnis", 0) == 0:
        return None
    return "bgpd still knows VNIs: {0}".format(output)


def _zebra_evpn_disabled(router):
    """zebra prints "{}" for "show evpn vni json" while no instance has
    advertise-all-vni configured."""
    output = router.vtysh_cmd("show evpn vni json", isjson=True)
    if output != {}:
        return "zebra still advertises VNIs: {0}".format(output)
    return None


def _es_not_local(router, esi=ESI):
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn es {0} json".format(esi), isjson=True
    )
    if isinstance(output, dict) and "local" in output.get("type", []):
        return "ES {0} is still local to bgpd: {1}".format(esi, output)
    return None


def _running_config_evpn(router, as_num, text, present, vrf=None):
    """text in the "router bgp <as> [vrf <vrf>]" block of
    "show running-config"."""
    output = router.vtysh_cmd("show running-config")
    header = "router bgp {0}{1}\n".format(as_num, " vrf " + vrf if vrf else "")
    start = output.find(header)
    if start < 0:
        return "running-config lacks {0}".format(header.strip())
    block = output[start + len(header) :]
    end = block.find("\nexit\n")
    if end >= 0:
        block = block[:end]
    found = text in block
    if found != present:
        return "{0}: {1!r} present={2}, want {3}".format(
            header.strip(), text, found, present
        )
    return None


def _vni_rd(router, vni, rd, present):
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {0} json".format(vni), isjson=True
    )
    found = isinstance(output, dict) and output.get("rd") == rd
    if found != present:
        return "VNI {0} RD {1} present={2}, want {3}: {4}".format(
            vni, rd, found, present, output
        )
    return None


def _zebra_es_state(router, esi, up):
    """Oper state of the local ES in zebra, which follows the bond."""
    output = router.vtysh_cmd("show evpn es {0} json".format(esi), isjson=True)
    flags = output.get("flags", []) if isinstance(output, dict) else None
    if flags is None or ("operUp" in flags) != up:
        return "zebra ES {0} flags {1}, want operUp={2}".format(esi, flags, up)
    return None


def _evpn_rib_empty(router):
    """No route of any type in the global EVPN RIB: the local type-2 and
    type-3 routes of the VNIs (under the configured RD) must go with the
    VNIs. "{}" means there is no EVPN instance."""
    output = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
    if output == {} or (isinstance(output, dict) and output.get("numPrefix") == 0):
        return None
    return "routes left in the EVPN RIB: {0}".format(output)


def _evpn_routes_under_rd(router, rd, present):
    output = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
    found = isinstance(output, dict) and bool(output.get(rd))
    if found != present:
        return "EVPN routes under RD {0} present={1}, want {2}: {3}".format(
            rd, found, present, output
        )
    return None


def _tunnel_ip(router, ip, count, vrf=None):
    """Reference count of the VTEP IP in the tunnel-IP (martian next-hop)
    table of the instance; None means it must not be listed. Each live VNI
    and each L3VNI holds one reference."""
    output = router.vtysh_cmd(
        "show bgp {0}martian next-hop".format("vrf " + vrf + " " if vrf else "")
    )
    found = None
    # the self-address table comes first, the tunnel-IP table last
    for line in output.split("Tunnel-ip database:")[-1].splitlines():
        if line.startswith("addr: {0},".format(ip)):
            found = int(line.split("count:")[1])
    if found != count:
        return "tunnel IP {0} count {1}, want {2}".format(ip, found, count)
    return None


def _zebra_svi_macip(router, enabled):
    """advertise-svi-ip as zebra sees it ("show evpn")."""
    output = router.vtysh_cmd("show evpn json", isjson=True)
    value = output.get("advertiseSviMacip") if isinstance(output, dict) else None
    if value != ("Yes" if enabled else "No"):
        return "zebra advertiseSviMacip {0}, want enabled={1}".format(value, enabled)
    return None


def _no_evpn_instance(router):
    """bgp_get_evpn()==NULL makes the handler emit "{}"."""
    output = router.vtysh_cmd("show bgp l2vpn evpn json", isjson=True)
    if output != {}:
        return "an instance still serves EVPN: {0}".format(output)
    return None


def _vrf_l3vni(router, vrf, l3vni):
    """L3VNI of the VRF instance (auto-created by zebra's L3VNI add); None
    means the instance must be gone."""
    vrfs = router.vtysh_cmd("show bgp vrfs json", isjson=True).get("vrfs", {})
    if l3vni is None:
        if vrf in vrfs:
            return "instance {0} still exists: {1}".format(vrf, vrfs[vrf])
        return None
    if vrf not in vrfs:
        return "no instance for {0}: {1}".format(vrf, list(vrfs))
    output = router.vtysh_cmd("show bgp vrf {0} vni json".format(vrf), isjson=True)
    value = output.get("vni") if isinstance(output, dict) else None
    if value != str(l3vni):
        return "{0} L3VNI {1}, want {2}".format(vrf, value, l3vni)
    return None


def _peer_es_route(router, present):
    """Type-4 (ES) route of r1's ESI as received by the peer router: the
    instance that owns EVPN advertises it, and withdraws it when it stops
    advertising VNIs."""
    output = router.vtysh_cmd("show bgp l2vpn evpn route type es json", isjson=True)
    prefix = "[4]:[{0}]".format(ESI)
    found = False
    if isinstance(output, dict):
        for rd in output.values():
            if isinstance(rd, dict) and any(k.startswith(prefix) for k in rd):
                found = True
    if found != present:
        return "ES route of {0} at the peer present={1}, want {2}".format(
            ESI, found, present
        )
    return None


def _advertise_all_vni(as_num, vrf=None, enable=True):
    return (
        "configure terminal\n"
        "router bgp {0}{1}\n"
        " address-family l2vpn evpn\n"
        "  {2}advertise-all-vni\n".format(
            as_num, " vrf " + vrf if vrf else "", "" if enable else "no "
        )
    )


def test_bgp_hidden_evpn_revival_vni_rt():
    """ "no router bgp" on the EVPN instance drops its EVPN state even when
    the instance is kept as a hidden instance: zebra is told to stop
    advertising VNIs and SVI MAC-IPs, the VNIs, their local routes, their
    tunnel IP and the local ESs are gone from bgpd and so are
    advertise-all-vni and the EVPN configuration of the instance. ES events
    while hidden are ignored and must not kill bgpd. The revived instance
    has no EVPN state until advertise-all-vni is configured again; zebra
    then replays the VNIs and ESs and the automatic route targets are
    derived from the new AS."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enable advertise-all-vni on AS {0}, learn VNI {1}".format(AS_NEW, VNI))
    r1.vtysh_cmd(_revive_config(AS_NEW, advertise_all_vni=True))
    # EVPN configuration that lives on the instance: an RD for the
    # instance, a configured VNI (kept by "no advertise-all-vni", it must
    # not outlive "no router bgp") with its RD, a MAC-VRF site-of-origin
    # and advertise-svi-ip (a knob zebra keeps state for).
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp {0}\n"
        " address-family l2vpn evpn\n"
        "  rd {1}\n"
        "  mac-vrf soo {2}\n"
        "  advertise-svi-ip\n"
        "  vni {3}\n"
        "   rd {4}\n".format(AS_NEW, DEFAULT_RD, MACVRF_SOO, VNI, VNI_RD)
    )
    test_func = functools.partial(_vni_export_rt, r1, AS_NEW)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_vni_rd, r1, VNI, VNI_RD, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    # the type-3 route of the VNI sits under its configured RD
    test_func = functools.partial(_evpn_routes_under_rd, r1, VNI_RD, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, 1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_zebra_svi_macip, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_running_config_evpn, r1, AS_NEW, "mac-vrf soo", True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_ead_evi_route_present, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res

    step("Delete AS {0}, hide the default: EVPN state is gone".format(AS_NEW))
    _delete_instances(r1, AS_NEW)
    test_func = functools.partial(_hidden_default, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "no hidden instance"
    test_func = functools.partial(_zebra_evpn_disabled, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "hidden default did not disable EVPN in zebra: {0}".format(res)
    test_func = functools.partial(_es_not_local, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    status = r1.check_router_running()
    assert status == "", "daemon died on delete: {0}".format(status)
    # the local routes of the VNI went with it (they are not reaped by the
    # RIB cleanup of a hidden instance) and so did its tunnel IP
    test_func = functools.partial(_evpn_rib_empty, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "local EVPN routes survived no router bgp: {0}".format(res)
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, None)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "tunnel IP survived no router bgp: {0}".format(res)

    # zebra keeps delivering ES events to the hidden instance through the VRF
    # lookup; bgpd ignores them (an unguarded ES add used to kill bgpd in
    # bgp_evpn_es_frag_new(), with no EVPN state on the hidden instance).
    step("ES link-down and link-up while the default is hidden")
    r1.run("ip link set bond0 down")
    test_func = functools.partial(_zebra_es_state, r1, ESI, False)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    status = r1.check_router_running()
    assert status == "", "daemon died on ES link-down while hidden: {0}".format(status)
    r1.run("ip link set bond0 up")
    test_func = functools.partial(_zebra_es_state, r1, ESI, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    status = r1.check_router_running()
    assert status == "", "daemon died on ES link-up while hidden: {0}".format(status)

    step("New ES on bond1, bond0 off br100 and new VNI {0} while hidden".format(VNI2))
    r1.run("ip link set bond0 nomaster")
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
    test_func = functools.partial(_zebra_es_state, r1, ESI2, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    status = r1.check_router_running()
    assert status == "", "daemon died on ES/VNI change while hidden: {0}".format(status)
    test_func = functools.partial(_es_not_local, r1, ESI2)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "hidden instance learnt an ES: {0}".format(res)

    step("Revive default as AS {0} without advertise-all-vni".format(AS_VNI))
    r1.vtysh_cmd(_revive_config(AS_VNI))
    r1.vtysh_cmd("show running-config")
    status = r1.check_router_running()
    assert status == "", "daemon died on revival: {0}".format(status)
    test_func = functools.partial(_evpn_served_by_default, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "revived default lost EVPN instance: {0}".format(res)
    test_func = functools.partial(
        _running_config_evpn, r1, AS_VNI, "advertise-all-vni", False
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "advertise-all-vni survived no router bgp: {0}".format(res)
    test_func = functools.partial(_no_vnis, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "VNIs survived no router bgp: {0}".format(res)
    # the instance RD is shown by "show bgp vrfs" (a configured RD that
    # outlived "no router bgp" crashed here)
    r1.vtysh_cmd("show bgp vrfs json")
    status = r1.check_router_running()
    assert status == "", "daemon died on show bgp vrfs after revival: {0}".format(
        status
    )
    for text in (DEFAULT_RD, "mac-vrf soo", "advertise-svi-ip", " vni {0}".format(VNI)):
        test_func = functools.partial(_running_config_evpn, r1, AS_VNI, text, False)
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
        assert res is None, "EVPN configuration survived no router bgp: {0}".format(res)
    test_func = functools.partial(_evpn_rib_empty, r1)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "stale EVPN routes on the revived instance: {0}".format(res)

    step(
        "Configure advertise-all-vni on AS {0}: zebra replays VNIs and ESs".format(
            AS_VNI
        )
    )
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI))
    test_func = functools.partial(_vni_export_rt, r1, AS_VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_vni_rd, r1, VNI, VNI_RD, False)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "configured RD survived no router bgp: {0}".format(res)
    test_func = functools.partial(_vni_known, r1, VNI2)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    # the old route under the configured RD is gone for good, the replayed
    # VNIs hold one reference each on the tunnel IP (none leaked)
    test_func = functools.partial(_evpn_routes_under_rd, r1, VNI_RD, False)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "stale route under the old RD: {0}".format(res)
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, 2)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        res is None
    ), "tunnel IP reference leaked across the hidden instance: {0}".format(res)
    # zebra was told to stop advertising SVI MAC-IPs before EVPN was
    # disabled on it (it only reports the knob while EVPN is enabled)
    test_func = functools.partial(_zebra_svi_macip, r1, False)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "zebra kept advertise-svi-ip: {0}".format(res)
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_local_es_state, r1, True, ESI2)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "ES configured while hidden: {0}".format(res)
    # bond0 left br100 while hidden: no ES-EVI, no EAD-EVI route
    test_func = functools.partial(_ead_evi_route_present, r1, False)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        res is None
    ), "stale EAD-EVI route after ES-EVI delete while hidden: {0}".format(res)
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


def test_bgp_hidden_evpn_vrf_owner_while_hidden():
    """A VRF instance may take over as the EVPN instance while the default
    is a hidden instance: zebra was told to stop advertising VNIs for the
    default, so it accepts the VRF. Giving EVPN up again while the default
    is still hidden must not hand it to the hidden instance: the L3VNI delete of
    a tenant VRF is processed and its instance goes away. Reviving the
    default must neither take EVPN back nor crash: it comes back without
    advertise-all-vni."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Delete AS {0}, hide the default".format(AS_VNI))
    _delete_instances(r1, AS_VNI)
    test_func = functools.partial(_hidden_default, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "no hidden instance"
    test_func = functools.partial(_zebra_evpn_disabled, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res

    step("L3VNI {0} for tenant vrf2 while the default is hidden".format(L3VNI))
    r1.cmd_raises(
        "ip link add vrf2 type vrf table 102 && "
        "ip link set vrf2 up && "
        "ip link add br{0} type bridge && "
        "ip link set br{0} address 00:aa:bb:cc:dd:01 && "
        "ip link set br{0} master vrf2 && "
        "ip link add vxlan{0} type vxlan id {0} dstport 4789 "
        "local {1} nolearning && "
        "ip link set vxlan{0} master br{0} && "
        "ip link set vxlan{0} up && "
        "ip link set br{0} up".format(L3VNI, VTEP_IP)
    )
    r1.vtysh_cmd("configure terminal\nvrf vrf2\n vni {0}\n".format(L3VNI))

    step("advertise-all-vni under vrf1 while the default is hidden")
    r1.vtysh_cmd("configure terminal\n" + _vrf1_config(AS_VNI))
    output = r1.vtysh_cmd(_advertise_all_vni(AS_VNI, vrf="vrf1"))
    assert "unconfigure" not in output, "vrf1 refused advertise-all-vni: {0}".format(
        output
    )
    test_func = functools.partial(_vni_known, r1, VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, "vrf1 did not learn the VNIs: {0}".format(res)
    # zebra replays the L3VNI too: bgpd creates the vrf2 instance for it
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", L3VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_peer_es_route, r2, True)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, "vrf1 did not advertise the ES route: {0}".format(res)
    # the two L2VNIs and the L3VNI of vrf2 hold one tunnel IP reference each
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, 3, "vrf1")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    status = r1.check_router_running()
    assert status == "", "daemon died on advertise-all-vni under vrf1: {0}".format(
        status
    )

    step("no advertise-all-vni under vrf1 while the default is still hidden")
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI, vrf="vrf1", enable=False))
    test_func = functools.partial(_zebra_evpn_disabled, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    # EVPN is not handed to the hidden instance (bgp_get_evpn() is NULL) and the
    # L3VNI delete zebra answers with is processed without an EVPN
    # instance: the auto-created vrf2 instance is gone
    test_func = functools.partial(_no_evpn_instance, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "EVPN handed to the hidden default: {0}".format(res)
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", None)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "L3VNI delete refused while the default is hidden: {0}".format(
        res
    )
    # the local ESs are deleted with their routes (zebra's deletes can not
    # be processed without an EVPN instance)
    test_func = functools.partial(_es_not_local, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_peer_es_route, r2, False)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "ES route not withdrawn by no advertise-all-vni: {0}".format(
        res
    )
    # the tenant L3VNI was torn down while vrf1 still was the EVPN instance:
    # no tunnel IP reference left behind
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, None, "vrf1")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        res is None
    ), "tunnel IP reference leaked by no advertise-all-vni: {0}".format(res)
    status = r1.check_router_running()
    assert status == "", "daemon died on no advertise-all-vni under vrf1: {0}".format(
        status
    )

    step("advertise-all-vni under vrf1 again")
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI, vrf="vrf1"))
    test_func = functools.partial(_vni_known, r1, VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, "vrf1 did not learn the VNIs: {0}".format(res)
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", L3VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    # the import route-target tables of vrf1 list the vrf2 instance that
    # was created for the replayed L3VNI, not the one deleted while vrf1
    # was not the EVPN instance (walking them used to dereference it)
    r1.vtysh_cmd("show bgp l2vpn evpn vrf-import-rt json")
    status = r1.check_router_running()
    assert status == "", "daemon died walking the VRF import RTs: {0}".format(status)

    step("Revive default as AS {0}: vrf1 stays the EVPN instance".format(AS_VNI))
    r1.vtysh_cmd(_revive_config(AS_VNI))
    r1.vtysh_cmd("show running-config")
    status = r1.check_router_running()
    assert status == "", "daemon died on revival: {0}".format(status)
    test_func = functools.partial(
        _running_config_evpn, r1, AS_VNI, "advertise-all-vni", False
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(
        _running_config_evpn, r1, AS_VNI, "advertise-all-vni", True, "vrf1"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_vni_known, r1, VNI)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "VNIs lost on revival of the default: {0}".format(res)

    step("no advertise-all-vni on the default, which does not advertise VNIs")
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI, enable=False))
    # nothing to disable there: vrf1 keeps EVPN, its VNIs and the tenant L3VNI
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", L3VNI)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "no advertise-all-vni on a non-EVPN instance: {0}".format(res)
    test_func = functools.partial(_vni_known, r1, VNI)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, res
    test_func = functools.partial(_tunnel_ip, r1, VTEP_IP, 3, "vrf1")
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, res

    step("Move EVPN back to the default")
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI, vrf="vrf1", enable=False))
    test_func = functools.partial(_zebra_evpn_disabled, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    r1.vtysh_cmd(_advertise_all_vni(AS_VNI))
    test_func = functools.partial(_vni_export_rt, r1, AS_VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_vni_rd, r1, VNI, VNI_RD, False)
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert res is None, "configured RD survived no router bgp: {0}".format(res)
    test_func = functools.partial(_local_es_state, r1, True)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", L3VNI)
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert res is None, res

    step("Remove the L3VNI of vrf2 again")
    r1.vtysh_cmd("configure terminal\nvrf vrf2\n no vni {0}\n".format(L3VNI))
    test_func = functools.partial(_vrf_l3vni, r1, "vrf2", None)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    r1.cmd_raises(
        "ip link del vxlan{0} && ip link del br{0} && ip link del vrf2".format(L3VNI)
    )


def test_bgp_hidden_evpn_shutdown_with_hidden_default():
    """bgpd must shut down cleanly while the default is a hidden instance
    whose VNI and local ES were dropped when it was hidden. Runs last, it
    stops the router."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Delete AS {0}, hide the default".format(AS_VNI))
    _delete_instances(r1, AS_VNI)
    test_func = functools.partial(_hidden_default, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "no hidden instance"
    test_func = functools.partial(_zebra_evpn_disabled, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res
    test_func = functools.partial(_es_not_local, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, res

    step("Stop the router with the hidden instance in place")
    # SIGTERM to the daemons. stop() returns the core, sanitizer and
    # memory-leak reports of the daemons; a crash or a sanitizer abort on
    # the way out fails the test, leaked allocations at exit are only
    # logged by the framework, as for every other test module.
    errors = r1.stop()
    assert "CORE FOUND" not in errors, "daemon crashed on shutdown: {0}".format(errors)
    assert "AddressSanitizer" not in errors, "sanitizer report on shutdown: {0}".format(
        errors
    )


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
