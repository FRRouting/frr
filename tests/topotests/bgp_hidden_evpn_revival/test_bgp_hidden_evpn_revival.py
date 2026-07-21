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
        "ip link set vrf1 up"
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


def _revive_config(as_num):
    return """configure terminal
router bgp {0}
 bgp router-id 10.200.200.200
 no bgp ebgp-requires-policy
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
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
""".format(as_num)


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


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
