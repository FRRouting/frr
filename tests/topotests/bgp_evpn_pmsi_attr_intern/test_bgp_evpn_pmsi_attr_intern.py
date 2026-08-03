#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_pmsi_attr_intern.py
#
# Copyright (c) 2026 Robin Christ for partimus GmbH
#

"""
Regression test: the PMSI Tunnel attribute of EVPN type-3 (IMET) routes
must survive attribute interning on the receiving side.

pmsi_tnl_type/tunn_id live in the lazily allocated attr->extra
("struct attr_extra", allocated by bgp_attr_extra_get() when
bgp_attr_pmsi_tunnel() stores the parsed PMSI).

The parent attr "struct attr attr" lives on the stack of bgp_update_receive(),
where it is filled by bgp_attr_parse() once per UPDATE message.
The EVPN NLRI parser gets this "parent attr" and passes it to bgp_update() once
per EVPN NLRI.
Unless the parser self-anchors that attr (attr->attr_intern_reuse.parsed_attr),
bgp_attr_owns_extra() treats it as transient and the intern path may
steal its attr->extra.

The trigger is "soft-reconfiguration inbound" on the EVPN session
(configured below - without it the bug does not manifest):

  bgp_update_receive()
    bgp_attr_parse(&attr, ...)  one "struct attr attr" per UPDATE (the
                                parent), the type-3 parse puts PMSI into
                                attr.extra, a heap-allocated
                                "struct attr_extra" (bgp_attr_pmsi_tunnel())
    bgp_nlri_parse(peer, NLRI_ATTR_ARG, &nlris[i], 0)
                                per-AFI/SAFI dispatcher switch
      bgp_nlri_parse_evpn(peer, attr, packet, withdraw)
                                loops over the NLRIs of this attribute
                                block. The fix self-anchors
                                attr->attr_intern_reuse.parsed_attr =
                                attr here for the loop's duration
        process_type3_route(..., attr, ...)
          bgp_update(..., attr, ...)
            bgp_adj_in_set(dest, peer, attr, ...)
                                only with soft-reconfig inbound
              adj->attr = bgp_attr_intern(attr)
                                first arrival: attrhash miss
                bgp_attr_hash_alloc(val)   val == attr (the parent)!
                                bgp_attr_owns_extra(val) is true for an
                                unanchored parent -> TRANSFERS val->extra
                                to the hashed copy, val->extra = NULL
            new_attr = *attr    RIB working copy: new_attr.extra == NULL
            attr_new = bgp_attr_intern(&new_attr)
                                RIB attr interned without PMSI
            evpn_zebra_install()
                                remote VTEP added with
                                flood_control = VXLAN_FLOOD_DISABLED

This bug is deterministic and not a memory error, so ASAN does not
report it.
A re-delivery of the same route heals it, because bgp_adj_in_set()
then finds the stored adj-in attr equal to the incoming one and skips
the intern).
This is the reason why this failure mode was noticed on clean restarts.

The receiver then holds the type-3 route without its
Ingress-Replication PMSI marker.
As a consequence, zebra installs the remote VTEP with flood control disabled
("flood": "-" instead of "HER"), no head-end replication FDB entries are
programmed and all BUM traffic in the VNI blackholes.

This bug is verifiable by inspecting zebra's per-VNI per-remote-VTEP
flood mode, which is directly derived from the PMSI value bgpd retained.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNIS = list(range(101, 111))

ROUTERS = {
    "r1": {"vtep": "10.0.0.1", "peer": "10.0.0.2"},
    "r2": {"vtep": "10.0.0.2", "peer": "10.0.0.1"},
}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    cmds_vxlan = [
        "ip link add name bridge-{vni} up type bridge stp_state 0",
        "ip link set dev bridge-{vni} up",
        "ip link add name vxlan-{vni} type vxlan id {vni} dstport 4789 "
        "dev {rname}-eth0 local {vtep}",
        "ip link set dev vxlan-{vni} master bridge-{vni}",
        "ip link set vxlan-{vni} up type bridge_slave "
        "learning off flood off mcast_flood off",
    ]

    for rname, params in ROUTERS.items():
        router = tgen.gears[rname]
        for vni in VNIS:
            for cmd in cmds_vxlan:
                formatted = cmd.format(rname=rname, vni=vni, vtep=params["vtep"])
                logger.info("cmd to {}: {}".format(rname, formatted))
                router.cmd_raises(formatted)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Assert the EVPN session comes up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, params in ROUTERS.items():
        router = tgen.gears[rname]
        expected = {"peers": {params["peer"]: {"state": "Established"}}}

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn summary json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, '"{}" BGP EVPN session did not establish'.format(rname)


def _check_flood_her(rname):
    """
    Every VNI's remote VTEP must be installed with head-end replication
    ("HER"). With the PMSI attribute lost in interning, zebra reports
    "-" (flood disabled) instead.
    """
    tgen = get_topogen()
    router = tgen.gears[rname]
    peer = ROUTERS[rname]["peer"]

    for vni in VNIS:
        expected = {
            "vni": vni,
            "type": "L2",
            "numRemoteVteps": 1,
            "remoteVteps": [{"ip": peer, "flood": "HER"}],
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show evpn vni {} json".format(vni),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, (
            '"{}" VNI {}: remote VTEP {} not installed with flood "HER" '
            "(PMSI Tunnel attribute lost?)".format(rname, vni, peer)
        )


def test_evpn_flood_her_initial():
    "Initial exchange: all VNIs must have HER flood entries on both VTEPs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ROUTERS:
        _check_flood_her(rname)


def test_evpn_flood_her_after_soft_clear():
    """
    Re-parse all routes in one burst (this is the post-restart convergence
    pattern that most reliably trips the lost-attr->extra bug) and verify
    the PMSI marker still survives.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ROUTERS:
        tgen.gears[rname].vtysh_cmd("clear bgp l2vpn evpn * soft in")

    for rname in ROUTERS:
        _check_flood_her(rname)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
