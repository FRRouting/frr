#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_vrf_metaq_leak.py
#

"""
Regression test for the zebra RIB meta-queue "stuck route" bug.

Background
----------
zebra tracks, per route_node (rib_dest_t->flags), a RIB_ROUTE_QUEUED bit that
says "this node is already sitting on a meta-queue sub-queue, don't enqueue it
again".  The normal dequeue path (process_subq_route) clears that bit.

When a VRF is *disabled* (e.g. its kernel netdev is recreated with a new
ifindex, or - for a user-configured VRF - the netdev is removed), zebra flushes
that VRF's nodes off the meta-queue via meta_queue_free()/rib_meta_queue_free().
The buggy version of rib_meta_queue_free() removed the node from the sub-queue
list but never cleared RIB_ROUTE_QUEUED.  Because a non-default VRF's table (and
its dests) are *retained* across a disable, the stale bit survived.  From then
on every rib_meta_queue_add() for that node was rejected as "already queued",
rib_process() never ran, and the node's routes were stuck ROUTE_ENTRY_CHANGED /
inactive until the daemon was restarted.

Reproduction strategy (deterministic)
-------------------------------------
1. Put kernel routes in user-VRF RED and let them install.
2. Freeze meta-queue processing with `zebra work-queue 10000` so anything we
   enqueue from here on just sits on its sub-queue.
3. Flap an interface: if_up() -> rib_update_handle_vrf_all(RIB_UPDATE_KERNEL)
   sets ROUTE_ENTRY_CHANGED and calls rib_queue_add() *directly* on RED's kernel
   route nodes, parking them on the (frozen) Kernel Routes sub-queue.
4. Remove RED's netdev -> zebra_vrf_disable() -> meta_queue_free() flushes those
   parked nodes.  Buggy zebra leaves RIB_ROUTE_QUEUED set; fixed zebra clears it.
5. Un-freeze, recreate RED, re-add the routes.

With the bug the re-added routes never get processed (stuck inactive).
With the fix they install normally.
"""

import os
import sys
import json
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

VRF = "RED"
TABLE = 1010
PREFIXES = ["10.0.0.{}/32".format(i) for i in range(10, 18)]
NHOP = "169.254.0.1"


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _add_vrf_netdev(r1):
    r1.run("ip link add {} type vrf table {}".format(VRF, TABLE))
    r1.run("ip link set {} up".format(VRF))
    r1.run("ip link set dev r1-eth0 master {}".format(VRF))
    r1.run("ip link set dev r1-eth0 up")


def _add_kernel_routes(r1):
    for p in PREFIXES:
        r1.run(
            "ip route replace {} via {} dev r1-eth0 onlink proto 200 "
            "metric 15 table {}".format(p, NHOP, TABLE)
        )


def _route_is_active(r1, prefix):
    out = r1.vtysh_cmd("show ip route vrf {} {} json".format(VRF, prefix))
    try:
        data = json.loads(out)
    except ValueError:
        return "no json for {}: {}".format(prefix, out)
    entries = data.get(prefix)
    if not entries:
        return "{} absent from RIB".format(prefix)
    re = entries[0]
    nhs = re.get("nexthops", [])
    active = any(nh.get("active") for nh in nhs)
    if not active or not re.get("selected") or not re.get("installed"):
        return "{} stuck (selected={} installed={} active={}) status={}".format(
            prefix,
            re.get("selected"),
            re.get("installed"),
            active,
            re.get("internalStatus"),
        )
    return None


def _all_routes_active(r1):
    for p in PREFIXES:
        bad = _route_is_active(r1, p)
        if bad:
            return bad
    return None


def test_vrf_disable_metaq_leak():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Create VRF RED netdev + kernel routes, confirm they install")
    _add_vrf_netdev(r1)
    r1.run("ip link add metaqflap type dummy")
    r1.run("ip link set metaqflap up")
    _add_kernel_routes(r1)

    test_func = partial(_all_routes_active, r1)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "routes never installed on initial add: {}".format(res)

    step("Freeze the meta-queue so re-queued nodes park on the Kernel sub-queue")
    r1.vtysh_cmd("configure terminal\nzebra work-queue 10000")

    step("Flap an interface: parks RED's kernel route nodes on the frozen queue")
    for _ in range(3):
        r1.run("ip link set metaqflap down")
        r1.run("ip link set metaqflap up")

    step("Disable VRF RED (remove netdev) -> meta_queue_free() flushes the queue")
    # NOTE: "VRF disable" here is the zebra lifecycle event zebra_vrf_disable(),
    # NOT removing the `vrf RED` stanza from the FRR config.  It is driven purely
    # by the kernel netdev: deleting the `type vrf` device sends RTM_DELLINK,
    # which lib/vrf.c turns into vrf_delete() -> vrf_disable().  Because `vrf RED`
    # is user-configured, vrf_delete() returns before the delete hook
    # (lib/vrf.c, vrf_is_user_cfged check), so only zebra_vrf_disable() runs and
    # the VRF's route table - and its route_node/rib_dest_t objects - are
    # RETAINED.  meta_queue_free() then flushes RED's nodes off the sub-queue;
    # the buggy rib_meta_queue_free() leaves RIB_ROUTE_QUEUED set on those kept
    # dests.  (In production the same disable came from the VRF device being
    # recreated with a new ifindex - a vrf-id change - not a config edit.)
    r1.run("ip link set dev r1-eth0 nomaster")
    r1.run("ip link del dev {}".format(VRF))

    step("Un-freeze processing")
    r1.vtysh_cmd("configure terminal\nno zebra work-queue")

    step("Re-enable VRF RED and re-add the same kernel routes")
    _add_vrf_netdev(r1)
    _add_kernel_routes(r1)

    step("Routes must install again (buggy zebra leaves them stuck inactive)")
    test_func = partial(_all_routes_active, r1)
    _, res = topotest.run_and_expect(test_func, None, count=40, wait=1)
    assert res is None, (
        "VRF route stuck after disable/re-enable - meta-queue bit leak: "
        "{}".format(res)
    )
    logger.info("All VRF routes recovered after disable/re-enable")


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.abspath(__file__)] + sys.argv[1:]))
