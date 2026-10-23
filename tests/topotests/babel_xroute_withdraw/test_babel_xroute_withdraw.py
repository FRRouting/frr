#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_xroute_withdraw.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_xroute_withdraw.py: When zebra withdraws a redistributed route
(ZEBRA_REDISTRIBUTE_ROUTE_DEL), babeld must not merely flush the xroute: it
must send an explicit retraction when no Babel route is left for the prefix,
and it must reinstall and advertise a feasible Babel fallback route that the
xroute had suppressed (the fallback is uninstalled when the xroute is added).

Topology:

    r2-eth1 (stub: PB=198.51.100.0/24, QB=198.51.201.0/24, added at runtime)
       |
    [ r2 ] --- r2-eth0 --- sw1 --- r1-eth0 --- [ r1 ] --- r1-eth1 --- sw2 --- r3-eth0 --- [ r3 ]
                                                  |
                                            r1-eth2 (stub: PA=198.51.101.0/24, QA=198.51.102.0/24, added at runtime)
                                                  |
                                            r1-eth3 (stub: PB address added/removed at runtime)

Scenario A (retraction of an xroute-only prefix): r1 redistributes connected
PA and QA (addresses added on r1-eth2 at runtime, so the triggered update
reaches the already-established neighbours); r2 and r3 learn both via Babel.
Deleting PA's address on r1-eth2 makes zebra send a route DEL.  Babel must
retract PA from r2 and r3 promptly (metric-infinity update), far below the
natural hold time, while QA keeps forwarding.  Re-adding the address
re-advertises PA, "no redistribute" withdraws both prefixes (the
pre-existing flush_xroutes_by_type path), and re-enabling restores both.

Scenario B (fallback reinstall): r2 originates PB and QB (addresses added on
r2-eth1 at runtime).  r1 learns PB via Babel (installed) and readvertises it
to r3.  Adding PB as a connected address on r1-eth3 makes zebra send a route
ADD: the resulting xroute suppresses the Babel fallback (uninstalled).
Deleting the address again makes zebra send a route DEL: babeld must
reinstall the fallback through r2 and advertise it to r3 with its finite
metric (r3's entry switches back to r2's router-id), instead of blackholing
PB locally and starving r3 until the hold time expires.  QB must keep
forwarding on r1 and r3 throughout.
Two guards make the unfixed build fail deterministically instead of being
rescued by coincidence.  r2-eth0 and r1-eth1 use a long update-interval
(600 s), so periodic updates cannot reinstall the fallback within the test
window.  Right before the route DEL, r1 gets an input distribute-list on
r1-eth0 denying PB, so no later update from r2 (periodic, resent, or
answering a request) can reinstall the fallback on the unfixed build; the
input filter leaves r1's already-learned route to PB untouched, so the
fixed build can still reinstall it from its own route table.
"""

import os
import re
import sys
import pytest
from functools import partial

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

PA = "198.51.101.0/24"  # scenario A target, originated by r1 (connected)
QA = "198.51.102.0/24"  # scenario A unrelated control, originated by r1
PB = "198.51.100.0/24"  # scenario B target, originated by r2, xroute on r1
QB = "198.51.201.0/24"  # scenario B unrelated control, originated by r2

# The Babel hold time is ~96 s with the default 16 s update interval; an
# explicit retraction or fallback readvertisement arrives within a few
# seconds, so these windows are far below the natural timeout.
RETRACT_COUNT = 30  # run_and_expect count=30, wait=1 -> 30 s window
RELEARN_COUNT = 40  # re-add / re-redistribute convergence window

# Cross-test state: router-ids observed at runtime.
STATE = {}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])
    sw2.add_link(tgen.gears["r3"])

    # Stubs: r2 originates PB/QB, r1 originates PA/QA and hosts PB at runtime
    for switch, router in [("sw3", "r2"), ("sw4", "r1"), ("sw5", "r1")]:
        sw = tgen.add_switch(switch)
        sw.add_link(tgen.gears[router])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    # Drop the runtime input filter installed by test_b_delete_reinstalls_fallback
    # so babeld does not report the access-list allocations as memory leaks at
    # exit.  The router may already be gone when earlier tests failed.
    try:
        tgen.gears["r1"].vtysh_cmd(
            "configure terminal\n"
            "router babel\n"
            "no distribute-list deny-pb in r1-eth0\n"
            "exit\n"
            "no access-list deny-pb\n"
        )
    except Exception:
        pass
    tgen.stop_topology()


def _forwarding_nexthops(router, prefix):
    """Return the list of active forwarding nexthops for prefix on router.

    A retracted/unreachable route stays in the RIB with a reject ("unreachable")
    nexthop and no gateway, so it is not counted here.
    """
    output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    if not output or prefix not in output:
        return []
    fwd = []
    for entry in output[prefix]:
        if entry.get("protocol") != "babel":
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("unreachable") or nh.get("reject") or nh.get("blackhole"):
                continue
            if nh.get("ip"):
                fwd.append(nh)
    return fwd


def _reachable(router, prefix):
    "Return None when prefix is installed via babel with a forwarding nexthop."
    if _forwarding_nexthops(router, prefix):
        return None
    return "{} is not reachable via babel on {}".format(prefix, router.name)


def _retracted(router, prefix):
    "Return None when prefix is gone or has no forwarding nexthop left."
    if not _forwarding_nexthops(router, prefix):
        return None
    return "{} still has a forwarding nexthop on {}".format(prefix, router.name)


def _babel_route_line(router, prefix):
    return router.vtysh_cmd("show babel route {}".format(prefix))


def _babel_installed(router, prefix):
    return "(installed)" in _babel_route_line(router, prefix)


def _babel_exported(router, prefix):
    return "(exported)" in _babel_route_line(router, prefix)


def _refmetric(router, prefix):
    "Return the refmetric of the babel route for prefix, or None."
    m = re.search(r"refmetric (\d+)", _babel_route_line(router, prefix))
    return int(m.group(1)) if m else None


def _route_id(router, prefix):
    "Return the router-id of the babel route for prefix, or None."
    m = re.search(r"id ((?:[0-9a-f]{2}:){7}[0-9a-f]{2})", _babel_route_line(router, prefix))
    return m.group(1) if m else None


def _expect(func, count, message):
    _, result = topotest.run_and_expect(func, None, count=count, wait=1)
    assert result is None, message


def _check_installed(router, prefix):
    "Return None when prefix has an installed babel route."
    if not _babel_installed(router, prefix):
        return "{} does not have {} installed".format(router.name, prefix)
    return None


def _check_exported(router, prefix):
    "Return None when prefix is present as an exported xroute."
    if not _babel_exported(router, prefix):
        return "{} does not export {} yet".format(router.name, prefix)
    return None


def _check_not_installed(router, prefix):
    "Return None when prefix has no installed babel route."
    if _babel_installed(router, prefix):
        return "{} still has {} installed".format(router.name, prefix)
    return None


def _check_refmetric(router, prefix, value):
    "Return None when the babel route for prefix has the given refmetric."
    if _refmetric(router, prefix) != value:
        return "{} has refmetric {} for {}, expected {}".format(
            router.name, _refmetric(router, prefix), prefix, value
        )
    return None


def _check_route_id(router, prefix, router_id):
    "Return None when the babel route for prefix carries the given router-id."
    if _route_id(router, prefix) != router_id:
        return "{} has router-id {} for {}, expected {}".format(
            router.name, _route_id(router, prefix), prefix, router_id
        )
    return None


def test_converge_protocols():
    "Wait for Babel adjacencies: r1-r2 and r1-r3."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router = tgen.gears[rname]

        def check_convergence(router=router):
            output = router.vtysh_cmd("show babel neighbor")
            if "Neighbour" not in output:
                return "{} has no babel neighbor yet".format(router.name)
            return None

        _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
        assert result is None, "{} failed to establish babel neighbor".format(rname)

    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show babel neighbor")
    assert "dev r1-eth0" in output and "dev r1-eth1" in output, (
        "r1 did not establish babel neighbors on both links"
    )


def test_a_xroute_learned():
    "r2 and r3 must learn PA and QA from r1 as reachable routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Adding %s and %s on r1-eth2 (zebra route ADD)", PA, QA)
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth2\n"
        "ip address 198.51.101.1/24\n"
        "ip address 198.51.102.1/24\n"
    )
    for prefix in (PA, QA):
        _expect(
            partial(_check_exported, r1, prefix),
            60,
            "r1 did not import {} into babel xroutes".format(prefix),
        )
    for rname in ("r2", "r3"):
        router = tgen.gears[rname]
        for prefix in (PA, QA):
            _expect(
                partial(_reachable, router, prefix),
                60,
                "{} did not learn a reachable {} via babel".format(rname, prefix),
            )


def test_a_delete_sends_retraction():
    "Deleting PA's address on r1 must retract PA from r2 and r3 promptly."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    for router in (r2, r3):
        _expect(
            partial(_reachable, router, PA),
            60,
            "{} never had a reachable {} to retract".format(router.name, PA),
        )

    logger.info("Deleting %s from r1-eth2 (zebra route DEL)", PA)
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth2\n"
        "no ip address 198.51.101.1/24\n"
    )

    # The retraction must arrive far below the natural hold time of ~96 s.
    for router in (r2, r3):
        _expect(
            partial(_retracted, router, PA),
            RETRACT_COUNT,
            "{} did not retract {} after the zebra route DEL".format(router.name, PA),
        )

    # The unrelated prefix QA must keep forwarding.
    for router in (r2, r3):
        assert _forwarding_nexthops(router, QA), (
            "{} lost the unrelated prefix {} after the DEL".format(router.name, QA)
        )


def test_a_readd_readvertises():
    "Re-adding PA's address on r1-eth2 must re-advertise PA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Re-adding %s on r1-eth2", PA)
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth2\n"
        "ip address 198.51.101.1/24\n"
    )

    for rname in ("r2", "r3"):
        router = tgen.gears[rname]
        _expect(
            partial(_reachable, router, PA),
            RELEARN_COUNT,
            "{} did not relearn a reachable {} after re-add".format(rname, PA),
        )


def test_a_no_redistribute_withdraws():
    "'no redistribute ipv4 connected' must still withdraw PA and QA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Removing 'redistribute ipv4 connected' on r1")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router babel\n"
        "no redistribute ipv4 connected\n"
    )

    for rname in ("r2", "r3"):
        router = tgen.gears[rname]
        for prefix in (PA, QA):
            _expect(
                partial(_retracted, router, prefix),
                RETRACT_COUNT,
                "{} did not retract {} after 'no redistribute'".format(rname, prefix),
            )


def test_a_redistribute_restores():
    "Re-enabling 'redistribute ipv4 connected' must restore PA and QA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Re-adding 'redistribute ipv4 connected' on r1")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router babel\n"
        "redistribute ipv4 connected\n"
    )

    for rname in ("r2", "r3"):
        router = tgen.gears[rname]
        for prefix in (PA, QA):
            _expect(
                partial(_reachable, router, prefix),
                RELEARN_COUNT,
                "{} did not relearn a reachable {} after re-redistribute".format(
                    rname, prefix
                ),
            )


def test_b_fallback_learned():
    "r1 must learn PB via r2 (installed); r3 must learn PB via r1."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    logger.info("Adding %s and %s on r2-eth1 (zebra route ADD)", PB, QB)
    r2.vtysh_cmd(
        "configure terminal\n"
        "interface r2-eth1\n"
        "ip address 198.51.100.1/24\n"
        "ip address 198.51.201.1/24\n"
    )
    _expect(
        partial(_check_installed, r1, PB),
        60,
        "r1 did not install the babel fallback for {}".format(PB),
    )
    _expect(
        partial(_reachable, r3, PB),
        60,
        "r3 did not learn a reachable {} via r1".format(PB),
    )
    # r1's fallback carries r2's router-id; remember it for later checks.
    STATE["r2_id"] = _route_id(r1, PB)
    assert STATE["r2_id"] is not None, "no router-id found for {} on r1".format(PB)


def test_b_xroute_suppresses_fallback():
    "Adding PB on r1-eth3 must export an xroute and un-install the fallback."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Adding %s on r1-eth3 (zebra route ADD -> xroute)", PB)
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth3\n"
        "ip address 198.51.100.2/24\n"
    )

    _expect(
        partial(_check_exported, r1, PB),
        30,
        "r1 did not import {} into babel xroutes".format(PB),
    )
    _expect(
        partial(_check_not_installed, r1, PB),
        30,
        "r1 kept the babel fallback for {} installed under the xroute".format(PB),
    )
    # r3 must see the xroute advertisement: refmetric drops to 0 and the
    # router-id switches from r2's to r1's.
    r3 = tgen.gears["r3"]
    _expect(
        partial(_check_refmetric, r3, PB, 0),
        30,
        "r3 did not see the xroute advertisement for {}".format(PB),
    )
    STATE["r1_id"] = _route_id(r3, PB)
    assert STATE["r1_id"] is not None
    assert STATE["r1_id"] != STATE["r2_id"], (
        "r3's router-id for {} did not switch to r1's xroute id".format(PB)
    )
    # QB keeps flowing through r2 while the xroute exists.
    _expect(
        partial(_reachable, r1, QB),
        30,
        "r1 lost the unrelated prefix {}".format(QB),
    )


def test_b_delete_reinstalls_fallback():
    "Deleting PB on r1-eth3 must reinstall the fallback and advertise it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    # Stop r1 from accepting any further updates for PB from r2: on the
    # unfixed build such an update (resent or request-driven) is the only
    # thing that could reinstall the fallback by coincidence.  An input
    # filter leaves r1's already-learned feasible route to PB untouched,
    # which is exactly what the fixed build reinstalls; it also does not
    # make r2 retract PB, unlike an output filter on r2 would.
    logger.info("Filtering %s out of r1-eth0 input updates", PB)
    r1.vtysh_cmd(
        "configure terminal\n"
        "access-list deny-pb deny 198.51.100.0/24\n"
        "access-list deny-pb permit any\n"
        "router babel\n"
        "distribute-list deny-pb in r1-eth0\n"
    )

    logger.info("Deleting %s from r1-eth3 (zebra route DEL)", PB)
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth3\n"
        "no ip address 198.51.100.2/24\n"
    )

    # The fallback must be reinstalled locally, far below the hold time.
    _expect(
        partial(_check_installed, r1, PB),
        RETRACT_COUNT,
        "r1 did not reinstall the babel fallback for {} after the zebra "
        "route DEL".format(PB),
    )
    assert _forwarding_nexthops(r1, PB), (
        "r1 has no forwarding route for {} after the DEL".format(PB)
    )
    assert _route_id(r1, PB) == STATE["r2_id"], (
        "r1's reinstalled fallback for {} does not carry r2's router-id".format(PB)
    )

    # r3 must keep a reachable route via r1, now with r2's router-id and a
    # finite refmetric again (not the stale xroute advertisement).
    _expect(
        partial(_check_route_id, r3, PB, STATE["r2_id"]),
        RETRACT_COUNT,
        "r3's {} did not switch back to r2's router-id".format(PB),
    )
    assert _forwarding_nexthops(r3, PB), (
        "r3 has no forwarding route for {} after the DEL".format(PB)
    )
    refmetric = _refmetric(r3, PB)
    assert refmetric is not None and refmetric > 0, (
        "r3's {} still shows the xroute advertisement (refmetric {})".format(
            PB, refmetric
        )
    )

    # The unrelated prefix QB must keep forwarding on r1 and r3.
    for router in (r1, r3):
        assert _forwarding_nexthops(router, QB), (
            "{} lost the unrelated prefix {} after the DEL".format(router.name, QB)
        )


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
