#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_mainloop_startup_init.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_mainloop_startup_init.py: `router babel` and `network <if>` in
one startup batch must not leave babeld with an unset router-id.

Topology:

    r1-eth1 (stub 10.1.1.0/24)          r2-eth1 (stub 10.1.2.0/24)
       |                                   |
    [ r1 ] --- r1-eth0 --- sw1 --- r2-eth0 --- [ r2 ]

r1's startup config carries `router babel` and `network r1-eth0` in the
same batch.  babel_create_routing_process() arms babel_init_routing_process()
on t_update with a 200 ms delay; an unguarded babel_schedule_now() from
interface_recalculate() cancels it, so myid/myseqno stay unset and every
Update r1 originates carries an all-zero router-id and is dropped by r2.
r2 must still learn 10.1.1.0/24.
"""

import os
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

R1_PREFIX = "10.1.1.0/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Babel link: r1-eth0 <-> r2-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    # Stubs carrying the originated prefixes
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "startup_init/{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_BABEL,
            os.path.join(CWD, "startup_init/{}/babeld.conf".format(rname)),
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _forwarding_nexthops(router, prefix):
    """Return the list of active forwarding nexthops for prefix on router.

    A retracted/unreachable route stays in the RIB with a reject
    ("unreachable") nexthop and no gateway, so it is not counted here.
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


def _prefix_reachable(router, prefix):
    "Return None when prefix is installed via babel with a forwarding nexthop."
    if _forwarding_nexthops(router, prefix):
        return None
    return "{} is not reachable via babel on {}".format(prefix, router.name)


def test_startup_same_batch_route_learned():
    "r2 must learn r1's stub even though r1's router babel + network were one batch."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2, R1_PREFIX), None, count=60, wait=1
    )
    assert result is None, "r2 did not learn a reachable {} via babel".format(R1_PREFIX)


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
