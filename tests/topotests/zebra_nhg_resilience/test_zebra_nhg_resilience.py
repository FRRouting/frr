#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Test that 'zebra nexthop-group resilience ...' causes every zebra-created
multipath nexthop group to be installed as a resilient nexthop group using
the configured parameters, while singleton groups are left alone and the
configuration can be removed again.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.mgmtd, pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_nhg_id(router, prefix):
    """Return the nexthop group id zebra assigned to a route, or None."""
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))

    entries = output.get(prefix)
    if not entries:
        return None

    return entries[0].get("nexthopGroupId")


def _check_nhg_resilience(router, prefix, buckets, idle, unbalanced, count):
    """Verify the route's nexthop group is resilient with the given params."""
    nhgid = _route_nhg_id(router, prefix)
    if nhgid is None:
        return "{}: no nexthop group id installed yet".format(prefix)

    output = json.loads(
        router.vtysh_cmd("show nexthop-group rib {} json".format(nhgid))
    )

    expected = {
        str(nhgid): {
            "nexthopCount": count,
            "buckets": buckets,
            "idleTimer": idle,
            "unbalancedTimer": unbalanced,
        }
    }

    return topotest.json_cmp(output, expected)


def _check_nhg_not_resilient(router, prefix):
    """Verify the route's nexthop group has no resilience configured."""
    nhgid = _route_nhg_id(router, prefix)
    if nhgid is None:
        return "{}: no nexthop group id installed yet".format(prefix)

    output = json.loads(
        router.vtysh_cmd("show nexthop-group rib {} json".format(nhgid))
    )

    group = output.get(str(nhgid))
    if group is None:
        return "{}: nexthop group {} not found".format(prefix, nhgid)

    if "buckets" in group:
        return "{}: nexthop group {} unexpectedly resilient: {}".format(
            prefix, nhgid, group
        )

    return None


def test_multipath_route_is_resilient():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    step("Multipath route inherits the configured resilience parameters")

    test_func = functools.partial(
        _check_nhg_resilience, router, "10.0.0.0/24", 8, 100, 200, 2
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Multipath nexthop group was not made resilient"


def test_singleton_route_is_not_resilient():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    step("Singleton route is not made resilient")

    test_func = functools.partial(_check_nhg_not_resilient, router, "10.1.1.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Singleton nexthop group should not be resilient"


def test_resilience_removal():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    step("Removing the configuration stops new groups from being resilient")

    router.vtysh_cmd("configure terminal\nno zebra nexthop-group resilience")
    router.vtysh_cmd(
        "configure terminal\n"
        "ip route 10.2.2.0/24 192.168.1.2 r1-eth0\n"
        "ip route 10.2.2.0/24 192.168.2.2 r1-eth1"
    )

    test_func = functools.partial(_check_nhg_not_resilient, router, "10.2.2.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Multipath group created after removal should not be resilient"

    step("Existing resilient group is untouched by the removal")

    test_func = functools.partial(
        _check_nhg_resilience, router, "10.0.0.0/24", 8, 100, 200, 2
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Existing resilient nexthop group should be unchanged"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
