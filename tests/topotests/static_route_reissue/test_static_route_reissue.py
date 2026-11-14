#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nexthop AI
# Authored by Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
test_static_route_reissue.py: re-entering `ip route` without an optional
nexthop attribute removes that attribute.

An existing static nexthop is modified in place rather than recreated when the
route is entered again, so every optional attribute the new command leaves out
has to be removed explicitly. Check weight, color and bfd: each is set, the
route is re-entered without it, and both the configuration and the RIB (or the
BFD session) must drop it.
"""

import os
import sys
import json
import pytest

pytestmark = [pytest.mark.staticd, pytest.mark.bfdd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

NH1 = "192.168.0.2"
NH2 = "192.168.0.3"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def configure(router, *lines):
    router.vtysh_multicmd("\n".join(("configure terminal",) + lines))


def route_config(router, prefix):
    "The running-config lines for prefix."
    return [
        line.strip()
        for line in router.vtysh_cmd("show running-config").splitlines()
        if line.strip().startswith("ip route {} ".format(prefix))
    ]


def route_nexthops(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    return output.get(prefix, [{}])[0].get("nexthops", [])


def expect(func, what):
    ok, _ = topotest.run_and_expect(func, True, count=30, wait=1)
    assert ok, what


def test_weight_removed_on_reissue():
    "Re-entering the route without weight returns the nexthops to equal cost."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    prefix = "10.1.1.0/24"

    configure(
        r1,
        "ip route {} {} weight 5".format(prefix, NH1),
        "ip route {} {} weight 10".format(prefix, NH2),
    )
    expect(
        lambda: len({nh.get("weight") for nh in route_nexthops(r1, prefix)}) == 2
        and len(route_nexthops(r1, prefix)) == 2,
        "weighted nexthops not installed: {}".format(route_nexthops(r1, prefix)),
    )

    configure(
        r1, "ip route {} {}".format(prefix, NH1), "ip route {} {}".format(prefix, NH2)
    )
    expect(
        lambda: not any("weight" in line for line in route_config(r1, prefix)),
        "weight kept in config: {}".format(route_config(r1, prefix)),
    )
    expect(
        lambda: len(route_nexthops(r1, prefix)) == 2
        and len({nh.get("weight") for nh in route_nexthops(r1, prefix)}) == 1,
        "nexthops still weighted: {}".format(route_nexthops(r1, prefix)),
    )


def test_color_removed_on_reissue():
    "Re-entering the route without color clears the nexthop's SR-TE color."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    prefix = "10.2.2.0/24"

    configure(r1, "ip route {} {} color 7".format(prefix, NH1))
    expect(
        lambda: any(nh.get("srteColor") == 7 for nh in route_nexthops(r1, prefix)),
        "colored nexthop not in the RIB: {}".format(route_nexthops(r1, prefix)),
    )

    configure(r1, "ip route {} {}".format(prefix, NH1))
    expect(
        lambda: not any("color" in line for line in route_config(r1, prefix)),
        "color kept in config: {}".format(route_config(r1, prefix)),
    )
    expect(
        lambda: route_nexthops(r1, prefix)
        and not any("srteColor" in nh for nh in route_nexthops(r1, prefix)),
        "nexthop still colored: {}".format(route_nexthops(r1, prefix)),
    )


def test_bfd_removed_on_reissue():
    "Re-entering the route without bfd stops monitoring and frees the session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    prefix = "10.3.3.0/24"

    def peers():
        return json.loads(r1.vtysh_cmd("show bfd peers json"))

    configure(r1, "ip route {} {} bfd".format(prefix, NH1))
    expect(
        lambda: any(p.get("peer") == NH1 for p in peers()),
        "no BFD session for the monitored nexthop: {}".format(peers()),
    )

    configure(r1, "ip route {} {}".format(prefix, NH1))
    expect(
        lambda: not any("bfd" in line for line in route_config(r1, prefix)),
        "bfd kept in config: {}".format(route_config(r1, prefix)),
    )
    expect(lambda: peers() == [], "BFD session not freed: {}".format(peers()))
    expect(
        lambda: len(route_nexthops(r1, prefix)) == 1,
        "route lost after removing bfd: {}".format(route_nexthops(r1, prefix)),
    )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
