#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Microsoft Corporation
#               Deepak Singhal
#

"""
Check that a peer split out of its update subgroup gets the withdraws that
were still queued on the old subgroup.

    r2 --+                 r2, r3: plain IPv4 eBGP peers (one subgroup)
    r3 --+-- r1            r4, r5: addpath-tx-all-paths   (one subgroup)
    r4 --+
    r5 --+

r1 originates 10.0.0.0/24 - 10.0.9.0/24. With UPDATEs plugged, r1 withdraws
half of them and "clear bgp X soft out" splits r2 and r4 from their
subgroups. Once UPDATEs are unplugged, every peer must hold only the
remaining prefixes.

"bgp test updates disable" is only built with --enable-dev-build, so the
test is skipped otherwise.
"""

import functools
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

PEERS = {
    "r2": "192.168.1.2",
    "r3": "192.168.1.3",
    "r4": "192.168.1.4",
    "r5": "192.168.1.5",
}
SPLIT = ["r2", "r4"]
PREFIXES = ["10.0.{}.0/24".format(i) for i in range(10)]
WITHDRAWN = PREFIXES[:5]
KEPT = PREFIXES[5:]


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        switch.add_link(tgen.add_router(rname))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _routes(router):
    output = router.vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
    return sorted(output.get("routes", {}).keys())


def _check_routes(router, expected):
    routes = _routes(router)
    if routes != sorted(expected):
        return "{} has {}, want {}".format(router.name, routes, sorted(expected))
    return None


def _subgroup(r1, rname):
    nbr = PEERS[rname]
    output = r1.vtysh_cmd("show bgp neighbor {} json".format(nbr), isjson=True)
    return output[nbr]["addressFamilyInfo"]["ipv4Unicast"].get("subGroupId")


def _check_same_subgroup(r1, rname1, rname2):
    sub1, sub2 = _subgroup(r1, rname1), _subgroup(r1, rname2)
    if sub1 is None or sub1 != sub2:
        return "{} is in subgroup {}, {} in {}".format(rname1, sub1, rname2, sub2)
    return None


def _wait(func, *args):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count=60, wait=1
    )
    assert result is None, result


def test_bgp_subgroup_split_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    if "Unknown command" in r1.vtysh_cmd("no bgp test updates disable"):
        pytest.skip("bgpd built without --enable-dev-build")

    step("All peers get every prefix; r2/r3 and r4/r5 share a subgroup")
    for rname in PEERS:
        _wait(_check_routes, tgen.gears[rname], PREFIXES)
    _wait(_check_same_subgroup, r1, "r2", "r3")
    _wait(_check_same_subgroup, r1, "r4", "r5")

    step("Plug UPDATEs on r1 and withdraw {}".format(WITHDRAWN))
    r1.vtysh_cmd("bgp test updates disable")
    cmds = ["configure terminal", "router bgp 65001", "address-family ipv4 unicast"]
    cmds += ["no network {}".format(p) for p in WITHDRAWN]
    r1.vtysh_cmd("\n".join(cmds))
    _wait(_check_routes, r1, KEPT)
    for rname in PEERS:
        assert (
            _check_routes(tgen.gears[rname], PREFIXES) is None
        ), "{} got UPDATEs while plugged".format(rname)

    step("Split {} from their subgroups".format(SPLIT))
    before = {rname: _subgroup(r1, rname) for rname in SPLIT}
    for rname in SPLIT:
        r1.vtysh_cmd("clear bgp {} soft out".format(PEERS[rname]))

    def _check_split():
        for rname in SPLIT:
            if _subgroup(r1, rname) == before[rname]:
                return "{} still in subgroup {}".format(rname, before[rname])
        return None

    _wait(_check_split)

    step("Unplug UPDATEs; every peer must drop the withdrawn prefixes")
    r1.vtysh_cmd("no bgp test updates disable")

    def _check_all():
        errors = [_check_routes(tgen.gears[rname], KEPT) for rname in PEERS]
        return "; ".join(e for e in errors if e) or None

    _wait(_check_all)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
