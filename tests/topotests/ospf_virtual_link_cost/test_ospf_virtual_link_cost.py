#!/usr/bin/env python
# SPDX-License-Identifier: ISC

r"""
test_ospf_virtual_link_cost.py: Test that a virtual link whose transit area
path cost exceeds the 16-bit Router-LSA metric is advertised with the maximum
metric (65535), instead of the cost being truncated (65536 used to become
metric 0 and abort ospfd in ospf_spf_add_parent(), 65537 silently became
metric 1).

          area 0.0.0.1                 area 0.0.0.1
    +----+  10.1.12.0/24   +----+  10.1.23.0/24   +----+
    | r1 |-----------------| r2 |-----------------| r3 |
    +----+ eth0       eth0 +----+ eth1       eth0 +----+
     lo 10.0.0.1/32 (area 0)            lo 10.0.0.3/32 (area 0)
        \______________ virtual-link (area 0.0.0.1) _______/
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _vlink_state(router, cost):
    status = router.check_router_running()
    if status:
        return status

    output = json.loads(router.vtysh_cmd("show ip ospf interface VLINK0 json"))
    expected = {
        "interfaces": {
            "VLINK0": {
                "cost": cost,
                "state": "Point-To-Point",
                "nbrAdjacentCount": 1,
            }
        }
    }
    return topotest.json_cmp(output, expected)


def _vlink_metric(router, adv_router, peer, metric):
    """
    Check the metric of the virtual link to `peer` in the backbone
    Router-LSA that `adv_router` originated, as seen in `router`'s LSDB.
    """
    status = router.check_router_running()
    if status:
        return status

    output = json.loads(
        router.vtysh_cmd("show ip ospf database router {} json".format(adv_router))
    )
    lsas = output.get("routerLinkStates", {}).get("areas", {}).get("0.0.0.0", [])
    found = []
    for lsa in lsas:
        for link in lsa.get("routerLinks", {}).values():
            if (
                link.get("linkType") == "a Virtual Link"
                and link.get("neighborRouterId") == peer
            ):
                found.append(link.get("tos0Metric"))

    if found == [metric]:
        return None
    return "virtual link {}->{} metrics {}, expected [{}]".format(
        adv_router, peer, found, metric
    )


def _set_costs(r1_eth0, r2_eth1, r3_eth0, r2_eth0):
    """
    r1 reaches r3 over r1-eth0 + r2-eth1, and r3 reaches r1 over
    r3-eth0 + r2-eth0, so each pair is one virtual link endpoint's cost.
    """
    tgen = get_topogen()

    def _cost(rname, ifname, cost):
        cmd = "no ip ospf cost" if cost is None else "ip ospf cost {}".format(cost)
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\ninterface {}\n{}\n".format(ifname, cmd)
        )

    _cost("r1", "r1-eth0", r1_eth0)
    _cost("r2", "r2-eth1", r2_eth1)
    _cost("r3", "r3-eth0", r3_eth0)
    _cost("r2", "r2-eth0", r2_eth0)


def _check_vlinks(cost, metric):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    for router in [r1, r3]:
        test_func = functools.partial(_vlink_state, router, cost)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: VLINK0 not up with cost {}: {}".format(
            router.name, cost, result
        )

    for router, adv_router, peer in [
        (r3, "1.1.1.1", "3.3.3.3"),
        (r1, "3.3.3.3", "1.1.1.1"),
    ]:
        test_func = functools.partial(_vlink_metric, router, adv_router, peer, metric)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: {}".format(router.name, result)


def test_vlink_default_cost():
    "The virtual link comes up with the transit path cost 10 + 10"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that both virtual link endpoints are up with cost 20")
    _check_vlinks(20, 20)


def test_vlink_cost_65535():
    "A transit path cost of 65535 still fits in the Router-LSA metric"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set the transit path cost to 32767 + 32768 in both directions")
    _set_costs(32767, 32768, 32767, 32768)
    _check_vlinks(65535, 65535)


def test_vlink_cost_65537():
    "A transit path cost of 65537 must not wrap around to metric 1"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set the transit path cost to 32767 + 32770 in both directions")
    _set_costs(32767, 32770, 32767, 32770)
    _check_vlinks(65535, 65535)


def test_vlink_cost_65536():
    "A transit path cost of 65536 must not become metric 0 and abort ospfd"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set the transit path cost to 32767 + 32769 in both directions")
    _set_costs(32767, 32769, 32767, 32769)
    _check_vlinks(65535, 65535)


def test_vlink_cost_recovery():
    "The virtual link cost follows the path again once it fits"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Restore the default interface costs")
    _set_costs(None, None, None, None)
    _check_vlinks(20, 20)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
