#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test LLGR helper behavior toward peers that did not advertise the
LLGR capability (RFC 9494 sec. 4.3 / sec. 6):

A receiver of an LLGR_STALE-tagged route SHOULD NOT re-advertise it to a
BGP peer that has not advertised the LLGR capability for the same AFI/SAFI.

Topology:

    r1 ----- r2 ----- r3   r3: LLGR-capable
              |
              +------ r4   r4: NO LLGR capability (no graceful-restart;
                               in FRR, GR advertises LLGR too)

  - r1 originates 172.16.1.1/32 and gets killed mid-test.
  - r2 is the LLGR helper for r1.
  - After r1 dies, r2 must:
      * mark 172.16.1.1/32 as stale with the llgr-stale community,
      * keep advertising it to r3 (LLGR-capable peer),
      * withdraw it from r4 (non-LLGR peer).
"""

import os
import sys
import json
import functools
import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import kill_router_daemons, step


PREFIX = "172.16.1.1/32"


def build_topo(tgen):
    for router_id in range(1, 5):
        tgen.add_router(f"r{router_id}")

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])

    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r2"])
    s2.add_link(tgen.gears["r3"])

    s3 = tgen.add_switch("s3")
    s3.add_link(tgen.gears["r2"])
    s3.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _route_present(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip bgp json"))
    if prefix not in output.get("routes", {}):
        return "{} missing on {}".format(prefix, router.name)
    return None


def _route_absent(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip bgp json"))
    if prefix in output.get("routes", {}):
        return "{} still present on {}".format(prefix, router.name)
    return None


def _route_stale_with_llgr_stale(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip bgp {} json".format(prefix)))
    # FRR sets BGP_PATH_STALE on LLGR-stale paths (surfacing as "stale": true), so
    # checking both the llgr-stale community and the stale flag is intentional: if a
    # future FRR split BGP_PATH_LLGR_STALE from BGP_PATH_STALE, this would catch it
    # rather than silently passing on the community alone.
    expected = {"paths": [{"community": {"string": "llgr-stale"}, "stale": True}]}
    return topotest.json_cmp(output, expected)


def _route_with_llgr_stale_community(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip bgp {} json".format(prefix)))
    paths = output.get("paths") or []
    if not paths:
        return "{} absent on {}".format(prefix, router.name)
    for p in paths:
        community_string = (p.get("community") or {}).get("string", "")
        if "llgr-stale" in community_string:
            return None
    return "{} present on {} but llgr-stale community missing".format(
        prefix, router.name
    )


def _not_advertised_to(helper, peer_ip, prefix):
    output = json.loads(
        helper.vtysh_cmd(
            "show ip bgp neighbor {} advertised-routes json".format(peer_ip)
        )
    )
    advertised = output.get("advertisedRoutes") or {}
    if prefix in advertised:
        return "{} still advertised by {} to {}".format(prefix, helper.name, peer_ip)
    return None


def _advertised_to(helper, peer_ip, prefix):
    output = json.loads(
        helper.vtysh_cmd(
            "show ip bgp neighbor {} advertised-routes json".format(peer_ip)
        )
    )
    advertised = output.get("advertisedRoutes") or {}
    if prefix not in advertised:
        return "{} no longer advertised by {} to {}".format(
            prefix, helper.name, peer_ip
        )
    return None


def test_bgp_llgr_no_capability_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    step("Initial convergence: r3 and r4 both learn {}".format(PREFIX))
    for r in (r3, r4):
        test_func = functools.partial(_route_present, r, PREFIX)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, result

    step("Kill bgpd on r1 to put r2 into LLGR helper mode")
    kill_router_daemons(tgen, "r1", ["bgpd"])

    step("r2 marks {} stale with llgr-stale community".format(PREFIX))
    test_func = functools.partial(_route_stale_with_llgr_stale, r2, PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r2 did not mark {} as stale/llgr-stale".format(PREFIX)

    step("r3 (LLGR-capable peer) still holds {} with llgr-stale community".format(PREFIX))
    test_func = functools.partial(_route_with_llgr_stale_community, r3, PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("r2 keeps advertising {} to r3 (LLGR-capable peer)".format(PREFIX))
    test_func = functools.partial(_advertised_to, r2, "192.168.2.2", PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("r4 (non-LLGR peer) no longer has {} (must withdraw fast, not wait for stale-time)".format(PREFIX))
    test_func = functools.partial(_route_absent, r4, PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("r2 stops advertising {} to r4 (non-LLGR peer)".format(PREFIX))
    test_func = functools.partial(_not_advertised_to, r2, "192.168.3.2", PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
