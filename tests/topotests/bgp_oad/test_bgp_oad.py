#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if local-preference is passed between different EBGP peers when
EBGP-OAD is configured.

Also check if no-export community is passed to the EBGP-OAD peer.

Also check that the (optional non-transitive) AIGP attribute is propagated
across EBGP-OAD sessions (r3 -> r2 -> r1) when explicitly enabled with
"neighbor PEER aigp", but stripped towards a regular EBGP peer (r1 -> r4).

Per draft-uttaro-idr-bgp-oad section 3.20 the default value of AIGP_SESSION
is "disabled" for EBGP-OAD sessions, hence "neighbor PEER aigp" is configured
on both ends of each OAD session (r3<->r2, r2<->r1).

Finally, check that AIGP is NOT propagated over an EBGP-OAD session once
"neighbor PEER aigp" is removed, confirming the default is "disabled".
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r4"), "s2": ("r2", "r3"), "s3": ("r4", "r5")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_oad():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {"string": "65002 65003"},
                    "metric": 123,
                    "locPrf": 123,
                    "peer": {
                        "hostname": "r2",
                        "type": "external (oad)",
                    },
                },
                {
                    "aspath": {"string": "65004 65005"},
                    "metric": 123,
                    "locPrf": 123,
                    "bestpath": {"selectionReason": "Peer Type"},
                    "peer": {
                        "hostname": "r4",
                        "type": "external",
                    },
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    def _bgp_check_no_export(router, arg=[{"valid": True}]):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.10.10.1/32": arg,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_no_export,
        r2,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.1/32 should be advertised to r2"

    test_func = functools.partial(
        _bgp_check_no_export,
        r3,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.1/32 should be advertised to r3"

    test_func = functools.partial(
        _bgp_check_no_export,
        r4,
        None,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.1/32 should not be advertised to r4 (not OAD peer)"

    def _bgp_check_non_transitive_extended_community(
        router, arg={"string": "LB:65003:12500000 (100.000 Mbps)"}
    ):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 10.10.10.20/32 json")
        )
        expected = {
            "paths": [
                {
                    "extendedCommunity": arg,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_non_transitive_extended_community,
        r4,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.10.10.20/32 should be received at r4 with non-transitive extended community"

    test_func = functools.partial(
        _bgp_check_non_transitive_extended_community, r5, None
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.10.10.20/32 should NOT be received at r5 with non-transitive extended community"

    def _bgp_check_aigp(router, arg=None):
        if arg is None:
            arg = {"aigpMetric": 50}
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 10.10.10.20/32 json")
        )
        expected = {"paths": [arg]}
        return topotest.json_cmp(output, expected)

    # AIGP must be propagated across the EBGP-OAD domain (r3 -> r2 -> r1)
    # when explicitly enabled with "neighbor PEER aigp".
    test_func = functools.partial(_bgp_check_aigp, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.20/32 should be received at r2 with aigp-metric"

    test_func = functools.partial(_bgp_check_aigp, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.20/32 should be received at r1 with aigp-metric"

    # AIGP must NOT leak towards a regular EBGP peer (r1 -> r4).
    test_func = functools.partial(_bgp_check_aigp, r4, {"aigpMetric": None})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.10.10.20/32 should NOT be received at r4 with aigp-metric (not OAD peer)"

    # By default (without "neighbor PEER aigp") AIGP MUST NOT be propagated over
    # an EBGP-OAD session (draft-uttaro-idr-bgp-oad section 3.20). Disable AIGP
    # on the r2 -> r1 OAD session only: r2 still learns the AIGP metric from r3
    # (that session keeps "neighbor aigp"), but r2 must no longer advertise it
    # to r1.
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor 192.168.1.1 aigp
        """
    )
    # Toggling PEER_FLAG_AIGP is peer_change_none, so force re-advertisement.
    r2.vtysh_cmd("clear bgp * soft out")

    # r2 still has the AIGP metric (received from r3).
    test_func = functools.partial(_bgp_check_aigp, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.20/32 should still have aigp-metric at r2"

    # r1 must NOT receive the AIGP metric anymore (OAD session without aigp).
    test_func = functools.partial(_bgp_check_aigp, r1, {"aigpMetric": None})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.10.10.20/32 should NOT have aigp-metric at r1 (OAD session without 'neighbor aigp')"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
