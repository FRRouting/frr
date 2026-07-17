#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test `maximum-prefix NUMBER include-additional-paths` under ADD-PATH.

The DUT (r1) receives multiple paths for a *single* prefix (172.16.16.254/32)
via ADD-PATH: r3 and r4 both originate it, and r2 reflects both paths to r1
using `addpath-tx-all-paths`. So r1 sees 1 prefix but 2 paths.

With `maximum-prefix 1 include-additional-paths`, the limit is exceeded by the *path*
count (2 > 1) even though there is only 1 prefix (a prefix-based limit of 1
would be satisfied). The session is therefore torn down with the Cease
NOTIFICATION subcode "Maximum Number of Paths Reached" (subcode 11), which
surfaces locally as the peer-down reason "Reached received path count".

Topology:

    r3 (originates 172.16.16.254/32) --\\
                                        r2 --(addpath-tx-all)--> r1 (DUT)
    r4 (originates 172.16.16.254/32) --/
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # r1 <-> r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2 <-> r3, r4 (both originate the same prefix)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _received_paths(router, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if "paths" not in output:
        return 0
    return len(output["paths"])


def test_bgp_maximum_prefix_include_paths():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify r1 receives 2 ADD-PATH paths for the single prefix 172.16.16.254/32")

    def _check_two_paths():
        if _received_paths(r1, "172.16.16.254/32") == 2:
            return None
        return "r1 does not have 2 paths yet"

    test_func = functools.partial(_check_two_paths)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not receive 2 ADD-PATH paths for the prefix"

    step(
        "Set maximum-prefix 1 (no include-additional-paths): 1 distinct prefix <= 1, both paths kept"
    )
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 1
        """
    )

    def _check_still_up_two_paths():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        if topotest.json_cmp(output, {"192.168.1.2": {"bgpState": "Established"}}):
            return "session went down (it should not: only 1 distinct prefix)"
        if _received_paths(r1, "172.16.16.254/32") != 2:
            return "both paths should still be present"
        return None

    test_func = functools.partial(_check_still_up_two_paths)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, (
        "Plain maximum-prefix 1 wrongly rejected ADD-PATH paths "
        "(it must count distinct prefixes, not paths)"
    )

    step("Set maximum-prefix 1 include-additional-paths on r1 (1 prefix, but 2 paths -> exceeds)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 1 include-additional-paths
        """
    )

    step("Verify include-additional-paths round-trips through running-config")

    def _check_running_config():
        output = r1.vtysh_cmd("show running-config")
        if "neighbor 192.168.1.2 maximum-prefix 1 include-additional-paths" in output:
            return None
        return output

    test_func = functools.partial(_check_running_config)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert (
        result is None
    ), "include-additional-paths keyword did not round-trip through running-config"

    step("Verify the session is torn down with the path-count Cease reason")

    def _check_path_count_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        expected = {
            "192.168.1.2": {
                "lastResetDueTo": "Reached received path count",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_path_count_reset)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was not reset due to received path count"

    step("Raise limit to maximum-prefix 2 include-additional-paths (>= 2 paths) -> recovers")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 2 include-additional-paths
        """
    )

    step("Verify session recovers and both paths are received again")

    def _check_recovered():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        if topotest.json_cmp(output, {"192.168.1.2": {"bgpState": "Established"}}):
            return "not established yet"
        if _received_paths(r1, "172.16.16.254/32") != 2:
            return "both paths not received yet"
        return None

    test_func = functools.partial(_check_recovered)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session/paths did not recover after raising the limit"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
