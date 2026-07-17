#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test `maximum-prefix NUMBER maximum-additional-paths Z` (per-prefix path cap).

r3, r4 and r5 all originate 172.16.16.254/32; r2 reflects all three paths to
r1 (DUT) via addpath-tx-all-paths. So r1 sees 1 prefix but 3 paths.

The per-prefix cap allows Z+1 paths for a single prefix, and is re-evaluated
immediately when configured (parity with the aggregate maximum-prefix limit):
  * warning-only  -> trim to Z+1 paths, keep the session
  * enforce       -> tear the session down with Cease "Maximum Number of Paths
                     Reached" (surfaced as "Reached received path count")
`maximum-additional-paths` is mutually exclusive with `include-additional-paths`.

Enforce is exercised before warning-only: warning-only trims the prefix to 2
paths at config time, after which an enforce cap of 2 would no longer see an
over-limit prefix.
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
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # r1 <-> r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2 <-> r3, r4, r5 (all originate the same prefix)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])


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


def test_bgp_maximum_additional_paths():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify r1 receives 3 ADD-PATH paths for the single prefix")

    def _check_three_paths():
        if _received_paths(r1, "172.16.16.254/32") == 3:
            return None
        return "r1 does not have 3 paths yet"

    _, result = topotest.run_and_expect(
        functools.partial(_check_three_paths), None, count=60, wait=1
    )
    assert result is None, "r1 did not receive 3 ADD-PATH paths for the prefix"

    step("Enforce: maximum-additional-paths 1 (cap 2), 3 paths -> session torn down")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 10 maximum-additional-paths 1
        """
    )

    def _check_path_count_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        return topotest.json_cmp(
            output,
            {"192.168.1.2": {"lastResetDueTo": "Reached received path count"}},
        )

    _, result = topotest.run_and_expect(
        functools.partial(_check_path_count_reset), None, count=30, wait=1
    )
    assert result is None, "Session was not reset due to per-prefix path count"

    step("Recover: maximum-additional-paths 2 (cap 3) -> established with 3 paths")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 10 maximum-additional-paths 2
        """
    )

    def _check_recovered():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        if topotest.json_cmp(output, {"192.168.1.2": {"bgpState": "Established"}}):
            return "not established yet"
        if _received_paths(r1, "172.16.16.254/32") != 3:
            return "all 3 paths not received yet"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_recovered), None, count=60, wait=1
    )
    assert result is None, "Session/paths did not recover after raising the cap"

    step("Verify recover form round-trips through running-config")

    def _check_running_config_recover():
        output = r1.vtysh_cmd("show running-config")
        if "maximum-prefix 10 maximum-additional-paths 2" in output:
            return None
        return output

    _, result = topotest.run_and_expect(
        functools.partial(_check_running_config_recover), None, count=10, wait=1
    )
    assert (
        result is None
    ), "maximum-additional-paths did not round-trip through running-config"

    step(
        "warning-only + maximum-additional-paths 1 (cap 2): config-time trim to 2, session up"
    )
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 10 warning-only maximum-additional-paths 1
        """
    )

    def _check_capped_two():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        if topotest.json_cmp(output, {"192.168.1.2": {"bgpState": "Established"}}):
            return "session went down (warning-only must preserve it)"
        if _received_paths(r1, "172.16.16.254/32") != 2:
            return "prefix should be trimmed to 2 paths"
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_check_capped_two), None, count=30, wait=1
    )
    assert result is None, "warning-only per-prefix cap did not trim to 2 paths"

    step("Verify warning-only form round-trips through running-config")

    def _check_running_config_warn():
        output = r1.vtysh_cmd("show running-config")
        if "maximum-prefix 10 warning-only maximum-additional-paths 1" in output:
            return None
        return output

    _, result = topotest.run_and_expect(
        functools.partial(_check_running_config_warn), None, count=10, wait=1
    )
    assert result is None, "warning-only maximum-additional-paths did not round-trip"

    step(
        "Mutual exclusion: include-additional-paths + maximum-additional-paths rejected by the grammar"
    )
    out = r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         address-family ipv4 unicast
          neighbor 192.168.1.2 maximum-prefix 10 maximum-additional-paths 1 include-additional-paths
        """
    )
    assert "Unknown command" in out, (
        "combining maximum-additional-paths with include-additional-paths "
        "should be rejected by the command grammar, got: %s" % out
    )
    running = r1.vtysh_cmd("show running-config")
    assert "include-additional-paths" not in running, (
        "include-additional-paths must not have been accepted alongside "
        "maximum-additional-paths"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
