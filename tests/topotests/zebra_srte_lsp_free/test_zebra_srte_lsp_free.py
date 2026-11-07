#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_srte_lsp_free.py
#
# Copyright (c) 2026 by Eduardo Terto
#

"""
test_zebra_srte_lsp_free.py:

An SR-TE policy in zebra caches the LSP of the first label of its segment
list (policy->lsp). When that LSP is freed while the policy is still up,
zebra must not keep the pointer: routes colored by the policy are re-resolved
on the next RIB run (nexthop_active()) and would walk freed memory.

This test exercises the policy/LSP life cycle around that pointer, with a
BGP route colored with the policy color resolved through policy (100,
2.2.2.2) and its first label 16020 (node SID of r2):

- flapping the preferred link moves the LSP 16020 to the other link;
- taking both links down frees the LSP 16020 while the policy is up, the
  policy must go down and come back once the links are restored.

After every step zebra must still be running; built with the address
sanitizer (topotest default), any access to a freed LSP is reported.

Note: the original crash also needs the colored route to be re-resolved in
the short window between the LSP being freed and the dataplane result that
revalidates the policy. This test does not force that ordering, so it is a
functional/regression check of the code path, not a deterministic
reproduction of the race.

    +---------+  eth-r2-1  10.0.1.0/24  eth-r1-1  +---------+
    |   r1    +-------------------------------------+   r2    |
    | 1.1.1.1 |        (OSPF cost 10, preferred)    | 2.2.2.2 |
    |         +-------------------------------------+         |
    +---------+  eth-r2-2  10.0.2.0/24  eth-r1-2  +---------+
                         (OSPF cost 100)

r2 advertises 9.9.9.0/24 over iBGP (next-hop 2.2.2.2); r1 colors it with
SR-TE color 100, steered into policy (100, 2.2.2.2) with segment list [16020].
"""

import os
import sys
import json
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.pathd]

FLAPS = 10
COLORED_PREFIX = "9.9.9.0/24"


def build_topo(tgen):
    "Build function"

    for router in ["r1", "r2"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2-1")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1-1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2-2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1-2")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built in:" + frrdir)

    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [("zebra", ""), ("ospfd", ""), ("bgpd", ""), ("pathd", "")],
    )
    tgen.gears["r2"].load_frr_config(
        os.path.join(CWD, "r2/frr.conf"),
        [("zebra", ""), ("ospfd", ""), ("bgpd", ""), ("staticd", "")],
    )

    tgen.start_router()

    # pathd can't apply its segment-routing/traffic-eng configuration from a
    # configuration file at start up, so it's configured here instead.
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
segment-routing
 traffic-eng
  segment-list TO_R2
   index 10 mpls label 16020
  !
  policy color 100 endpoint 2.2.2.2
   name TO_R2
   candidate-path preference 100 name CP explicit segment-list TO_R2
  !
 !
!
"""
    )


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _policy_is_operational(router):
    # "show sr-te policy" has no JSON output; parse the table
    # (Endpoint Color Name BSID Status).
    output = router.vtysh_cmd("show sr-te policy", isjson=False)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "2.2.2.2" and fields[1] == "100":
            return fields[-1] == "Active"
    return False


def _colored_route_via(router, ifname):
    """None when COLORED_PREFIX is installed, resolved over ifname."""
    output = router.vtysh_cmd(
        "show ip route {} json".format(COLORED_PREFIX), isjson=True
    )
    for route in output.get(COLORED_PREFIX, []):
        if not route.get("installed"):
            continue
        for nexthop in route.get("nexthops", []):
            if nexthop.get("interfaceName") == ifname and nexthop.get("fib"):
                return None
    return "{} not installed via {}".format(COLORED_PREFIX, ifname)


def _wait_colored_route(router, ifname):
    test_func = partial(_colored_route_via, router, ifname)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r1: {}".format(result)

    test_func = partial(_policy_is_operational, router)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result is True, "r1: SR policy (100, 2.2.2.2) is not operational"


def test_colored_route_uses_policy():
    "The colored BGP route must be resolved through the SR policy."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _wait_colored_route(tgen.gears["r1"], "eth-r2-1")


def test_flap_preferred_link():
    "Flapping the link the policy LSP uses must not crash zebra."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for flap in range(1, FLAPS + 1):
        logger.info("flap %d/%d: eth-r2-1 down", flap, FLAPS)
        r1.cmd("ip link set eth-r2-1 down")
        _wait_colored_route(r1, "eth-r2-2")
        assert not tgen.routers_have_failure(), tgen.errors

        logger.info("flap %d/%d: eth-r2-1 up", flap, FLAPS)
        r1.cmd("ip link set eth-r2-1 up")
        _wait_colored_route(r1, "eth-r2-1")
        assert not tgen.routers_have_failure(), tgen.errors


def _policy_is_down(router):
    return not _policy_is_operational(router)


def test_lose_endpoint():
    """
    Take both links down at once: the LSP of the first label (16020) loses
    all its NHLFEs and is freed, while the colored BGP route is still in the
    RIB (iBGP hold time) and gets re-resolved. The policy must go down, and
    come back once the links are restored, without zebra crashing.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for flap in range(1, FLAPS + 1):
        logger.info("loss %d/%d: both links down", flap, FLAPS)
        r1.cmd("ip link set eth-r2-1 down; ip link set eth-r2-2 down")
        test_func = partial(_policy_is_down, r1)
        _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
        assert result is True, "r1: SR policy (100, 2.2.2.2) is still up"
        assert not tgen.routers_have_failure(), tgen.errors

        logger.info("loss %d/%d: both links up", flap, FLAPS)
        r1.cmd("ip link set eth-r2-1 up; ip link set eth-r2-2 up")
        _wait_colored_route(r1, "eth-r2-1")
        assert not tgen.routers_have_failure(), tgen.errors


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
