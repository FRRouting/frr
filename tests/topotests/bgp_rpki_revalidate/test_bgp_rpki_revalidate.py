#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test that a change of the RPKI VRP set re-applies the inbound route-map.

r1 (AS 65001) runs an RTR cache and announces five /24s to r2 (AS 65002). r2
denies "match rpki invalid" inbound, with soft-reconfiguration inbound. The VRP
set is then changed while the RTR session stays up, and r2 must re-filter the
routes on its own, without "clear bgp ... soft in":

    prefix          initial     step 1      step 2      step 3
    10.10.1.0/24    valid       invalid     invalid     valid
    10.10.2.0/24    valid       valid       valid       valid
    10.10.3.0/24    invalid     valid       valid       invalid
    10.10.4.0/24    not found   not found   invalid     not found
    10.20.0.0/24    not found   not found   not found   not found

The BGP session is brought up only after r2 holds the initial VRP set, so
that the initial filtering does not depend on revalidation. A last step stops
and restarts RPKI on r2: routes accepted while RPKI is stopped must be
re-filtered once the VRP set is loaded again.

None of the covering prefixes is announced, so the path from the top of r2's
BGP table to each /24 goes through holder route_nodes (no bgp_dest), and the
covering VRP of step 2 (10.10.0.0/16 maxlen 24) has a holder as subtree root.
Invalid routes must be gone from the BGP table but kept in Adj-RIB-In, so that
they come back when they are no longer invalid.
"""

import os
import sys
import json
import shutil
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

PREFIXES = [
    "10.10.1.0/24",
    "10.10.2.0/24",
    "10.10.3.0/24",
    "10.10.4.0/24",
    "10.20.0.0/24",
]

VRPS_INITIAL = [
    (65001, "10.10.1.0/24", 24),
    (65001, "10.10.2.0/24", 24),
    (65099, "10.10.3.0/24", 24),
]

VRPS_STEP1 = [
    (65099, "10.10.1.0/24", 24),
    (65001, "10.10.2.0/24", 24),
    (65001, "10.10.3.0/24", 24),
]

VRPS_STEP2 = VRPS_STEP1 + [(65099, "10.10.0.0/16", 24)]

EXPECTED_INITIAL = {
    "10.10.1.0/24": "valid",
    "10.10.2.0/24": "valid",
    "10.10.3.0/24": None,
    "10.10.4.0/24": "not found",
    "10.20.0.0/24": "not found",
}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def vrps_file():
    return os.path.join(get_topogen().logdir, "r1", "vrps.csv")


def write_vrps(vrps):
    with open(vrps_file() + ".tmp", "w") as fh:
        fh.write("ASN,IP Prefix,Max Length,Trust Anchor\n")
        for asn, prefix, maxlen in vrps:
            fh.write("AS{},{},{},private\n".format(asn, prefix, maxlen))
    os.rename(vrps_file() + ".tmp", vrps_file())


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        daemons = (
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bgpd_rpki")]
            if rname == "r2"
            else [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BGP, None),
            ]
        )
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)), daemons=daemons
        )

    # Start the RTR cache before the routers, so that bgpd's first connect
    # attempt does not fail and wait for retry_interval.
    global rtrd_process
    rtr_path = os.path.join(CWD, "r1")
    log_dir = os.path.join(tgen.logdir, "r1")
    os.makedirs(log_dir, exist_ok=True)
    shutil.copyfile(os.path.join(rtr_path, "vrps.csv"), vrps_file())

    tgen.gears["r1"].cmd("chmod u+x {}/rtrd.py".format(rtr_path))
    rtrd_process = tgen.gears["r1"].popen(
        "{}/rtrd.py {} {}".format(
            rtr_path, os.path.join(log_dir, "rtrd.log"), vrps_file()
        )
    )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    logger.info("r1: sending SIGTERM to rtrd RPKI server")
    rtrd_process.kill()

    tgen.stop_topology()


def _rpki_prefix_table(expected):
    """r2 holds exactly the expected VRPs."""
    output = json.loads(
        get_topogen().gears["r2"].vtysh_cmd("show rpki prefix-table json")
    )
    got = sorted(
        (p["asn"], "{}/{}".format(p["prefix"], p["prefixLenMin"]), p["prefixLenMax"])
        for p in output.get("prefixes", [])
    )
    want = sorted(expected)
    if got != want:
        return "VRPs {}, expected {}".format(got, want)
    return None


def _bgp_state(expected):
    """Every prefix is in r2's BGP table with the expected RPKI state, or is
    absent from it (None) while still present in Adj-RIB-In."""
    r2 = get_topogen().gears["r2"]
    received = json.loads(
        r2.vtysh_cmd("show bgp ipv4 unicast neighbors 10.0.0.1 received-routes json")
    ).get("receivedRoutes", {})

    for prefix, state in expected.items():
        if prefix not in received:
            return "{} not in Adj-RIB-In".format(prefix)

        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        paths = output.get("paths", [])
        if state is None:
            if paths:
                return "{} is in the BGP table ({}), expected denied".format(
                    prefix, paths[0].get("rpkiValidationState")
                )
            continue
        if not paths:
            return "{} is not in the BGP table, expected {}".format(prefix, state)
        if state == "any":
            continue
        if paths[0].get("rpkiValidationState") != state:
            return "{} is {}, expected {}".format(
                prefix, paths[0].get("rpkiValidationState"), state
            )
    return None


def change_vrps(vrps, expected):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if rtrd_process.poll() is not None:
        pytest.skip("rtrd is not running")

    write_vrps(vrps)

    step("Wait for r2 to receive the new VRP set")
    test_func = functools.partial(_rpki_prefix_table, vrps)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not receive the new VRP set: {}".format(result)

    step("Check that r2 re-applied its inbound policy, without soft in")
    test_func = functools.partial(_bgp_state, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "inbound policy not re-applied: {}".format(result)


def test_initial_state():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for r2 to receive the initial VRP set")
    test_func = functools.partial(_rpki_prefix_table, VRPS_INITIAL)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not receive the VRP set: {}".format(result)

    step("Bring up the BGP session with r1")
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          no neighbor 10.0.0.1 shutdown
        """
    )

    step("Check the initial filtering on r2")
    test_func = functools.partial(_bgp_state, EXPECTED_INITIAL)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "unexpected initial state: {}".format(result)


def test_valid_to_invalid_and_invalid_to_valid():
    change_vrps(
        VRPS_STEP1,
        {
            "10.10.1.0/24": None,
            "10.10.2.0/24": "valid",
            "10.10.3.0/24": "valid",
            "10.10.4.0/24": "not found",
            "10.20.0.0/24": "not found",
        },
    )


def test_covering_vrp_invalidates_notfound():
    change_vrps(
        VRPS_STEP2,
        {
            "10.10.1.0/24": None,
            "10.10.2.0/24": "valid",
            "10.10.3.0/24": "valid",
            "10.10.4.0/24": None,
            "10.20.0.0/24": "not found",
        },
    )


def test_revert_vrps():
    change_vrps(VRPS_INITIAL, EXPECTED_INITIAL)


def test_rpki_restart_refilters():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if rtrd_process.poll() is not None:
        pytest.skip("rtrd is not running")

    r2 = tgen.gears["r2"]

    step("Stop RPKI on r2 and re-run the inbound policy without VRPs")
    r2.vtysh_cmd("rpki stop")
    r2.vtysh_cmd("clear bgp ipv4 unicast 10.0.0.1 soft in")

    test_func = functools.partial(_bgp_state, {p: "any" for p in PREFIXES})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "routes not accepted with RPKI stopped: {}".format(result)

    step("Start RPKI on r2 and wait for the VRP set")
    r2.vtysh_cmd("rpki start")
    test_func = functools.partial(_rpki_prefix_table, VRPS_INITIAL)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not receive the VRP set: {}".format(result)

    step("Check that r2 re-filtered the routes, without soft in")
    test_func = functools.partial(_bgp_state, EXPECTED_INITIAL)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "inbound policy not re-applied: {}".format(result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
