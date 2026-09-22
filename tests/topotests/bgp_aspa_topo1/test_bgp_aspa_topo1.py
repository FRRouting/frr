#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
Test ASPA AS_PATH verification.

r1 (AS 65001) runs an RTR cache serving the ASPA records in r1/aspa.csv and
announces three prefixes with hand-built AS_PATHs.  r2 (AS 65500) validates
them and maps each ASPA state onto a distinct local-preference:

    prefix          AS_PATH at r2        upstream    local-pref
    172.16.1.0/24   65001 65002 65003    valid       300
    172.16.2.0/24   65001 65004          invalid     100
    172.16.3.0/24   65001 65100          unknown     200

The expected verdicts were taken from librtr itself rather than from the
draft, so this test pins FRR's plumbing, not our reading of the algorithm.

172.16.2.0/24 is the interesting one: it is upstream-invalid but
downstream-valid, which is why the direction has to be stated explicitly in
the route-map.
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
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

PREFIX_VALID = "172.16.1.0/24"
PREFIX_INVALID = "172.16.2.0/24"
PREFIX_UNKNOWN = "172.16.3.0/24"

LOCPRF_VALID = 300
LOCPRF_INVALID = 100
LOCPRF_UNKNOWN = 200


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
        # r2 is the only router that needs the RPKI module.
        daemons = (
            ["zebra", ("bgpd", "-M bgpd_rpki")]
            if rname == "r2"
            else ["zebra", "staticd", "bgpd"]
        )
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)), daemons=daemons
        )

    # Start the RTR cache before the routers.  If bgpd's first connect
    # attempt fails, rtrlib sleeps for retry_interval before trying again,
    # which would otherwise stall the test.
    global rtrd_process
    rtr_path = os.path.join(CWD, "r1")
    log_dir = os.path.join(tgen.logdir, "r1")
    log_file = os.path.join(log_dir, "rtrd.log")

    tgen.gears["r1"].cmd("chmod u+x {}/rtrd.py".format(rtr_path))
    rtrd_process = tgen.gears["r1"].popen("{}/rtrd.py {}".format(rtr_path, log_file))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    logger.info("r1: sending SIGTERM to rtrd RPKI server")
    rtrd_process.kill()

    tgen.stop_topology()


def _locpref(rname, prefix):
    """Local-preference of the first path for prefix, or None."""
    tgen = get_topogen()
    output = json.loads(
        tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    paths = output.get("paths")
    if not paths:
        return None
    return paths[0].get("locPrf")


def _aspath(rname, prefix):
    tgen = get_topogen()
    output = json.loads(
        tgen.gears[rname].vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    paths = output.get("paths")
    if not paths:
        return None
    return paths[0].get("aspath", {}).get("string")


def test_rpki_cache_connected():
    """The RTR session must come up; ASPA needs RTR protocol version 2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _connected():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show rpki cache-connection json")
        )
        for server in output.get("rpkiCacheServer", []):
            if server.get("serverPrefix") == "10.0.0.1":
                return True
        return output != {}

    _, result = topotest.run_and_expect(_connected, True, count=60, wait=1)
    assert result is True, "r2 did not connect to the RTR cache on r1"


def test_as_paths_as_expected():
    """Guard the fixture: if r1's prepending changes, the ASPA assertions
    below would be testing something other than what they claim."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        PREFIX_VALID: "65001 65002 65003",
        PREFIX_INVALID: "65001 65004",
        PREFIX_UNKNOWN: "65001 65100",
    }

    for prefix, aspath in expected.items():
        test_func = functools.partial(_aspath, "r2", prefix)
        _, result = topotest.run_and_expect(test_func, aspath, count=60, wait=1)
        assert result == aspath, "{}: AS_PATH is {}, expected {}".format(
            prefix, result, aspath
        )


def test_aspa_upstream_valid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("172.16.1.0/24 is a complete customer-to-provider chain")

    test_func = functools.partial(_locpref, "r2", PREFIX_VALID)
    _, result = topotest.run_and_expect(test_func, LOCPRF_VALID, count=60, wait=1)
    assert (
        result == LOCPRF_VALID
    ), "{} should be ASPA upstream valid (locPrf {}), got {}".format(
        PREFIX_VALID, LOCPRF_VALID, result
    )


def test_aspa_upstream_invalid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("172.16.2.0/24 traverses 65004, which does not attest 65001")

    test_func = functools.partial(_locpref, "r2", PREFIX_INVALID)
    _, result = topotest.run_and_expect(test_func, LOCPRF_INVALID, count=60, wait=1)
    assert (
        result == LOCPRF_INVALID
    ), "{} should be ASPA upstream invalid (locPrf {}), got {}".format(
        PREFIX_INVALID, LOCPRF_INVALID, result
    )


def test_aspa_upstream_unknown():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("172.16.3.0/24 traverses 65100, which has no ASPA record")

    test_func = functools.partial(_locpref, "r2", PREFIX_UNKNOWN)
    _, result = topotest.run_and_expect(test_func, LOCPRF_UNKNOWN, count=60, wait=1)
    assert (
        result == LOCPRF_UNKNOWN
    ), "{} should be ASPA upstream unknown (locPrf {}), got {}".format(
        PREFIX_UNKNOWN, LOCPRF_UNKNOWN, result
    )


def test_aspa_direction_matters():
    """Same route, opposite direction, different verdict.

    172.16.2.0/24 is upstream-invalid but downstream-valid.  Swap the
    route-map to downstream and it must move from the invalid bucket to the
    valid one.  This is the whole reason the direction is a route-map
    argument rather than something inferred from the session.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("re-evaluate the same prefix as a downstream path")

    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         route-map ASPA-IN permit 10
          match aspa downstream valid
         exit
         route-map ASPA-IN permit 20
          match aspa downstream invalid
         exit
         route-map ASPA-IN permit 30
          match aspa downstream unknown
         exit
        """
    )
    tgen.gears["r2"].vtysh_cmd("clear bgp * soft in")

    test_func = functools.partial(_locpref, "r2", PREFIX_INVALID)
    _, result = topotest.run_and_expect(test_func, LOCPRF_VALID, count=60, wait=1)
    assert (
        result == LOCPRF_VALID
    ), "{} should be ASPA downstream valid (locPrf {}), got {}".format(
        PREFIX_INVALID, LOCPRF_VALID, result
    )


def test_show_rpki_aspa():
    """The ASPA records served by the cache must be visible in the shadow
    table that backs 'show rpki aspa'."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "65002": {"providerAsns": ["65001"]},
        "65003": {"providerAsns": ["65002"]},
        "65004": {"providerAsns": ["65009"]},
    }

    def _aspa():
        return json.loads(tgen.gears["r2"].vtysh_cmd("show rpki aspa json"))

    test_func = functools.partial(lambda: topotest.json_cmp(_aspa(), expected))
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "'show rpki aspa' does not list the served records"


def test_show_rpki_aspa_by_asn():
    """Filtering by customer ASN returns only that record."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = json.loads(tgen.gears["r2"].vtysh_cmd("show rpki aspa 65003 json"))

    assert list(output.keys()) == [
        "65003"
    ], "expected only customer ASN 65003, got {}".format(list(output.keys()))


def test_aspa_state_in_route_detail():
    """The per-prefix detail view reports both directions, since outside a
    route-map there is no direction to choose."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _states(prefix):
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        path = output["paths"][0]
        return (
            path.get("aspaUpstreamState"),
            path.get("aspaDownstreamState"),
        )

    # 65001 65004 is upstream-invalid but downstream-valid.
    test_func = functools.partial(_states, PREFIX_INVALID)
    _, result = topotest.run_and_expect(
        test_func, ("invalid", "valid"), count=60, wait=1
    )
    assert result == (
        "invalid",
        "valid",
    ), "{} detail should show upstream invalid / downstream valid, got {}".format(
        PREFIX_INVALID, result
    )


def test_aspa_match_survives_config_write():
    """'match aspa' must render back into running-config, or the condition is
    silently lost on save/restore."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r2"].vtysh_cmd("show running-config")
    assert (
        "match aspa downstream valid" in output
    ), "'match aspa' missing from running-config:\n{}".format(output)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
