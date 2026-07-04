#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 RouteViews
# Authored by Anton Berezin <tobez@tobez.org>
#

"""
test_bgp_bmp_prepolicy_no_softreconfig.py: BMP pre-policy monitoring of a
neighbor that does NOT have ``soft-reconfiguration inbound``.

    +----------+            +----------+               +----------+
    |          |            |          |               |          |
    | bmp1nosr |------------|  r1nosr  |---------------|  r2nosr  |
    |          |            |          |               |          |
    +----------+            +----------+               +----------+

Without ``soft-reconfiguration inbound`` bgpd keeps no Adj-RIB-In for the
peer.  BMP pre-policy monitoring reads exclusively from Adj-RIB-In, so an
announcement from r2nosr must NOT be turned into a fabricated pre-policy
*withdrawal* towards the BMP collector (FRRouting/frr issue #10240).
Post-policy monitoring, which reads the main RIB, must stay correct.
"""

import os
import sys
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.bgp import bgp_configure_prefixes
from .bgpbmp import BMPSequenceContext, bmp_update_seq, get_bmp_messages
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# Prefix whose BMP treatment we assert on, plus a sentinel prefix announced
# afterwards.  Once the sentinel's post-policy update is logged, any message
# bgpd fabricated while processing WATCHED_PREFIX is already in the log, so
# the "no fabricated pre-policy withdrawal" assertion has no timing race.
WATCHED_PREFIX = "203.0.113.1/32"
SENTINEL_PREFIX = "203.0.113.254/32"

bmp_seq_context = BMPSequenceContext()


def build_topo(tgen):
    tgen.add_router("r1nosr")
    tgen.add_router("r2nosr")
    tgen.add_bmp_server("bmp1nosr", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1nosr"])
    switch.add_link(tgen.gears["bmp1nosr"])

    tgen.add_link(tgen.gears["r1nosr"], tgen.gears["r2nosr"], "r1nosr-eth1", "r2nosr-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=["zebra", ("bgpd", "-M bmp")],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bmp_log_file():
    tgen = get_topogen()
    return os.path.join(tgen.logdir, "bmp1nosr", "bmp.log")


def _route_messages(policy, bmp_log_type, prefix):
    """
    Return the new BMP route-monitoring messages (seq beyond the recorded
    baseline) matching the given policy, message type and prefix.
    """
    tgen = get_topogen()
    baseline = bmp_seq_context.get_seq()
    messages = get_bmp_messages(tgen.gears["bmp1nosr"], _bmp_log_file())
    return [
        m
        for m in messages
        if m.get("seq", 0) > baseline
        and m.get("policy") == policy
        and m.get("bmp_log_type") == bmp_log_type
        and m.get("ip_prefix") == prefix
    ]


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1nosr")
    assert result is True, "BGP is not converging"


def test_bmp_server_logging():
    """
    Wait for the BMP collector to start logging (session established).
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1nosr"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1nosr"))
        )
        return "bmp.log" in output

    success, _ = topotest.run_and_expect(check_for_log_file, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_no_fabricated_prepolicy_withdrawal():
    """
    Announce a prefix from r2nosr (which r1nosr does not keep an Adj-RIB-In
    for) and assert that:

    * a post-policy update is emitted for it (control: the RIB path is fine);
    * no pre-policy *withdrawal* is fabricated for it (the bug).
    """
    tgen = get_topogen()

    # Record the BMP sequence baseline so we only look at messages produced
    # from here on (peer-up, table sync, etc. are excluded).
    bmp_update_seq(tgen.gears["bmp1nosr"], _bmp_log_file(), bmp_seq_context)

    # Announce the watched prefix, then a sentinel prefix.  Both are injected
    # from r2nosr and travel over a session with no soft-reconfiguration.
    bgp_configure_prefixes(
        tgen.gears["r2nosr"], 65502, "unicast", [WATCHED_PREFIX], update=True
    )
    bgp_configure_prefixes(
        tgen.gears["r2nosr"], 65502, "unicast", [SENTINEL_PREFIX], update=True
    )

    # Wait until both prefixes have reached r1nosr's BGP table.
    def _prefixes_in_rib():
        out = tgen.gears["r1nosr"].vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
        routes = out.get("routes", {}) or {}
        for p in (WATCHED_PREFIX, SENTINEL_PREFIX):
            if p not in routes:
                return "prefix {} not in RIB yet".format(p)
        return True

    success, res = topotest.run_and_expect(_prefixes_in_rib, True, count=30, wait=1)
    assert success, "prefixes did not reach r1nosr's BGP table: {}".format(res)

    # Gate on the sentinel's post-policy update.  Once it is logged, every
    # message bgpd emitted while processing WATCHED_PREFIX is already present.
    def _sentinel_seen():
        if _route_messages("post-policy", "update", SENTINEL_PREFIX):
            return True
        return "sentinel post-policy update not logged yet"

    success, res = topotest.run_and_expect(_sentinel_seen, True, count=30, wait=1)
    assert success, "sentinel post-policy update never reached the BMP log: {}".format(
        res
    )

    # Control: the watched prefix must have a post-policy update.
    post_updates = _route_messages("post-policy", "update", WATCHED_PREFIX)
    assert post_updates, (
        "expected a post-policy update for {} but none was logged".format(
            WATCHED_PREFIX
        )
    )

    # The bug: with no Adj-RIB-In, bgpd fabricated a pre-policy withdrawal for
    # a prefix that was only ever announced.  There must be none.
    fabricated = _route_messages("pre-policy", "withdraw", WATCHED_PREFIX)
    assert not fabricated, (
        "bgpd fabricated {} pre-policy withdrawal(s) for {} that was only "
        "announced (no soft-reconfiguration inbound -> no Adj-RIB-In): {}".format(
            len(fabricated), WATCHED_PREFIX, fabricated
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
