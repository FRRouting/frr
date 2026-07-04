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

BMP pre-policy monitoring reads from Adj-RIB-In, which bgpd maintains
whenever pre-policy monitoring covers the peer -- no user-visible
``soft-reconfiguration inbound`` is required (FRRouting/frr issue #10240).

Checks, in order:

* announcements from r2nosr produce pre-policy updates (and no fabricated
  pre-policy withdrawals);
* no "no Adj-RIB-In" warning is logged;
* a fresh table sync carries the initial pre-policy dump before the
  pre-policy End-of-RIB;
* genuine withdrawals produce pre-policy withdrawals -- and only those;
* a peer bounce re-announces the full pre-policy feed;
* disabling pre-policy monitoring at runtime frees the Adj-RIB-In memory;
* re-enabling it repopulates Adj-RIB-In via route refresh;
* ``show bgp ... received-routes`` still requires the user-visible
  soft-reconfiguration flag.
"""

import os
import re
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
# bgpd emitted while processing WATCHED_PREFIX is already in the log, so the
# assertions on WATCHED_PREFIX have no timing race.
WATCHED_PREFIX = "203.0.113.1/32"
SENTINEL_PREFIX = "203.0.113.254/32"

ADJ_RIB_IN_WARNING = "has no Adj-RIB-In for"

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


def _prepolicy_eor_seq():
    """
    Return the seq of the first pre-policy End-of-RIB logged beyond the
    recorded baseline, or None.  An EoR is a route-monitoring message (an
    empty BGP UPDATE) carrying neither an NLRI nor withdrawn routes, so the
    collector logs it as an "update" without an "ip_prefix" field.
    """
    tgen = get_topogen()
    baseline = bmp_seq_context.get_seq()
    messages = get_bmp_messages(tgen.gears["bmp1nosr"], _bmp_log_file())
    for m in messages:
        if (
            m.get("seq", 0) > baseline
            and m.get("policy") == "pre-policy"
            and m.get("bmp_log_type") == "update"
            and "ip_prefix" not in m
        ):
            return m["seq"]
    return None


def _r1nosr_bgpd_log():
    tgen = get_topogen()
    path = os.path.join(tgen.logdir, "r1nosr", "bgpd.log")
    return tgen.gears["r1nosr"].run("cat {}".format(path))


def _adj_in_count():
    """
    r1nosr's Adj-RIB-In entry count, from bgpd's MTYPE_BGP_ADJ_IN allocation
    counter in ``show memory``.  Returns None if the counter has never been
    non-zero (bgpd omits such lines).
    """
    tgen = get_topogen()
    out = tgen.gears["r1nosr"].vtysh_cmd("show memory")
    m = re.search(r"BGP adj in\s*:\s*(\d+)", out)
    if m is None:
        return None
    return int(m.group(1))


def _r1nosr_bmp_targets_config(*lines):
    tgen = get_topogen()
    cmd = "configure terminal\nrouter bgp 65501\nbmp targets bmp1nosr\n"
    cmd += "\n".join(lines) + "\n"
    return tgen.gears["r1nosr"].vtysh_cmd(cmd)


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


def test_prepolicy_feed_announce():
    """
    Announce a prefix from r2nosr (whose session has no soft-reconfiguration
    inbound) and assert that:

    * a pre-policy update is emitted for it (BMP pre-policy monitoring keeps
      Adj-RIB-In by itself);
    * a post-policy update is emitted for it (control: the RIB path is fine);
    * no pre-policy *withdrawal* is fabricated for it (the original
      FRRouting/frr issue #10240 bug).
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

    # The fix: pre-policy monitoring maintains Adj-RIB-In itself, so the
    # announcement must show up in the pre-policy feed even without
    # soft-reconfiguration inbound.
    def _prepolicy_update_seen():
        if _route_messages("pre-policy", "update", WATCHED_PREFIX):
            return True
        return "pre-policy update not logged yet"

    success, res = topotest.run_and_expect(_prepolicy_update_seen, True, count=30, wait=1)
    assert success, (
        "expected a pre-policy update for {} (no soft-reconfiguration "
        "inbound, adj-in driven by BMP pre-policy monitoring): {}".format(
            WATCHED_PREFIX, res
        )
    )

    # The original bug: with no Adj-RIB-In, bgpd fabricated a pre-policy
    # withdrawal for a prefix that was only ever announced.  Must stay fixed.
    fabricated = _route_messages("pre-policy", "withdraw", WATCHED_PREFIX)
    assert not fabricated, (
        "bgpd fabricated {} pre-policy withdrawal(s) for {} that was only "
        "announced: {}".format(len(fabricated), WATCHED_PREFIX, fabricated)
    )


def test_no_adj_rib_in_warning():
    """
    Pre-policy monitoring drives Adj-RIB-In maintenance itself, so bgpd must
    NOT warn about a missing Adj-RIB-In -- neither at peer-up nor at
    configuration time.
    """
    out = _r1nosr_bgpd_log()

    # Positive control: make sure we are looking at a live bgpd log before
    # asserting on the absence of the warning.
    assert "ADJCHANGE" in out, (
        "r1nosr's bgpd.log looks empty or unreadable; cannot assert on it"
    )

    assert ADJ_RIB_IN_WARNING not in out, (
        "bgpd warned about a missing Adj-RIB-In although BMP pre-policy "
        "monitoring maintains it"
    )


def test_prepolicy_initial_dump():
    """
    Force a fresh table sync on the live BMP session (any monitor flag
    change re-triggers it; the test collector only accepts a single TCP
    session, so the BMP session itself cannot be bounced) and verify that
    the pre-policy routes are dumped from Adj-RIB-In before the pre-policy
    End-of-RIB.
    """
    tgen = get_topogen()

    bmp_update_seq(tgen.gears["bmp1nosr"], _bmp_log_file(), bmp_seq_context)

    _r1nosr_bmp_targets_config("no bmp monitor ipv4 unicast post-policy")

    def _eor_seen():
        if _prepolicy_eor_seq() is not None:
            return True
        return "pre-policy EoR not logged yet"

    success, res = topotest.run_and_expect(_eor_seen, True, count=60, wait=1)
    assert success, "no pre-policy EoR after the forced table sync: {}".format(res)

    eor_seq = _prepolicy_eor_seq()
    for prefix in (WATCHED_PREFIX, SENTINEL_PREFIX):
        updates = _route_messages("pre-policy", "update", prefix)
        assert updates, (
            "expected {} in the initial pre-policy dump of the new BMP "
            "session but it was never logged".format(prefix)
        )
        assert min(m["seq"] for m in updates) < eor_seq, (
            "{} was logged only after the pre-policy EoR (seq {}); it must "
            "be part of the initial table dump".format(prefix, eor_seq)
        )

    # Restore the configuration for the remaining tests.
    _r1nosr_bmp_targets_config("bmp monitor ipv4 unicast post-policy")


def test_prepolicy_genuine_withdraw():
    """
    Withdraw the watched prefix on r2nosr: the pre-policy feed must carry a
    withdrawal for it -- and no withdrawal for the still-announced sentinel.
    """
    tgen = get_topogen()

    bmp_update_seq(tgen.gears["bmp1nosr"], _bmp_log_file(), bmp_seq_context)

    bgp_configure_prefixes(
        tgen.gears["r2nosr"], 65502, "unicast", [WATCHED_PREFIX], update=False
    )

    def _withdraw_seen():
        if _route_messages("pre-policy", "withdraw", WATCHED_PREFIX):
            return True
        return "pre-policy withdraw not logged yet"

    success, res = topotest.run_and_expect(_withdraw_seen, True, count=30, wait=1)
    assert success, (
        "expected a pre-policy withdrawal for the genuinely withdrawn "
        "{}: {}".format(WATCHED_PREFIX, res)
    )

    fabricated = _route_messages("pre-policy", "withdraw", SENTINEL_PREFIX)
    assert not fabricated, (
        "pre-policy withdrawal(s) logged for {} which was never "
        "withdrawn: {}".format(SENTINEL_PREFIX, fabricated)
    )


def test_prepolicy_peer_bounce():
    """
    Hard-clear the BGP session on r1nosr.  After re-establishment the peer
    re-announces its routes, and the pre-policy feed must carry them again.
    """
    tgen = get_topogen()

    bmp_update_seq(tgen.gears["bmp1nosr"], _bmp_log_file(), bmp_seq_context)

    tgen.gears["r1nosr"].vtysh_cmd("clear ip bgp 192.168.0.2")

    def _reannounced():
        if _route_messages("pre-policy", "update", SENTINEL_PREFIX):
            return True
        return "pre-policy update not re-logged yet"

    success, res = topotest.run_and_expect(_reannounced, True, count=60, wait=1)
    assert success, (
        "expected a pre-policy update for {} after the peer bounce: "
        "{}".format(SENTINEL_PREFIX, res)
    )


def test_prepolicy_disable_frees_adj_in():
    """
    Disabling pre-policy monitoring at runtime must free the Adj-RIB-In
    entries bgpd only kept on its behalf (observable through the
    MTYPE_BGP_ADJ_IN allocation count in ``show memory``).
    """
    count = _adj_in_count()
    assert count is not None and count > 0, (
        "expected a non-zero Adj-RIB-In entry count while BMP pre-policy "
        "monitoring is enabled, got {}".format(count)
    )

    _r1nosr_bmp_targets_config("no bmp monitor ipv4 unicast pre-policy")

    def _adj_in_freed():
        count = _adj_in_count()
        if count == 0:
            return True
        return "Adj-RIB-In count still {}".format(count)

    success, res = topotest.run_and_expect(_adj_in_freed, True, count=30, wait=1)
    assert success, (
        "Adj-RIB-In was not freed after disabling pre-policy "
        "monitoring: {}".format(res)
    )


def test_prepolicy_reenable_repopulates_adj_in():
    """
    Re-enabling pre-policy monitoring must repopulate Adj-RIB-In via route
    refresh (the peer stays established) and resume the pre-policy feed,
    without any warning on the configuration terminal.
    """
    tgen = get_topogen()

    bmp_update_seq(tgen.gears["bmp1nosr"], _bmp_log_file(), bmp_seq_context)

    out = _r1nosr_bmp_targets_config("bmp monitor ipv4 unicast pre-policy")
    assert ADJ_RIB_IN_WARNING not in out, (
        "enabling pre-policy monitoring warned about a missing Adj-RIB-In "
        "although bgpd now maintains it: {}".format(out)
    )

    def _repopulated():
        count = _adj_in_count()
        if not count:
            return "Adj-RIB-In count is {}".format(count)
        if not _route_messages("pre-policy", "update", SENTINEL_PREFIX):
            return "pre-policy update not logged yet"
        return True

    success, res = topotest.run_and_expect(_repopulated, True, count=60, wait=1)
    assert success, (
        "Adj-RIB-In was not repopulated or the pre-policy feed did not "
        "resume after re-enabling pre-policy monitoring: {}".format(res)
    )


def test_received_routes_still_refused():
    """
    ``show bgp ... received-routes`` remains gated on the user-visible
    soft-reconfiguration flag, even while BMP pre-policy monitoring keeps
    an Adj-RIB-In for the peer.
    """
    tgen = get_topogen()

    out = tgen.gears["r1nosr"].vtysh_cmd(
        "show bgp ipv4 unicast neighbors 192.168.0.2 received-routes"
    )
    assert "Inbound soft reconfiguration not enabled" in out, (
        "received-routes must still require soft-reconfiguration inbound, "
        "got: {}".format(out)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
