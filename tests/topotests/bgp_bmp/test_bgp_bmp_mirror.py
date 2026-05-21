#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_bmp_mirror.py: demonstrate BMP route-mirroring
#
#   +---------+
#   |  bmpA   |---+
#   |192.0.2. |   |
#   |  10/24  |   |     +-----------+              +-----------+
#   +---------+   |     |           |              |           |
#                 +-----| r1mirror  |--------------|  r2mirror |
#   +---------+   |     |           |              |           |
#   |  bmpB   |---+     +-----------+              +-----------+
#   |192.0.2. |
#   |  20/24  |
#   +---------+
#
# r1mirror is the BMP client.  It has TWO distinct ``bmp targets`` blocks
# under the same ``router bgp`` instance.  Both have ``bmp mirror`` enabled
# and each one is connected to a different BMP collector.  R2mirror is a
# BGP peer that simply exists so that BGP packets (OPEN/KEEPALIVE/UPDATE)
# flow into r1mirror -- those packets are what trigger the mirror code
# path in ``bmp_mirror_packet()``.
#

#
"""
Reproducer for the bgpd BMP route-mirroring multi-target queueing bug.
"""

import json
import os
import pytest
import re
import sys
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
from lib import topotest
from lib.bgp import bgp_configure_prefixes
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1mirror")
    tgen.add_router("r2mirror")

    tgen.add_bmp_server("bmpA", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_bmp_server(
        "bmpB", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1mirror"])
    switch.add_link(tgen.gears["bmpA"])
    switch.add_link(tgen.gears["bmpB"])

    tgen.add_link(
        tgen.gears["r1mirror"], tgen.gears["r2mirror"], "r1mirror-eth1", "r2mirror-eth0"
    )


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s", rname)
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _daemon_pid(router, daemon):
    """
    Return the pid (as a string) of ``daemon`` running on ``router``,
    or an empty string if it is not running.
    """
    output = router.vtysh_cmd("show module")
    if not output:
        return ""

    in_section = False
    header_re = re.compile(r"^Module information for (\S+):")
    pid_re = re.compile(r"^pid:\s*(\d+)")
    for line in output.splitlines():
        m = header_re.match(line)
        if m:
            in_section = m.group(1) == daemon
            continue
        if in_section:
            m = pid_re.match(line)
            if m:
                return m.group(1)
    return ""


def _bmp_target_state(router, bmp_collector_addr_port, state):
    """Helper used by run_and_expect to wait for a BMP target to reach
    ``state`` ("Up" or "Down") in ``show bmp``.

    The ``bmp_collector_addr_port`` argument is something like
    ``192.0.2.10:1789`` -- the format that ``show bmp`` prints for the
    remote side of an outbound (``bmp connect``) session.
    """
    output = router.cmd(
        'vtysh -c "show bmp" 2>/dev/null | grep {} | grep {}'.format(
            bmp_collector_addr_port, state
        )
    )
    if not output:
        return "not in {} state yet".format(state)
    return True


def _bgp_prefixes_state(router, prefixes, present):
    """Helper used by run_and_expect to wait until all of ``prefixes`` are
    either present (``present=True``) or absent (``present=False``) in
    ``router``'s BGP IPv4 unicast table.
    """
    output = router.vtysh_cmd("show bgp ipv4 unicast json")
    try:
        data = json.loads(output)
    except ValueError:
        return "could not parse 'show bgp ipv4 unicast json'"

    routes = data.get("routes", {}) or {}
    for p in prefixes:
        in_table = p in routes
        if present and not in_table:
            return "prefix {} not yet present".format(p)
        if not present and in_table:
            return "prefix {} not yet withdrawn".format(p)
    return True


def _bmp_mirror_quiesced(router, expected_pid):
    """Return True once bgpd is healthy and the per-VRF mirror queue has
    drained.  Used with ``run_and_expect`` to replace a fixed sleep --
    under heavy load 1-2 seconds is not always enough.

    Returns True only when ALL of the following hold:

    * bgpd is still running with ``expected_pid`` (no crash / restart);
    * ``vtysh -c 'show bmp'`` returns output (bgpd is responsive, not
      wedged in an infinite loop walking a self-referential queue);
    * the per-VRF mirror queue reports ``0 messages`` pending in
      ``show bmp`` (pullwr / wrmirror has drained everything we
      enqueued).

    Otherwise it returns a short string describing why the state is not
    yet acceptable, so ``run_and_expect`` can keep polling.
    """
    pid_now = _daemon_pid(router, "bgpd")
    if not pid_now:
        return "bgpd is not running"
    if pid_now != expected_pid:
        return "bgpd pid changed: was {}, is {}".format(expected_pid, pid_now)

    show_bmp = router.vtysh_cmd("show bmp")
    if not show_bmp:
        return "show bmp returned no output (bgpd may be wedged)"
    if "0 bytes (0 messages) pending" not in show_bmp:
        return "mirror queue not yet drained"

    return True


def test_bgp_convergence():
    """
    Make sure the BGP session between r1mirror and r2mirror comes up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1mirror")
    assert result is True, "BGP is not converging"


def test_bmp_targets_connected():
    """
    Both BMP collectors must be connected to r1mirror.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for collector in ("192.0.2.10:1789", "192.0.2.20:1790"):
        logger.info("Waiting for BMP target %s to be Up", collector)
        test_func = partial(_bmp_target_state, tgen.gears["r1mirror"], collector, "Up")
        success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
        assert success, "BMP target {} did not reach Up state".format(collector)


def test_bgpd_survives_mirrored_traffic():
    """
    Drive BGP traffic through r1mirror so the mirror queue is
    exercised repeatedly.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1mirror"]
    r2 = tgen.gears["r2mirror"]

    bgpd_pid_before = _daemon_pid(r1, "bgpd")
    assert bgpd_pid_before, "bgpd is not running on r1mirror"
    logger.info("bgpd pid on r1mirror is %s", bgpd_pid_before)

    prefixes_a = [
        "203.0.113.1/32",
        "203.0.113.2/32",
        "203.0.113.3/32",
        "203.0.113.4/32",
    ]
    prefixes_b = [
        "203.0.113.5/32",
        "203.0.113.6/32",
        "203.0.113.7/32",
        "203.0.113.8/32",
    ]

    all_prefixes = prefixes_a + prefixes_b

    logger.info("driving BGP UPDATE traffic to exercise the mirror queue")
    for i in range(5):
        bgp_configure_prefixes(r2, 65502, "unicast", prefixes_a, update=True)
        bgp_configure_prefixes(r2, 65502, "unicast", prefixes_b, update=True)

        test_func = partial(_bgp_prefixes_state, r1, all_prefixes, True)
        success, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
        assert success, (
            "iteration {}: announced prefixes did not reach r1mirror's BGP "
            "table: {}".format(i, res)
        )

        bgp_configure_prefixes(r2, 65502, "unicast", prefixes_a, update=False)
        bgp_configure_prefixes(r2, 65502, "unicast", prefixes_b, update=False)

        test_func = partial(_bgp_prefixes_state, r1, all_prefixes, False)
        success, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
        assert success, (
            "iteration {}: withdrawn prefixes did not disappear from "
            "r1mirror's BGP table: {}".format(i, res)
        )

    # Wait for pullwr / wrmirror to run on the (possibly corrupted) queue
    # and drain it before we sample state -- a fixed sleep is not reliable
    # under heavy load.
    logger.info("waiting for the BMP route-mirroring queue to drain")
    test_func = partial(_bmp_mirror_quiesced, r1, bgpd_pid_before)
    success, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "bgpd / BMP did not reach a quiesced state on r1mirror: {}".format(
        res
    )

    bgpd_pid_after = _daemon_pid(r1, "bgpd")
    logger.info("bgpd pid on r1mirror after traffic is %r", bgpd_pid_after)

    assert bgpd_pid_after, (
        "bgpd on r1mirror is no longer running -- it most likely crashed "
        "while walking a mirror queue corrupted by bmp_mirror_packet()"
    )
    assert bgpd_pid_after == bgpd_pid_before, (
        "bgpd on r1mirror was restarted (pid changed from {} to {}) -- it "
        "probably crashed while walking a mirror queue corrupted by "
        "bmp_mirror_packet()".format(bgpd_pid_before, bgpd_pid_after)
    )

    # Also fail if any router (including bgpd) is reported as having
    # died by the topotest infrastructure.
    assert not tgen.routers_have_failure(), (
        "a router daemon died during the test -- see logs above; this is "
        "consistent with the bmp_mirror_packet() typesafe-list corruption "
        "bug being exercised"
    )

    # Finally, make sure bgpd is still responsive (not wedged in an
    # infinite loop walking a self-referential queue).
    show_bmp = r1.vtysh_cmd("show bmp")
    assert show_bmp, (
        "vtysh 'show bmp' returned nothing -- bgpd may be wedged walking a "
        "mirror queue corrupted by bmp_mirror_packet()"
    )
    logger.info("show bmp output:\n%s", show_bmp)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
