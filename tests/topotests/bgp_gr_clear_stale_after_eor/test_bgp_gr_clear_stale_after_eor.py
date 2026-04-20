#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Nageswara Soma <nsoma@cisco.com>
#

"""
Test that stale routes are cleaned up immediately once all EORs are received
during graceful restart, instead of waiting for the stalepath timer to fire.

Topology:

    +----+   192.168.255.0/24   +----+
    | r1 |----------------------| r2 |
    +----+                      +----+
    AS 65001                    AS 65002
    networks:
      172.16.255.1/32
      172.16.255.2/32

Scenario:
  1. r1 advertises 172.16.255.1/32 and 172.16.255.2/32 to r2.
  2. r2 confirms both prefixes are present and not stale.
  3. r1's bgpd is killed (write memory saves the running config).
  4. r2 marks both prefixes as stale (graceful-restart helper behavior).
  5. The persisted r1 config is edited to remove the network statement for
     172.16.255.2/32.
  6. r1's bgpd is restarted.  The session re-establishes and r1 sends an EOR
     for ipv4-unicast (the only NSF AFI/SAFI on this peer).
  7. With the C3 fix in this PR, once r2 sees the EOR for every NSF AFI/SAFI
     on this peer it walks the stale routes immediately and cancels the
     t_gr_stale timer.  We assert 172.16.255.2/32 is gone from r2's BGP
     table well before the configured stalepath-time of 600s could fire.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    step,
    start_router_daemons,
)

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_converge(r2):
    output = json.loads(
        r2.vtysh_cmd("show bgp ipv4 neighbors 192.168.255.1 json")
    )
    expected = {
        "192.168.255.1": {
            "bgpState": "Established",
            "addressFamilyInfo": {
                "ipv4Unicast": {"acceptedPrefixCounter": 2}
            },
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_prefix_present(r2, prefix):
    output = json.loads(
        r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if not output or "paths" not in output or not output["paths"]:
        return "{} not present".format(prefix)
    return None


def _bgp_prefix_stale(r2, prefix):
    output = json.loads(
        r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    expected = {"paths": [{"stale": True}]}
    return topotest.json_cmp(output, expected)


def _bgp_prefix_absent(r2, prefix):
    output = json.loads(
        r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if not output or "paths" not in output or not output["paths"]:
        return None
    return "{} still present: {}".format(prefix, output)


def test_bgp_gr_clear_stale_after_eor():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Initial BGP convergence (both prefixes accepted on r2)")
    test_func = functools.partial(_bgp_converge, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see initial BGP convergence on r2"

    step("Confirm both prefixes are live (not stale) on r2")
    for prefix in ("172.16.255.1/32", "172.16.255.2/32"):
        assert _bgp_prefix_present(r2, prefix) is None, (
            "Prefix {} missing on r2 before restart".format(prefix)
        )

    step("Kill bgpd on r1 (write memory persists current config)")
    # NOTE: We deliberately bypass kill_router_daemons() here because in this
    # 2-router topology the topotest framework's wait loop never observes the
    # killed bgpd as gone (its parent does not reap the zombie within the
    # poll window) and the call hangs indefinitely. A direct SIGKILL plus
    # pid-file cleanup is sufficient for our purposes; the only requirement
    # is that bgpd is no longer accepting BGP messages from r2.
    r1.vtysh_cmd("write memory")
    r1.run("kill -KILL $(cat /var/run/frr/bgpd.pid 2>/dev/null) 2>/dev/null || true")
    r1.run("rm -f /var/run/frr/bgpd.pid /var/run/frr/bgpd.vty")

    step("Wait for r2 to mark 172.16.255.2/32 as stale")
    test_func = functools.partial(_bgp_prefix_stale, r2, "172.16.255.2/32")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "r2 did not mark 172.16.255.2/32 stale: {}".format(
        result
    )

    step(
        "Rewrite r1 unified frr.conf to drop both the static route and the "
        "BGP network statement for 172.16.255.2/32 so when bgpd restarts and "
        "vtysh -b replays the config, r1 only re-advertises 172.16.255.1/32"
    )
    r1.run(
        "sed -i -e '/^ip route 172.16.255.2\\/32 Null0$/d' "
        "-e '/^  network 172.16.255.2\\/32$/d' /etc/frr/frr.conf"
    )

    step("Restart bgpd on r1")
    start_router_daemons(tgen, "r1", ["bgpd"])
    # In unified-config mode the per-daemon /etc/frr/bgpd.conf is empty;
    # bgpd needs the unified config re-pushed via vtysh to learn its neighbors
    # and networks again. start_router_daemons() does not do this.
    r1.run("vtysh -b -f /etc/frr/frr.conf >/dev/null 2>&1 || true")

    step("Wait for r2 to see the session re-established and 1 prefix accepted")

    def _bgp_one_prefix(r2):
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 neighbors 192.168.255.1 json")
        )
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {"acceptedPrefixCounter": 1}
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_one_prefix, r2)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert result is None, "r2 did not see post-restart convergence: {}".format(
        result
    )

    step(
        "Assert 172.16.255.2/32 is removed from r2's BGP table (stalepath "
        "cleared promptly after EOR rather than waiting for the 600s "
        "stalepath timer)"
    )
    test_func = functools.partial(
        _bgp_prefix_absent, r2, "172.16.255.2/32"
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, (
        "Stale 172.16.255.2/32 still present on r2 after r1 EOR; "
        "stalepath cleanup did not run promptly: {}".format(result)
    )

    step("Assert 172.16.255.1/32 is still present (re-advertised after restart)")
    assert (
        _bgp_prefix_present(r2, "172.16.255.1/32") is None
    ), "172.16.255.1/32 unexpectedly missing on r2 after restart"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
