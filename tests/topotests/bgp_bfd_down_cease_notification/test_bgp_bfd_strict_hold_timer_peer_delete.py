#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Local regression reproducer for stale BGP/BFD strict hold timers.

The test uses only the local topotest topology.  It arms a strict BFD hold timer
on R2, deletes the R2 BGP neighbor before the timer expires, and then verifies
that bgpd survives past the original timer deadline.
"""

import functools
import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

R1_NEIGHBOR = "192.168.255.2"
R2_NEIGHBOR = "192.168.255.1"
BFD_STRICT_HOLD_TIME = 5


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _neighbor_json(router, neighbor):
    output = router.vtysh_cmd(f"show ip bgp neighbor {neighbor} json")
    return json.loads(output)[neighbor]


def _r2_neighbor_observation(r2):
    neighbor = _neighbor_json(r2, R2_NEIGHBOR)
    peer_bfd_info = neighbor.get("peerBfdInfo", {})

    return {
        "bgpState": neighbor.get("bgpState"),
        "connectionsDropped": neighbor.get("connectionsDropped"),
        "bfdHoldTimerExpireInMsecs": neighbor.get("bfdHoldTimerExpireInMsecs"),
        "bfdHoldTimerExpired": neighbor.get("bfdHoldTimerExpired"),
        "peerBfdStatus": peer_bfd_info.get("status"),
    }


def _bgpd_alive(router):
    return (
        router.cmd("test -d /proc/$(cat /var/run/frr/bgpd.pid) && echo alive || true")
        .strip()
    )


def test_bfd_strict_hold_timer_peer_delete_no_stale_crash():
    """
    Deleting a peer must cancel any strict BFD hold timer owned by that peer.

    Current broken behavior with an ASAN build:
    - BFD Down arms peer->bfd_config->t_hold_timer.
    - `no neighbor` frees peer->bfd_config, and may release the peer.
    - The stale timer later fires and touches freed memory.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Configure zero BGP holdtime and strict BFD hold timers")
    r1.vtysh_cmd(
        f"""
    configure terminal
     router bgp 65001
      neighbor {R1_NEIGHBOR} timers 0 0
      neighbor {R1_NEIGHBOR} bfd strict hold-time {BFD_STRICT_HOLD_TIME}
    """
    )
    r2.vtysh_cmd(
        f"""
    configure terminal
     router bgp 65002
      neighbor {R2_NEIGHBOR} timers 0 0
      neighbor {R2_NEIGHBOR} bfd strict hold-time {BFD_STRICT_HOLD_TIME}
    """
    )

    def _r2_bgp_bfd_up():
        obs = _r2_neighbor_observation(r2)
        if obs["bgpState"] != "Established":
            return obs
        if obs["peerBfdStatus"] != "Up":
            return obs
        return None

    step("Wait for R2 BGP and BFD to converge")
    test_func = functools.partial(_r2_bgp_bfd_up)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Stop R1 bfdd so R2 arms the strict hold timer")
    kill_router_daemons(tgen, "r1", ["bfdd"])

    def _r2_bfd_down_timer_running():
        obs = _r2_neighbor_observation(r2)
        if obs["peerBfdStatus"] != "Down":
            return obs
        if (
            obs["bfdHoldTimerExpireInMsecs"] is None
            or obs["bfdHoldTimerExpireInMsecs"] <= 0
        ):
            return obs
        return None

    test_func = functools.partial(_r2_bfd_down_timer_running)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    step("Delete the R2 peer before the strict hold timer expires")
    r2.vtysh_cmd(
        f"""
    configure terminal
     router bgp 65002
      no neighbor {R2_NEIGHBOR}
    """
    )

    deadline = time.monotonic() + BFD_STRICT_HOLD_TIME + 2

    def _r2_bgpd_alive_after_stale_timer_deadline():
        if _bgpd_alive(r2) != "alive":
            return "r2 bgpd is not alive"

        remaining = deadline - time.monotonic()
        if remaining > 0:
            return "waiting {:.1f}s for stale strict BFD hold timer deadline".format(
                remaining
            )

        return None

    step("Verify R2 bgpd stays alive past the stale strict hold timer deadline")
    test_func = functools.partial(_r2_bgpd_alive_after_stale_timer_deadline)
    _, result = topotest.run_and_expect(
        test_func, None, count=BFD_STRICT_HOLD_TIME + 10, wait=1
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
