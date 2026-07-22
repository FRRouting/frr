#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Regression test for stale BGP LLGR timers after peer AF deletion.

The test arms peer->t_llgr_stale[afi][safi], deletes the peer AF that was used
as the timer callback argument, and verifies that bgpd survives beyond the
original timer deadline.
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

pytestmark = [pytest.mark.bgpd]

R1_PREFIX = "10.0.0.1/32"
R2_AS = 65002
R2_NEIGHBOR = "192.168.255.1"
LLGR_STALE_TIME = 10


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


def _bgpd_alive(router):
    return (
        router.cmd("test -d /proc/$(cat /var/run/frr/bgpd.pid) && echo alive || true")
        .strip()
    )


def _neighbor_json(router, neighbor):
    output = router.vtysh_cmd("show ip bgp neighbor {} json".format(neighbor))
    return json.loads(output).get(neighbor, {})


def _prefix_json(router, prefix):
    output = router.vtysh_cmd("show ip bgp {} json".format(prefix))
    return json.loads(output)


def _route_observation(router, prefix):
    output = _prefix_json(router, prefix)
    paths = output.get("paths", [])
    first_path = paths[0] if paths else {}
    community = first_path.get("community", {}) if first_path else {}

    return {
        "bgpdAlive": _bgpd_alive(router),
        "present": bool(paths),
        "stale": first_path.get("stale"),
        "llgrSecondsRemaining": first_path.get("llgrSecondsRemaining"),
        "community": community.get("string"),
    }


def test_bgp_llgr_stale_timer_cancelled_on_peer_af_delete():
    """
    Deleting a peer AF must cancel any LLGR stale timer using that peer_af.

    Broken behavior:
    - GR helper mode arms peer->t_llgr_stale[afi][safi] with struct peer_af.
    - `no neighbor ... activate` deletes and frees that peer_af.
    - The stale timer later fires and dereferences the freed callback argument.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _r2_bgp_established():
        neighbor = _neighbor_json(r2, R2_NEIGHBOR)
        if neighbor.get("bgpState") != "Established":
            return neighbor
        return None

    step("Wait for R2 BGP to establish")
    test_func = functools.partial(_r2_bgp_established)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    def _r2_has_prefix():
        obs = _route_observation(r2, R1_PREFIX)
        if not obs["present"]:
            return obs
        if obs["stale"]:
            return obs
        return None

    step("Wait for R2 to learn R1 prefix")
    test_func = functools.partial(_r2_has_prefix)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("Stop R1 bgpd so R2 arms the LLGR stale timer")
    kill_router_daemons(tgen, "r1", ["bgpd"])

    def _r2_llgr_timer_running():
        obs = _route_observation(r2, R1_PREFIX)
        if not obs["present"]:
            return obs
        if obs["stale"] is not True:
            return obs
        if obs["community"] != "llgr-stale":
            return obs
        if (
            obs["llgrSecondsRemaining"] is None
            or obs["llgrSecondsRemaining"] < 2
        ):
            return obs
        return None

    test_func = functools.partial(_r2_llgr_timer_running)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
    assert result is None, result

    step("Delete R2 IPv4 peer AF before the LLGR stale timer expires")
    r2.vtysh_cmd(
        """
    configure terminal
     router bgp {}
      address-family ipv4 unicast
       no neighbor {} activate
    """.format(
            R2_AS, R2_NEIGHBOR
        )
    )

    deadline = time.monotonic() + LLGR_STALE_TIME + 2

    def _r2_bgpd_alive_after_stale_timer_deadline():
        if _bgpd_alive(r2) != "alive":
            return "r2 bgpd is not alive"

        remaining = deadline - time.monotonic()
        if remaining > 0:
            return "waiting {:.1f}s for stale LLGR timer deadline".format(remaining)

        return None

    step("Verify R2 bgpd stays alive past the stale LLGR timer deadline")
    test_func = functools.partial(_r2_bgpd_alive_after_stale_timer_deadline)
    _, result = topotest.run_and_expect(
        test_func, None, count=LLGR_STALE_TIME + 10, wait=1
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
