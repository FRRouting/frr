#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""A second RT-3 route must remove an obsolete HREP FDB entry."""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNI = 101
REMOTE_VTEP = "10.0.0.2"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer = tgen.add_host("peer", ip="10.0.0.2/24", defaultRoute="via 10.0.0.1")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    r1 = tgen.gears["r1"]
    r1.cmd_raises("ip link add br101 type bridge stp_state 0")
    r1.cmd_raises("ip link set br101 up")
    r1.cmd_raises(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 "
        "dev r1-eth0 local 10.0.0.1 nolearning"
    )
    r1.cmd_raises("ip link set vxlan101 master br101")
    r1.cmd_raises("ip link set vxlan101 up")
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()

    # bgpd rejects incoming peers while frr.conf is still being applied.
    check = partial(_bgp_ready, r1)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, f"BGP peer configuration did not finish: {result}"

    peer = tgen.gears["peer"]
    speaker = os.path.join(CWD, "peer/speaker.py")
    peer.cmd_raises(f"python3 {speaker} 10.0.0.1 > /tmp/imet-speaker.log 2>&1 &")


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.gears["peer"].cmd("pkill -f '[s]peaker.py 10.0.0.1'")
    tgen.stop_topology()


def _bgp_ready(router):
    output = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    state = output.get("peers", {}).get(REMOTE_VTEP, {}).get("state")
    return None if state in ("Connect", "Active") else f"BGP peer state: {state}"


def _flood_mode(router, expected):
    output = router.vtysh_cmd(f"show evpn vni {VNI} json", isjson=True)
    for vtep in output.get("remoteVteps", []):
        if vtep.get("ip") == REMOTE_VTEP:
            return None if vtep.get("flood") == expected else vtep
    return f"Remote VTEP {REMOTE_VTEP} missing from VNI {VNI}: {output}"


def _hrep_entry(router, present):
    output = router.run("bridge -j fdb show dev vxlan101")
    try:
        entries = json.loads(output)
    except json.JSONDecodeError:
        return f"Invalid bridge FDB JSON: {output}"
    found = any(
        entry.get("mac") == "00:00:00:00:00:00" and entry.get("dst") == REMOTE_VTEP
        for entry in entries
    )
    return None if found == present else f"HREP present={found}, expected={present}"


def _both_imet_routes(router):
    routes = router.vtysh_cmd(
        "show bgp l2vpn evpn route type multicast json", isjson=True
    )
    expected = {f"{REMOTE_VTEP}:2", f"{REMOTE_VTEP}:3"}
    found = expected.intersection(routes)
    return None if found == expected else f"Missing IMET routes: {expected - found}"


def test_second_imet_disables_her():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peer = tgen.gears["peer"]

    check = partial(_flood_mode, r1, "HER")
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, f"Initial IMET route did not enable HER: {result}"

    check = partial(_hrep_entry, r1, True)
    _, result = topotest.run_and_expect(check, None, count=20, wait=1)
    assert result is None, f"Initial HREP entry missing: {result}"

    peer.cmd_raises("kill -USR1 $(cat /tmp/imet-speaker.pid)")

    check = partial(_both_imet_routes, r1)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, result

    check = partial(_flood_mode, r1, "-")
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, f"Second IMET did not disable flooding: {result}"

    check = partial(_hrep_entry, r1, False)
    _, result = topotest.run_and_expect(check, None, count=20, wait=1)
    assert result is None, f"HREP entry survived the second IMET: {result}"


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
