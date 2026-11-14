#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# test_rip_source_interface.py
# Part of NetDEF Topology Tests
#
"""
test_rip_source_interface.py: RIP ingress interface selection

ripd used to receive RIP packets on a wildcard UDP socket with recvfrom()
and select the interface object with if_lookup_address(from.sin_addr),
i.e. by the packet's source address.  A packet arriving on an interface
that requires authentication, but carrying a source address from another
interface's connected prefix, was processed with the other interface's
RIP context (running, version, authentication, filters) and next-hop
interface.  An unauthenticated RESPONSE could thereby bypass the
authentication required on the real ingress interface.

Topology:
  r1-eth0 (10.0.12.1/24, RIP + MD5 auth key-chain r5key) --- sw1 ---
    r2-eth0 (10.0.12.2/24, same auth; lo 203.0.113.1/32)
    h1-eth0 (10.0.12.66/24, injector)
  r1-eth1 (10.0.13.1/24, RIP no auth) --- sw2 ---
    r3-eth0 (10.0.13.3/24; lo 203.0.113.2/32)

The trigger sends an unauthenticated RIPv2 RESPONSE from h1 with source
10.0.13.66 (inside r1-eth1's connected prefix) to multicast 224.0.0.9 and
to unicast 10.0.12.1.  The fixed daemon selects the real ingress
interface r1-eth0 and drops the packet; the unfixed daemon processes it
with r1-eth1's no-auth context and installs the route via r1-eth1.
"""

import os
import re
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripd]

THISDIR = os.path.dirname(os.path.realpath(__file__))

H1_IP = "10.0.12.66"
SPOOF_SRC = "10.0.13.66"  # inside r1-eth1's connected 10.0.13.0/24
KEY = "r5secret"

P_R2 = "203.0.113.1/32"
P_R3 = "203.0.113.2/32"
P_SPOOF_MC = "198.18.9.0/24"
P_SPOOF_UC = "198.18.11.0/24"
P_LEGIT = "198.18.10.0/24"
P_BADAUTH = "198.18.12.0/24"
P_NOAUTH = "198.18.13.0/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_host("h1", "10.0.12.66/24", "via 10.0.12.1")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])  # r1-eth0
    sw1.add_link(tgen.gears["r2"])  # r2-eth0
    sw1.add_link(tgen.gears["h1"])  # h1-eth0

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])  # r1-eth1
    sw2.add_link(tgen.gears["r3"])  # r3-eth0


def setup_module(module):
    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    net = tgen.net
    for rname in ("r1", "r2", "r3"):
        net[rname].loadConf("zebra", "%s/%s/zebra.conf" % (THISDIR, rname))
        net[rname].loadConf("ripd", "%s/%s/ripd.conf" % (THISDIR, rname))
        tgen.gears[rname].start()


def teardown_module(module):
    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    net = get_topogen().net
    for rname in ("r1", "r2", "r3"):
        assert net[rname].cmd("pidof zebra").strip(), "zebra not running on %s" % rname
        assert net[rname].cmd("pidof ripd").strip(), "ripd not running on %s" % rname


def rip_paths(router, prefix):
    """[{nh, metric, from}] for the prefix in `show ip rip` output."""
    out = []
    for line in router.vtysh_cmd("show ip rip").splitlines():
        if prefix not in line:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[1] == prefix and re.fullmatch(r"\d+", parts[3]):
            out.append({"nh": parts[2], "metric": int(parts[3]), "from": parts[4]})
    return out


def zebra_route(router, prefix):
    """(nexthops, oifs) from `show ip route <prefix>`."""
    out = router.vtysh_cmd("show ip route %s" % prefix)
    nhs = re.findall(r"(\d+\.\d+\.\d+\.\d+), via", out)
    oifs = [
        x.rstrip(",")
        for x in re.findall(r"^\s*\*?\s*\d+\.\d+\.\d+\.\d+, via (\S+)", out, re.M)
    ]
    return {"nh": nhs, "oif": oifs}


def route_absent(router, prefix, timeout=10):
    """True when the prefix stays out of the RIP RIB and zebra for the
    whole window."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if rip_paths(router, prefix) or zebra_route(router, prefix)["nh"]:
            return False
        time.sleep(1)
    return True


def route_gone(router, prefix, timeout=60):
    """True when the prefix leaves the RIP RIB (no finite path) and zebra
    within the window; metric-16 garbage-collection rows do not count."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        finite = [p for p in rip_paths(router, prefix) if p["metric"] < 16]
        if not finite and not zebra_route(router, prefix)["nh"]:
            return True
        time.sleep(1)
    return False


def route_present(router, prefix, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if [p for p in rip_paths(router, prefix) if p["metric"] < 16] and zebra_route(
            router, prefix
        )["nh"]:
            return True
        time.sleep(1)
    return False


def inject(tgen, src, dst, prefix, auth="none", key="", count=3):
    h1 = tgen.gears["h1"]
    cmd = (
        "python3 %s/rip_inject.py --iface h1-eth0 --src %s --dst %s "
        "--prefix %s --auth %s --count %d"
        % (THISDIR, src, dst, prefix.split("/")[0], auth, count)
    )
    if key:
        cmd += " --key %s" % key
    h1.cmd_raises(cmd)


def test_rip_baseline():
    "Baseline: r1 learns 203.0.113.1/32 from r2 and 203.0.113.2/32 from r3."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    assert route_present(r1, P_R2, timeout=90), "baseline route from r2 missing"
    assert route_present(r1, P_R3, timeout=30), "baseline route from r3 missing"


def test_rip_cross_interface_spoof_mcast_dropped():
    "Unauthenticated RESPONSE with a source from r1-eth1's prefix, sent on r1-eth0's segment to 224.0.0.9, must not enter the RIB."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    inject(tgen, SPOOF_SRC, "224.0.0.9", P_SPOOF_MC)
    assert route_absent(r1, P_SPOOF_MC), (
        "cross-interface spoof (multicast) installed: "
        "rip=%s zebra=%s" % (rip_paths(r1, P_SPOOF_MC), zebra_route(r1, P_SPOOF_MC))
    )
    # Processing proof: a correctly authenticated update from the same
    # injector is accepted, so the absence above is a drop, not a dead path.
    inject(tgen, H1_IP, "224.0.0.9", P_LEGIT, auth="md5", key=KEY)
    assert route_present(r1, P_LEGIT), "authenticated same-interface update not installed"
    assert "r1-eth0" in zebra_route(r1, P_LEGIT)["oif"], (
        "authenticated update not attributed to r1-eth0: %s" % zebra_route(r1, P_LEGIT)
    )


def test_rip_cross_interface_spoof_ucast_dropped():
    "Same spoof unicast to 10.0.12.1 must not enter the RIB either."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    inject(tgen, SPOOF_SRC, "10.0.12.1", P_SPOOF_UC)
    assert route_absent(r1, P_SPOOF_UC), (
        "cross-interface spoof (unicast) installed: "
        "rip=%s zebra=%s" % (rip_paths(r1, P_SPOOF_UC), zebra_route(r1, P_SPOOF_UC))
    )


def test_rip_wrong_key_dropped():
    "An MD5 RESPONSE with a wrong key must be dropped."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    inject(tgen, H1_IP, "224.0.0.9", P_BADAUTH, auth="md5", key="wrongkey")
    assert route_absent(r1, P_BADAUTH), "wrong-key update installed"


def test_rip_unauthenticated_dropped_on_auth_interface():
    "An unauthenticated RESPONSE from the injector's own address must be dropped on the auth-enabled interface."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    inject(tgen, H1_IP, "224.0.0.9", P_NOAUTH)
    assert route_absent(r1, P_NOAUTH), "unauthenticated update installed on auth interface"


def test_rip_normal_withdraw():
    "A metric-16 withdraw from the legitimate neighbor still removes the route."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    assert route_present(r1, P_R2, timeout=15), "baseline route from r2 missing"
    r2.vtysh_cmd(
        "configure terminal\ninterface lo\nno ip address 203.0.113.1/32\nend"
    )
    assert route_gone(r1, P_R2, timeout=60), "metric-16 withdraw did not remove the route"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
