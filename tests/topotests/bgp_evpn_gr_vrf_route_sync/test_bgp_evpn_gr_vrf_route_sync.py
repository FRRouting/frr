#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by NVIDIA Corporation
#
#   +-------+       +----+  EVPN  +----+
#   | host1 +-------+ r1 +--------+ r2 |
#   +-------+       +----+        +----+
#
# host1 sits in L2VNI 100 behind r1, so r1 advertises IPv4 and IPv6 EVPN
# type-2 MAC/IP routes for it. Both L2VNI 100 and L3VNI 1000 belong to
# vrf-blue. r2 has a vrf-blue BGP instance without any peers that only
# imports the host routes from EVPN.
#
# r2 restarts zebra and bgpd gracefully. zebra keeps the vrf-blue host routes
# as stale and sweeps them when bgpd sends UPDATE_COMPLETE for vrf-blue. r1
# keeps its session to r2 shut for a while, so the EVPN instance of r2 is
# still deferring path selection when the vrf-blue configuration is loaded.
# The peerless vrf-blue instance must hold UPDATE_COMPLETE until the EVPN
# instance completes its deferred bestpath, otherwise zebra deletes the
# imported host routes from the RIB and the kernel before bgpd imports them
# again.

import functools
import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

HOST1_MAC = "00:00:5e:00:53:11"
HOST1_V4 = "203.0.113.11"
HOST1_V6 = "2001:db8:1::11"
HOST1_PREFIXES = {f"{HOST1_V4}/32": 1, f"{HOST1_V6}/128": 2}
VRF_TABLE = 10
# Time r2 runs with the EVPN deferral open after loading its configuration,
# long enough for zebra to act on a vrf-blue UPDATE_COMPLETE.
EVPN_HOLD_TIME = 5
# GR restart-time of r1. r1 sets the R-bit until its startup timer, armed
# with this value, expires, and r2 does not wait for EORs from a peer that
# set the R-bit.
R1_RESTART_TIME = 5

PENDING_RE = re.compile(
    r"Client bgp vrf vrf-blue\(\d+\) route update pending for AFI (\d+)"
)
COMPLETE_RE = re.compile(
    r"Client bgp vrf vrf-blue\(\d+\) route update complete for AFI (\d+)"
)
EVPN_COMPLETE_RE = re.compile(
    r"Client bgp vrf default\(0\) route update complete for AFI 3,"
)
STALE_DELETE_RE = re.compile(r"Client bgp stale route (\S+) is deleted")


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("host1", f"{HOST1_V4}/24", "via 203.0.113.1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["host1"], "r1-eth1", "host1-eth0")


def _add_vxlan_bridge(node, vni, vtep):
    node.cmd_raises(
        f"ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local {vtep}"
        " nolearning"
    )
    node.cmd_raises(f"ip link add name br{vni} type bridge stp_state 0")
    node.cmd_raises(f"ip link set dev vxlan{vni} master br{vni}")
    node.cmd_raises(f"ip link set dev br{vni} master vrf-blue")
    node.cmd_raises(f"ip link set up dev br{vni}")
    node.cmd_raises(f"ip link set up dev vxlan{vni}")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    host1 = tgen.net["host1"]
    host1.cmd_raises("ip link set dev host1-eth0 down")
    host1.cmd_raises(f"ip link set dev host1-eth0 address {HOST1_MAC}")
    host1.cmd_raises("ip link set dev host1-eth0 up")
    host1.cmd_raises(f"ip -6 addr add {HOST1_V6}/64 dev host1-eth0 nodad")

    pe_suffix = {"r1": "1", "r2": "2"}
    for name, suffix in pe_suffix.items():
        node = tgen.net[name]
        node.cmd_raises(f"ip link add vrf-blue type vrf table {VRF_TABLE}")
        node.cmd_raises("ip link set dev vrf-blue up")
        _add_vxlan_bridge(node, 1000, f"192.0.2.{suffix}")
        _add_vxlan_bridge(node, 100, f"192.0.2.{suffix}")
        node.cmd_raises(f"ip addr add 203.0.113.{suffix}/24 dev br100")
        node.cmd_raises(f"ip -6 addr add 2001:db8:1::{suffix}/64 dev br100 nodad")
        node.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        node.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")

    r1 = tgen.net["r1"]
    r1.cmd_raises("ip link set dev r1-eth1 master br100")
    r1.cmd_raises("ip link set dev r1-eth1 up")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _evpn_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp l2vpn evpn summary json"))
    peer = output.get("peers", {}).get(neighbor, {})
    return peer.get("state") == "Established"


def _prime_host1_neighbors(tgen):
    host1 = tgen.net["host1"]
    host1.cmd("ping -c 2 -W 1 203.0.113.1")
    host1.cmd("ping -6 -c 2 -W 1 2001:db8:1::1")


def _missing_host1_routes(router):
    missing = []
    for cmd, prefix in (
        ("show ip route vrf vrf-blue json", f"{HOST1_V4}/32"),
        ("show ipv6 route vrf vrf-blue json", f"{HOST1_V6}/128"),
    ):
        if prefix not in json.loads(router.vtysh_cmd(cmd)):
            missing.append(f"rib {prefix}")
    for family, prefix in (("-4", f"{HOST1_V4}/32"), ("-6", f"{HOST1_V6}/128")):
        output = router.cmd(f"ip {family} route show table {VRF_TABLE} {prefix}")
        if not output.strip():
            missing.append(f"kernel {prefix}")
    return missing or None


def _wait_for_host1_routes(tgen, router):
    def _check():
        _prime_host1_neighbors(tgen)
        return _missing_host1_routes(router)

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, f"{router.name}: vrf-blue is missing {result}"


def _zebra_log(router):
    return os.path.join(router.logdir, router.name, "zebra.log")


def _route_sync_events(router, offset):
    """
    Replay the zebra log of `router` from `offset`.

    Returns a dict with the vrf-blue UPDATE_PENDING and UPDATE_COMPLETE
    counts per AFI, the vrf-blue UPDATE_COMPLETEs received before the EVPN
    UPDATE_COMPLETE of the default instance, the vrf-blue AFIs reopened by an
    UPDATE_PENDING after their UPDATE_COMPLETE, and the host1 prefixes zebra
    deleted as stale.
    """
    events = {
        "pending": {},
        "complete": {},
        "before_evpn": [],
        "reopened": set(),
        "stale_deleted": [],
        "evpn_complete": False,
    }
    completed = set()

    with open(_zebra_log(router), "r", errors="replace") as logf:
        logf.seek(offset)
        for line in logf:
            if EVPN_COMPLETE_RE.search(line):
                events["evpn_complete"] = True
                continue
            match = STALE_DELETE_RE.search(line)
            if match:
                if match.group(1) in HOST1_PREFIXES:
                    events["stale_deleted"].append(match.group(1))
                continue
            match = PENDING_RE.search(line)
            if match:
                afi = int(match.group(1))
                events["pending"][afi] = events["pending"].get(afi, 0) + 1
                if afi in completed:
                    events["reopened"].add(afi)
                continue
            match = COMPLETE_RE.search(line)
            if match:
                afi = int(match.group(1))
                events["complete"][afi] = events["complete"].get(afi, 0) + 1
                completed.add(afi)
                if not events["evpn_complete"]:
                    events["before_evpn"].append(afi)

    return events


def _kernel_deleted_host1_routes(monitor_file):
    deleted = []
    with open(monitor_file, "r", errors="replace") as monf:
        for line in monf:
            if not line.startswith("Deleted"):
                continue
            for prefix in HOST1_PREFIXES:
                host = prefix.split("/")[0]
                if re.search(rf"\s{re.escape(host)}(/\d+)?\s", line):
                    deleted.append(line.strip())
    return deleted


def test_evpn_session_and_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = functools.partial(_evpn_established, r2, "192.0.2.1")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result, "r2: EVPN session with r1 not established"

    _wait_for_host1_routes(tgen, r2)
    logger.info("r2 imported host1 type-2 routes into vrf-blue")


def test_vrf_routes_kept_over_graceful_restart():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    daemons = ["zebra", "bgpd"]
    monitor_file = os.path.join(r2.logdir, r2.name, "ip-monitor-route.log")

    # The startup timer of a new instance always uses the default restart
    # time, re-arm it with R1_RESTART_TIME and let it expire.
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
         bgp shutdown
         no bgp shutdown
        """)
    time.sleep(R1_RESTART_TIME + 1)
    test_func = functools.partial(_evpn_established, r2, "192.0.2.1")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result, "r2: EVPN session with r1 not re-established"

    _wait_for_host1_routes(tgen, r2)
    monitor_pid = r2.cmd(f"ip -o monitor route > {monitor_file} 2>&1 & echo $!").strip()

    kill_router_daemons(tgen, "r2", daemons, save_config=False)
    offset = os.path.getsize(_zebra_log(r2))

    # Keep the EVPN deferral of r2 open by not letting the session come up.
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
         neighbor 192.0.2.2 shutdown
        """)

    saved_opts = {d: r2.net.daemons_options.get(d, "") for d in daemons}
    for daemon, opts in saved_opts.items():
        r2.net.daemons_options[daemon] = f"{opts} -K".strip()
    try:
        # The sweep only removes routes strictly older than the restart
        # time, which has one second resolution.
        start_router_daemons(tgen, "r2", ["zebra"])
        time.sleep(2)
        start_router_daemons(tgen, "r2", ["bgpd"])
    finally:
        r2.net.daemons_options.update(saved_opts)
    r2.cmd(f"vtysh -f {os.path.join(CWD, 'r2/frr.conf')}")

    def _vrf_pending_sent():
        events = _route_sync_events(r2, offset)
        return all(events["pending"].get(afi, 0) for afi in (1, 2))

    result, _ = topotest.run_and_expect(_vrf_pending_sent, True, count=60, wait=1)
    assert result, "r2: vrf-blue did not send UPDATE_PENDING after restart"
    time.sleep(EVPN_HOLD_TIME)

    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
         no neighbor 192.0.2.2 shutdown
        """)

    test_func = functools.partial(_evpn_established, r2, "192.0.2.1")
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=1)
    assert result, "r2: EVPN session with r1 not re-established after restart"

    def _route_sync_done():
        events = _route_sync_events(r2, offset)
        return (
            all(
                events["complete"].get(afi, 0) >= events["pending"].get(afi, 0) > 0
                for afi in (1, 2)
            )
            and events["evpn_complete"]
        )

    result, _ = topotest.run_and_expect(_route_sync_done, True, count=120, wait=1)
    _wait_for_host1_routes(tgen, r2)
    r2.cmd(f"kill {monitor_pid}")

    events = _route_sync_events(r2, offset)
    kernel_deleted = _kernel_deleted_host1_routes(monitor_file)
    logger.info(f"r2 vrf-blue GR route sync events: {events}")
    logger.info(f"r2 kernel deletes of host1 routes: {kernel_deleted}")

    assert result, f"r2: vrf-blue GR route sync did not finish: {events}"
    assert not events["stale_deleted"], (
        "r2: zebra deleted the EVPN-imported vrf-blue routes "
        f"{events['stale_deleted']} as stale during graceful restart"
    )
    assert not kernel_deleted, (
        "r2: vrf-blue host routes were removed from the kernel during "
        f"graceful restart: {kernel_deleted}"
    )
    assert not events["before_evpn"], (
        "r2: vrf-blue sent UPDATE_COMPLETE for AFI "
        f"{events['before_evpn']} before the EVPN instance completed"
    )
    assert not events["reopened"], (
        "r2: vrf-blue sent UPDATE_PENDING for AFI "
        f"{sorted(events['reopened'])} after its UPDATE_COMPLETE"
    )
    assert events["pending"] == events["complete"], (
        "r2: vrf-blue UPDATE_PENDING and UPDATE_COMPLETE counts differ "
        f"(pending={events['pending']}, complete={events['complete']})"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
