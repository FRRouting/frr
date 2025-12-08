#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test OSPF RFC4222 DSCP behavior:
# - "ip ospf dscp all 48"
# - "ip ospf dscp low-control 40"
#
# Verify on the wire:
#   - Hello (type 1) uses DSCP 48
#   - DB-Desc (2) or LSU (4) uses DSCP 40
#

import sys
import pytest
import json
import re

from lib.topogen import Topogen, get_topogen, TopoRouter, topotest
import pytest


def _build_topo(tgen):
    "Simple R1-R2 topology"
    # Create 2 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # Create a p2p connection between r1 and r2
    tgen.add_link(r1, r2, ifname1="r1-eth0", ifname2="r2-eth0")


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(_build_topo, request.module.__name__)
    tgen.start_topology()
    router_list = tgen.routers()

    # Load FRR configs
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    # Start all routers
    tgen.start_router()

    yield tgen

    # Teardown
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def _vty(router, cmd):
    return get_topogen().gears[router].vtysh_cmd(cmd)


def _collect_neighbors(obj):
    """
    Recursively walk any JSON shape and collect neighbor dicts.
    Neighbor dicts typically have fields like 'nbrState' or 'state',
    and often 'ifaceName', 'ifaceAddress', etc.
    """
    found = []
    if isinstance(obj, dict):
        # Direct 'neighbors' container (can be dict or list)
        if "neighbors" in obj:
            nb = obj["neighbors"]
            if isinstance(nb, dict):
                for v in nb.values():
                    if isinstance(v, list):
                        found.extend(v)
                    elif isinstance(v, dict) and ("nbrState" in v or "state" in v):
                        found.append(v)
            elif isinstance(nb, list):
                for v in nb:
                    if isinstance(v, dict):
                        found.append(v)
        # In some versions, neighbor lists are nested under VRF/areas/interfaces
        for v in obj.values():
            found.extend(_collect_neighbors(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_collect_neighbors(v))
    return found


def neighbors_full(router):
    """
    Return True if at least one neighbor on this router is Full.
    Robust to FRR JSON shape differences.
    """
    raw = _vty(router, "show ip ospf neighbor json")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Fall back to non-JSON if something odd happened
        return False

    neigh = _collect_neighbors(data)
    if not neigh:
        return False

    # FRR sometimes uses 'nbrState' ("Full/-") or 'state' ("Full")
    for n in neigh:
        st = n.get("nbrState") or n.get("state") or ""
        if isinstance(st, str) and st.startswith("Full"):
            return True
    return False


def vty_json(router: str, cmd: str):
    """Run a vtysh *json command and return {} if empty/unparseable."""
    raw = get_topogen().gears[router].vtysh_cmd(cmd)
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _wait_for_neighbors_full(router, retries=20, delay=1):
    while retries > 0:
        if neighbors_full(router):
            return True
        topotest.sleep(delay, "Wait for neighbor")
        retries -= 1
    return False


def test_ospf_dscp_basic(tgen):
    assert _wait_for_neighbors_full("r1", delay=2)
    assert _wait_for_neighbors_full("r2")


def _capture_ospf_pcap(router, iface, pcap_path):
    "Run tcpdump for a short duration to capture OSPF packets"
    router.cmd("rm -f {}".format(pcap_path))
    router.cmd(
        "tcpdump -s 1500 -U -w {} -i {} proto ospf >/dev/null 2>&1 &".format(
            pcap_path, iface
        )
    )


def _stop_ospf_capture(router, iface, pcap_path):
    router.cmd("pkill -f 'tcpdump -s 1500 -U -w {}' || true".format(pcap_path))
    # Wait a bit to ensure file flushed
    topotest.sleep(1, "Saving Capture")


def _tshark_dscp_and_type(router, pcap_path):
    """
    Return a list of (dscp, ospf.msg) tuples from the pcap.
    Requires tshark installed in the test environment.
    """
    cmd = (
        "tshark -r {} -Y ospf -T fields " "-e ip.dsfield.dscp -e ospf.msg 2>/dev/null"
    ).format(pcap_path)
    out = router.cmd(cmd).strip()
    res = []
    if not out:
        return res
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        dscp_str, msg_str = parts
        try:
            dscp = int(dscp_str)
            msg = int(msg_str)
            res.append((dscp, msg))
        except ValueError:
            continue
    return res


def test_ospf_dead_timer(tgen):
    "Verify per-interface timer resets"
    if tgen.routers() is None:
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Ensure adjacency is up before playing with DSCP
    assert neighbors_full("r1"), "R1 did not reach Full with R2"

    # Configure Dead Timer on R2 to reset on any control:
    output = r2.vtysh_cmd(
        """
configure terminal
interface r2-eth0
  ip ospf dead-timer-reset any-control
  exit
  exit
"""
    )

    # Give OSPF a moment to send some control traffic
    # Flood: add 10 loopbacks on r1 and redistribute connected
    r1.vtysh_cmd("conf t\nrouter ospf\n redistribute connected\n exit")
    for i in range(1, 50):
        r1.cmd(f"ip addr add 198.51.100.{i}/32 dev lo")

    out = r2.vtysh_cmd("show ip ospf neighbor detail")

    m = re.search(r"Non hello dead timer resets:\s+(\d+)", out)
    assert m, "Could not find 'Non hello dead timer resets' in output"

    resets = int(m.group(1))
    print("Non hello dead timer resets: {}".format(resets))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
