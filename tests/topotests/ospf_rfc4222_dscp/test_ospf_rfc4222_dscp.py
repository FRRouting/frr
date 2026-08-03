#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test OSPF RFC4222 DSCP behavior:
# - "ip ospf dscp all 46"
# - "ip ospf dscp low-control 40"
#
# Verify on the wire:
#   - Hello (type 1) uses DSCP 46
#   - Ack (type 5) uses DSCP 46
#   - DB-Desc (2) or LSU (4) uses DSCP 40
#

import sys
import os
import pytest
import json

from lib.topogen import Topogen, get_topogen, TopoRouter, topotest
from lib.topolog import logger

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
    for router in router_list.values():
        router.load_frr_config()

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


def ospf_if_json(router: str, ifname: str):
    data = vty_json(router, "show ip ospf interface {} json".format(ifname))
    if not data:
        return {}

    if "interfaces" in data and ifname in data["interfaces"]:
        return data["interfaces"][ifname]

    if ifname in data:
        return data[ifname]

    return data


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
    """Run tshark for a short duration to capture OSPF packets"""
    router.cmd(f"rm -f {pcap_path}")
    router.cmd(f"tshark -i {iface} -w {pcap_path} -f 'proto ospf' >/dev/null 2>&1 &")


def _stop_ospf_capture(router, iface, pcap_path):
    """Stop tshark capture"""
    # tshark uses its own process name, so kill by output file
    router.cmd(f"pkill -f 'tshark -i {iface} -w {pcap_path}' || true")
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


def test_ospf_dscp_all_and_low_control(tgen):
    "Verify per-interface DSCP all/low-control markings on the wire"
    if not tgen.routers():
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Ensure adjacency is up before playing with DSCP
    assert neighbors_full("r1"), "R1 did not reach Full with R2"

    # Configure DSCP on R1:
    # - all = 46
    # - low-control = 40 (CS5, for example)
    output = r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  ip ospf dscp low-control 40
  exit
  exit
"""
    )
    # print("output is: {}".format(output))

    pcap = os.path.join(tgen.logdir, "r1-ospf-dscp.pcap")
    logger.info("PCAP DIR: {}".format(pcap))

    _capture_ospf_pcap(r1, "r1-eth0", pcap)
    topotest.sleep(2, "Setup packet capture")

    # Force adjacency re-establishment to guarantee DB-Desc/LS-Req/LS-Upd
    # packets are exchanged with the new DSCP settings
    r1.vtysh_cmd("clear ip ospf process")

    # Wait for adjacency to re-form
    assert _wait_for_neighbors_full("r1"), "R1 did not reach Full after OSPF restart"
    # Allow time for final LS-Ack packets after Full state
    topotest.sleep(2, "Capture remaining LS-Acks")
    _stop_ospf_capture(r1, "r1-eth0", pcap)

    tuples = _tshark_dscp_and_type(r1, pcap)
    assert tuples, "No OSPF packets captured on r1-eth0"

    hello_ok = False
    low_ctrl_ok = False
    ack_ok = False
    # print(tuples)

    for dscp, msg in tuples:
        # msg: 1=Hello, 2=DB-Desc, 3=LS-Req, 4=LS-Upd, 5=LS-Ack
        if msg == 1 and dscp == 46:
            hello_ok = True
        if msg == 5 and dscp == 46:
            ack_ok = True
        if msg in (2, 3, 4) and dscp == 40:
            low_ctrl_ok = True

    assert hello_ok, "No Hello packet from R1 with DSCP 46 observed"
    assert ack_ok, "No Ack packet from R1 with DSCP 46 observed"
    assert low_ctrl_ok, "No DB-Desc/LS-Req/LS-Upd from R1 with DSCP 40 observed"


def test_ospf_dscp_display(tgen):
    "Verify OSPF interface DSCP operational display"

    if tgen.routers() is None:
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]

    assert neighbors_full("r1"), "R1 did not reach Full with R2"

    #
    # Case 1: no DSCP config => display should not be present
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  no ip ospf dscp low-control
  no ip ospf dscp all
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    assert (
        "dscpControlPackets" not in data
    ), "dscpControlPackets unexpectedly present with no DSCP config: {}".format(data)

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" not in text

    #
    # Case 2: only 'all' configured => low-control should inherit
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  no ip ospf dscp low-control
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    dscp = data.get("dscpControlPackets", {})
    assert dscp, "missing dscpControlPackets for 'ip ospf dscp all 46'"

    assert dscp.get("allConfigured") is True
    assert dscp.get("lowControlConfigured") is False
    assert dscp.get("highControlDscp") == 46
    assert dscp.get("lowControlDscp") == 46
    assert dscp.get("lowControlInheritedFromAll") is True

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" in text
    assert "high-control : 46" in text
    assert "low-control  : 46" in text
    assert "inherited from all" in text

    #
    # Case 3: both configured => low-control should override
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  ip ospf dscp low-control 40
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    dscp = data.get("dscpControlPackets", {})
    assert dscp, "missing dscpControlPackets for all+low-control config"

    assert dscp.get("allConfigured") is True
    assert dscp.get("lowControlConfigured") is True
    assert dscp.get("highControlDscp") == 46
    assert dscp.get("lowControlDscp") == 40
    assert "lowControlInheritedFromAll" not in dscp

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" in text
    assert "high-control : 46" in text
    assert "low-control  : 40" in text
    assert "inherited from all" not in text


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
