#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Reference topology from bgp_evpn_overlay_index_gateway/test_bgp_evpn_overlay_index_gateway.py:
# 
#          +--------+ BGP     +--------+ BGP  +--------+      +--------+
#     SN1  |        | IPv4/v6 |        | EVPN |        |      |        |
#   =======+ Host1  +---------+   PE1  +------+   PE2  +------+  Host2 +
#          |        |         |        |      |        |      |        |
#          +--------+         +--------+      +--------+      +--------+
# 
# Host1 is connected to PE1 and Host2 is connected to PE2.
# Host1 and PE1 have IPv4/v6 BGP sessions.
# PE1 and PE2 have an EVPN session.
# Host1 advertises IPv4/v6 prefixes to PE1.
# PE1 advertises these prefixes to PE2 as EVPN type-5 routes (gateway IP = Host1 IP).
# Host1 MAC/IP is advertised by PE1 as EVPN type-2 route.

import os
import sys
import json
import time
import functools
import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    check_router_status,
    kill_router_daemons,
    start_router_daemons,
)

def build_topo(tgen):
    # Create PE and host routers
    for name in ["PE1", "PE2", "host1", "host2"]:
        tgen.add_router(name)
    # Links: PE1-PE2, PE1-host1, PE2-host2
    tgen.add_link(tgen.gears["PE1"], tgen.gears["PE2"], "PE1-eth0", "PE2-eth0")
    tgen.add_link(tgen.gears["PE1"], tgen.gears["host1"], "PE1-eth1", "host1-eth0")
    tgen.add_link(tgen.gears["PE2"], tgen.gears["host2"], "PE2-eth1", "host2-eth0")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Configure host MACs
    host_macs = {"host1": "1a:2b:3c:4d:5e:61", "host2": "1a:2b:3c:4d:5e:62"}
    for name, mac in host_macs.items():
        host = tgen.net[name]
        host.cmd_raises(f"ip link set dev {name}-eth0 down")
        host.cmd_raises(f"ip link set dev {name}-eth0 address {mac}")
        host.cmd_raises(f"ip link set dev {name}-eth0 up")

    # Configure PE devices: vrf-blue, vxlan100/1000, bridges and sysctls
    pe_suffix = {"PE1": "1", "PE2": "2"}
    for name, suf in pe_suffix.items():
        pe = tgen.net[name]
        vtep_ip = f"10.100.0.{suf}"
        bridge_ip = f"192.168.50.{suf}/24"
        bridge_ipv6 = f"fd00:50:1::{suf}/48"
        pe.cmd_raises("ip link add vrf-blue type vrf table 10")
        pe.cmd_raises("ip link set dev vrf-blue up")
        pe.cmd_raises(f"ip link add vxlan100 type vxlan id 100 dstport 4789 local {vtep_ip}")
        pe.cmd_raises("ip link add name br100 type bridge stp_state 0")
        pe.cmd_raises("ip link set dev vxlan100 master br100")
        pe.cmd_raises(f"ip link set dev {name}-eth1 master br100")
        pe.cmd_raises(f"ip addr add {bridge_ip} dev br100")
        pe.cmd_raises("ip link set up dev br100")
        pe.cmd_raises("ip link set up dev vxlan100")
        pe.cmd_raises(f"ip link set up dev {name}-eth1")
        pe.cmd_raises("ip link set dev br100 master vrf-blue")
        pe.cmd_raises(f"ip -6 addr add {bridge_ipv6} dev br100")
        pe.cmd_raises(f"ip link add vxlan1000 type vxlan id 1000 dstport 4789 local {vtep_ip}")
        pe.cmd_raises("ip link add name br1000 type bridge stp_state 0")
        pe.cmd_raises("ip link set dev vxlan1000 master br1000")
        pe.cmd_raises("ip link set up dev br1000")
        pe.cmd_raises("ip link set up dev vxlan1000")
        pe.cmd_raises("ip link set dev br1000 master vrf-blue")
        pe.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        pe.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")

    # Load FRR configuration for each router
    for rname, router in tgen.routers().items():
        logger.info(f"Loading config to router {rname}")
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _evpn_peer_established(router: TopoRouter, neighbor_ip: str) -> bool:
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn summary json")
        data = json.loads(output)
    except Exception:
        return False

    peers = data.get("peers", {})
    if neighbor_ip not in peers:
        logger.info(f"Neighbor {neighbor_ip} not found in BGP summary")
        return False
    logger.info(f"Neighbor {neighbor_ip} found in BGP summary with state: {peers[neighbor_ip].get('state')}")
    return peers[neighbor_ip].get("state") == "Established"


def _evpn_any_prefixes(router: TopoRouter) -> bool:
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn route json")
        data = json.loads(output)
        logger.info(f"EVPN routes found: {data.get('numPrefix', 0)}")
    except Exception:
        return False
    # numPrefix > 0 indicates some EVPN routes exist (e.g., IMET)
    return bool(data) and data.get("numPrefix", 0) > 0


def _evpn_has_any_stale(router: TopoRouter) -> bool:
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn route json")
        evpn = json.loads(output)
    except Exception:
        return False

    # Iterate all RDs and prefixes to find any path marked stale
    for key, rd_data in evpn.items():
        if not isinstance(rd_data, dict):
            continue
        for prefix, pdata in rd_data.items():
            if not isinstance(pdata, dict):
                continue
            for path_entry in pdata.get("paths", []):
                # path_entry may be a dict or list of dicts based on FRR JSON
                if isinstance(path_entry, dict):
                    if path_entry.get("stale"):
                        logger.info(f"Path {path_entry} is stale")
                        return True
                elif isinstance(path_entry, list):
                    for p in path_entry:
                        if isinstance(p, dict) and p.get("stale"):
                            logger.info(f"Path {p} is stale")
                            return True
    logger.info(f"No stale paths found")
    return False


def _evpn_no_stale(router: TopoRouter) -> bool:
    return not _evpn_has_any_stale(router)


def _evpn_has_remote_route_type(router: TopoRouter, route_type: int) -> bool:
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn route json")
        evpn = json.loads(output)
    except Exception:
        return False

    for key, rd_data in evpn.items():
        if not isinstance(rd_data, dict):
            continue
        for prefix, pdata in rd_data.items():
            if not isinstance(pdata, dict):
                continue
            for path_entry in pdata.get("paths", []):
                entries = path_entry if isinstance(path_entry, list) else [path_entry]
                for p in entries:
                    if not isinstance(p, dict):
                        continue
                    if p.get("routeType") == route_type and not p.get("local", False):
                        logger.info(f"Remote route type {route_type} found")
                        return True
    logger.info(f"No remote route type {route_type} found")
    return False


def _evpn_remote_type_paths_stale(router: TopoRouter, route_type: int) -> bool:
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn route json")
        evpn = json.loads(output)
    except Exception:
        return False

    found_remote = False
    found_stale = False
    for key, rd_data in evpn.items():
        if not isinstance(rd_data, dict):
            continue
        for prefix, pdata in rd_data.items():
            if not isinstance(pdata, dict):
                continue
            for path_entry in pdata.get("paths", []):
                entries = path_entry if isinstance(path_entry, list) else [path_entry]
                for p in entries:
                    if not isinstance(p, dict):
                        continue
                    if p.get("routeType") == route_type and not p.get("local", False):
                        found_remote = True
                        logger.info(f"Remote route type {route_type} found")
                        if p.get("stale"):
                            found_stale = True
                            logger.info(f"Stale route type {route_type} found")
    logger.info(f"No remote route type {route_type} found")
    logger.info(f"No stale route type {route_type} found")
    return found_remote and found_stale


def _evpn_routes_with_stale_only_for_rd(router: TopoRouter, rd: str, route_type: int) -> bool:
    """
    Verify that all paths whose RD matches the input RD and route_type are marked as stale.
    Succeeds only if at least one matching path is found and all such paths are stale.
    """
    try:
        output = router.vtysh_cmd("show bgp l2vpn evpn route json")
        evpn = json.loads(output)
    except Exception:
        return False

    found_matching_path = False

    for key, rd_data in evpn.items():
        if not isinstance(rd_data, dict):
            continue
        if key != rd:
            continue
        for prefix, pdata in rd_data.items():
            if not isinstance(pdata, dict):
                continue
            for path_entry in pdata.get("paths", []):
                entries = path_entry if isinstance(path_entry, list) else [path_entry]
                for p in entries:
                    if not isinstance(p, dict):
                        continue
                    rtype = p.get("routeType")
                    if rtype != route_type:
                        continue
                    found_matching_path = True
                    logger.info(f"Checking prefix: {prefix} path: {p}")
                    if not bool(p.get("stale")):
                        logger.info(f"Checking prefix: {prefix} path: {p} is not stale, returning False")
                        return False
    if not found_matching_path:
        logger.info(f"No matching path found for RD: {rd} and route type: {route_type}")
        return False
    return True

def _vrf_has_kernel_routes(router: TopoRouter, vrf_name: str, prefixes):
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    output = router.cmd(f"ip -j route show vrf {vrf_name}")
    try:
        routes = json.loads(output)
    except Exception:
        return False
    have = set()
    for r in routes:
        dst = r.get("dst") or r.get("destination") or r.get("to")
        if dst:
            have.add(dst)
    for pfx in prefixes:
        if pfx not in have:
            logger.info(f"Prefix {pfx} not found in kernel VRF {vrf_name}")
            return False
    logger.info(f"All prefixes {prefixes} found in kernel VRF {vrf_name}")
    return True


def _bridge_has_extern_learn(router: TopoRouter, dev: str, mac: str) -> bool:
    # Check for external-learned MAC on vxlan device
    out = router.cmd(f"bridge fdb show dev {dev}")
    for line in out.splitlines():
        if mac.lower() in line.lower() and "extern_learn" in line:
            logger.info(f"MAC {mac} found in bridge FDB on device {dev}")
            return True
    logger.info(f"MAC {mac} not found in bridge FDB on device {dev}")
    return False


def _ip_neigh_has_extern_learn(router: TopoRouter, mac: str) -> bool:
    """
    Check kernel's ip neigh show for MAC entry with extern_learn flag.
    (Extern_learn shows as 'extern_learn' in 'ip neigh' flags.)
    """
    output = router.cmd("ip neigh show")
    for line in output.splitlines():
        if mac.lower() in line.lower() and "extern_learn" in line:
            logger.info(f"MAC {mac} found as extern_learn in 'ip neigh'")
            return True
    logger.info(f"MAC {mac} NOT extern_learn in 'ip neigh'")
    return False


def fetch_vni_rd_from_pe2(pe2: TopoRouter, vni: int):
    """
    Fetch the Route Distinguisher (RD) of the given l2vni from PE2
    using 'show bgp l2vpn evpn vni <vni>' command.

    Returns:
        The RD as a string, e.g., '10.100.0.2:102', or None if not found.
    """
    output = pe2.vtysh_cmd(f"show bgp l2vpn evpn vni {vni} json")
    try:
        if isinstance(output, str):
            output = json.loads(output)
        if "rd" in output:
            logger.info(f"RD for VNI {vni} found: {output.get('rd')}")
            return output.get("rd") 
    except Exception as e:
        logger.info(f"Failed to fetch RD from PE2 VNI {vni}: {e}")
    return None


def _evpn_f_bit_set(router: TopoRouter, neighbor_ip: str) -> bool:
    """
    Verify that EVPN AF F-bit is set for a neighbor during GR.
    Tries EVPN-specific CLI first, then falls back to generic neighbors JSON.
    """
    commands = [
        f"show bgp neighbors {neighbor_ip} graceful-restart json",
    ]
    for cmd in commands:
        try:
            output = router.vtysh_cmd(cmd)
            data = json.loads(output)
        except Exception:
            continue

        # EVPN-specific show typically returns dict keyed by neighbor IP
        if isinstance(data, dict) and neighbor_ip in data:
            nbr = data[neighbor_ip]
            gr = nbr.get("gracefulRestartInfo", {})
            if isinstance(gr, dict):
                # Some builds expose fBit directly
                if isinstance(gr.get("fBit"), bool):
                    if gr.get("fBit") is True:
                        logger.info(f"F-bit is set for neighbor {neighbor_ip}")
                        return True
                # Others nest per-AF
                evpn = gr.get("l2VpnEvpn", {})
                if isinstance(evpn, dict) and isinstance(evpn.get("fBit"), bool):
                    if evpn.get("fBit") is True:
                        logger.info(f"F-bit is set for neighbor {neighbor_ip}")
                        return True

        # Generic neighbors JSON; try to locate EVPN AF entry
        if isinstance(data, dict):
            # data may be the neighbor object directly
            gr = data.get("gracefulRestartInfo", {})
            if isinstance(gr, dict):
                if isinstance(gr.get("fBit"), bool) and gr.get("fBit") is True:
                    logger.info(f"F-bit is set for neighbor {neighbor_ip}")
                    return True
                evpn = gr.get("l2VpnEvpn", {})
                if isinstance(evpn, dict) and isinstance(evpn.get("fBit"), bool):
                    if evpn.get("fBit") is True:
                        logger.info(f"F-bit is set for neighbor {neighbor_ip}")
                        return True
    logger.info(f"F-bit is not set for neighbor {neighbor_ip}")
    return False


def _gr_r_bit_set(router: TopoRouter, neighbor_ip: str) -> bool:
    """
    Verify that R-bit is set in GR capability for the neighbor (restarting peer).
    Checks both generic neighbors JSON and EVPN-specific GR JSON.
    """
    commands = [
        f"show bgp neighbors {neighbor_ip} graceful-restart json",
    ]
    for cmd in commands:
        try:
            output = router.vtysh_cmd(cmd)
            data = json.loads(output)
        except Exception:
            continue

        # EVPN-specific keyed by neighbor
        if isinstance(data, dict) and neighbor_ip in data:
            nbr = data[neighbor_ip]
            gr = nbr.get("gracefulRestartInfo", {})
            if isinstance(gr, dict):
                if isinstance(gr.get("rBit"), bool) and gr.get("rBit") is True:
                    logger.info(f"R-bit is set for neighbor {neighbor_ip}")
                    return True
                # Also try per-AF container if present
                evpn = gr.get("l2VpnEvpn", {})
                if isinstance(evpn, dict) and isinstance(evpn.get("rBit"), bool):
                    if evpn.get("rBit") is True:
                        logger.info(f"R-bit is set for neighbor {neighbor_ip}")
                        return True

        # Generic neighbor JSON shape
        if isinstance(data, dict):
            gr = data.get("gracefulRestartInfo", {})
            if isinstance(gr, dict):
                if isinstance(gr.get("rBit"), bool) and gr.get("rBit") is True:
                    logger.info(f"R-bit is set for neighbor {neighbor_ip}")
                    return True
                evpn = gr.get("l2VpnEvpn", {})
                if isinstance(evpn, dict) and isinstance(evpn.get("rBit"), bool):
                    if evpn.get("rBit") is True:
                        logger.info(f"R-bit is set for neighbor {neighbor_ip}")
                        return True
    logger.info(f"R-bit is not set for neighbor {neighbor_ip}")
    return False


def test_bgp_evpn_gr_stale_and_recovery():
    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    logger.info("STEP 1: Verify routers are up and healthy")
    check_router_status(tgen)

    # Wait for EVPN session to establish
    logger.info("STEP 2: Wait for EVPN session to establish between PE1 and PE2")
    test_func = functools.partial(_evpn_peer_established, pe1, "10.0.1.2")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE1 EVPN session with PE2 not established"

    test_func = functools.partial(_evpn_peer_established, pe2, "10.0.1.1")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE2 EVPN session with PE1 not established"

    # Ensure we have some EVPN routes (e.g., IMET)
    logger.info("STEP 3: Ensure EVPN routes (e.g., IMET) are present")
    test_func = functools.partial(_evpn_any_prefixes, pe1)
    result, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "No EVPN routes present on PE1"

    # Ensure type-5 routes exist on both PEs (host1->PE1->PE2, host2->PE2->PE1)
    logger.info("STEP 4: Verify remote EVPN type-5 routes exist on both PEs")
    test_func = functools.partial(_evpn_has_remote_route_type, pe1, 5)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-5 routes seen on PE1"
    test_func = functools.partial(_evpn_has_remote_route_type, pe2, 5)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-5 routes seen on PE2"

    # Kernel VRF routes imported (type-5): verify PE2 has host1, PE1 has host2
    logger.info("STEP 5: Verify type-5 routes are installed into kernel VRF on both PEs")
    test_func = functools.partial(_vrf_has_kernel_routes, pe2, "vrf-blue", ["172.31.0.21"])
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Type-5 prefix 172.31.0.21/32 not installed in PE2 kernel VRF vrf-blue"
    test_func = functools.partial(_vrf_has_kernel_routes, pe1, "vrf-blue", ["172.31.0.22"])
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Type-5 prefix 172.31.0.22/32 not installed in PE1 kernel VRF vrf-blue"

    # Ensure type-2 routes exist on both PEs
    logger.info("STEP 6: Verify remote EVPN type-2 routes exist on both PEs")
    test_func = functools.partial(_evpn_has_remote_route_type, pe1, 2)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-2 routes seen on PE1"
    test_func = functools.partial(_evpn_has_remote_route_type, pe2, 2)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-2 routes seen on PE2"

    # Ensure type-2 are installed as extern_learn in FDB (remote MACs)
    logger.info("STEP 7: Verify remote MACs are extern_learn in FDB (type-2)")
    test_func = functools.partial(_bridge_has_extern_learn, pe1, "vxlan100", "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Remote MAC (host2) not extern_learn in PE1 FDB for vxlan100"
    test_func = functools.partial(_bridge_has_extern_learn, pe2, "vxlan100", "1a:2b:3c:4d:5e:61")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Remote MAC (host1) not extern_learn in PE2 FDB for vxlan100"

    # Verify that remote MACs on PE1 are installed as extern_learn in kernel's ip_neigh table
    logger.info("STEP 7b: Verify remote MACs are extern_learn in PE1 kernel's ip_neigh table")

    # For PE1, check host2's MAC (remote side)
    test_func = functools.partial(_ip_neigh_has_extern_learn, pe1, "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "Remote MAC (host2) not extern_learn in kernel ip_neigh table on PE1"

    # For PE2, check host1's MAC (remote side)
    test_func = functools.partial(_ip_neigh_has_extern_learn, pe2, "1a:2b:3c:4d:5e:61")
    result, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "Remote MAC (host1) not extern_learn in kernel ip_neigh table on PE2"

    # Fetch L2VNI RD from PE2 for validation
    pe2_rd_vni_100 = fetch_vni_rd_from_pe2(pe2, 100)
    # Fetch L3VNI RD from PE2 for validation
    pe2_rd_vni_1000 = fetch_vni_rd_from_pe2(pe2, 1000)

    # Kill bgpd on PE2 to trigger GR restart
    logger.info("STEP 8: Stop bgpd on PE2 to trigger graceful restart")
    kill_router_daemons(tgen, "PE2", ["bgpd"])

    # PE1 should retain only PE2-originated EVPN routes as stale during GR (type-2 and type-5), not local
    # Verify only type-5 routes from PE2's RD are stale
    logger.info("STEP 9: Check PE1 retains ONLY PE2-originated type-5 routes as stale")
    test_func = functools.partial(_evpn_routes_with_stale_only_for_rd, pe1, rd=pe2_rd_vni_1000, route_type=5)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, (
        "PE1 did not retain ONLY PE2-originated EVPN type-5 routes as stale during PE2 restart"
    )
    
    logger.info(f"PE2 RD for VNI 100: {pe2_rd_vni_100}")
    # Verify only type-2 routes from PE2's RD are stale
    logger.info("STEP 10: Check PE1 retains ONLY PE2-originated type-2 routes as stale")
    test_func = functools.partial(_evpn_routes_with_stale_only_for_rd, pe1, rd=pe2_rd_vni_100, route_type=2)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, (
        "PE1 did not retain ONLY PE2-originated EVPN type-2 routes as stale during PE2 restart"
    )

    # Also generic check for any stale presence
    logger.info("STEP 11: Confirm PE1 shows some EVPN routes as stale during PE2 restart")
    test_func = functools.partial(_evpn_has_any_stale, pe1)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE1 did not retain EVPN routes as stale during PE2 restart"

    # Verify PE1 kernel still has routes learned from PE2 in vrf-blue (type-5 retained)
    logger.info("STEP 12: Verify PE1 kernel retains type-5 routes from PE2 during GR")
    test_func = functools.partial(_vrf_has_kernel_routes, pe1, "vrf-blue", ["172.31.0.22"])
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE1 kernel VRF routes learned from PE2 disappeared during GR"

    # Verify PE1 FDB retains extern learned MAC from PE2 (type-2 retained)
    logger.info("STEP 13: Verify PE1 FDB retains extern_learn MAC from PE2 during GR")
    test_func = functools.partial(_bridge_has_extern_learn, pe1, "vxlan100", "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE1 FDB extern_learn entry from PE2 disappeared during GR"

    # Verify PE1 kernel still has routes learned from PE2 in vrf-blue (type-5 retained)
    test_func = functools.partial(_ip_neigh_has_extern_learn, pe1, "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "PE1 kernel ip_neigh table extern_learn entry from PE2 disappeared during GR"

    # Bring bgpd back on PE2
    logger.info("STEP 14: Restart bgpd on PE2 to recover session")
    # Get config file path and router object
    source_config = os.path.join(CWD, "PE2/frr.conf")
    router_pe2 = tgen.gears["PE2"]
    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP daemon on PE2...")
    try:
        start_router_daemons(tgen, "PE2", ["bgpd"])
        logger.info("BGP daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP config from: {source_config}")
        config_result = router_pe2.cmd(f"vtysh -f {source_config}")
        logger.info("BGP configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP config: {e}")
        raise

    # Wait for EVPN session to establish
    logger.info("STEP 15: Wait for EVPN session to establish between PE1 and PE2")
    test_func = functools.partial(_evpn_peer_established, pe1, "10.0.1.2")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE1 EVPN session with PE2 not established"

    test_func = functools.partial(_evpn_peer_established, pe2, "10.0.1.1")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "PE2 EVPN session with PE1 not established"

    # Verify R-bit and F-bit set on PE1 neighbor view after PE2 restart
    logger.info("STEP 16: Verify GR R-bit and EVPN AF F-bit set on PE1 neighbor view")
    test_func = functools.partial(_gr_r_bit_set, pe1, "10.0.1.2")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "EVPN GR R-bit not set on PE1 neighbor view after PE2 restart"
    
    test_func = functools.partial(_evpn_f_bit_set, pe1, "10.0.1.2")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "EVPN AF F-bit not set on PE1 neighbor view during PE2 restart"

    # After session recovery, stale flags should be cleared for type-2 and type-5 on PE1
    logger.info("STEP 17: Ensure remote EVPN type-5 and type-2 remain active after recovery")
    test_func = functools.partial(_evpn_has_remote_route_type, pe1, 5)
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=2)
    assert result, "Remote EVPN type-5 routes disappeared on PE1 after PE2 recovered"
    test_func = functools.partial(_evpn_has_remote_route_type, pe1, 2)
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=2)
    assert result, "Remote EVPN type-2 routes disappeared on PE1 after PE2 recovered"

    # After bgpd recovery on PE2, verify PE1 kernel still has routes learned from PE2
    logger.info("STEP 18: Verify PE1 kernel still has routes from PE2 after recovery")
    test_func = functools.partial(_vrf_has_kernel_routes, pe1, "vrf-blue", ["172.31.0.22"])
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=2)
    assert result, "PE1 kernel VRF routes learned from PE2 disappeared after recovery"

    # And verify PE1 FDB still has extern_learn entry from PE2
    logger.info("STEP 19: Verify PE1 FDB retains extern_learn MAC after recovery")
    test_func = functools.partial(_bridge_has_extern_learn, pe1, "vxlan100", "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=2)
    assert result, "PE1 FDB extern_learn entry from PE2 disappeared after recovery"

    logger.info("STEP 20: Confirm no EVPN stale routes remain on PE1 after recovery")
    test_func = functools.partial(_evpn_no_stale, pe1)
    result, _ = topotest.run_and_expect(test_func, True, count=120, wait=2)
    assert result, "PE1 still shows EVPN stale routes after PE2 recovered"


def _vrf_routes_absent(router: TopoRouter, vrf_name: str, prefixes):
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    output = router.cmd(f"ip -j route show vrf {vrf_name}")
    try:
        routes = json.loads(output)
    except Exception:
        # If we can't parse routes, treat as absent
        return True
    have = set()
    for r in routes:
        dst = r.get("dst") or r.get("destination") or r.get("to")
        if dst:
            have.add(dst)
    for pfx in prefixes:
        if pfx in have:
            return False
    return True


def _bridge_extern_absent(router: TopoRouter, dev: str, mac: str) -> bool:
    out = router.cmd(f"bridge fdb show dev {dev}")
    for line in out.splitlines():
        if mac.lower() in line.lower() and "extern_learn" in line:
            return False
    return True


def test_bgp_evpn_gr_stale_cleanup_on_timeout():
    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]

    logger.info("STEP 1: Verify routers are up and healthy")
    check_router_status(tgen)

    # Ensure EVPN session and baseline presence
    logger.info("STEP 2: Verify EVPN session established (PE1 -> PE2)")
    test_func = functools.partial(_evpn_peer_established, pe1, "10.0.1.2")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "EVPN session not established (PE1->PE2)"

    logger.info("STEP 3: Verify remote EVPN type-5 routes present on PE1")
    test_func = functools.partial(_evpn_has_remote_route_type, pe1, 5)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-5 routes on PE1"

    logger.info("STEP 4: Verify kernel VRF has type-5 route on PE1 prior to GR")
    test_func = functools.partial(_vrf_has_kernel_routes, pe1, "vrf-blue", ["172.31.0.22"])
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Missing kernel VRF routes on PE1 prior to GR"

    logger.info("STEP 5: Verify extern_learn MAC is present on PE1 prior to GR")
    test_func = functools.partial(_bridge_has_extern_learn, pe1, "vxlan100", "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Missing extern_learn MAC on PE1 prior to GR"

    # Kill bgpd on PE2 and do not restart for >140 seconds
    logger.info("STEP 6: Stop bgpd on PE2 and keep it down (>140s)")
    kill_router_daemons(tgen, "PE2", ["bgpd"])

    # Wait for restart timer (120 secs) on PE1 to expire and stale paths to be cleaned up
    logger.info("STEP 7: Wait for GR stalepath-time to expire on PE1 (sleep 150s)")
    time.sleep(150)

    # Expect kernel VRF routes and FDB extern entry to be cleaned from PE1
    logger.info("STEP 8: Verify kernel VRF routes learned from PE2 are cleaned on PE1")
    test_func = functools.partial(_vrf_routes_absent, pe1, "vrf-blue", ["172.31.0.22"])
    result, _ = topotest.run_and_expect(test_func, True, count=160, wait=1)
    assert result, "VRF kernel routes on PE1 not cleaned after GR stalepath-time expiry"

    logger.info("STEP 9: Verify FDB extern_learn MAC learned from PE2 is cleaned on PE1")
    test_func = functools.partial(_bridge_extern_absent, pe1, "vxlan100", "1a:2b:3c:4d:5e:62")
    result, _ = topotest.run_and_expect(test_func, True, count=160, wait=1)
    assert result, "FDB extern_learn MAC on PE1 not cleaned after GR stalepath-time expiry"

    # Restore bgpd on PE2 for subsequent tests
    logger.info("STEP 10: Restart bgpd on PE2 for subsequent tests")
    source_config = os.path.join(CWD, "PE2/frr.conf")
    router_pe2 = tgen.gears["PE2"]
    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP daemon on PE2...")
    try:
        start_router_daemons(tgen, "PE2", ["bgpd"])
        logger.info("BGP daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP config from: {source_config}")
        config_result = router_pe2.cmd(f"vtysh -f {source_config}")
        logger.info("BGP configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP config: {e}")
        raise


"""
Commenting this test out until MR 12975 is merged
def test_bgp_evpn_gr_select_deferral_cleanup_on_pe2():
    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    logger.info("STEP 1: Verify routers are up and healthy")
    check_router_status(tgen)

    # Baseline: session up and PE2 has remote routes/MAC from PE1
    logger.info("STEP 2: Verify EVPN session established (PE2 -> PE1)")
    test_func = functools.partial(_evpn_peer_established, pe2, "10.0.1.1")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "EVPN session not established (PE2->PE1)"

    logger.info("STEP 3: Verify remote EVPN type-5 routes present on PE2 (from PE1)")
    test_func = functools.partial(_evpn_has_remote_route_type, pe2, 5)
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "No remote EVPN type-5 routes on PE2 (from PE1)"

    # PE1-originated type-5 network should be in PE2 kernel VRF
    logger.info("STEP 4: Verify kernel VRF has type-5 route on PE2 prior to GR")
    test_func = functools.partial(_vrf_has_kernel_routes, pe2, "vrf-blue", ["172.31.0.21"])
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Missing kernel VRF routes on PE2 prior to GR/select-deferral"

    # PE1 MAC should be extern_learn on PE2
    logger.info("STEP 5: Verify extern_learn MAC is present on PE2 prior to GR")
    test_func = functools.partial(_bridge_has_extern_learn, pe2, "vxlan100", "1a:2b:3c:4d:5e:61")
    result, _ = topotest.run_and_expect(test_func, True, count=60, wait=2)
    assert result, "Missing extern_learn MAC on PE2 prior to GR/select-deferral"

    pe2.vtysh_cmd(
            "configure terminal\n"
            "log syslog debugging\n"
            "log file zebra.log\n"
            "log timestamp precision 6\n"
            "debug zebra events\n"
            "debug bgp graceful-restart\n"
            "debug bgp neighbor-events\n"
            "exit\n"
            "write\n"
    )
    # Simulate PE2 restart: stop bgpd on PE2
    logger.info("STEP 6: Stop bgpd and zebra on PE2 to simulate restart")
    kill_router_daemons(tgen, "PE2", ["zebra", "bgpd"])
    # Before starting PE2, administratively shutdown neighbor on PE1 to keep session down
    logger.info("STEP 7: Shutdown neighbor 10.0.1.2 on PE1 to keep session down")
    pe1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 101\n"
        "neighbor 10.0.1.2 shutdown\n"
    )

    # Start bgpd on PE2; session will remain down due to neighbor shutdown on PE1
    logger.info("STEP 8: Start bgpd on PE2 (session should stay down due to neighbor shutdown)")
    #start_router_daemons(tgen, "PE2", ["bgpd", "zebra"])
    source_config = os.path.join(CWD, "PE2/frr.conf")
    router_pe2 = tgen.gears["PE2"]
    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP and zebra daemon on PE2...")
    try:
        start_router_daemons(tgen, "PE2", ["bgpd, "zebra""])
        logger.info("BGP and zebra daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP and zebra config from: {source_config}")
        config_result = router_pe2.cmd(f"vtysh -f {source_config}")
        logger.info("BGP and zebra configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP and zebra config: {e}")
        raise

    # Wait beyond select deferral timer (default 120s) so PE2 purges stale paths
    logger.info("STEP 9: Wait beyond select-deferral (sleep 150s) so PE2 purges stale paths")
    time.sleep(150)

    # Verify PE2 kernel cleaned routes learned from PE1
    logger.info("STEP 10: Verify kernel VRF routes learned from PE1 are cleaned on PE2")
    test_func = functools.partial(_vrf_routes_absent, pe2, "vrf-blue", ["172.31.0.21"])
    result, _ = topotest.run_and_expect(test_func, True, count=160, wait=1)
    assert result, "VRF kernel routes on PE2 not cleaned after select-deferral expiry"

    # Verify PE2 FDB cleaned extern_learn entry learned from PE1
    logger.info("STEP 11: Verify FDB extern_learn MAC learned from PE1 is cleaned on PE2")
    test_func = functools.partial(_bridge_extern_absent, pe2, "vxlan100", "1a:2b:3c:4d:5e:61")
    result, _ = topotest.run_and_expect(test_func, True, count=160, wait=1)
    assert result, "FDB extern_learn MAC on PE2 not cleaned after select-deferral expiry"

    # Cleanup: re-enable neighbor on PE1 so subsequent tests can proceed
    logger.info("STEP 12: Re-enable neighbor 10.0.1.2 on PE1 to restore normal operation")
    pe1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 101\n"
        "no neighbor 10.0.1.2 shutdown\n"
    )
"""
