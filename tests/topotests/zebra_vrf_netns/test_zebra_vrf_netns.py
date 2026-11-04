#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_vrf_netns.py
#
# Multiple namespaced VRFs with overlapping interface names and IP addresses.
# Uses integrated FRR config (single frr.conf).
#

"""
test_zebra_vrf_netns.py: Test zebra with multiple netns-based VRFs.
Each VRF has an interface with the same IP (10.0.0.1/24) and logically
the same role (first data interface), demonstrating overlapping addresses
and interface naming across VRFs.
"""

import os
import re
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from functools import partial

# VRFs (netns names) and overlapping IP used in each
VRF_NAMES = ["vrf-red", "vrf-blue", "vrf-green"]
OVERLAP_IP = "10.0.0.1"
OVERLAP_PREFIX = "10.0.0.1/24"

# Neighbor table entry per VRF: (ip, mac) on the VRF's interface (r1-eth0, r1-eth1, r1-eth2)
# Same IP 10.0.0.2 in each VRF (overlapping), different MACs to identify
NEIGH_PER_VRF = [
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "ifname": "r1-eth0"},
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:03", "ifname": "r1-eth1"},
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:04", "ifname": "r1-eth2"},
]

# Static route (same prefix and gateway in each VRF) used to check that kernel
# nexthop groups are installed in the namespace of the VRF
STATIC_PREFIX = "192.168.0.0/24"

# ECMP static routes (same prefixes in each VRF) over two interface-only
# nexthops, the VRF interface and a dummy. A v4 and a v6 route with the same
# nexthops must get two different kernel nexthop groups.
DUMMY_IFNAME = "r1-dum"
ECMP_PREFIX_V4 = "192.168.1.0/24"
ECMP_PREFIX_V6 = "2001:db8:1::/64"

# New neighbors added at test time to verify runtime receipt (10.0.0.3 in each VRF)
NEIGH_NEW_PER_VRF = [
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:12", "ifname": "r1-eth0"},
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:13", "ifname": "r1-eth1"},
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:14", "ifname": "r1-eth2"},
]


def build_topo(tgen):
    "One router, one link per VRF to a switch."
    tgen.add_router("r1")
    for i in range(len(VRF_NAMES)):
        sw = tgen.add_switch("s{}".format(i + 1))
        sw.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Create netns VRFs, move interfaces, then start FRR with integrated config."
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    if r1.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") is False:
        pytest.skip("VRF NETNS backend not available on FRR")
    if os.system("ip netns list") != 0:
        pytest.skip("NETNS not available on system")

    logger.info("Testing with VRF Namespace support (overlapping IPs per VRF)")

    # Create one netns per VRF and move one interface into each
    for i, vrf in enumerate(VRF_NAMES):
        r1.net.add_netns(vrf)
        ifname = "r1-eth{}".format(i)
        r1.net.set_intf_netns(ifname, vrf, up=True)
        r1.run(
            "ip netns exec {0} ip link add {1} type dummy && "
            "ip netns exec {0} ip link set {1} up".format(vrf, DUMMY_IFNAME)
        )

    r1.use_netns_vrf()
    r1.load_frr_config(extra_daemons=["staticd"])
    tgen.start_router()

    # Wait for each per-VRF interface to be fully up in zebra (in the correct
    # VRF, with the configured address) before adding kernel neighbors. Without
    # this barrier there is a race where the `ip neigh add` below can fire
    # before zebra has finished registering the interface in its per-NS
    # interface table, causing the RTM_NEWNEIGH netlink event to be silently
    # dropped (zebra_neigh_ipaddr_update() bails out if if_lookup_by_index_per_ns
    # returns NULL).
    expected_ifaces = {
        "r1-eth{}".format(i): {
            "administrativeStatus": "up",
            "operationalStatus": "up",
            "vrfName": vrf,
            "ipAddresses": [{"address": OVERLAP_PREFIX}],
        }
        for i, vrf in enumerate(VRF_NAMES)
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show interface vrf all json",
        expected_ifaces,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Per-VRF interfaces not ready in zebra: {}".format(
        result
    )

    # Add neighbor table entries in each VRF (same IP per VRF, different MACs)
    for vrf, neigh in zip(VRF_NAMES, NEIGH_PER_VRF):
        r1.run(
            "ip netns exec {} ip neigh add {} lladdr {} dev {} nud reachable".format(
                vrf, neigh["ip"], neigh["mac"], neigh["ifname"]
            )
        )


def teardown_module(_mod):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    for i in range(len(VRF_NAMES)):
        r1.net.reset_intf_netns("r1-eth{}".format(i))
    for vrf in VRF_NAMES:
        r1.net.delete_netns(vrf)
    tgen.stop_topology()


def test_vrf_list():
    "All three VRFs should appear in show vrf."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show vrf", isjson=False)
    for vrf in VRF_NAMES:
        assert vrf in out, "VRF {} missing from show vrf: {}".format(vrf, out)


def test_same_ip_per_vrf():
    "Each VRF should have 10.0.0.1/24 on its interface (overlapping IPs)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for vrf in VRF_NAMES:
        out = r1.vtysh_cmd("show interface vrf {} json".format(vrf), isjson=True)
        found = False
        for ifname, data in out.items():
            if ifname.startswith("r1-eth"):
                addrs = data.get("ipAddresses", []) or []
                for a in addrs:
                    if isinstance(a, dict) and a.get("address") == OVERLAP_PREFIX:
                        found = True
                        break
                    if isinstance(a, str) and a == OVERLAP_PREFIX:
                        found = True
                        break
            if found:
                break
        assert found, "VRF {} should have {} on an interface".format(
            vrf, OVERLAP_PREFIX
        )


def test_interface_names_overlap():
    "Each VRF has one data interface; show interface shows correct VRF per if."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show interface vrf all json", isjson=True)
    by_vrf = {}
    for ifname, data in out.items():
        vrf = data.get("vrfName") or "default"
        if vrf not in by_vrf:
            by_vrf[vrf] = []
        by_vrf[vrf].append(ifname)
    for vrf in VRF_NAMES:
        assert vrf in by_vrf, "No interfaces in VRF {}: {}".format(
            vrf, list(by_vrf.keys())
        )
        assert len(by_vrf[vrf]) >= 1, "VRF {} has no interfaces".format(vrf)


def test_neighbor_entries_per_vrf():
    "Neighbor entries added via ip netns exec in each VRF show up in show ip neighbor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected = {
        "neighbors": [
            {
                "interface": n["ifname"],
                "neighbor": n["ip"],
                "mac": n["mac"],
                "ruleCount": 0,
                "state": "REACHABLE",
            }
            for n in NEIGH_PER_VRF
        ]
    }
    test_func = partial(topotest.router_json_cmp, r1, "show ip neighbor json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert (
        result is None
    ), "Neighbor entries per VRF missing from show ip neighbor: {}".format(result)


def test_new_neighbor_entries_received():
    "Add new neighbor entries in each VRF at test time and ensure they are received."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add new neighbors in each VRF via ip netns exec
    for vrf, neigh in zip(VRF_NAMES, NEIGH_NEW_PER_VRF):
        r1.run(
            "ip netns exec {} ip neigh add {} lladdr {} dev {} nud reachable".format(
                vrf, neigh["ip"], neigh["mac"], neigh["ifname"]
            )
        )

    # Expect these new entries to show up in show ip neighbor
    expected = {
        "neighbors": [
            {
                "interface": n["ifname"],
                "neighbor": n["ip"],
                "mac": n["mac"],
                "ruleCount": 0,
                "state": "REACHABLE",
            }
            for n in NEIGH_NEW_PER_VRF
        ]
    }
    test_func = partial(topotest.router_json_cmp, r1, "show ip neighbor json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert (
        result is None
    ), "New neighbor entries per VRF not received in show ip neighbor: {}".format(
        result
    )


def _kernel_nhg_in_netns(r1, netns, nhg_id):
    "Return True if the kernel nexthop id exists in the namespace (None: default)"
    cmd = "ip nexthop show id {}".format(nhg_id)
    if netns:
        cmd = "ip netns exec {} {}".format(netns, cmd)
    rc, _, _ = r1.net.cmd_status(cmd, warn=False)
    return rc == 0


def _check_kernel_nhg_in_vrf_netns(r1, vrf, ifname, nhg_ids):
    "Return None when all the nexthop ids and the route are in the VRF's netns."
    for nhg_id in nhg_ids:
        if not _kernel_nhg_in_netns(r1, vrf, nhg_id):
            return "nexthop id {} is not in the {} namespace".format(nhg_id, vrf)
        if _kernel_nhg_in_netns(r1, None, nhg_id):
            return "nexthop id {} leaked in the default namespace".format(nhg_id)

    out = r1.run("ip netns exec {} ip route show {}".format(vrf, STATIC_PREFIX))
    if "nhid {}".format(nhg_ids[0]) not in out:
        return "route {} of {} does not use nhid {}: {}".format(
            STATIC_PREFIX, vrf, nhg_ids[0], out
        )

    out = r1.run("ip netns exec {} ip nexthop show".format(vrf))
    if "via 10.0.0.2 dev {}".format(ifname) not in out:
        return "no nexthop via 10.0.0.2 dev {} in {}: {}".format(ifname, vrf, out)

    return None


def test_kernel_nhg_per_vrf():
    "Kernel nexthop groups are installed in the namespace of their VRF."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    nhg_ids = {}
    for vrf in VRF_NAMES:
        cmd = "show ip route vrf {} {} json".format(vrf, STATIC_PREFIX)
        expected = {STATIC_PREFIX: [{"installed": True}]}
        test_func = partial(topotest.router_json_cmp, r1, cmd, expected)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "Static route not installed in VRF {}: {}".format(
            vrf, result
        )

        nhg_id = r1.vtysh_cmd(cmd, isjson=True)[STATIC_PREFIX][0].get("nexthopGroupId")
        assert nhg_id, "Static route of VRF {} has no nexthop group".format(vrf)

        # The route uses the singleton with the gateway, or a group depending on it
        nhg = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id), isjson=True)
        depends = nhg[str(nhg_id)].get("depends") or []
        nhg_ids[vrf] = [nhg_id] + depends

    # Nexthop ids are allocated by zebra, they cannot be shared between VRFs
    all_ids = [i for ids in nhg_ids.values() for i in ids]
    assert len(set(all_ids)) == len(all_ids), "Nexthop ids reused: {}".format(nhg_ids)

    for i, vrf in enumerate(VRF_NAMES):
        test_func = partial(
            _check_kernel_nhg_in_vrf_netns, r1, vrf, "r1-eth{}".format(i), nhg_ids[vrf]
        )
        _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
        assert result is None, "Kernel nexthop group check failed: {}".format(result)


def _route_nhg_id(r1, vrf, prefix, v6=False):
    "Return the nexthop group id of an installed static route, None otherwise."
    cmd = "show {} route vrf {} {} json".format("ipv6" if v6 else "ip", vrf, prefix)
    out = r1.vtysh_cmd(cmd, isjson=True)
    routes = out.get(prefix) or []
    if not routes or not routes[0].get("installed"):
        return None
    return routes[0].get("nexthopGroupId")


def _route_installed(r1, vrf, prefix, v6=False):
    "Return None when the static route is installed, an error string otherwise."
    if _route_nhg_id(r1, vrf, prefix, v6) is None:
        return "route {} not installed in VRF {}".format(prefix, vrf)
    return None


def _check_ecmp_dev_only_route(r1, vrf, prefix, nhg_id, v6):
    "Return None when the kernel route uses the group and has two nexthops."
    family = "-6" if v6 else "-4"
    out = r1.run("ip netns exec {} ip {} route show {}".format(vrf, family, prefix))
    if "nhid {}".format(nhg_id) not in out:
        return "route {} of {} does not use nhid {}: {}".format(
            prefix, vrf, nhg_id, out
        )
    if out.count("nexthop dev") != 2:
        return "route {} of {} is not ECMP over two interfaces: {}".format(
            prefix, vrf, out
        )
    out = r1.run("ip netns exec {} ip nexthop show id {}".format(vrf, nhg_id))
    if "group" not in out:
        return "nexthop id {} of {} is not a group: {}".format(nhg_id, vrf, out)
    return None


def test_kernel_nhg_ecmp_dev_only_v4_v6():
    "A v4 and a v6 ECMP route over interface-only nexthops use two groups."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for vrf in VRF_NAMES:
        ids = {}
        for v6, prefix in ((False, ECMP_PREFIX_V4), (True, ECMP_PREFIX_V6)):
            test_func = partial(_route_installed, r1, vrf, prefix, v6)
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, result
            ids[prefix] = _route_nhg_id(r1, vrf, prefix, v6)

        # Interface-only nexthop objects are address family specific in the
        # kernel: the two routes cannot share a group, or the v6 route is
        # refused ("IPv6 routes can not use an IPv4 nexthop").
        assert (
            ids[ECMP_PREFIX_V4] != ids[ECMP_PREFIX_V6]
        ), "v4 and v6 ECMP routes of VRF {} share nexthop group {}".format(
            vrf, ids[ECMP_PREFIX_V4]
        )

        for v6, prefix in ((False, ECMP_PREFIX_V4), (True, ECMP_PREFIX_V6)):
            test_func = partial(
                _check_ecmp_dev_only_route, r1, vrf, prefix, ids[prefix], v6
            )
            _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
            assert result is None, "Kernel ECMP route check failed: {}".format(result)


def _check_nhg_untouched(r1, vrf, nhg_id):
    "Return None when the group is still installed in its VRF for its route."
    nhg = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id), isjson=True)
    entry = nhg.get(str(nhg_id)) or {}
    if entry.get("vrf") != vrf or not entry.get("installed"):
        return "nexthop group {} not installed in {}: {}".format(nhg_id, vrf, entry)
    if _route_nhg_id(r1, vrf, STATIC_PREFIX) != nhg_id:
        return "route {} of {} no longer uses nhid {}".format(
            STATIC_PREFIX, vrf, nhg_id
        )
    if not _kernel_nhg_in_netns(r1, vrf, nhg_id):
        return "nexthop id {} is gone from the {} namespace".format(nhg_id, vrf)
    return None


def test_kernel_nhg_foreign_netns_id_reuse():
    "A kernel nexthop with the id of our group, in another netns, is ignored."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    owner, other, other_ifname = VRF_NAMES[0], VRF_NAMES[1], "r1-eth1"

    nhg_id = _route_nhg_id(r1, owner, STATIC_PREFIX)
    assert nhg_id, "Static route of VRF {} not installed".format(owner)
    assert not _kernel_nhg_in_netns(
        r1, other, nhg_id
    ), "nexthop id {} already exists in {}".format(nhg_id, other)

    # Kernel nexthop ids are per namespace: another namespace is free to use
    # the id of our group. Zebra must not take these events for its own group.
    r1.run(
        "ip netns exec {} ip nexthop add id {} dev {}".format(
            other, nhg_id, other_ifname
        )
    )
    test_func = partial(_check_nhg_untouched, r1, owner, nhg_id)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Group changed after foreign add: {}".format(result)

    r1.run("ip netns exec {} ip nexthop del id {}".format(other, nhg_id))
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Group changed after foreign delete: {}".format(result)

    log = r1.net.getLog("log", "zebra")
    pattern = r"Kernel (updated|deleted) a nexthop group with ID \({}".format(nhg_id)
    assert not re.search(
        pattern, log
    ), "zebra reacted to the foreign nexthop id {}: {}".format(
        nhg_id, re.search(pattern, log).group(0)
    )


FOREIGN_PREFIX = "192.168.77.0/24"


def _check_route_off_group(r1, vrf, prefix, ifname, nhg_id):
    "Return None unless zebra resolved the route through the group or off ifname."
    cmd = "show ip route vrf {} {} json".format(vrf, prefix)
    for route in r1.vtysh_cmd(cmd, isjson=True).get(prefix) or []:
        if route.get("nexthopGroupId") == nhg_id:
            return "route {} of {} uses nhid {}".format(prefix, vrf, nhg_id)
        for nexthop in route.get("nexthops") or []:
            if nexthop.get("interfaceName") != ifname:
                return "route {} of {} resolved via {}".format(prefix, vrf, nexthop)
    return None


def test_kernel_route_foreign_netns_id_reuse():
    "A kernel route of another netns using the id of our group does not use it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    owner, other, other_ifname = VRF_NAMES[0], VRF_NAMES[1], "r1-eth1"

    nhg_id = _route_nhg_id(r1, owner, STATIC_PREFIX)
    assert nhg_id, "Static route of VRF {} not installed".format(owner)

    # The other netns has its own nexthop with this id, and a route on it.
    netns = "ip netns exec {} ".format(other)
    r1.run(netns + "ip nexthop add id {} dev {}".format(nhg_id, other_ifname))
    r1.run(netns + "ip route add {} nhid {}".format(FOREIGN_PREFIX, nhg_id))
    try:
        # Let zebra handle the route, then check what it made of it.
        time.sleep(5)
        result = _check_route_off_group(r1, other, FOREIGN_PREFIX, other_ifname, nhg_id)
        assert result is None, "Foreign route took our group: {}".format(result)

        test_func = partial(_check_nhg_untouched, r1, owner, nhg_id)
        _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
        assert result is None, "Group changed by the foreign route: {}".format(result)

        # A group of the other netns holding our id is not built from our nhe.
        r1.run(netns + "ip nexthop add id 60123 group {}".format(nhg_id))
        r1.run(netns + "ip route add 192.168.78.0/24 nhid 60123")
        r1.run(netns + "ip route add 192.168.79.0/24 dev {}".format(other_ifname))
        test_func = partial(_route_installed, r1, other, "192.168.79.0/24")
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, result

        nhg = r1.vtysh_cmd("show nexthop-group rib 60123 json", isjson=True)
        assert "60123" not in nhg, "Foreign group was created: {}".format(nhg)
        owner_nhg = r1.vtysh_cmd(
            "show nexthop-group rib {} json".format(nhg_id), isjson=True
        )
        dependents = owner_nhg.get(str(nhg_id), {}).get("dependents") or []
        assert 60123 not in dependents, "Foreign group is a dependent: {}".format(
            owner_nhg
        )
        result = _check_route_off_group(
            r1, other, "192.168.78.0/24", other_ifname, 60123
        )
        assert result is None, "Route took the foreign group: {}".format(result)
    finally:
        r1.run(netns + "ip route del 192.168.78.0/24")
        r1.run(netns + "ip route del 192.168.79.0/24")
        r1.run(netns + "ip nexthop del id 60123")
        r1.run(netns + "ip route del {}".format(FOREIGN_PREFIX))
        r1.run(netns + "ip nexthop del id {}".format(nhg_id))


GONE_PREFIX = "192.168.9.0/24"


def _check_deleted_vrf_nhg(r1, vrf, remove_vrf):
    "Delete the netns of a new VRF, the VRF too if asked, and wait for its group."
    r1.net.add_netns(vrf)
    r1.run("ip -n {} link add dum0 type dummy".format(vrf))
    r1.run("ip -n {} address add 10.9.0.1/24 dev dum0".format(vrf))
    r1.run("ip -n {} link set dum0 up".format(vrf))
    r1.vtysh_cmd(
        "configure terminal\nvrf {}\nip route {} 10.9.0.2\nexit-vrf".format(
            vrf, GONE_PREFIX
        )
    )
    test_func = partial(_route_installed, r1, vrf, GONE_PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result
    nhg_id = _route_nhg_id(r1, vrf, GONE_PREFIX)
    assert _kernel_nhg_in_netns(
        r1, vrf, nhg_id
    ), "nexthop id {} not installed in {}".format(nhg_id, vrf)

    # The default netns has a nexthop of its own with the id of our group.
    r1.run("ip nexthop add id {} blackhole".format(nhg_id))
    try:
        r1.vtysh_cmd("configure terminal\nzebra nexthop-group keep 10")
        r1.run("ip netns del {}".format(vrf))
        time.sleep(3)
        if remove_vrf:
            r1.vtysh_cmd("configure terminal\nno vrf {}".format(vrf))
        # The groups of the VRF are uninstalled once the keep timer expires.
        time.sleep(15)

        assert not r1.check_router_running(), "a daemon crashed"
        assert _kernel_nhg_in_netns(
            r1, None, nhg_id
        ), "nexthop id {} of the default netns was deleted".format(nhg_id)
    finally:
        r1.run("ip nexthop del id {}".format(nhg_id))


def test_kernel_nhg_inactive_vrf():
    "The groups of a VRF whose netns is deleted go away with the netns."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _check_deleted_vrf_nhg(tgen.gears["r1"], "vrf-gone1", False)


def test_kernel_nhg_deleted_vrf():
    "The groups of a deleted netns VRF are not removed from the default netns."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _check_deleted_vrf_nhg(tgen.gears["r1"], "vrf-gone2", True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
