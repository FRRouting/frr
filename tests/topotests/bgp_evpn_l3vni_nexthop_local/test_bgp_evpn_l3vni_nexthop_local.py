#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_l3vni_nexthop_local.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Google LLC
#

"""
test_bgp_evpn_l3vni_nexthop_local.py: In a tenant VRF, prefer a nexthop that
is attached to the receiving VTEP over one that is only reachable over the
L3VNI, for EVPN gateway IPs (RFC 9136 overlay index) and for routes learned
from peers in the VRF.

             +------+                    +------+
             |  r1  |  100.0.0.21/32     |  r4  |  100.0.0.21/32
             +--+---+  via h2            +--+---+  via h3
                |                           |
     s1  -------+------+----------+---------+------+----------
                       |          |                |      |
                    +--+---+   +--+---+         +--+---+ +--+---+
                    |  r2  |   |  r3  |         |  r5  | |  r6  |
                    +-+--+-+   +-+--+-+         +------+ +------+
                      |  |       |  |           L2VNI     L3VNI
                     h2  h4     h3  h5          no host   only

All six routers are VTEPs in AS 65000 with L3VNI 2234 in vrf-blue. r1 to r5
also have L2VNI 100 (br100, 10.20.0.0/24), stretched across them; r6 has only
the L3VNI. h2 (10.20.0.25) and h4 (10.20.0.44) are attached to r2, h3
(10.20.0.26) and h5 (10.20.0.45) to r3.

Gateway IPs: r1 and r4 export an anycast prefix as type-5 routes with gateway
IP h2 and h3 respectively, like a pair of leaves that peer with the hosts
announcing it. r2 resolves h2 over br100 and h3 over the L3VNI SVI, through
the host route from r3's type-2 route; r3 the other way round. With equal
metrics both would ECMP the prefix to their own host and to each other, and
the flows that both hash across the fabric would loop. Each must use only its
attached gateway. r5 and r6 reach both gateways over the L3VNI and must keep
both paths. When r2 forgets h2, its gateway is unknown everywhere and r2 must
fall back to h3. When h3 resolves over br100 on r2, r2 must use both gateways,
and only h2 again when h3 is back over the L3VNI, with the same imported paths.

Peers: h4 and h5 both peer with r2 over eBGP multihop and announce
100.0.0.31/32, like hosts in two racks that peer with one leaf. r2 resolves
h5 over the L3VNI SVI and must use only h4. When h5's address resolves over
br100 instead, both are equal again; when h4 withdraws, r2 falls back to h5.
"""

import os
import platform
import sys
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

LEAVES = ["r1", "r2", "r3", "r4", "r5", "r6"]
L2VNI_LEAVES = ["r1", "r2", "r3", "r4", "r5"]
HOSTS = {"h2": ("r2", "1a:2b:3c:4d:5e:05"), "h3": ("r3", "1a:2b:3c:4d:5e:06")}
# Hosts that peer with r2: (leaf, MAC, address, leaf SVI address)
PEERS = {
    "h4": ("r2", "1a:2b:3c:4d:5e:44", "10.20.0.44", "10.20.0.2"),
    "h5": ("r3", "1a:2b:3c:4d:5e:45", "10.20.0.45", "10.20.0.3"),
}
PEER_PREFIX = "100.0.0.31/32"
VRF = "vrf-blue"
L2VNI_SVI = "br100"
L3VNI = 2234
L3VNI_SVI = "br{}".format(L3VNI)
# (afi, prefix, gateway h2, gateway h3, r2's SVI address, r3's SVI address)
ROUTES = [
    ("ip", "100.0.0.21/32", "10.20.0.25", "10.20.0.26", "10.20.0.2", "10.20.0.3"),
    (
        "ipv6",
        "100::21/128",
        "2001:db8:20::25",
        "2001:db8:20::26",
        "2001:db8:20::2",
        "2001:db8:20::3",
    ),
]


def build_topo(tgen):
    "Build function"

    for rname in LEAVES + list(HOSTS) + list(PEERS):
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    for rname in LEAVES:
        switch.add_link(tgen.gears[rname])

    for hname, (rname, _) in HOSTS.items():
        tgen.add_link(
            tgen.gears[rname],
            tgen.gears[hname],
            "{}-eth1".format(rname),
            "{}-eth0".format(hname),
        )

    for hname, (rname, _, _, _) in PEERS.items():
        tgen.add_link(
            tgen.gears[rname],
            tgen.gears[hname],
            "{}-eth2".format(rname),
            "{}-eth0".format(hname),
        )


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info("EVPN tests need kernel 4.18, have {}".format(krel))
        return pytest.skip("Skipping EVPN gateway IP test. Kernel not supported")

    for idx, rname in enumerate(LEAVES, start=1):
        tgen.net[rname].cmd_raises("""
ip link add {vrf} type vrf table 10
ip link set dev {vrf} up
ip link add br{l3vni} address 52:54:00:00:0{n}:ba type bridge stp_state 0
ip link set dev br{l3vni} master {vrf}
ip link add vxlan{l3vni} type vxlan id {l3vni} dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan{l3vni} master br{l3vni}
ip link set dev br{l3vni} up
ip link set dev vxlan{l3vni} up
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
""".format(vrf=VRF, n=idx, l3vni=L3VNI))

    for rname in L2VNI_LEAVES:
        idx = LEAVES.index(rname) + 1
        tgen.net[rname].cmd_raises("""
ip link add br100 address 52:54:00:00:0{n}:64 type bridge stp_state 0
ip link set dev br100 master {vrf}
ip addr add 10.20.0.{n}/24 dev br100
ip -6 addr add 2001:db8:20::{n}/64 dev br100 nodad
ip link add vxlan100 type vxlan id 100 dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan100 master br100
ip link set dev br100 up
ip link set dev vxlan100 up
""".format(vrf=VRF, n=idx))

    for hname, (rname, mac) in HOSTS.items():
        tgen.net[rname].cmd_raises("""
ip link set dev {r}-eth1 master br100
ip link set dev {r}-eth1 up
sysctl -w net.ipv4.neigh.br100.base_reachable_time_ms=3600000
sysctl -w net.ipv6.neigh.br100.base_reachable_time_ms=3600000
""".format(r=rname))
        tgen.net[hname].cmd_raises("""
ip link set dev {h}-eth0 down
ip link set dev {h}-eth0 address {mac}
ip link set dev {h}-eth0 up
sysctl -w net.ipv4.neigh.{h}-eth0.base_reachable_time_ms=3600000
sysctl -w net.ipv6.neigh.{h}-eth0.base_reachable_time_ms=3600000
sysctl -w net.ipv6.conf.{h}-eth0.accept_dad=0
""".format(h=hname, mac=mac))

    for hname, (rname, mac, _, _) in PEERS.items():
        tgen.net[rname].cmd_raises(
            "ip link set dev {r}-eth2 master br100\nip link set dev {r}-eth2 up".format(
                r=rname
            )
        )
        tgen.net[hname].cmd_raises("""
ip link set dev {h}-eth0 down
ip link set dev {h}-eth0 address {mac}
ip link set dev {h}-eth0 up
sysctl -w net.ipv4.neigh.{h}-eth0.base_reachable_time_ms=3600000
""".format(h=hname, mac=mac))

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _learn_host(tgen, hname):
    """
    Have the host talk to its leaf so that the leaf learns its MAC and IPs as
    local neighbors and advertises them in type-2 routes.
    """
    host = tgen.net[hname]
    for afi, _, _, _, r2_svi, r3_svi in ROUTES:
        ping = "ping" if afi == "ip" else "ping -6"
        svi = r2_svi if hname == "h2" else r3_svi
        host.cmd("{} -c 3 -i 0.2 -W 1 {}".format(ping, svi))


def _forget_host(tgen, hname):
    "Have the host's leaf forget its IPs, which withdraws its MAC/IP routes."
    rname = HOSTS[hname][0]
    for _, _, gw_h2, gw_h3, _, _ in ROUTES:
        gateway = gw_h2 if hname == "h2" else gw_h3
        tgen.net[rname].cmd_raises("ip neigh del {} dev {}".format(gateway, L2VNI_SVI))


def _check_installed(router, afi, prefix, gateways, ifname):
    """
    Check that BGP selected exactly the paths for ``prefix`` in vrf-blue
    whose nexthop is in ``gateways``, and that zebra installed the route
    through those gateways, resolved out of ``ifname``.
    """
    afi_bgp = "ipv4" if afi == "ip" else "ipv6"
    output = router.vtysh_cmd(
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        isjson=True,
    )
    selected = set()
    for path in output.get("paths", []):
        best = path.get("bestpath", {}).get("overall")
        if path.get("valid") and (best or path.get("multipath")):
            for nh in path.get("nexthops", []):
                selected.add(nh.get("ip"))
    if selected != set(gateways):
        paths = [
            (
                [nh.get("ip") for nh in path.get("nexthops", [])],
                path.get("valid"),
                path.get("bestpath"),
                path.get("multipath"),
            )
            for path in output.get("paths", [])
        ]
        nht = router.vtysh_cmd("show bgp vrf {} nexthop detail".format(VRF))
        return "BGP selected {} for {}, want {}: paths {}\n{}".format(
            selected, prefix, gateways, paths, nht
        )

    output = router.vtysh_cmd(
        "show {} route vrf {} {} json".format(afi, VRF, prefix), isjson=True
    )
    for entry in output.get(prefix, []):
        if not (entry.get("protocol") == "bgp" and entry.get("installed")):
            continue
        nexthops = entry.get("nexthops", [])
        # A recursive nexthop is followed by the nexthops that resolve it.
        got = {nh.get("ip") for nh in nexthops if not nh.get("resolver")}
        ifnames = {
            nh.get("interfaceName")
            for nh in nexthops
            if nh.get("active") and nh.get("interfaceName")
        }
        if got == set(gateways) and ifnames == {ifname}:
            return None
        return "{} installed via {} out of {}, want {} out of {}".format(
            prefix, got, ifnames, gateways, ifname
        )
    return "{} is not installed: {}".format(prefix, output)


def _expect(func, message):
    _, result = topotest.run_and_expect(func, None, count=40, wait=1)
    assert result is None, "{}: {}".format(message, result)


def _expect_steady(tgen):
    """
    r2 and r3 use only their attached gateway, r5 and r6 both gateways over
    the L3VNI SVI.
    """
    for afi, prefix, gw_h2, gw_h3, _, _ in ROUTES:
        for rname, gateways, ifname in [
            ("r2", [gw_h2], L2VNI_SVI),
            ("r3", [gw_h3], L2VNI_SVI),
            ("r5", [gw_h2, gw_h3], L3VNI_SVI),
            ("r6", [gw_h2, gw_h3], L3VNI_SVI),
        ]:
            _expect(
                partial(
                    _check_installed, tgen.gears[rname], afi, prefix, gateways, ifname
                ),
                rname,
            )


def test_bgp_convergence():
    "Wait for the EVPN sessions and for the leaves to learn h2 and h3."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in LEAVES:
        router = tgen.gears[rname]
        peers = {
            "10.0.0.{}".format(n): {"state": "Established"}
            for n in range(1, 7)
            if "r{}".format(n) != rname
        }
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn summary json",
            {"peers": peers},
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{} EVPN sessions did not come up: {}".format(
            rname, result
        )

    r6 = tgen.gears["r6"]

    def _learned():
        for hname in HOSTS:
            _learn_host(tgen, hname)
        for afi, _, gw_h2, gw_h3, _, _ in ROUTES:
            for gateway in (gw_h2, gw_h3):
                host_prefix = "{}/{}".format(gateway, 32 if afi == "ip" else 128)
                result = topotest.router_json_cmp(
                    r6,
                    "show {} route vrf {} {} json".format(afi, VRF, host_prefix),
                    {host_prefix: [{"protocol": "bgp", "installed": True}]},
                )
                if result is not None:
                    return result
        return None

    _, result = topotest.run_and_expect(_learned, None, count=60, wait=1)
    assert result is None, "the hosts were not learned: {}".format(result)

    r2 = tgen.gears["r2"]

    def _peers_up():
        for hname, (_, _, _, svi) in PEERS.items():
            tgen.net[hname].cmd("ping -c 3 -i 0.2 -W 1 {}".format(svi))
        peers = {addr: {"state": "Established"} for _, _, addr, _ in PEERS.values()}
        result = topotest.router_json_cmp(
            r2,
            "show bgp vrf {} ipv4 unicast summary json".format(VRF),
            {"peers": peers},
        )
        if result is not None:
            return result
        host_prefix = "{}/32".format(PEERS["h5"][2])
        return topotest.router_json_cmp(
            r2,
            "show ip route vrf {} {} json".format(VRF, host_prefix),
            {host_prefix: [{"protocol": "bgp", "installed": True}]},
        )

    _, result = topotest.run_and_expect(_peers_up, None, count=60, wait=1)
    assert result is None, "r2's sessions to h4 and h5 did not come up: {}".format(
        result
    )


def test_gateway_ip_prefer_local():
    """
    r2 and r3 each select only the path whose gateway is attached to them,
    which wins on IGP metric. r5 (L2VNI, no host) and r6 (L3VNI only) reach
    both gateways over the L3VNI and keep both paths.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _expect_steady(tgen)

    for afi, prefix, gw_h2, _, _, _ in ROUTES:
        afi_bgp = "ipv4" if afi == "ip" else "ipv6"
        output = tgen.gears["r2"].vtysh_cmd(
            "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
            isjson=True,
        )
        best = [
            p for p in output.get("paths", []) if p.get("bestpath", {}).get("overall")
        ]
        assert (
            best and best[0]["bestpath"].get("selectionReason") == "IGP Metric"
        ), "r2 did not select {} on IGP metric: {}".format(prefix, output)


def test_gateway_ip_local_withdrawn():
    """
    When r2 forgets h2, h2's gateway is unknown everywhere: r2 falls back to
    h3 over the L3VNI, and r5 and r6 keep only h3. When r2 learns h2 again,
    everything goes back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _forget_host(tgen, "h2")
    for afi, prefix, _, gw_h3, _, _ in ROUTES:
        for rname, ifname in [
            ("r2", L3VNI_SVI),
            ("r3", L2VNI_SVI),
            ("r5", L3VNI_SVI),
            ("r6", L3VNI_SVI),
        ]:
            _expect(
                partial(
                    _check_installed, tgen.gears[rname], afi, prefix, [gw_h3], ifname
                ),
                "{} after r2 forgot h2".format(rname),
            )

    _learn_host(tgen, "h2")
    _expect_steady(tgen)


def _path_last_update(router, afi, prefix, gateway):
    """
    Return the last update time of the valid path for ``prefix`` in vrf-blue
    through ``gateway``, or None.
    """
    afi_bgp = "ipv4" if afi == "ip" else "ipv6"
    output = router.vtysh_cmd(
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        isjson=True,
    )
    for path in output.get("paths", []):
        if path.get("valid") and any(
            nh.get("ip") == gateway for nh in path.get("nexthops", [])
        ):
            return path.get("lastUpdate", {}).get("epoch")
    return None


def test_gateway_ip_metric_follows_nht():
    """
    A static route on r2 makes h3 resolve over br100, so both gateways have
    the same metric and r2 uses both. Without it h3 is back over the L3VNI
    and r2 uses only h2. The type-5 routes don't change: r2 updates the
    metric of the paths it imported.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _static(add):
        cmds = ["configure terminal", " vrf {}".format(VRF)]
        for afi, _, _, gw_h3, _, _ in ROUTES:
            cmds.append(
                "  {}{} route {}/{} {}".format(
                    "" if add else "no ",
                    afi,
                    gw_h3,
                    32 if afi == "ip" else 128,
                    L2VNI_SVI,
                )
            )
        r2.vtysh_cmd("\n".join(cmds))

    updated = {}
    for afi, prefix, _, gw_h3, _, _ in ROUTES:
        updated[prefix] = _path_last_update(r2, afi, prefix, gw_h3)
        assert updated[prefix], "r2 has no valid path for {} via {}".format(
            prefix, gw_h3
        )

    _static(True)
    for afi, prefix, gw_h2, gw_h3, _, _ in ROUTES:
        _expect(
            partial(_check_installed, r2, afi, prefix, [gw_h2, gw_h3], L2VNI_SVI),
            "r2 with h3 on br100",
        )
    _static(False)
    for afi, prefix, gw_h2, gw_h3, _, _ in ROUTES:
        _expect(
            partial(_check_installed, r2, afi, prefix, [gw_h2], L2VNI_SVI),
            "r2 with h3 over the L3VNI",
        )
        # bgpd shows the last update as the wall clock minus the path's
        # monotonic age, both in whole seconds and read separately, so two
        # reads of an unchanged path can differ by one second.
        last_update = _path_last_update(r2, afi, prefix, gw_h3)
        assert (
            last_update is not None and abs(last_update - updated[prefix]) <= 1
        ), "r2 replaced its path for {} via {}: last update {}, was {}".format(
            prefix, gw_h3, last_update, updated[prefix]
        )


def _peer_announce(tgen, hname, announce):
    tgen.gears[hname].vtysh_cmd("""
configure terminal
 router bgp 4200000002
  address-family ipv4 unicast
   {}network {}
""".format("" if announce else "no ", PEER_PREFIX))


def test_peer_prefer_local():
    """
    h4 and h5 announce the same prefix to r2. h5 resolves over the L3VNI SVI,
    so r2 selects only h4, on IGP metric.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    h4, h5 = PEERS["h4"][2], PEERS["h5"][2]
    _expect(partial(_check_installed, r2, "ip", PEER_PREFIX, [h4], L2VNI_SVI), "r2")
    output = r2.vtysh_cmd(
        "show bgp vrf {} ipv4 unicast {} json".format(VRF, PEER_PREFIX), isjson=True
    )
    paths = output.get("paths", [])
    best = [p for p in paths if p.get("bestpath", {}).get("overall")]
    assert (
        best and best[0]["bestpath"].get("selectionReason") == "IGP Metric"
    ), "r2 did not select {} on IGP metric: {}".format(PEER_PREFIX, output)
    assert any(
        nh.get("ip") == h5 for p in paths for nh in p.get("nexthops", [])
    ), "r2 has no path from h5: {}".format(output)


def test_peer_metric_follows_nht():
    """
    A static route on r2 makes h5 resolve over br100, so both paths have the
    same metric again and r2 uses both. Without it r2 is back to h4 only.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    h4, h5 = PEERS["h4"][2], PEERS["h5"][2]

    def _static(add):
        r2.vtysh_cmd("""
configure terminal
 vrf {}
  {}ip route {}/32 {}
""".format(VRF, "" if add else "no ", h5, L2VNI_SVI))

    _static(True)
    _expect(
        partial(_check_installed, r2, "ip", PEER_PREFIX, [h4, h5], L2VNI_SVI),
        "r2 with h5 on br100",
    )
    _static(False)
    _expect(
        partial(_check_installed, r2, "ip", PEER_PREFIX, [h4], L2VNI_SVI),
        "r2 with h5 over the L3VNI",
    )


def test_peer_local_withdrawn():
    """
    When h4 withdraws the prefix, r2 falls back to h5 over the L3VNI. When h4
    announces it again, r2 goes back to h4.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    h4, h5 = PEERS["h4"][2], PEERS["h5"][2]

    _peer_announce(tgen, "h4", False)
    _expect(
        partial(_check_installed, r2, "ip", PEER_PREFIX, [h5], L3VNI_SVI),
        "r2 after h4 withdrew",
    )
    _peer_announce(tgen, "h4", True)
    _expect(
        partial(_check_installed, r2, "ip", PEER_PREFIX, [h4], L2VNI_SVI),
        "r2 after h4 announced again",
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
