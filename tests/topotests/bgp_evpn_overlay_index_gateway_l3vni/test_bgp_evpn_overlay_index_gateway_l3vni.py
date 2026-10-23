#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_overlay_index_gateway_l3vni.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Google LLC
#

"""
test_bgp_evpn_overlay_index_gateway_l3vni.py: Resolve the gateway IP overlay
index (RFC 9136) of an EVPN type-5 route on a VTEP that has the L3VNI of the
VRF but no L2VNI, such as a border leaf.

                        +------+
                        |  r1  |  exports 100.0.0.21/32 and 100::21/128
                        +--+---+  as type-5 routes with gateway IP h2
                           |
          s1  -------------+-------------
                   |               |
                +--+---+        +--+---+
                |  r2  |        |  r3  |  L3VNI 2234 only,
                +--+---+        +------+  enable-resolve-overlay-index
                   |
                +--+---+
                |  h2  |  10.20.0.5, 2001:db8:20::5
                +------+

r1 and r2 are VTEPs with L2VNI 100 (br100, 10.20.0.0/24) and L3VNI 2234 in
vrf-blue. r3 has only the L3VNI. h2 is attached to r2. r1 exports a route
whose nexthop is h2 as an EVPN type-5 route carrying h2's address as gateway
IP. r1 and r3 are in AS 65000, r2 in AS 65002: r3 gets the type-5 routes
over iBGP, so zebra may resolve their gateway recursively.

r3 has no EVI that could know h2. It gets h2's host route over the L3VNI SVI
from r2's type-2 route, which carries the L3VNI, and later from a type-5
route for the host. Either must resolve the gateway, and the type-5 route
through h2 must be installed through that host route. When the host route
goes away, the type-5 route through h2 must go away too. r3 has an aggregate
covering h2 with summary-only, so h2's host route is suppressed, which only
stops its advertisement: it still resolves the gateway.

The type-5 route through h2 must also carry traffic: a ping from r3 to the
prefix in vrf-blue must leave r3 VXLAN-encapsulated with the L3VNI, to r2's
VTEP and router MAC, and never unencapsulated.

r1 also exports 10.20.0.50/32 through h2 and 100.0.0.22/32 through
10.20.0.50, both with gateway IP. On r3 the first one resolves through h2's
host route. The second one must not resolve through it: a gateway IP is
not resolved through a route that has a gateway IP itself.

Unsetting "enable-resolve-overlay-index" on r3 must make it stop using the
type-5 routes through h2, and setting it again must resolve them again,
which r3 cannot do by walking its EVIs: it has none.
"""

import os
import platform
import sys
import time
from functools import partial

import pytest
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.utils import rdpcap

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

LEAVES = ["r1", "r2", "r3"]
ASN = {"r1": 65000, "r2": 65002, "r3": 65000}
VRF = "vrf-blue"
L2VNI_SVI = "br100"
L3VNI = 2234
L3VNI_SVI = "br{}".format(L3VNI)
HOST_MAC = "1a:2b:3c:4d:5e:05"
# r2's VTEP address and router MAC, the address of its L3VNI SVI.
R2_VTEP = "10.100.0.2"
R2_RMAC = "52:54:00:00:02:ba"
# Source addresses r3 pings from in vrf-blue.
R3_VRF_ADDR = {"ip": "10.30.0.3", "ipv6": "2001:db8:30::3"}
# (afi, prefix exported by r1, gateway IP = h2, r2's SVI address,
#  route exported by r1 through h2, prefix exported by r1 through that route)
ROUTES = [
    ("ip", "100.0.0.21/32", "10.20.0.5", "10.20.0.2", "10.20.0.50", "100.0.0.22/32"),
    (
        "ipv6",
        "100::21/128",
        "2001:db8:20::5",
        "2001:db8:20::2",
        "2001:db8:20::50",
        "100::22/128",
    ),
]


def build_topo(tgen):
    "Build function"

    for rname in LEAVES + ["h2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    for rname in LEAVES:
        switch.add_link(tgen.gears[rname])

    tgen.add_link(tgen.gears["r2"], tgen.gears["h2"], "r2-eth1", "h2-eth0")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info("EVPN tests need kernel 4.18, have {}".format(krel))
        return pytest.skip("Skipping EVPN gateway IP test. Kernel not supported")

    for idx, rname in enumerate(LEAVES, start=1):
        tgen.net[rname].cmd_raises(
            """
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
""".format(
                vrf=VRF, n=idx, l3vni=L3VNI
            )
        )

    # r3 has no L2VNI.
    for idx, rname in [(1, "r1"), (2, "r2")]:
        tgen.net[rname].cmd_raises(
            """
ip link add br100 address 52:54:00:00:0{n}:64 type bridge stp_state 0
ip link set dev br100 master {vrf}
ip addr add 10.20.0.{n}/24 dev br100
ip -6 addr add 2001:db8:20::{n}/64 dev br100 nodad
ip link add vxlan100 type vxlan id 100 dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan100 master br100
ip link set dev br100 up
ip link set dev vxlan100 up
""".format(
                vrf=VRF, n=idx
            )
        )

    tgen.net["r2"].cmd_raises(
        """
ip link set dev r2-eth1 master br100
ip link set dev r2-eth1 up
sysctl -w net.ipv4.neigh.br100.base_reachable_time_ms=3600000
sysctl -w net.ipv6.neigh.br100.base_reachable_time_ms=3600000
"""
    )
    tgen.net["h2"].cmd_raises(
        """
ip link set dev h2-eth0 down
ip link set dev h2-eth0 address {}
ip link set dev h2-eth0 up
sysctl -w net.ipv4.neigh.h2-eth0.base_reachable_time_ms=3600000
sysctl -w net.ipv6.neigh.h2-eth0.base_reachable_time_ms=3600000
""".format(
            HOST_MAC
        )
    )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _host_prefix(afi, ip):
    return "{}/{}".format(ip, 32 if afi == "ip" else 128)


def _learn_host(tgen):
    """
    Have h2 talk to r2 so that r2 learns h2's MAC and IPs as local
    neighbors and advertises them in type-2 routes.
    """
    h2 = tgen.net["h2"]
    for afi, _, _, r2_svi, _, _ in ROUTES:
        ping = "ping" if afi == "ip" else "ping -6"
        h2.cmd("{} -c 3 -i 0.2 -W 1 {}".format(ping, r2_svi))


def _forget_host(tgen):
    "Have r2 forget h2's IPs, which withdraws its MAC/IP routes."
    for _, _, gateway, _, _, _ in ROUTES:
        tgen.net["r2"].cmd_raises("ip neigh del {} dev {}".format(gateway, L2VNI_SVI))


def _check_host_route(router, afi, host_prefix):
    """
    Check that ``router`` has an installed BGP host route for
    ``host_prefix`` in vrf-blue over the L3VNI SVI.
    """
    expected = {
        host_prefix: [
            {
                "protocol": "bgp",
                "installed": True,
                "nexthops": [{"interfaceName": L3VNI_SVI, "active": True}],
            }
        ]
    }
    return topotest.router_json_cmp(
        router,
        "show {} route vrf {} {} json".format(afi, VRF, host_prefix),
        expected,
    )


def _check_no_host_route(router, afi, host_prefix):
    "Check that ``router`` has no route for ``host_prefix`` in vrf-blue."
    output = router.vtysh_cmd(
        "show {} route vrf {} {} json".format(afi, VRF, host_prefix), isjson=True
    )
    return output.get(host_prefix) or None


def _check_gateway_route(router, afi, prefix, gateway, ifname):
    """
    Check that ``router`` has a valid best BGP path for ``prefix`` in vrf-blue
    with nexthop ``gateway``, and that zebra installed it through
    ``gateway`` out of ``ifname``.
    """
    afi_bgp = "ipv4" if afi == "ip" else "ipv6"
    expected = {"paths": [{"valid": True, "bestpath": {"overall": True}}]}
    result = topotest.router_json_cmp(
        router,
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        expected,
    )
    if result is not None:
        return "BGP path for {} is not valid: {}".format(prefix, result)

    output = router.vtysh_cmd(
        "show {} route vrf {} {} json".format(afi, VRF, prefix), isjson=True
    )
    entries = output.get(prefix, [])
    for entry in entries:
        if not (entry.get("protocol") == "bgp" and entry.get("installed")):
            continue
        nexthops = entry.get("nexthops", [])
        if not any(nh.get("ip") == gateway and nh.get("active") for nh in nexthops):
            continue
        if any(
            nh.get("interfaceName") == ifname and nh.get("active") for nh in nexthops
        ):
            return None
    return "{} is not installed via {} on {}: {}".format(
        prefix, gateway, ifname, entries
    )


def _check_gateway_route_invalid(router, afi, prefix):
    "Check that ``router`` has no valid path, and no route, for ``prefix``."
    afi_bgp = "ipv4" if afi == "ip" else "ipv6"
    output = router.vtysh_cmd(
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        isjson=True,
    )
    if not output.get("paths"):
        return "no BGP path for {}".format(prefix)
    if any(path.get("valid") for path in output.get("paths", [])):
        return "BGP path for {} is still valid: {}".format(prefix, output)

    output = router.vtysh_cmd(
        "show {} route vrf {} {} json".format(afi, VRF, prefix), isjson=True
    )
    if output.get(prefix):
        return "{} is still installed: {}".format(prefix, output)
    return None


def _check_type5_received(router, afi, prefix, gateway):
    """
    Check that ``router`` imported the type-5 route into vrf-blue with
    ``gateway`` as nexthop, which is where the gateway IP overlay index goes.
    """
    afi_bgp = "ipv4" if afi == "ip" else "ipv6"
    expected = {"paths": [{"nexthops": [{"ip": gateway}]}]}
    return topotest.router_json_cmp(
        router,
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        expected,
    )


def _expect(func, message):
    _, result = topotest.run_and_expect(func, None, count=30, wait=1)
    assert result is None, "{}: {}".format(message, result)


def _expect_resolved(tgen):
    "r3 installs the type-5 routes through h2's host route on the L3VNI SVI."
    r3 = tgen.gears["r3"]
    for afi, prefix, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_gateway_route, r3, afi, prefix, gateway, L3VNI_SVI), "r3"
        )


def _expect_unresolved(tgen):
    "r3 has the type-5 routes through h2 but uses none of them."
    r3 = tgen.gears["r3"]
    for afi, prefix, _, _, _, _ in ROUTES:
        _expect(partial(_check_gateway_route_invalid, r3, afi, prefix), "r3")


def test_bgp_convergence():
    "Wait for the EVPN sessions, for r2 to learn h2 and for r3 to get the routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in LEAVES:
        router = tgen.gears[rname]
        peers = {
            "10.0.0.{}".format(n): {"state": "Established"}
            for n in range(1, 4)
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

    r3 = tgen.gears["r3"]

    def _learned():
        _learn_host(tgen)
        for afi, _, gateway, _, _, _ in ROUTES:
            result = _check_host_route(r3, afi, _host_prefix(afi, gateway))
            if result is not None:
                return result
        return None

    _, result = topotest.run_and_expect(_learned, None, count=30, wait=1)
    assert result is None, "r3 has no host route to h2: {}".format(result)

    for afi, prefix, gateway, _, via, via_prefix in ROUTES:
        for p, gw in [(prefix, gateway), (_host_prefix(afi, via), gateway)]:
            _expect(
                partial(_check_type5_received, r3, afi, p, gw),
                "r3 did not get {} with gateway IP {}".format(p, gw),
            )
        _expect(
            partial(_check_type5_received, r3, afi, via_prefix, via),
            "r3 did not get {} with gateway IP {}".format(via_prefix, via),
        )


def test_gateway_ip_l3vni_host_route():
    """
    r3 has no EVI, so no EVI knows h2. h2's host route, imported from r2's
    type-2 route over the L3VNI SVI, must resolve the gateway.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r3"].vtysh_cmd("show bgp l2vpn evpn vni json", isjson=True)
    assert output.get("numVnis", 0) == 0 or not any(
        vni.get("type") == "L2" for vni in output.values() if isinstance(vni, dict)
    ), "r3 has an L2VNI: {}".format(output)

    # The aggregate suppresses h2's host route.
    r3 = tgen.gears["r3"]
    for afi, _, gateway, _, _, _ in ROUTES:
        afi_bgp = "ipv4" if afi == "ip" else "ipv6"
        _expect(
            partial(
                topotest.router_json_cmp,
                r3,
                "show bgp vrf {} {} unicast {} json".format(
                    VRF, afi_bgp, _host_prefix(afi, gateway)
                ),
                {"paths": [{"valid": True, "suppressed": True}]},
            ),
            "r3's host route to {} is not suppressed".format(gateway),
        )

    _expect_resolved(tgen)


def _capture_pings(tgen, pcap):
    """
    Capture what r3 sends on its underlay interface while it pings each
    type-5 prefix in vrf-blue, and return the captured packets.
    """
    r3 = tgen.gears["r3"]
    if os.path.exists(pcap):
        os.unlink(pcap)
    pid = r3.cmd(
        "tcpdump -n -U -s 0 -i r3-eth0 -w {} >/dev/null 2>&1 & echo $!".format(pcap)
    ).strip()
    try:
        # tcpdump creates the file once it captures.
        _, result = topotest.run_and_expect(
            lambda: os.path.exists(pcap), True, count=30, wait=0.5
        )
        assert result, "tcpdump on r3-eth0 did not start"
        for afi, prefix, _, _, _, _ in ROUTES:
            r3.cmd(
                "ip vrf exec {} ping {} -c 3 -i 0.2 -W 1 -I {} {}".format(
                    VRF,
                    "-4" if afi == "ip" else "-6",
                    R3_VRF_ADDR[afi],
                    prefix.split("/")[0],
                )
            )
    finally:
        r3.cmd("kill -INT {} 2>/dev/null; sleep 1".format(pid))
    return rdpcap(pcap)


def _check_encapsulated(packets):
    """
    Check that ``packets`` have echo requests to each type-5 prefix in VXLAN
    with the L3VNI, to r2's VTEP and router MAC, and none outside VXLAN.
    """
    def _echo_request(pkt, dst):
        if pkt.haslayer(IP) and pkt[IP].dst == dst:
            return pkt.haslayer(ICMP) and pkt[ICMP].type == 8
        if pkt.haslayer(IPv6) and pkt[IPv6].dst == dst:
            return pkt.haslayer(ICMPv6EchoRequest)
        return False

    for _, prefix, _, _, _, _ in ROUTES:
        dst = prefix.split("/")[0]
        encapsulated = 0
        for pkt in packets:
            if not pkt.haslayer(VXLAN):
                # The outer header is the first IP header of the packet.
                if _echo_request(pkt, dst):
                    return "an echo request to {} left r3 unencapsulated: {}".format(
                        dst, pkt.summary()
                    )
                continue
            inner = pkt[VXLAN].payload
            if not (inner.haslayer(Ether) and _echo_request(inner, dst)):
                continue
            outer = (
                pkt[IP].dst,
                pkt[UDP].dport,
                pkt[VXLAN].vni,
                inner[Ether].dst,
            )
            if outer != (R2_VTEP, 4789, L3VNI, R2_RMAC):
                return "an echo request to {} left r3 as {}, want {}".format(
                    dst, outer, (R2_VTEP, 4789, L3VNI, R2_RMAC)
                )
            encapsulated += 1
        if not encapsulated:
            return "no echo request to {} left r3 in VXLAN: {}".format(
                dst, [pkt.summary() for pkt in packets]
            )
        logger.info("r3 sent %d echo requests to %s in VXLAN", encapsulated, dst)
    return None


def test_gateway_ip_l3vni_datapath():
    """
    r3 pings the type-5 prefixes in vrf-blue. The echo requests must leave
    r3 over the underlay in VXLAN with the L3VNI, to r2's VTEP address and
    router MAC, since r2 is where h2's host route goes, and none may leave
    unencapsulated.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r3.cmd_raises(
        "ip addr add {}/32 dev {}\nip -6 addr add {}/128 dev {} nodad".format(
            R3_VRF_ADDR["ip"], VRF, R3_VRF_ADDR["ipv6"], VRF
        )
    )
    pcap = os.path.join(tgen.logdir, "r3", "r3-eth0-pings.pcap")
    try:
        # Packets only go out once r3 resolved the type-5 routes: retry
        # rather than depend on when that happened.
        _, result = topotest.run_and_expect(
            lambda: _check_encapsulated(_capture_pings(tgen, pcap)),
            None,
            count=15,
            wait=1,
        )
    finally:
        r3.cmd(
            "ip addr del {}/32 dev {}; ip -6 addr del {}/128 dev {}".format(
                R3_VRF_ADDR["ip"], VRF, R3_VRF_ADDR["ipv6"], VRF
            )
        )
    assert result is None, "r3: {}".format(result)


def test_gateway_ip_not_resolved_through_gateway_ip():
    """
    10.20.0.50 resolves through h2 on r3, so its host route is installed over
    the L3VNI SVI. It comes from a type-5 route with gateway IP, which must
    not resolve the gateway of 100.0.0.22/32.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    for afi, _, gateway, _, via, _ in ROUTES:
        _expect(
            partial(
                _check_gateway_route,
                r3,
                afi,
                _host_prefix(afi, via),
                gateway,
                L3VNI_SVI,
            ),
            "r3",
        )

    # Give a wrong resolution a moment to happen before checking.
    time.sleep(2)
    for afi, _, _, _, _, via_prefix in ROUTES:
        result = _check_gateway_route_invalid(r3, afi, via_prefix)
        assert result is None, "r3: {}".format(result)


def test_gateway_ip_l3vni_host_withdrawn():
    """
    When r2 forgets h2, r3 loses h2's host route and must stop using the
    type-5 routes. When r2 learns h2 again, r3 must use them again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    _forget_host(tgen)

    for afi, _, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_no_host_route, r3, afi, _host_prefix(afi, gateway)),
            "r3 still has a host route to {}".format(gateway),
        )
    _expect_unresolved(tgen)

    _learn_host(tgen)
    for afi, _, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_host_route, r3, afi, _host_prefix(afi, gateway)),
            "r3 has no host route to {}".format(gateway),
        )
    _expect_resolved(tgen)


def test_gateway_ip_l3vni_resolve_toggled():
    """
    Removing "enable-resolve-overlay-index" from r3 while it has h2's host
    route makes it stop using the type-5 routes. Configuring it again must
    resolve the gateways again: r3 has no EVI that would reach them.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _resolve_overlay_index(enable):
        r3.vtysh_cmd(
            """
configure terminal
 router bgp {}
  address-family l2vpn evpn
   {}enable-resolve-overlay-index
""".format(
                ASN["r3"], "" if enable else "no "
            )
        )

    _resolve_overlay_index(False)
    _expect_unresolved(tgen)
    for afi, _, gateway, _, _, _ in ROUTES:
        result = _check_host_route(r3, afi, _host_prefix(afi, gateway))
        assert result is None, "r3 lost its host route to {}: {}".format(
            gateway, result
        )

    _resolve_overlay_index(True)
    _expect_resolved(tgen)


def test_gateway_ip_l3vni_prefix_host_route():
    """
    Stop r2 from advertising h2 with the L3VNI, so that r3 loses the host
    route, then have r2 export h2's host route as a type-5 route without
    gateway IP. That host route must resolve the gateway on r3, until r2
    withdraws it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    r2.vtysh_cmd(
        """
configure terminal
 vrf {1}
  no vni {0}
  vni {0} prefix-routes-only
""".format(
            L3VNI, VRF
        )
    )
    # Have r2 learn h2 again, so that its type-2 routes no longer carry the
    # L3VNI.
    _forget_host(tgen)
    _learn_host(tgen)

    for afi, _, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_no_host_route, r3, afi, _host_prefix(afi, gateway)),
            "r3 still has a host route to {}".format(gateway),
        )
    _expect_unresolved(tgen)

    def _static(add):
        cmds = ["configure terminal", " vrf {}".format(VRF)]
        for afi, _, gateway, _, _, _ in ROUTES:
            cmds.append(
                "  {}{} route {} {}".format(
                    "" if add else "no ",
                    afi,
                    _host_prefix(afi, gateway),
                    L2VNI_SVI,
                )
            )
        r2.vtysh_cmd("\n".join(cmds))

    _static(True)
    for afi, _, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_host_route, r3, afi, _host_prefix(afi, gateway)),
            "r3 has no type-5 host route to {}".format(gateway),
        )
    _expect_resolved(tgen)

    _static(False)
    for afi, _, gateway, _, _, _ in ROUTES:
        _expect(
            partial(_check_no_host_route, r3, afi, _host_prefix(afi, gateway)),
            "r3 still has a host route to {}".format(gateway),
        )
    _expect_unresolved(tgen)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
