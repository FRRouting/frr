#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_overlay_index_gateway_irb.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Google LLC
#

"""
test_bgp_evpn_overlay_index_gateway_irb.py: Resolve the gateway IP overlay
index (RFC 9136) of an EVPN type-5 route in a symmetric IRB fabric.

                        +------+
                        |  r1  |  exports 100.0.0.21/32 and 100::21/128
                        +--+---+  as type-5 routes with gateway IP h2
                           |
          s1  -------------+-------------
                   |               |
                +--+---+        +--+---+
                |  r2  |        |  r3  |
                +--+---+        +------+
                   |
                +--+---+
                |  h2  |  10.20.0.5, 2001:db8:20::5
                +------+

r1, r2 and r3 are VTEPs sharing L2VNI 100 (br100, 10.20.0.0/24) and L3VNI
1000 in vrf-blue. r1 and r3 are in AS 65000, r2 in AS 65002: r2 gets the
type-5 routes over eBGP, r3 over iBGP. h2 is attached to r2. r1 exports a
route whose nexthop is h2 as an EVPN type-5 route carrying h2's address as
gateway IP. r2 and r3 have "enable-resolve-overlay-index".

- r2 learns h2 locally: the gateway's MAC/IP is a local type-2 route and
  the gateway resolves over the L2VNI SVI.
- r3 learns h2 from r2's type-2 route, which carries the L3VNI, so r3 has a
  host route to h2 over the L3VNI SVI (symmetric IRB) and the gateway
  resolves over that SVI. Once r2 stops advertising the L3VNI with its
  type-2 routes, the gateway resolves over the L2VNI SVI on r3 as well.

Both must accept the type-5 route and install it through h2, also when
"enable-resolve-overlay-index" is configured after the routes exist.
"""

import os
import platform
import sys
import time
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

LEAVES = ["r1", "r2", "r3"]
ASN = {"r1": 65000, "r2": 65002, "r3": 65000}
VRF = "vrf-blue"
L2VNI_SVI = "br100"
L3VNI_SVI = "br1000"
HOST_MAC = "1a:2b:3c:4d:5e:05"
# (afi, prefix exported by r1, gateway IP = h2, r2's SVI address)
ROUTES = [
    ("ip", "100.0.0.21/32", "10.20.0.5", "10.20.0.2"),
    ("ipv6", "100::21/128", "2001:db8:20::5", "2001:db8:20::2"),
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
ip link add br100 address 52:54:00:00:0{n}:64 type bridge stp_state 0
ip link set dev br100 master {vrf}
ip addr add 10.20.0.{n}/24 dev br100
ip -6 addr add 2001:db8:20::{n}/64 dev br100 nodad
ip link add vxlan100 type vxlan id 100 dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan100 master br100
ip link set dev br100 up
ip link set dev vxlan100 up
ip link add br1000 address 52:54:00:00:0{n}:e8 type bridge stp_state 0
ip link set dev br1000 master {vrf}
ip link add vxlan1000 type vxlan id 1000 dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan1000 master br1000
ip link set dev br1000 up
ip link set dev vxlan1000 up
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
""".format(
                vrf=VRF, n=idx
            )
        )

    # Keep the neighbor entries of r2 and h2 for each other reachable for
    # the whole test: an update of r2's entry for h2, such as one h2's ARP
    # or ND refresh causes, makes zebra send the local MAC/IP to bgpd again,
    # which would re-resolve the gateways behind the test's back.
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


def _learn_host(tgen):
    """
    Have h2 talk to r2 so that r2 learns h2's MAC and IPs as local
    neighbors and advertises them in type-2 routes.
    """
    h2 = tgen.net["h2"]
    for afi, _, _, r2_svi in ROUTES:
        ping = "ping" if afi == "ip" else "ping -6"
        h2.cmd("{} -c 3 -i 0.2 -W 1 {}".format(ping, r2_svi))


def _check_host_macip(router, ip, local, vni=100):
    "Check that ``router`` has an EVPN type-2 route for ``ip`` in ``vni``."
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route vni {} mac {} ip {} json".format(vni, HOST_MAC, ip),
        isjson=True,
    )
    paths = [path for paths in output.get("paths", []) for path in paths]
    if not paths:
        return "no type-2 route for {}".format(ip)
    if local and not any(path.get("local") for path in paths):
        return "type-2 route for {} is not local: {}".format(ip, paths)
    if not local and any(path.get("local") for path in paths):
        return "type-2 route for {} is local: {}".format(ip, paths)
    return None


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
    if any(path.get("valid") for path in output.get("paths", [])):
        return "BGP path for {} is still valid: {}".format(prefix, output)

    output = router.vtysh_cmd(
        "show {} route vrf {} {} json".format(afi, VRF, prefix), isjson=True
    )
    if output.get(prefix):
        return "{} is still installed: {}".format(prefix, output)
    return None


def _check_type5_received(router, prefix, gateway):
    """
    Check that ``router`` imported the type-5 route into vrf-blue with
    ``gateway`` as nexthop, which is where the gateway IP overlay index goes.
    """
    expected = {"paths": [{"nexthops": [{"ip": gateway}]}]}
    afi_bgp = "ipv4" if ":" not in prefix else "ipv6"
    return topotest.router_json_cmp(
        router,
        "show bgp vrf {} {} unicast {} json".format(VRF, afi_bgp, prefix),
        expected,
    )


def test_bgp_convergence():
    "Wait for the EVPN sessions and for r2 to learn h2."
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

    def _learned():
        _learn_host(tgen)
        for _, _, gateway, _ in ROUTES:
            result = _check_host_macip(tgen.gears["r2"], gateway, local=True)
            if result is None:
                result = _check_host_macip(tgen.gears["r3"], gateway, local=False)
            if result is not None:
                return result
        return None

    _, result = topotest.run_and_expect(_learned, None, count=30, wait=1)
    assert result is None, "h2 was not learned in EVPN: {}".format(result)

    for rname in ["r2", "r3"]:
        for _, prefix, gateway, _ in ROUTES:
            test_func = partial(
                _check_type5_received, tgen.gears[rname], prefix, gateway
            )
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{} did not get {} with gateway IP {}: {}".format(
                rname, prefix, gateway, result
            )


def test_gateway_ip_local_host():
    """
    On r2 the gateway is a locally attached host: its MAC/IP is a local
    type-2 route. The type-5 route must resolve and be installed through
    the host on the L2VNI SVI.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    for afi, prefix, gateway, _ in ROUTES:
        test_func = partial(_check_gateway_route, r2, afi, prefix, gateway, L2VNI_SVI)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r2: {}".format(result)


def test_gateway_ip_symmetric_irb_host():
    """
    On r3 the gateway is a remote host reached through its symmetric IRB
    host route on the L3VNI SVI. The type-5 route must resolve and be
    installed through that host route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    for afi, prefix, gateway, _ in ROUTES:
        host_prefix = "{}/{}".format(gateway, 32 if afi == "ip" else 128)
        expected = {
            host_prefix: [
                {
                    "protocol": "bgp",
                    "installed": True,
                    "nexthops": [{"interfaceName": L3VNI_SVI, "active": True}],
                }
            ]
        }
        test_func = partial(
            topotest.router_json_cmp,
            r3,
            "show {} route vrf {} {} json".format(afi, VRF, host_prefix),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3 has no host route to {} on {}: {}".format(
            gateway, L3VNI_SVI, result
        )

        test_func = partial(_check_gateway_route, r3, afi, prefix, gateway, L3VNI_SVI)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3: {}".format(result)


def test_gateway_ip_resolve_enabled_late():
    """
    Removing "enable-resolve-overlay-index" from r2 and r3 makes them stop
    using the type-5 routes. Configuring it again, now that the routes and
    h2's MAC/IP routes exist, must resolve the gateways again, including
    r2's local one.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _resolve_overlay_index(router, enable):
        router.vtysh_cmd(
            """
configure terminal
 router bgp {}
  address-family l2vpn evpn
   {}enable-resolve-overlay-index
""".format(
                ASN[router.name], "" if enable else "no "
            )
        )

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Let r2's neighbor entries for h2 settle in REACHABLE first: their last
    # state change sends the local MAC/IP routes again (see setup_module()).
    def _neighbors_reachable():
        for _, _, gateway, _ in ROUTES:
            neigh = tgen.net["r2"].cmd(
                "ip neigh show {} dev {}".format(gateway, L2VNI_SVI)
            )
            if "REACHABLE" not in neigh:
                return "{}: {}".format(gateway, neigh.strip())
        return None

    _, result = topotest.run_and_expect(_neighbors_reachable, None, count=30, wait=1)
    assert result is None, "r2's neighbor entry for h2 is not reachable: {}".format(
        result
    )
    # ... and give zebra and bgpd time to process that last update.
    time.sleep(2)

    for router in [r2, r3]:
        _resolve_overlay_index(router, False)

    for router in [r2, r3]:
        for afi, prefix, _, _ in ROUTES:
            test_func = partial(_check_gateway_route_invalid, router, afi, prefix)
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{}: {}".format(router.name, result)

    for router in [r2, r3]:
        _resolve_overlay_index(router, True)

    for router, ifname in [(r2, L2VNI_SVI), (r3, L3VNI_SVI)]:
        for afi, prefix, gateway, _ in ROUTES:
            test_func = partial(
                _check_gateway_route, router, afi, prefix, gateway, ifname
            )
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{}: {}".format(router.name, result)


def test_gateway_ip_host_withdrawn():
    """
    When r2 forgets h2, the gateway is no longer a known host on r2 or on r3
    and both must stop using the type-5 routes. When r2 learns h2 again,
    both must use them again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    for _, _, gateway, _ in ROUTES:
        tgen.net["r2"].cmd_raises("ip neigh del {} dev {}".format(gateway, L2VNI_SVI))

    for router in [r2, r3]:
        for afi, prefix, _, _ in ROUTES:
            test_func = partial(_check_gateway_route_invalid, router, afi, prefix)
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{}: {}".format(router.name, result)

    def _relearned():
        _learn_host(tgen)
        for _, _, gateway, _ in ROUTES:
            result = _check_host_macip(r2, gateway, local=True)
            if result is not None:
                return result
        return None

    _, result = topotest.run_and_expect(_relearned, None, count=30, wait=1)
    assert result is None, "r2 did not learn h2 again: {}".format(result)

    for router, ifname in [(r2, L2VNI_SVI), (r3, L3VNI_SVI)]:
        for afi, prefix, gateway, _ in ROUTES:
            test_func = partial(
                _check_gateway_route, router, afi, prefix, gateway, ifname
            )
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{}: {}".format(router.name, result)


def test_gateway_ip_known_in_another_evi():
    """
    Over the L3VNI SVI, a MAC/IP route in any EVI of the VRF resolves the
    gateway. Have r2 advertise h2's addresses in a second L2VNI, 200, and
    then take r3's VNI 200 out of vrf-blue: VNI 100 still knows h2, so r3
    must keep using the type-5 routes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    for n, rname in [(2, "r2"), (3, "r3")]:
        tgen.net[rname].cmd_raises(
            """
ip link add br200 address 52:54:00:00:0{n}:c8 type bridge stp_state 0
ip link set dev br200 master {vrf}
ip link add vxlan200 type vxlan id 200 dstport 4789 local 10.100.0.{n} nolearning
ip link set dev vxlan200 master br200
ip link set dev br200 up
ip link set dev vxlan200 up
""".format(
                vrf=VRF, n=n
            )
        )
        tgen.gears[rname].vtysh_cmd(
            """
configure terminal
 router bgp {}
  address-family l2vpn evpn
   vni 200
    route-target import 65000:200
    route-target export 65000:200
""".format(
                ASN[rname]
            )
        )

    # On r2, h2's MAC is a static entry on a port that only holds it, and
    # h2's addresses are permanent neighbors on VNI 200's SVI, so that r2
    # advertises them in VNI 200 as well.
    cmds = [
        "ip link add dummy200 type dummy",
        "ip link set dev dummy200 master br200",
        "ip link set dev dummy200 up",
        "bridge fdb replace {} dev dummy200 master static".format(HOST_MAC),
    ]
    for _, _, gateway, _ in ROUTES:
        cmds.append(
            "ip neigh replace {} lladdr {} dev br200 nud permanent".format(
                gateway, HOST_MAC
            )
        )
    tgen.net["r2"].cmd_raises("\n".join(cmds))

    def _known_in_vni_200():
        for _, _, gateway, _ in ROUTES:
            result = _check_host_macip(r3, gateway, local=False, vni=200)
            if result is not None:
                return result
        return None

    _, result = topotest.run_and_expect(_known_in_vni_200, None, count=30, wait=1)
    assert result is None, "r3 did not learn h2 in VNI 200: {}".format(result)

    for afi, prefix, gateway, _ in ROUTES:
        test_func = partial(_check_gateway_route, r3, afi, prefix, gateway, L3VNI_SVI)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3: {}".format(result)

    tgen.net["r3"].cmd_raises("ip link set dev br200 nomaster")

    def _left_vrf():
        output = r3.vtysh_cmd("show bgp l2vpn evpn vni 200")
        return None if "Tenant-Vrf: default" in output else output

    _, result = topotest.run_and_expect(_left_vrf, None, count=30, wait=1)
    assert result is None, "r3's VNI 200 did not leave {}: {}".format(VRF, result)

    # Nothing re-resolves a gateway that was wrongly unresolved, so give it
    # a moment to go wrong before checking.
    time.sleep(2)
    for afi, prefix, gateway, _ in ROUTES:
        result = _check_gateway_route(r3, afi, prefix, gateway, L3VNI_SVI)
        assert result is None, "r3: {}".format(result)

    for rname in ["r2", "r3"]:
        tgen.gears[rname].vtysh_cmd(
            """
configure terminal
 router bgp {}
  address-family l2vpn evpn
   no vni 200
""".format(
                ASN[rname]
            )
        )
        tgen.net[rname].cmd_raises(
            "ip link del vxlan200\nip link del br200"
            + ("\nip link del dummy200" if rname == "r2" else "")
        )

    for afi, prefix, gateway, _ in ROUTES:
        test_func = partial(_check_gateway_route, r3, afi, prefix, gateway, L3VNI_SVI)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3: {}".format(result)


def test_gateway_ip_l2vni_svi_remote_host():
    """
    Without symmetric IRB host routes the remote gateway resolves over the
    L2VNI SVI, as before: stop r2 from advertising h2 with the L3VNI and
    check that r3 then installs the type-5 routes through h2 on the L2VNI
    SVI.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
 vrf {}
  no vni 1000
  vni 1000 prefix-routes-only
""".format(
            VRF
        )
    )

    # Have r2 learn h2 again, so that its type-2 routes no longer carry the
    # L3VNI.
    for _, _, gateway, _ in ROUTES:
        tgen.net["r2"].cmd_raises("ip neigh del {} dev {}".format(gateway, L2VNI_SVI))

    def _relearned():
        _learn_host(tgen)
        for _, _, gateway, _ in ROUTES:
            result = _check_host_macip(r3, gateway, local=False)
            if result is not None:
                return result
        return None

    _, result = topotest.run_and_expect(_relearned, None, count=30, wait=1)
    assert result is None, "r3 did not learn h2 again: {}".format(result)

    for afi, prefix, gateway, _ in ROUTES:
        host_prefix = "{}/{}".format(gateway, 32 if afi == "ip" else 128)
        test_func = partial(
            topotest.router_json_cmp,
            r3,
            "show {} route vrf {} {} json".format(afi, VRF, host_prefix),
            {host_prefix: None},
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3 still has a host route to {}: {}".format(
            gateway, result
        )

        test_func = partial(_check_gateway_route, r3, afi, prefix, gateway, L2VNI_SVI)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r3: {}".format(result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
