#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_srv6_dualstack_l3vpn.py: dual-stack SRv6 L3VPN topology test (OSPF PE-CE).

Topology:
    Core network (r1-r6) with ISIS and SRv6:

                                                  SRv6 L3VPN Topology
                                            iBGP AS 65000 · ISIS 49.0001
                                             (all IPv6 under 2001:)

+--------------------------------------------+    +--------------------------------------------+
| r7 CE  Client1                             |    | r9 CE  Client2                             |
| lo: 192.168.11.1/32   dead:11::1/128       |    | lo: 192.168.21.1/32   dead:21::1/128       |
| eth0: 172.16.11.1/24  cafe:11::1/64        |    | eth0: 172.16.21.1/24  cafe:21::1/64        |
+-----------------------+--------------------+    +-----------------------+--------------------+
            [C1]        |VPN1 Client1                          [C2]       | VPN2 Client2
                        +-------------------------------------------------+
                        |
  +-----------------------+-----------------+      +----------------------------+      +-----------------------------------------+
  | r3 PE  lo: db8:33::3/64                 |======| r1 P  lo: db8:11::1/64     |======| r2 P  lo: db8:22::2/64                  |
  | Loc FRR3: dead:30::/64                  |      | eth0: db8:12::1/64  →r2    |      | eth0: db8:12::2/64  →r1                 |
  | eth0: db8:31::3/64  →r1                 |      | eth1: db8:31::1/64  →r3    |      | eth1: db8:26::2/64  →r6                 |
  | eth1: db8:34::3/64  →r4                 |      | eth2: db8:15::1/64  →r5    |      +-----------------------+-----------------+
  | eth2: 172.16.11.3/24  cafe:11::3/64 [C1]|      +--------------+-------------+                              |
  | eth3: 172.16.21.3/24  cafe:21::3/64 [C2]|                     |                                            |
  +-----------------------+-----------------+                     |                                            |
             db8:34::/64  |                          db8:15::/64  |                            db8:26::/64     |
                          |                                       |                                            |
  +-----------------------+--------------------+      +--------------+-------------+      +-----------------------+-----------------+
  | r4 P  (no loopback)                        |======| r5 P  (no loopback)        |======| r6 PE  lo: db8:66::6/64                 |
  | eth0: db8:45::4/64  →r5                    |      | eth0: db8:45::5/64  →r4    |      | Loc FRR6: dead:60::/64                  |
  | eth1: db8:34::4/64  →r3                    |      | eth1: db8:56::5/64  →r6    |      | eth0: db8:26::6/64  →r2                 |
  +--------------------------------------------+      | eth2: db8:15::5/64  →r1    |      | eth1: db8:56::6/64  →r5                 |
                                                      +----------------------------+      | eth2: 172.16.12.6/24  cafe:12::6/64 [C1]|
                                                                                          | eth3: 172.16.22.6/24  cafe:22::6/64 [C2]|
                                                                                          +-------------------------+---------------+
                                                                                                                    |
                                                              +-----------------------------------------------------+
                                                              |                                                     |
                                      +-----------------------+--------------------+        +-----------------------+-----------------+
                                      |  r8 CE  Client1                            |        |  r10 CE  Client2                        |
                                      | lo: 192.168.12.1/32  dead:12::1/128        |        |  lo: 192.168.22.1/32  dead:22::1/128    |
                                      | eth0: 172.16.12.1/24  cafe:12::1/64        |        |  eth0: 172.16.22.1/24  cafe:22::1/64    |
                                      +--------------------------------------------+        +-----------------------------------------+
                                                  [C1]                                                  [C2]



    PE routers: r3, r6 (with VRFs Client1 and Client2)
    CE routers:
      - Client1: r7 (connects to r3), r8 (connects to r6)
      - Client2: r9 (connects to r3), r10 (connects to r6)

    Tests SRv6-based L3VPN with BGP VPNv4/VPNv6 over ISIS core.
"""

import os
import re
import sys
import pytest
import json

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib import topotest
from lib.checkping import check_ping

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.isisd,
    pytest.mark.ospfd,
    pytest.mark.ospf6d,
]


def build_topo(tgen):
    "Build function for SRv6 L3VPN topology"

    # Add all routers (r1-r6: core, r7-r8: Client1 CEs, r9-r10: Client2 CEs)
    for routern in range(1, 11):
        tgen.add_router("r{}".format(routern))

    # Core network links (based on SRv6 lab topology)
    # Link order is critical - it determines interface numbering (eth0, eth1, etc.)

    # r1 - r2 link (r1-eth0, r2-eth0)
    sw = tgen.add_switch("sw12")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])

    # r1 - r3 link (r1-eth1, r3-eth0)
    sw = tgen.add_switch("sw13")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])

    # r2 - r6 link (r2-eth1, r6-eth0)
    sw = tgen.add_switch("sw26")
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r6"])

    # r4 - r5 link (r4-eth0, r5-eth0) - MUST come before sw34 for correct r4 numbering
    sw = tgen.add_switch("sw45")
    sw.add_link(tgen.gears["r4"])
    sw.add_link(tgen.gears["r5"])

    # r3 - r4 link (r3-eth1, r4-eth1)
    sw = tgen.add_switch("sw34")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r4"])

    # r5 - r6 link (r5-eth1, r6-eth1)
    sw = tgen.add_switch("sw56")
    sw.add_link(tgen.gears["r5"])
    sw.add_link(tgen.gears["r6"])

    # r1 - r5 link (r1-eth2, r5-eth2)
    sw = tgen.add_switch("sw15")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r5"])

    # PE-CE links for VRF Client1
    # r3 - r7 link (r3-eth2, r7-eth0)
    sw = tgen.add_switch("sw37")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r7"])

    # r6 - r8 link (r6-eth2, r8-eth0)
    sw = tgen.add_switch("sw68")
    sw.add_link(tgen.gears["r6"])
    sw.add_link(tgen.gears["r8"])

    # PE-CE links for VRF Client2
    # r3 - r9 link (r3-eth3, r9-eth0)
    sw = tgen.add_switch("sw39")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r9"])

    # r6 - r10 link (r6-eth3, r10-eth0)
    sw = tgen.add_switch("sw610")
    sw.add_link(tgen.gears["r6"])
    sw.add_link(tgen.gears["r10"])


def setup_module(mod):
    "Sets up the pytest environment"

    # Check for minimum kernel version for SRv6 support
    result = required_linux_kernel_version("5.19")
    if result is not True:
        pytest.skip("Kernel requirements not met for SRv6")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Configure VRFs BEFORE loading configs (so zebra.conf can apply VRF interface settings)
    for rname in ["r3", "r6"]:
        router = router_list[rname]

        # Enable VRF strict mode
        router.run("sysctl -w net.vrf.strict_mode=1")

        # Create VRF devices
        router.run("ip link add Client1 type vrf table 1001")
        router.run("ip link set Client1 up")
        router.run("ip link add Client2 type vrf table 1002")
        router.run("ip link set Client2 up")

        # Enslave interfaces to VRFs BEFORE loading config
        if rname == "r3":
            router.run("ip link set r3-eth2 master Client1")
            router.run("ip link set r3-eth3 master Client2")
        elif rname == "r6":
            router.run("ip link set r6-eth2 master Client1")
            router.run("ip link set r6-eth3 master Client2")

    # Load configurations for all routers
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )

        # Load IS-IS only for the SRv6 core routers (r1-r6); CEs use OSPF only
        if rname in ["r1", "r2", "r3", "r4", "r5", "r6"]:
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )

        # Load BGP only for PE routers (r3, r6)
        if rname in ["r3", "r6"]:
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
            )

        # Load OSPF for CE routers (r7, r8, r9, r10)
        if rname in ["r7", "r8", "r9", "r10"]:
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
            )

    tgen.start_router()

    # Configure IP addresses on VRF interfaces using kernel commands
    # FRR doesn't apply addresses to pre-enslaved VRF interfaces from config
    for rname in ["r3", "r6"]:
        router = router_list[rname]

        if rname == "r3":
            # Configure r3-eth2 (Client1)
            router.run("ip addr add 172.16.11.3/24 dev r3-eth2")
            router.run("ip -6 addr add 2001:cafe:11::3/64 dev r3-eth2")
            # Configure r3-eth3 (Client2)
            router.run("ip addr add 172.16.21.3/24 dev r3-eth3")
            router.run("ip -6 addr add 2001:cafe:21::3/64 dev r3-eth3")
        elif rname == "r6":
            # Configure r6-eth2 (Client1)
            router.run("ip addr add 172.16.12.6/24 dev r6-eth2")
            router.run("ip -6 addr add 2001:cafe:12::6/64 dev r6-eth2")
            # Configure r6-eth3 (Client2)
            router.run("ip addr add 172.16.22.6/24 dev r6-eth3")
            router.run("ip -6 addr add 2001:cafe:22::6/64 dev r6-eth3")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_routers_up():
    "Check that all routers are up"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("All routers are up")


def _check_json(rname, cmd, expected, count=60, wait=1):
    """Poll ``cmd`` on ``rname`` until its JSON output contains ``expected``.

    ``expected`` is matched as a subset (topotest.json_cmp), so fixtures only
    need to spell out the keys that matter for the assertion.
    """
    tgen = get_topogen()
    router = tgen.gears[rname]

    def _cmp():
        output = json.loads(router.vtysh_cmd(cmd))
        return topotest.json_cmp(output, expected)

    logger.info("checking {} '{}'".format(rname, cmd))
    _, result = topotest.run_and_expect(_cmp, None, count=count, wait=wait)
    assert result is None, "{} '{}' did not converge:\n{}".format(rname, cmd, result)


def _assert_no_ping(name, dest_addr):
    """Assert a single ping from ``name`` to ``dest_addr`` does NOT succeed.

    ``check_ping`` only understands a "N% packet loss" statistics line, but a
    fully isolated destination (no route at all) makes ping bail out with
    "connect: Network is unreachable" and print no statistics.  Both that (no
    match) and a high packet loss mean "not connected".  Isolation is a
    structural property, so a single probe is enough -- we deliberately do NOT
    retry, unlike the positive connectivity checks.
    """
    tgen = get_topogen()
    # Append '|| true' so the (desired) ping failure exits 0 and does NOT surface
    # as a noisy 'proc failed' warning -- we parse the output ourselves to decide
    # pass/fail, and only dump it if the isolation assertion is violated.
    output = tgen.gears[name].run("ping {} -c 1 -w 1 2>&1 || true".format(dest_addr))
    match = re.search(r", (\d+)% packet loss", output)
    connected = match is not None and int(match.group(1)) <= 90
    assert not connected, "{} unexpectedly reached {}:\n{}".format(
        name, dest_addr, output
    )
    logger.info(
        "    OK: {} cannot reach {} (isolated as expected)".format(name, dest_addr)
    )


def _wait_for_ce_route(rname, dest_addr):
    """Block until ``rname`` has an INSTALLED route that reaches ``dest_addr``.

    A CE only learns how to reach the remote site via OSPF/OSPFv3 from its PE,
    which is not usable until the PE-CE adjacency forms and the routes install.
    We poll the RIB (``show ip[v6] route <addr> json``, a longest-match lookup
    that returns ``{}`` until a covering route exists) BEFORE pinging, and log
    that we are waiting for convergence -- otherwise the ping loop would spam
    misleading "Network is unreachable" errors while routing is still settling.

    Crucially we require the matched route to be both ``selected`` and
    ``installed``: a route can sit in zebra's RIB before it is pushed into the
    kernel FIB, and ``ping`` uses the FIB -- so gating on mere RIB presence is
    not enough to guarantee the ping will succeed.
    """
    afi = "ipv6" if ":" in dest_addr else "ip"
    cmd = "show {} route {} json".format(afi, dest_addr)
    tgen = get_topogen()
    router = tgen.gears[rname]

    def _have_route():
        output = json.loads(router.vtysh_cmd(cmd))
        for entries in output.values():
            for entry in entries:
                if entry.get("selected") and entry.get("installed"):
                    return None
        return "no installed route to {} yet".format(dest_addr)

    logger.info("waiting for {} to converge on a route to {}".format(rname, dest_addr))
    _, result = topotest.run_and_expect(_have_route, None, count=60, wait=1)
    assert (
        result is None
    ), "{} never installed a route to {} (OSPF not converged)".format(rname, dest_addr)
    logger.info(
        "{} has an installed route to {}; proceeding to ping".format(rname, dest_addr)
    )
    # The route is in the FIB, but give neighbor discovery (ARP/ND) a moment to
    # settle so the very first ping does not fail on an unresolved next-hop.
    topotest.sleep(2, "letting the dataplane settle before pinging")


def test_isis_srv6_underlay():
    "IS-IS core carries PE loopbacks and remote SRv6 locators (proves adjacency)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # If IS-IS adjacencies are up, each PE learns the other PE's loopback and
    # SRv6 locator as an IS-IS route across the core -- this is also what makes
    # the BGP session (update-source lo) and the SRv6 next-hops reachable.
    _check_json(
        "r3",
        "show ipv6 route json",
        {
            "2001:db8:66::/64": [{"protocol": "isis"}],
            "2001:dead:60::/64": [{"protocol": "isis"}],
        },
    )
    _check_json(
        "r6",
        "show ipv6 route json",
        {
            "2001:db8:33::/64": [{"protocol": "isis"}],
            "2001:dead:30::/64": [{"protocol": "isis"}],
        },
    )


def test_srv6_locators():
    "Verify SRv6 locators are configured and up on the PE routers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _check_json(
        "r3",
        "show segment-routing srv6 locator json",
        {
            "locators": [
                {"name": "FRR3", "prefix": "2001:dead:30::/64", "statusUp": True}
            ]
        },
    )
    _check_json(
        "r6",
        "show segment-routing srv6 locator json",
        {
            "locators": [
                {"name": "FRR6", "prefix": "2001:dead:60::/64", "statusUp": True}
            ]
        },
    )


def test_bgp_vpn_routes():
    "Verify VPNv4/VPNv6 routes are exchanged between the PEs under the right RD."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # r3 must receive r6's Client sites (Client1 -> r8, Client2 -> r10).
    _check_json(
        "r3",
        "show bgp ipv4 vpn json",
        {
            "routes": {
                "routeDistinguishers": {
                    "65000:1": {"172.16.12.0/24": [{"valid": True}]},
                    "65000:2": {"172.16.22.0/24": [{"valid": True}]},
                }
            }
        },
    )
    _check_json(
        "r3",
        "show bgp ipv6 vpn json",
        {
            "routes": {
                "routeDistinguishers": {
                    "65000:1": {"2001:cafe:12::/64": [{"valid": True}]},
                    "65000:2": {"2001:cafe:22::/64": [{"valid": True}]},
                }
            }
        },
    )

    # r6 must receive r3's Client sites (Client1 -> r7, Client2 -> r9).
    _check_json(
        "r6",
        "show bgp ipv4 vpn json",
        {
            "routes": {
                "routeDistinguishers": {
                    "65000:1": {"172.16.11.0/24": [{"valid": True}]},
                    "65000:2": {"172.16.21.0/24": [{"valid": True}]},
                }
            }
        },
    )
    _check_json(
        "r6",
        "show bgp ipv6 vpn json",
        {
            "routes": {
                "routeDistinguishers": {
                    "65000:1": {"2001:cafe:11::/64": [{"valid": True}]},
                    "65000:2": {"2001:cafe:21::/64": [{"valid": True}]},
                }
            }
        },
    )


def test_vrf_dataplane_srv6():
    "Remote VPN prefixes land in the VRF RIB via BGP with an SRv6 seg6 next-hop."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # An empty ``seg6`` dict only asserts the key is present (json_cmp subset),
    # so we prove the route is SRv6-encapsulated without pinning the exact SID.
    _check_json(
        "r3",
        "show ip route vrf Client1 json",
        {"172.16.12.0/24": [{"protocol": "bgp", "nexthops": [{"seg6": {}}]}]},
    )
    _check_json(
        "r3",
        "show ipv6 route vrf Client1 json",
        {"2001:cafe:12::/64": [{"protocol": "bgp", "nexthops": [{"seg6": {}}]}]},
    )
    _check_json(
        "r3",
        "show ip route vrf Client2 json",
        {"172.16.22.0/24": [{"protocol": "bgp", "nexthops": [{"seg6": {}}]}]},
    )
    _check_json(
        "r6",
        "show ip route vrf Client1 json",
        {"172.16.11.0/24": [{"protocol": "bgp", "nexthops": [{"seg6": {}}]}]},
    )
    _check_json(
        "r6",
        "show ipv6 route vrf Client1 json",
        {"2001:cafe:11::/64": [{"protocol": "bgp", "nexthops": [{"seg6": {}}]}]},
    )


def test_ce_connectivity_ipv4():
    "CE-to-CE IPv4 reachability within the same VRF, across the SRv6 core."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Client1: r7 -> r8 loopback; Client2: r9 -> r10 loopback.
    # Wait for the CE RIB to converge first, then ping (avoids misleading
    # "Network is unreachable" spam while OSPF is still forming).
    _wait_for_ce_route("r7", "192.168.12.1")
    check_ping("r7", "192.168.12.1", True, 20, 1)
    _wait_for_ce_route("r9", "192.168.22.1")
    check_ping("r9", "192.168.22.1", True, 20, 1)


def test_ce_connectivity_ipv6():
    "CE-to-CE IPv6 reachability within the same VRF, across the SRv6 core."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Client1: r7 -> r8 loopback; Client2: r9 -> r10 loopback.
    # Wait for the CE RIB to converge first, then ping.
    _wait_for_ce_route("r7", "2001:dead:12::1")
    check_ping("r7", "2001:dead:12::1", True, 20, 1)
    _wait_for_ce_route("r9", "2001:dead:22::1")
    check_ping("r9", "2001:dead:22::1", True, 20, 1)


def test_vrf_isolation():
    "Client1 and Client2 VRFs must stay isolated (no cross-VRF routes or ping)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # A Client1 CE must NOT reach a Client2 CE (different RT, separate VRF).
    _assert_no_ping("r7", "192.168.22.1")
    _assert_no_ping("r7", "2001:dead:22::1")

    # And Client2's prefixes must never appear in VRF Client1 on the PE.
    logger.info("checking no cross-VRF route leak of Client2 prefixes into Client1")
    r3 = tgen.gears["r3"]
    out4 = r3.vtysh_cmd("show ip route vrf Client1 json")
    assert "172.16.22." not in out4, "Client2 IPv4 route leaked into VRF Client1"
    out6 = r3.vtysh_cmd("show ipv6 route vrf Client1 json")
    assert "cafe:22" not in out6, "Client2 IPv6 route leaked into VRF Client1"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
