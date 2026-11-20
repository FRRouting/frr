#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Demetrius Cassidy
#

"""
Test 6VPE and 6PE: IPv6 routes whose BGP nexthop is an IPv4-mapped IPv6
address are installed in the kernel and forward over IPv4 MPLS.

    vrf1                                               vrf1
  2001:db8:1::/64                                 2001:db8:3::/64
  172.16.1.0/24                                   172.16.3.0/24
      |                                                 |
   +--+--+   10.0.12.0/24   +-----+   10.0.23.0/24   +--+--+
   | r1  +------------------+ r2  +------------------+ r3  |
   |     +------------------+     |                  +-----+
   +--+--+  10.0.112.0/24   +-----+                 192.0.2.3
      |    192.0.2.1        192.0.2.2
      | 10.0.14.0/24
   +--+----+
   | peer1 | ExaBGP: 2001:db8:4::4/128 via ::ffff:10.0.14.4
   +-------+

IS-IS with segment routing carries the IPv4 loopbacks, over two equal-cost
links between r1 and r2. r1 and r3 peer over iBGP between their IPv4
loopbacks for VPNv4 and VPNv6. Their loopbacks have only an IPv4 address
configured, so bgpd advertises the VPNv6 routes with the IPv4-mapped
nexthop ::ffff:<loopback>, the form 6VPE peers send (RFC 4659), and each
PE starts zebra with --v6-with-v4-nexthops so that bgpd brings up the
IPv6 address families without a local IPv6 address.

peer1 is a directly connected 6PE router (RFC 4798) on another BGP
implementation. Over eBGP IPv6 labeled-unicast, it sends its link's
IPv4-mapped address as the nexthop, which resolves through a connected
route. FRR itself sends a link-local nexthop there instead.

test_zebra_6vpe_mapped_nexthop_inline.py runs the same checks with kernel
nexthop objects disabled, so that zebra installs the nexthops inline.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]

# The SR transport label towards each PE loopback: SRGB base plus index.
R1_TRANSPORT_LABEL = 16001
R3_TRANSPORT_LABEL = 16003
PEER1_LABEL = 100

PE_DAEMONS = [("zebra", "--v6-with-v4-nexthops"), "isisd", "bgpd"]


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    # r1-eth0, r2-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2-eth1, r3-eth0
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # One stub VRF link on each PE: r1-eth1, r3-eth1.
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])

    # The second, equal-cost r1-r2 link: r1-eth2, r2-eth2.
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # The 6PE link: r1-eth3.
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="10.0.14.4/24", defaultRoute="via 10.0.14.1"
    )
    switch.add_link(peer1)


def _prepare_pe(router):
    rname = router.name
    for cmd in [
        "ip link add vrf1 type vrf table 10",
        "ip link set vrf1 up",
        f"ip link set {rname}-eth1 master vrf1",
    ]:
        router.cmd_raises(cmd)


def _config(tgen, rname, nexthop_objects):
    "The router's frr.conf, with kernel nexthop objects disabled if asked."
    source = os.path.join(CWD, f"{rname}/frr.conf")
    if nexthop_objects:
        return source

    config = os.path.join(tgen.logdir, f"{rname}-inline.conf")
    with open(source, encoding="utf-8") as src, open(
        config, "w", encoding="utf-8"
    ) as dst:
        dst.write("no zebra nexthop kernel enable\n!\n")
        dst.write(src.read())
    return config


def setup_routers(mod, nexthop_objects):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    if not tgen.hasmpls:
        pytest.skip("MPLS not supported or disabled")

    tgen.nexthop_objects = nexthop_objects

    _prepare_pe(tgen.gears["r1"])
    _prepare_pe(tgen.gears["r3"])
    for rname, interfaces in [
        ("r1", ["r1-eth0", "r1-eth2"]),
        ("r2", ["r2-eth0", "r2-eth1", "r2-eth2"]),
        ("r3", ["r3-eth0"]),
    ]:
        for ifname in interfaces:
            tgen.gears[rname].cmd_raises(f"sysctl -w net.mpls.conf.{ifname}.input=1")

    # The PEs peer for IPv6 without a local IPv6 address: zebra tells bgpd
    # that the dataplane carries IPv6 routes over IPv4-mapped nexthops.
    for rname, router in tgen.routers().items():
        daemons = None if rname == "r2" else PE_DAEMONS
        router.load_frr_config(_config(tgen, rname, nexthop_objects), daemons=daemons)

    tgen.start_router()

    peer1 = tgen.gears["peer1"]
    peer1.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def setup_module(mod):
    setup_routers(mod, nexthop_objects=True)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _check_json(router, cmd, expected):
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, "{}: unexpected '{}':\n{}".format(router.name, cmd, result)


def _parse_hop(text):
    """
    One kernel nexthop, from 'ip route' or 'ip nexthop' text output. Only the
    outer label is kept: the transport label, or the 6PE explicit-null.
    """
    labels = re.search(r"encap mpls\s+(\S+)", text)
    gateway = re.search(r"\bvia (?:inet6 |inet )?(\S+)", text)
    dev = re.search(r"\bdev (\S+)", text)
    return {
        "gateway": gateway.group(1) if gateway else None,
        "dev": dev.group(1) if dev else None,
        "label": int(labels.group(1).split("/")[0]) if labels else None,
        "onlink": re.search(r"\bonlink\b", text) is not None,
    }


def _kernel_hops(router, family, prefix, vrf):
    "The route's nexthops in the kernel, or a string saying what is wrong."
    table = f"vrf {vrf}" if vrf else ""
    route = router.cmd(f"ip -{family} route show {table} {prefix}").strip()
    if not route:
        return f"no route to {prefix}"

    nhid = re.search(r"\bnhid (\d+)", route)
    tgen = get_topogen()
    if tgen.nexthop_objects != bool(nhid):
        return f"nexthop objects {tgen.nexthop_objects}, but route is: {route}"

    if not nhid:
        segments = route.split("nexthop ")[1:] or [route]
        return [_parse_hop(segment) for segment in segments]

    nexthop = router.cmd(f"ip nexthop show id {nhid.group(1)}")
    group = re.search(r"\bgroup (\S+)", nexthop)
    ids = (
        [member.split(",")[0] for member in group.group(1).split("/")] if group else []
    )
    if not ids:
        return [_parse_hop(nexthop)]
    return [_parse_hop(router.cmd(f"ip nexthop show id {nh_id}")) for nh_id in ids]


def _check_kernel_route(router, family, prefix, hops, vrf="vrf1"):
    """
    Check the kernel route's nexthops: a list of (gateway, dev, outer label).
    An IPv4-mapped gateway has no IPv6 route, so its nexthop must be onlink.
    """
    expected = sorted(
        (
            {
                "gateway": gateway,
                "dev": dev,
                "label": label,
                "onlink": gateway.startswith("::ffff:"),
            }
            for gateway, dev, label in hops
        ),
        key=lambda hop: hop["dev"],
    )

    def _kernel_route():
        found = _kernel_hops(router, family, prefix, vrf)
        if isinstance(found, str):
            return found
        found = sorted(found, key=lambda hop: hop["dev"] or "")
        if found != expected:
            return f"nexthops {found}, expected {expected}"
        return None

    _, result = topotest.run_and_expect(_kernel_route, None, count=60, wait=1)
    assert result is None, "{}: {} is not in the kernel:\n{}".format(
        router.name, prefix, result
    )


def _check_ping(router, family, source, destination):
    "Ping with a large payload: the labeled packet must still fit the link MTU."

    # Source from the VRF's own address. Kernels without the l3mdev check in
    # ip6_route_get_saddr() pick it from the nexthop interface, which is in
    # the default VRF.
    def _ping():
        output = router.cmd(
            f"ip vrf exec vrf1 ping -{family} -c 1 -w 1 -s 1400 -I {source} {destination}"
        )
        return " 0% packet loss" in output

    _, result = topotest.run_and_expect(_ping, True, count=30, wait=1)
    assert result, "{}: no reply from {}".format(router.name, destination)


def test_isis_sr_transport():
    "Each PE reaches the other PE's loopback through its SR label."
    tgen = get_topogen()

    for rname, peer, label in [
        ("r1", "192.0.2.3/32", R3_TRANSPORT_LABEL),
        ("r3", "192.0.2.1/32", R1_TRANSPORT_LABEL),
    ]:
        logger.info("Checking the IS-IS route to %s on %s", peer, rname)
        expected = {
            peer: [
                {
                    "protocol": "isis",
                    "installed": True,
                    "nexthops": [{"fib": True, "labels": [label]}],
                }
            ]
        }
        _check_json(tgen.gears[rname], f"show ip route {peer} json", expected)


def _check_bgp_nexthop(router, cmd, prefix, nexthop):
    expected = {
        "prefix": prefix,
        "paths": [{"valid": True, "nexthops": [{"ip": nexthop}]}],
    }
    _check_json(router, f"{cmd} {prefix} json", expected)


def test_bgp_vpnv6_mapped_nexthop():
    "Each PE receives the remote VPNv6 prefix with an IPv4-mapped nexthop."
    tgen = get_topogen()

    for rname, prefix, nexthop in [
        ("r1", "2001:db8:3::/64", "::ffff:192.0.2.3"),
        ("r3", "2001:db8:1::/64", "::ffff:192.0.2.1"),
    ]:
        _check_bgp_nexthop(
            tgen.gears[rname], "show bgp vrf vrf1 ipv6 unicast", prefix, nexthop
        )


def test_zebra_6vpe_route_installed():
    "Zebra resolves the mapped nexthop to onlink IPv6 nexthops and installs it."
    tgen = get_topogen()

    for rname, prefix, nexthop, resolved in [
        (
            "r1",
            "2001:db8:3::/64",
            "::ffff:192.0.2.3",
            [("::ffff:10.0.12.2", "r1-eth0"), ("::ffff:10.0.112.2", "r1-eth2")],
        ),
        (
            "r3",
            "2001:db8:1::/64",
            "::ffff:192.0.2.1",
            [("::ffff:10.0.23.2", "r3-eth0")],
        ),
    ]:
        logger.info("Checking zebra's route to %s on %s", prefix, rname)
        nexthops = [{"ip": nexthop, "afi": "ipv6", "recursive": True}]
        for gateway, interface in resolved:
            nexthops.append(
                {
                    "fib": True,
                    "ip": gateway,
                    "afi": "ipv6",
                    "interfaceName": interface,
                    "onLink": True,
                }
            )
        expected = {
            prefix: [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "installed": True,
                    "nexthops": nexthops,
                }
            ]
        }
        _check_json(
            tgen.gears[rname], f"show ipv6 route vrf vrf1 {prefix} json", expected
        )


def test_kernel_6vpe_route():
    "The VPNv6 route is in each PE's kernel VRF table, over every equal-cost link."
    tgen = get_topogen()

    _check_kernel_route(
        tgen.gears["r1"],
        6,
        "2001:db8:3::/64",
        [
            ("::ffff:10.0.12.2", "r1-eth0", R3_TRANSPORT_LABEL),
            ("::ffff:10.0.112.2", "r1-eth2", R3_TRANSPORT_LABEL),
        ],
    )
    _check_kernel_route(
        tgen.gears["r3"],
        6,
        "2001:db8:1::/64",
        [("::ffff:10.0.23.2", "r3-eth0", R1_TRANSPORT_LABEL)],
    )


def test_vpnv6_ping():
    "IPv6 traffic forwards VRF to VRF over the IPv4 SR-MPLS transport."
    tgen = get_topogen()

    _check_ping(tgen.gears["r1"], 6, "2001:db8:1::1", "2001:db8:3::1")


def test_vpnv4_ping():
    "VPNv4 over the same transport keeps forwarding."
    tgen = get_topogen()

    _check_kernel_route(
        tgen.gears["r1"],
        4,
        "172.16.3.0/24",
        [
            ("10.0.12.2", "r1-eth0", R3_TRANSPORT_LABEL),
            ("10.0.112.2", "r1-eth2", R3_TRANSPORT_LABEL),
        ],
    )
    _check_ping(tgen.gears["r1"], 4, "172.16.1.1", "172.16.3.1")


def test_6pe_connected_route():
    "A 6PE route whose mapped nexthop is directly connected is installed onlink."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    prefix = "2001:db8:4::4/128"

    _check_bgp_nexthop(r1, "show bgp ipv6 unicast", prefix, "::ffff:10.0.14.4")

    # zebra keeps the route's own nexthop free of the onlink flag, so that it
    # resolves the gateway again when the connected route changes; only the
    # kernel route is onlink.
    expected = {
        prefix: [
            {
                "protocol": "bgp",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "::ffff:10.0.14.4",
                        "afi": "ipv6",
                        "interfaceName": "r1-eth3",
                        "labels": [PEER1_LABEL],
                        "onLink": None,
                    }
                ],
            }
        ]
    }
    _check_json(r1, f"show ipv6 route {prefix} json", expected)
    _check_kernel_route(
        r1, 6, prefix, [("::ffff:10.0.14.4", "r1-eth3", PEER1_LABEL)], vrf=None
    )


def test_6pe_label_swap():
    """
    r1 passes peer1's 6PE route on to r3 with its own label. r1's label swap
    goes to peer1's IPv4 address, and r3 installs the route over the SR
    transport.
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    prefix = "2001:db8:4::4/128"

    _check_bgp_nexthop(r3, "show bgp ipv6 unicast", prefix, "::ffff:192.0.2.1")

    def _r1_label():
        output = json.loads(
            r3.vtysh_cmd(f"show bgp ipv6 labeled-unicast {prefix} json") or "{}"
        )
        for path in output.get("paths", []):
            if path.get("remoteLabels"):
                return path["remoteLabels"][0]
        return None

    _, label = topotest.run_and_expect_type(_r1_label, int, count=60, wait=1)
    assert isinstance(label, int), f"r3: no label from r1 for {prefix}"

    expected = {
        "inLabel": label,
        "installed": True,
        "nexthops": [
            {
                "outLabel": PEER1_LABEL,
                "installed": True,
                "nexthop": "10.0.14.4",
                "interface": "r1-eth3",
            }
        ],
    }
    _check_json(r1, f"show mpls table {label} json", expected)

    def _kernel_lsp():
        output = r1.cmd(f"ip -f mpls route show {label}")
        if "via inet 10.0.14.4 dev r1-eth3" not in output:
            return f"label {label}: {output}"
        return None

    _, result = topotest.run_and_expect(_kernel_lsp, None, count=30, wait=1)
    assert result is None, f"r1: kernel label swap is wrong: {result}"

    _check_kernel_route(
        r3,
        6,
        prefix,
        [("::ffff:10.0.23.2", "r3-eth0", R1_TRANSPORT_LABEL)],
        vrf=None,
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
