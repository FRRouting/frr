#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test that IPv4 EVPN RT-2 routes learned over an IPv6 VTEP keep their IPv6
nexthop when leaked again with BGP import vrf.
"""

import functools
import os
import platform
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def build_topo(tgen):
    tgen.add_router("pe1")
    tgen.add_router("pe2")
    tgen.add_host("h2", "192.168.0.2/24", "via 192.168.0.254")

    switch = tgen.add_switch("s-pe1-pe2")
    switch.add_link(tgen.gears["pe1"], nodeif="eth-pe2")
    switch.add_link(tgen.gears["pe2"], nodeif="eth-pe1")

    switch = tgen.add_switch("s-h2-pe2")
    switch.add_link(tgen.gears["h2"], nodeif="eth-pe2")
    switch.add_link(tgen.gears["pe2"], nodeif="eth-h2")


def _run_cmds(node, commands):
    for command in commands:
        node.cmd_raises(command)


def _setup_pe(router, idx):
    vtep = f"2001:db8:12::{idx}"
    peer_if = "eth-pe2" if idx == 1 else "eth-pe1"

    commands = [
        "ip link add up vrf10 type vrf table 10",
        "ip link add up br10 type bridge",
        "ip link set br10 master vrf10",
        (
            f"ip link add up vni10 type vxlan id 10 local {vtep} "
            f"dev {peer_if} nolearning dstport 4789"
        ),
        "ip link set vni10 master br10",
        "bridge link set dev vni10 learning off",
        "ip link add up br100 type bridge",
        "ip link set br100 master vrf10",
        (
            f"ip link add up vni100 type vxlan id 100 local {vtep} "
            f"dev {peer_if} nolearning dstport 4789"
        ),
        "ip link set vni100 master br100",
        "bridge link set dev vni100 learning off",
        "ip address add 192.168.0.254/24 dev br100",
    ]

    if idx == 2:
        commands.extend(
            [
                "ip link set eth-h2 master br100",
                "bridge link set dev eth-h2 learning off",
                "bridge fdb add 02:00:00:00:00:02 dev eth-h2 master static sticky",
                "ip neigh add 192.168.0.2 lladdr 02:00:00:00:00:02 dev br100",
            ]
        )

    _run_cmds(router, commands)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(f'Skipping EVPN IPv6 VTEP test, kernel "{krel}" is too old')

    _run_cmds(
        tgen.gears["h2"],
        [
            "ip link set eth-pe2 down",
            "ip link set eth-pe2 address 02:00:00:00:00:02",
            "ip link set eth-pe2 up",
        ],
    )

    for idx in (1, 2):
        _setup_pe(tgen.gears[f"pe{idx}"], idx)

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_rt2_import_vrf_preserves_ipv6_nexthop():
    """
    pe1 imports pe2's RT-2 host route into vrf10, then leaks vrf10 into the
    default VRF. The leaked IPv4 route must keep pe2's IPv6 VTEP nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]

    step("Wait for pe2's RT-2 host route in pe1 vrf10")
    expected_vrf = {
        "192.168.0.2/32": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [{"ip": "2001:db8:12::2", "afi": "ipv6"}],
            }
        ]
    }
    test_func = functools.partial(
        topotest.router_json_cmp,
        pe1,
        "show ip route vrf vrf10 192.168.0.2/32 json",
        expected_vrf,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "pe1 vrf10 did not install the RT-2 route with IPv6 nexthop"

    step("Check the same RT-2 route after import vrf into pe1 default VRF")
    expected_default_bgp = {
        "paths": [
            {
                "valid": True,
                "nexthops": [{"ip": "2001:db8:12::2", "afi": "ipv6"}],
            }
        ]
    }
    test_func = functools.partial(
        topotest.router_json_cmp,
        pe1,
        "show bgp ipv4 unicast 192.168.0.2/32 json",
        expected_default_bgp,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "import vrf did not preserve the RT-2 IPv6 nexthop in BGP"

    expected_default_route = {
        "192.168.0.2/32": [
            {
                "protocol": "bgp",
                "selected": True,
                "nexthops": [{"ip": "2001:db8:12::2", "afi": "ipv6"}],
            }
        ]
    }
    test_func = functools.partial(
        topotest.router_json_cmp,
        pe1,
        "show ip route 192.168.0.2/32 json",
        expected_default_route,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "import vrf did not preserve the RT-2 IPv6 nexthop in zebra"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
