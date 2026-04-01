#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_suppress_fib.py
#
# Copyright (c) 2019 by
#

"""
"""

import os
import sys
import json
import pytest
from functools import partial
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assertmsg = '"r3" JSON output mismatches'
    assert result is None, assertmsg

    json_file = "{}/r3/v4_route2.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 50.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, assertmsg

    json_file = "{}/r3/v4_route3.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 60.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, assertmsg


def test_bgp_better_admin_won():
    "A better Admin distance protocol may come along and knock us out"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf\nip route 40.0.0.0/8 10.0.0.10")

    json_file = "{}/r2/v4_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    logger.info(expected)
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 40.0.0.0 json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assertmsg = '"r2" static route did not take over'
    assert result is None, assertmsg

    r3 = tgen.gears["r3"]

    json_file = "{}/r3/v4_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 40.0.0.0 json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r3" route to 40.0.0.0 should have been lost'
    assert result is None, assertmsg

    r2.vtysh_cmd("conf\nno ip route 40.0.0.0/8 10.0.0.10")

    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r3" route to 40.0.0.0 did not come back'
    assert result is None, assertmsg


def test_bgp_allow_as_in():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    config_file = "{}/r2/bgpd.allowas_in.conf".format(CWD)
    r2.run("vtysh -f {}".format(config_file))

    json_file = "{}/r2/bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assertmsg = '"r2" static redistribution failed into bgp'
    assert result is None, assertmsg

    r1 = tgen.gears["r1"]

    json_file = "{}/r1/bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" 192.168.1.1/32 route should have arrived'
    assert result is None, assertmsg

    r2.vtysh_cmd("conf\nno ip route 192.168.1.1/32 10.0.0.10")

    json_file = "{}/r2/no_bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r2" 192.168.1.1/32 route should be gone'
    assert result is None, assertmsg


def test_local_vs_non_local():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def check_no_fib_pending():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 uni 60.0.0.0/24 json"))
        paths = output.get("paths", [])
        return all("fibPending" not in path for path in paths)

    _, result = topotest.run_and_expect(check_no_fib_pending, True, count=20, wait=1)
    assert result is True, "Route 60.0.0.0/24 should not have fibPending"


def test_ip_protocol_any_fib_filter():
    #    "Filtered route of source protocol any should not get installed in fib"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf\nno ip protocol bgp")
    r2.vtysh_cmd("conf\nip protocol any route-map LIMIT")
    test_bgp_route()


def test_bgp_suppress_fib_adv_delay():
    """Test configurable advertisement delay for suppress-fib-pending"""

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Verify default: suppress-fib-pending is already configured without
    # explicit delay, so running-config should show bare command
    output = r2.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending" in output
    assert "bgp suppress-fib-pending 1000" not in output, \
        "Default delay should not appear in running-config"

    # Wait for peers to be established before testing delay changes
    def _check_peers_established():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        peers = output.get("ipv4Unicast", {}).get("peers", {})
        for peer_info in peers.values():
            if peer_info.get("state") != "Established":
                return False
        return True

    _, result = topotest.run_and_expect(_check_peers_established, True,
                                        count=30, wait=1)
    assert result is True, "Peers should be established before delay test"

    # Record peer uptime before delay change
    output = json.loads(r2.vtysh_cmd("show bgp summary json"))
    peers_before = output.get("ipv4Unicast", {}).get("peers", {})
    pfx_rcvd_before = {
        peer: info.get("pfxRcd", 0) for peer, info in peers_before.items()
    }

    # Change delay while suppress-fib is already enabled (delay-only change)
    r2.vtysh_cmd("conf\nrouter bgp 2\nbgp suppress-fib-pending 50")
    output = r2.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending 50" in output, \
        "Custom delay should appear in running-config"

    # Verify peers were NOT reset — they should still be Established
    # with the same prefix count (no session flap)
    output = json.loads(r2.vtysh_cmd("show bgp summary json"))
    peers_after = output.get("ipv4Unicast", {}).get("peers", {})
    for peer, info in peers_after.items():
        assert info.get("state") == "Established", \
            "Peer {} should remain Established after delay-only change".format(peer)
        assert info.get("pfxRcd", 0) == pfx_rcvd_before.get(peer, 0), \
            "Peer {} prefix count should not change on delay-only update".format(peer)

    # Change delay to 0 (no batching) — still delay-only, no reset
    r2.vtysh_cmd("conf\nrouter bgp 2\nbgp suppress-fib-pending 0")
    output = r2.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending 0" in output, \
        "Zero delay should appear in running-config"

    output = json.loads(r2.vtysh_cmd("show bgp summary json"))
    peers_after = output.get("ipv4Unicast", {}).get("peers", {})
    for peer, info in peers_after.items():
        assert info.get("state") == "Established", \
            "Peer {} should remain Established after delay change to 0".format(peer)

    # Change delay to >1000ms — validates extended range up to 10000
    r2.vtysh_cmd("conf\nrouter bgp 2\nbgp suppress-fib-pending 5000")
    output = r2.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending 5000" in output, \
        "Extended delay (5000ms) should appear in running-config"

    output = json.loads(r2.vtysh_cmd("show bgp summary json"))
    peers_after = output.get("ipv4Unicast", {}).get("peers", {})
    for peer, info in peers_after.items():
        assert info.get("state") == "Established", \
            "Peer {} should remain Established after delay change to 5000".format(peer)

    # Restore default delay (no explicit value)
    r2.vtysh_cmd("conf\nrouter bgp 2\nbgp suppress-fib-pending")
    output = r2.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending" in output
    assert "bgp suppress-fib-pending 1000" not in output, \
        "Default delay should not appear after restore"

    # Verify routes still work after delay changes
    r3 = tgen.gears["r3"]
    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Routes should still be present after delay changes"


def test_bgp_suppress_fib_adv_delay_global():
    """Test configurable advertisement delay at global (CONFIG_NODE) level"""

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Enable global suppress-fib-pending with custom delay
    r1.vtysh_cmd("conf\nbgp suppress-fib-pending 100")
    output = r1.vtysh_cmd("show running-config")
    assert "bgp suppress-fib-pending 100" in output, \
        "Global custom delay should appear in running-config"

    # Disable global suppress-fib-pending
    r1.vtysh_cmd("conf\nno bgp suppress-fib-pending")
    output = r1.vtysh_cmd("show running-config")
    # After 'no', the command should not appear at global level
    lines = output.split("\n")
    global_lines = [l for l in lines if l.strip() == "bgp suppress-fib-pending"
                    or "bgp suppress-fib-pending" in l and not l.startswith(" ")]
    # Filter out per-instance lines (indented with space)
    assert not any(not l.startswith(" ") and "bgp suppress-fib-pending" in l
                   for l in lines), \
        "Global suppress-fib-pending should be removed after 'no'"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
