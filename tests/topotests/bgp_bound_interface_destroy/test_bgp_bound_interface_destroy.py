#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_bound_interface_destroy.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#

"""Exercise iBGP over an IPv6 VLAN between r1 and r2.

The numbered peers are directly connected over the VLAN, so bgpd binds
the session to that device. The loopback peers reach each other through
static routes over the same VLAN.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]

IFACE = "swp1.100"
R1_ADDR = "fd00:1::1"
R2_ADDR = "fd00:1::2"
R1_LO = "fd00:2::1"
R2_LO = "fd00:2::2"
PREFIX = "2001:db8:100::1/128"
HOLD_TIME = 15
PROMPT_TIMEOUT = 5


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="swp1")
    switch.add_link(tgen.gears["r2"], nodeif="swp1")


def _vlan_create_cmd(address):
    return (
        "ip link add link swp1 name {iface} type vlan id 100 && "
        "ip -6 addr add {address}/64 dev {iface} nodad && "
        "ip link set {iface} up".format(iface=IFACE, address=address)
    )


def setup_module(mod):
    # 1. Connect r1 and r2 through a shared switch.
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # 2. Create the VLAN subinterface and configure numbered IPv6 iBGP
    # on each router.
    for name, address in (("r1", R1_ADDR), ("r2", R2_ADDR)):
        router = tgen.gears[name]
        router.cmd_raises(_vlan_create_cmd(address))
        router.load_frr_config(
            os.path.join(CWD, name, "frr.conf"),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_MGMTD, None),
             (TopoRouter.RD_BGP, None)],
        )

    # 3. Start the routing daemons.
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _session(router, peer=R2_ADDR):
    return json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(peer)))[peer]


def _session_established(router, peer=R2_ADDR, *, before=None):
    """Check that the peer is established and optionally has not reset."""
    expected = {"bgpState": "Established"}
    if before is not None:
        for counter in ("connectionsEstablished", "connectionsDropped"):
            expected[counter] = before[counter]
    return topotest.json_cmp(_session(router, peer), expected)


def _ifindex(router):
    link = json.loads(router.cmd_raises(f"ip -j link show dev {IFACE}"))
    return link[0]["ifindex"]


def wait_until_ok(check, message, timeout):
    # run_and_expect expands waits shorter than 15 seconds to 60 seconds.
    # Use an explicit deadline to prove deletion resets well before hold time.
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        result = check()
        if result is None:
            return
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    pytest.fail("{}: {}".format(message, result))


def _nht_resolution(router, peer, ifindex=None, *, gateway=None):
    """Verify BGP and zebra agree on the peer's nexthop resolution."""
    bgp = {"valid": ifindex is not None}
    zebra = {"clientList": [{"protocol": "bgp"}]}
    if ifindex is None:
        zebra["unresolved"] = True
    else:
        nexthop = {"interfaceName": IFACE}
        if gateway is not None:
            nexthop["ip"] = gateway
        bgp["nexthops"] = [dict(nexthop, ifindex=ifindex)]
        zebra["nexthops"] = [dict(nexthop, interfaceIndex=ifindex, active=True)]

    result = topotest.router_json_cmp(
        router, f"show bgp nexthop {peer} json", {"ipv6": {peer: bgp}}
    )
    if result is not None:
        return f"BGP NHT for {peer}: {result}"

    result = topotest.router_json_cmp(
        router,
        f"show ipv6 nht {peer} json",
        {"default": {"ipv6": {peer: {"resolutions": [zebra]}}}},
    )
    if result is not None:
        return f"zebra NHT for {peer}: {result}"
    return None


def _link_local_route_installed(router, ifindex):
    path = json.loads(router.vtysh_cmd("show bgp ipv6 unicast {} json".format(PREFIX)))
    result = topotest.json_cmp(path, {"paths": [{
        "valid": True, "bestpath": {"overall": True},
        "nexthops": [{"scope": "link-local", "used": True}],
    }]})
    if result is not None:
        return result
    link_local = next(
        nh["ip"]
        for bgp_path in path["paths"]
        if bgp_path.get("bestpath", {}).get("overall")
        for nh in bgp_path["nexthops"]
        if nh.get("scope") == "link-local" and nh.get("used")
    )
    route = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(PREFIX)))
    return topotest.json_cmp(route, {PREFIX: [{
        "protocol": "bgp", "installed": True,
        "nexthops": [{"ip": link_local, "interfaceName": IFACE, "interfaceIndex": ifindex,
                      "active": True}],
    }]})


def _numbered_session_converged(router, ifindex):
    result = _session_established(router)
    if result is not None:
        return result
    result = _nht_resolution(router, R2_ADDR, ifindex)
    if result is not None:
        return result
    return _link_local_route_installed(router, ifindex)


@pytest.fixture
def topology():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def test_bound_vlan_delete_resets_session(topology):
    """Deleting the bound VLAN resets iBGP before the hold timer expires."""
    r1 = topology.gears["r1"]

    # 1. Wait for iBGP and the link-local route to converge. Record the
    # original ifindex, session counters, and negotiated hold time.
    old_index = _ifindex(r1)
    wait_until_ok(
        lambda: _numbered_session_converged(r1, old_index), "initial route convergence", 40
    )
    before = _session(r1)
    assert before["bgpTimerHoldTimeMsecs"] == HOLD_TIME * 1000

    def reset():
        peer = _session(r1)
        if (peer["connectionsDropped"] <= before["connectionsDropped"] or
                peer["bgpState"] == "Established"):
            return "session still in {}; last reset: {}".format(
                peer["bgpState"], peer.get("lastResetDueTo")
            )
        if peer.get("lastResetDueTo") != "Bound interface deleted":
            return "unexpected reset reason: {}".format(peer.get("lastResetDueTo"))
        rib = json.loads(r1.vtysh_cmd("show ipv6 route {} json".format(PREFIX)))
        if any(route["protocol"] == "bgp" for route in rib.get(PREFIX, [])):
            return "BGP route still present in the RIB"
        return _nht_resolution(r1, R2_ADDR)

    # 2. Delete the VLAN. Verify the session resets before hold expiry,
    # zebra withdraws the route, and the tracked peer nexthop is unresolved.
    r1.cmd_raises(f"ip link del {IFACE}")
    try:
        wait_until_ok(reset, "reset and withdrawal before recreation/hold expiry", PROMPT_TIMEOUT)
    finally:
        # 3. Recreate the VLAN subinterface with the same IPv6 address.
        r1.cmd_raises(_vlan_create_cmd(R1_ADDR))

    # 4. Verify that iBGP reconnects once, the peer nexthop resolves on the
    # new ifindex, and the installed route uses that ifindex.
    new_index = _ifindex(r1)
    assert new_index != old_index
    wait_until_ok(
        lambda: _numbered_session_converged(r1, new_index),
        "route recovery after reconnection",
        40,
    )
    after = _session(r1)
    assert after["connectionsDropped"] == before["connectionsDropped"] + 1
    assert after["connectionsEstablished"] == before["connectionsEstablished"] + 1


def _assert_session_preserved(router, before, peer=R2_ADDR):
    result = _session_established(router, peer, before=before)
    assert result is None, f"{router.name} session to {peer}: {result}"


def test_bound_vlan_down_keeps_session_until_hold_timer(topology):
    """A short flap preserves iBGP. A sustained outage expires its hold timer."""
    r1 = topology.gears["r1"]

    # 1. Wait for iBGP and the route to converge. Record the session
    # counters and the VLAN's ifindex before the flap.
    old_index = _ifindex(r1)
    wait_until_ok(
        lambda: _numbered_session_converged(r1, old_index), "initial route convergence", 40
    )
    before = _session(r1)
    assert before["bgpTimerHoldTimeMsecs"] == HOLD_TIME * 1000
    # Linux can remove the test's IPv6 address when the VLAN goes down.
    restore = f"ip link set {IFACE} up && ip -6 addr replace {R1_ADDR}/64 dev {IFACE} nodad"

    def withdrawn():
        paths = json.loads(r1.vtysh_cmd(
            "show bgp ipv6 unicast {} json".format(PREFIX)
        )).get("paths", [])
        if paths and not any(path.get("valid", False) for path in paths):
            return _nht_resolution(r1, R2_ADDR)
        return "link-down was not processed"

    # 2. Bring the VLAN down. Verify BGP marks the tracked peer nexthop
    # invalid and zebra reports it unresolved while iBGP stays established.
    r1.cmd_raises(f"ip link set {IFACE} down")
    try:
        wait_until_ok(withdrawn, "interface-down handling", PROMPT_TIMEOUT)
        _assert_session_preserved(r1, before)
    finally:
        # 3. Bring it back up and restore the configured IPv6 address.
        r1.cmd_raises(restore)

    # 4. Verify that the peer nexthop resolves again and the route is
    # reinstalled on the same ifindex. The session counters stay unchanged.
    wait_until_ok(
        lambda: _numbered_session_converged(r1, old_index), "route recovery after link-up", 30
    )
    assert _ifindex(r1) == old_index
    _assert_session_preserved(r1, before)

    def hold_expired():
        peer = _session(r1)
        drops = peer["connectionsDropped"] - before["connectionsDropped"]
        reason = peer.get("lastNotificationReason")
        if drops == 1 and reason == "Hold Timer Expired":
            return None
        return f'{peer["bgpState"]}, session drops: {drops}, last notification: {reason}'

    # 5. Bring the VLAN down again and leave it down until hold timer
    # expiry drops the session exactly once.
    r1.cmd_raises(f"ip link set {IFACE} down")
    try:
        wait_until_ok(hold_expired, "hold timer expiry while interface is down", HOLD_TIME + 5)
    finally:
        r1.cmd_raises(restore)


def test_unbound_loopback_session_survives_vlan_recreate(topology):
    """Loopback iBGP survives VLAN recreation and the peer nexthop resolves again."""
    r1, r2 = (topology.gears[name] for name in ("r1", "r2"))
    underlay_route = f"ip -6 route replace {R2_LO}/128 via {R2_ADDR} dev {IFACE} onlink"

    # 1. Configure loopback iBGP peers and static routes through the VLAN.
    for router, local, peer, gateway in (
        (r1, R1_LO, R2_LO, R2_ADDR),
        (r2, R2_LO, R1_LO, R1_ADDR),
    ):
        router.cmd_raises(
            f"ip -6 addr add {local}/128 dev lo nodad && "
            f"ip -6 route replace {peer}/128 via {gateway} dev {IFACE} onlink"
        )
        router.vtysh_cmd(
            f"configure terminal\nrouter bgp 65100\n"
            f"neighbor {peer} remote-as internal\n"
            f"neighbor {peer} update-source {local}\n"
            f"neighbor {peer} timers 1 90\n"
            f"address-family ipv6 unicast\nneighbor {peer} activate",
            raises=True,
        )

    def keepalive_after(count):
        peer = _session(r1, R2_LO)
        if (
            peer["bgpState"] == "Established"
            and peer["messageStats"]["keepalivesRecv"] > count
        ):
            return None
        return f'{peer["bgpState"]}: waiting for a loopback peer keepalive'

    # 2. Wait for both peers to establish and verify that BGP and zebra
    # resolve r2's loopback through the original VLAN ifindex on r1.
    wait_until_ok(lambda: _session_established(r1, R2_LO), "r1 loopback session", 40)
    wait_until_ok(lambda: _session_established(r2, R1_LO), "r2 loopback session", 40)
    old_index = _ifindex(r1)
    wait_until_ok(
        lambda: _nht_resolution(r1, R2_LO, old_index, gateway=R2_ADDR),
        "initial loopback resolution",
        PROMPT_TIMEOUT,
    )
    before_r1 = _session(r1, R2_LO)
    before_r2 = _session(r2, R1_LO)

    # 3. Delete r1's VLAN and verify the tracked loopback nexthop becomes
    # unresolved while both peers remain established.
    r1.cmd_raises(f"ip link del {IFACE}")
    try:
        wait_until_ok(
            lambda: _nht_resolution(r1, R2_LO),
            "loopback nexthop invalidation",
            PROMPT_TIMEOUT,
        )
        _assert_session_preserved(r1, before_r1, R2_LO)
        _assert_session_preserved(r2, before_r2, R1_LO)
        keepalives = _session(r1, R2_LO)["messageStats"]["keepalivesRecv"]
    finally:
        # 4. Recreate the VLAN and restore the static route that Linux
        # removed when its device was deleted.
        r1.cmd_raises(f"{_vlan_create_cmd(R1_ADDR)} && {underlay_route}")

    # 5. Verify that BGP and zebra resolve through the new ifindex and
    # the existing session resumes receiving keepalives.
    new_index = _ifindex(r1)
    assert new_index != old_index
    wait_until_ok(
        lambda: _nht_resolution(r1, R2_LO, new_index, gateway=R2_ADDR),
        "loopback resolution on new ifindex",
        PROMPT_TIMEOUT,
    )
    wait_until_ok(lambda: keepalive_after(keepalives), "loopback session recovery", PROMPT_TIMEOUT)
    _assert_session_preserved(r1, before_r1, R2_LO)
    _assert_session_preserved(r2, before_r2, R1_LO)


def test_bound_vlan_delete_resets_loopback_sourced_session(topology):
    """Deleting the VLAN resets a session bound to it but sourced from loopback.

    The neighbor address is inside the VLAN's connected prefix, so bgpd binds
    the socket to the VLAN. The loopback source address makes loopback, not the
    VLAN, the interface that owns the session's source address.
    """
    r1, r2 = (topology.gears[name] for name in ("r1", "r2"))
    underlay_route = f"ip -6 route replace {R2_LO}/128 via {R2_ADDR} dev {IFACE} onlink"

    # 1. Reuse the previous test's loopback and the existing VLAN addresses.
    # Replace the previous peerings so they cannot interfere with this session.
    for router in (r1, r2):
        for peer in json.loads(router.vtysh_cmd("show bgp neighbors json")):
            router.vtysh_cmd(
                f"configure terminal\nrouter bgp 65100\nno neighbor {peer}",
                raises=True,
            )
    # replace also permits running this test without the previous test.
    r1.cmd_raises(f"ip -6 addr replace {R1_LO}/128 dev lo nodad")
    r2.cmd_raises(
        f"ip -6 route replace {R1_LO}/128 via {R1_ADDR} dev {IFACE} onlink"
    )
    for router, peer, source in (
        (r1, R2_ADDR, R1_LO),
        (r2, R1_LO, R2_ADDR),
    ):
        router.vtysh_cmd(
            f"configure terminal\nrouter bgp 65100\n"
            f"neighbor {peer} remote-as internal\n"
            f"neighbor {peer} update-source {source}\n"
            f"neighbor {peer} timers 1 {HOLD_TIME}\n"
            f"neighbor {peer} timers connect 1\n"
            f"address-family ipv6 unicast\nneighbor {peer} activate",
            raises=True,
        )

    # Let r1 initiate so its outgoing socket binding is exercised consistently.
    r2.vtysh_cmd(
        f"configure terminal\nrouter bgp 65100\nneighbor {R1_LO} passive",
        raises=True,
    )

    # 2. Wait for the session and verify it is sourced from r1's loopback.
    wait_until_ok(lambda: _session_established(r1, R2_ADDR), "r1 session", 40)
    wait_until_ok(lambda: _session_established(r2, R1_LO), "r2 session", 40)
    before = _session(r1, R2_ADDR)
    assert before["hostLocal"] == R1_LO

    def reset():
        peer = _session(r1, R2_ADDR)
        if (
            peer["connectionsDropped"] <= before["connectionsDropped"]
            or peer["bgpState"] == "Established"
        ):
            return "session still in {}; last reset: {}".format(
                peer["bgpState"], peer.get("lastResetDueTo")
            )
        if peer.get("lastResetDueTo") != "Bound interface deleted":
            return "unexpected reset reason: {}".format(peer.get("lastResetDueTo"))
        return None

    # 3. Delete the VLAN and verify the session resets before hold expiry.
    r1.cmd_raises(f"ip link del {IFACE}")
    try:
        wait_until_ok(reset, "reset on bound interface deletion", PROMPT_TIMEOUT)
    finally:
        # 4. Recreate the VLAN and restore the underlay route to r2's loopback
        # that Linux removed with the device.
        r1.cmd_raises(f"{_vlan_create_cmd(R1_ADDR)} && {underlay_route}")

    # 5. Verify that the session reestablishes.
    wait_until_ok(lambda: _session_established(r1, R2_ADDR), "r1 session recovery", 40)
    wait_until_ok(lambda: _session_established(r2, R1_LO), "r2 session recovery", 40)
