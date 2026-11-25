#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Cisco Systems, Inc.

"""Keep local, downstream PIM, and inherited OIF ownership independent.

Three packet peers surround r1: h1 shares the local IGMP receiver LAN,
h2 keeps another downstream output alive, and h3 is the RPF neighbor
toward the remote RP and source. One-shot PIM packets control downstream
join expiry without racing periodic joins from another FRR router.
"""

import functools
import json
import os
import socket
import struct
import sys

import pytest
from scapy.contrib.pim import (
    PIMv2GroupAddrs,
    PIMv2Hdr,
    PIMv2Hello,
    PIMv2HelloDRPriority,
    PIMv2HelloGenerationID,
    PIMv2HelloHoldtime,
    PIMv2JoinAddrs,
    PIMv2JoinPrune,
    PIMv2PruneAddrs,
)
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.pim import scapy_send_autorp_raw_packet
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]
RP = "10.0.0.1"
SOURCE = "10.0.0.2"
RECV_IF = "r1-eth0"


def build_topo(tgen):
    router = tgen.add_router("r1")
    for n in range(1, 4):
        host = tgen.add_host(f"h{n}", f"10.{n}.0.2/24", f"via 10.{n}.0.1")
        switch = tgen.add_switch(f"s{n}")
        switch.add_link(router)
        switch.add_link(host)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    tgen.gears["r1"].load_frr_config("frr.conf")
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _send(peer, payload, message_type=None):
    packet = (
        Ether(dst="01:00:5e:00:00:0d")
        / IP(src=f"10.{peer}.0.2", dst="224.0.0.13", ttl=1)
        / (PIMv2Hdr() if message_type is None else PIMv2Hdr(type=message_type))
        / payload
    )
    scapy_send_autorp_raw_packet(
        get_topogen(), f"h{peer}", f"h{peer}-eth0", bytes(packet).hex()
    )


def _expect(command, expected, count=30):
    check = functools.partial(
        topotest.router_json_cmp, get_topogen().gears["r1"], command, expected
    )
    _, result = topotest.run_and_expect(check, None, count=count, wait=1)
    assert result is None, result


@pytest.fixture(autouse=True)
def neighbors():
    tgen = get_topogen()
    # Independent groups let all scenarios run even when an earlier assertion
    # fails during baseline validation. Still stop if a daemon is unavailable.
    assert tgen.gears["r1"].check_router_running() == ""
    for n in range(1, 4):
        _send(
            n,
            PIMv2Hello(
                option=[
                    PIMv2HelloHoldtime(holdtime=600),
                    PIMv2HelloDRPriority(dr_priority=1),
                    PIMv2HelloGenerationID(generation_id=n),
                ]
            ),
        )
        _expect(
            "show ip pim neighbor json",
            {f"r1-eth{n - 1}": {f"10.{n}.0.2": {}}},
        )


def _jp(peer, group, source="*", prune=False, holdtime=600, rpt=False):
    address = PIMv2PruneAddrs if prune else PIMv2JoinAddrs
    entry = address(
        src_ip=RP if source == "*" else source,
        sparse=1,
        wildcard=int(source == "*"),
        rpt=int(source == "*" or rpt),
    )
    _send(
        peer,
        PIMv2JoinPrune(
            up_neighbor_ip=f"10.{peer}.0.1",
            holdtime=holdtime,
            jp_ips=[
                PIMv2GroupAddrs(
                    gaddr=group,
                    join_ips=[] if prune else [entry],
                    prune_ips=[entry] if prune else [],
                )
            ],
        ),
    )


def _static_group(group, add=True):
    get_topogen().gears["r1"].vtysh_cmd(
        f"configure terminal\ninterface {RECV_IF}\n"
        f"{'' if add else 'no '}ip igmp static-group {group}"
    )


def _channel(group, source, state, peer=1, count=30):
    _expect(
        "show ip pim join json",
        {f"r1-eth{peer - 1}": {group: {source: {"channelJoinName": state}}}},
        count=count,
    )


def _oif(group, source, origin, peer=1, igmp=False):
    _expect(
        "show ip mroute detail json",
        {
            group: {
                source: {
                    "installed": 1,
                    "iif": "r1-eth2",
                    "oil": {
                        f"r1-eth{peer - 1}": {
                            "origin": origin,
                            "protocolPim": True if "P" in origin else None,
                            "protocolIgmp": True if igmp else None,
                            "protocolInherited": True if "*" in origin else None,
                        }
                    },
                }
            }
        },
    )


def test_mixed_igmp_pim_membership():
    """Either owner may leave without removing the other owner's output."""
    group = "239.10.0.1"
    _jp(1, group)
    _channel(group, "*", "JOIN")
    _oif(group, "*", "P")
    _static_group(group)
    try:
        _oif(group, "*", "SP", igmp=True)
        _static_group(group, add=False)
        _oif(group, "*", "P")
        _static_group(group)
        _oif(group, "*", "SP", igmp=True)
        _jp(1, group, prune=True)
        _channel(group, "*", "NOINFO")
        _oif(group, "*", "S", igmp=True)
    finally:
        _static_group(group, add=False)


@pytest.mark.parametrize("local_receiver", [False, True])
def test_join_expiry(local_receiver):
    """Actual holdtime expiry releases PIM while preserving local membership."""
    group = "239.10.0.3" if local_receiver else "239.10.0.2"
    try:
        _jp(1, group, holdtime=30)
        _channel(group, "*", "JOIN")
        _oif(group, "*", "P")
        if local_receiver:
            _static_group(group)
            _oif(group, "*", "SP", igmp=True)
            _channel(group, "*", "NOINFO", count=60)
            _oif(group, "*", "S", igmp=True)
        else:

            def _expired():
                data = json.loads(
                    get_topogen().gears["r1"].vtysh_cmd("show ip pim join json")
                )
                return data.get(RECV_IF, {}).get(group)

            _, result = topotest.run_and_expect(_expired, None, count=60, wait=1)
            assert result is None, result
            _expect("show ip mroute detail json", {group: None})
    finally:
        if local_receiver:
            _static_group(group, add=False)


@pytest.mark.parametrize("direct_child", [False, True])
def test_inherited_output_after_parent_and_child_prune(direct_child):
    """Parent local membership keeps STAR across parent and child PIM prunes."""
    group = "239.10.0.4" if direct_child else "239.10.0.5"
    try:
        _jp(1, group)
        _channel(group, "*", "JOIN")
        _static_group(group)
        _oif(group, "*", "SP", igmp=True)
        if direct_child:
            _jp(1, group, SOURCE)
            _channel(group, SOURCE, "JOIN")
        _jp(2, group, SOURCE)
        _channel(group, SOURCE, "JOIN", peer=2)
        # Static (*,G) configuration also contributes the display letter S
        # to covered (S,G)s; only the parent owns GM, the child owns STAR.
        origin = "*SP" if direct_child else "*S"
        _oif(group, SOURCE, origin)

        # Only the parent's PIM join ends. Its local receiver still keeps
        # this interface in inherited_olist(S,G), including inherited-only OIFs.
        _jp(1, group, prune=True)
        _channel(group, "*", "NOINFO")
        _oif(group, SOURCE, origin)

        # A second output keeps the OIL nonempty; the router is not the RP.
        # Missing inheritance must not be hidden by the empty-OIL repair path.
        upstream = (
            get_topogen()
            .gears["r1"]
            .vtysh_cmd("show ip pim upstream json", isjson=True)[group][SOURCE]
        )
        assert upstream["keepaliveTimer"] != "--:--:--", upstream
        if direct_child:
            _jp(1, group, SOURCE, prune=True)
            _channel(group, SOURCE, "NOINFO")
            _oif(group, SOURCE, "*S")

            # The original join ET and keepalive defer channel deletion.
            channel = (
                get_topogen()
                .gears["r1"]
                .vtysh_cmd("show ip pim join json", isjson=True)[RECV_IF][group][SOURCE]
            )
            assert channel["expire"] != "--:--", channel
        _oif(group, SOURCE, "P", peer=2)
        _expect(
            "show ip pim upstream json",
            {group: {SOURCE: {"joinState": "Joined", "inboundInterface": "r1-eth2"}}},
        )
    finally:
        _static_group(group, add=False)

    # Once local membership also leaves, STAR must go; the other PIM output stays.
    _expect(
        "show ip mroute detail json",
        {group: {SOURCE: {"oil": {RECV_IF: None}}}},
    )
    _oif(group, SOURCE, "P", peer=2)


def test_assert_loser_does_not_regain_pim_ownership():
    """A parent's local receiver must not hide the direct child's Assert loss."""
    group = "239.10.0.6"
    router = get_topogen().gears["r1"]
    router.vtysh_cmd("configure terminal\nrouter pim\nkeep-alive-timer 30")
    _jp(1, group)
    _static_group(group)
    try:
        _jp(1, group, SOURCE)
        _channel(group, SOURCE, "JOIN")
        _oif(group, SOURCE, "*SP")
        _expect("show ip pim upstream json", {group: {SOURCE: {"joinState": "Joined"}}})

        # Scapy's PIM contrib has no Assert layer: encode the group, unicast
        # source, and a winning SPT preference/metric in the existing raw sender.
        body = struct.pack(
            "!BBBB4sBB4sII",
            1,
            0,
            0,
            32,
            socket.inet_aton(group),
            1,
            0,
            socket.inet_aton(SOURCE),
            0,
            0,
        )
        _send(1, Raw(body), message_type=5)
        lost_assert = {
            group: {SOURCE: {"interface": RECV_IF, "joins": True, "lostAssert": True}}
        }
        _expect("show ip pim channel json", lost_assert)

        # KAT expiry invokes forward_off while the direct downstream join is
        # still active but has lost Assert. The parent INCLUDE must not cause
        # forward_stop to retain the child's PIM ownership through its fallback.
        _expect(
            "show ip pim upstream json",
            {group: {SOURCE: {"joinState": "NotJoined"}}},
            count=60,
        )
        _expect("show ip pim channel json", lost_assert)
        _channel(group, SOURCE, "JOIN")

        def _no_pim_owner():
            data = json.loads(router.vtysh_cmd("show ip mroute detail json"))
            oif = data.get(group, {}).get(SOURCE, {}).get("oil", {}).get(RECV_IF, {})
            return topotest.json_cmp(oif, {"protocolPim": None})

        # Check only PIM ownership: correcting inherited forwarding under
        # Assert loss later may legitimately remove STAR or the entire OIF.
        _, result = topotest.run_and_expect(_no_pim_owner, None, count=30, wait=1)
        assert result is None, result
    finally:
        _static_group(group, add=False)
        router.vtysh_cmd("configure terminal\nrouter pim\nno keep-alive-timer")


def test_local_receiver_inheritance_survives_rpt_prune():
    """An (S,G,rpt) prune must not withdraw the parent's local IGMP receiver."""
    group = "239.10.0.7"
    _jp(1, group, holdtime=45)
    _channel(group, "*", "JOIN")
    _static_group(group)
    try:
        _jp(2, group, SOURCE)
        _channel(group, SOURCE, "JOIN", peer=2)
        _oif(group, SOURCE, "*S")

        _jp(1, group, SOURCE, prune=True, rpt=True)
        _channel(group, SOURCE + ",S,Grpt", "SGRpt(P)")
        _channel(group, "*", "JOIN")
        _expect("show ip pim join json", {RECV_IF: {group: {SOURCE: None}}})
        _oif(group, SOURCE, "*S")

        # Expiry preserves the RPT prune; receiving a (*,G) prune deletes it.
        # Parent NOINFO still has local INCLUDE interest that the neighbour's
        # RPT prune cannot withdraw.
        _channel(group, "*", "NOINFO", count=75)
        _channel(group, SOURCE + ",S,Grpt", "SGRpt(P)")
        _oif(group, SOURCE, "*S")
        _oif(group, SOURCE, "P", peer=2)
    finally:
        _static_group(group, add=False)

    _expect("show ip mroute detail json", {group: {SOURCE: {"oil": {RECV_IF: None}}}})
    _oif(group, SOURCE, "P", peer=2)
