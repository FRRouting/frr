#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
RFC 5549 BGP unnumbered on a multi-access segment: remote-as external
matches more than one neighbor.

The server peers with "remote-as external", and both upstreams on the
segment have their own AS, so either could get the session.  The server
cannot know which one was meant: once both have established with it,
bgpd warns and "show bgp neighbors" lists them.  bgpd does not try other
neighbors while Established, so the second one is only seen after the
session has moved to it (here: the first upstream shuts its session).

Topology:

    srv (AS 65001, remote-as external) ---+--- switch s1
    u1  (AS 65011)                     ---+
    u2  (AS 65012)                     ---+
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

SRV_AS = 65001
UPSTREAM_AS = {"u1": 65011, "u2": 65012}
LINK_LOCALS = {}

SRV_CONF = """frr defaults traditional
hostname srv
log stdout debugging
debug bgp neighbor-events
!
interface srv-eth0
 ipv6 nd multi-access
 ipv6 nd ra-interval 1
 no ipv6 nd suppress-ra
!
router bgp {asn}
 bgp router-id 10.0.0.1
 no bgp ebgp-requires-policy
 timers bgp 3 9
 neighbor srv-eth0 interface remote-as external
 !
 address-family ipv4 unicast
  neighbor srv-eth0 activate
 exit-address-family
!
"""

UPSTREAM_CONF = """frr defaults traditional
hostname {name}
log stdout debugging
debug bgp neighbor-events
!
interface {name}-eth0
 ipv6 nd ra-interval 1
 no ipv6 nd suppress-ra
!
router bgp {asn}
 bgp router-id {router_id}
 no bgp ebgp-requires-policy
 timers bgp 3 9
 neighbor {srv} remote-as external
 neighbor {srv} interface {name}-eth0
 neighbor {srv} capability extended-nexthop
 neighbor {srv} timers connect 1
 !
 address-family ipv4 unicast
  neighbor {srv} activate
 exit-address-family
!
"""


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ["srv"] + list(UPSTREAM_AS):
        tgen.add_router(name)
        switch.add_link(tgen.gears[name])


def _link_local(router, iface):
    for _ in range(10):
        out = json.loads(
            router.cmd("ip -6 -j addr show dev {} scope link".format(iface))
        )
        addrs = out[0].get("addr_info", []) if out else []
        if addrs:
            return addrs[0]["local"]
        time.sleep(1)
    raise RuntimeError("{} has no link-local address on {}".format(router.name, iface))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name in tgen.gears:
        if name != "s1":
            LINK_LOCALS[name] = _link_local(tgen.gears[name], "{}-eth0".format(name))

    conf = os.path.join(tgen.logdir, "srv.frr.conf")
    with open(conf, "w") as f:
        f.write(SRV_CONF.format(asn=SRV_AS))
    tgen.gears["srv"].load_frr_config(conf)
    for idx, (name, asn) in enumerate(UPSTREAM_AS.items(), 11):
        conf = os.path.join(tgen.logdir, "{}.frr.conf".format(name))
        with open(conf, "w") as f:
            f.write(
                UPSTREAM_CONF.format(
                    name=name,
                    asn=asn,
                    srv=LINK_LOCALS["srv"],
                    router_id="10.0.0.{}".format(idx),
                )
            )
        tgen.gears[name].load_frr_config(conf)

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _srv_peer(tgen):
    output = json.loads(tgen.gears["srv"].vtysh_cmd("show bgp neighbors srv-eth0 json"))
    return output.get("srv-eth0", {})


def _wait_established(tgen, asns, seconds):
    def _check():
        p = _srv_peer(tgen)
        if p.get("bgpState") == "Established" and p.get("remoteAs") in asns:
            return None
        return "{} remoteAs={} peer={}".format(
            p.get("bgpState"), p.get("remoteAs"), p.get("hostForeign")
        )

    _, result = topotest.run_and_expect(_check, None, count=seconds, wait=1)
    assert result is None, "srv not Established with {}: {}".format(asns, result)
    return _srv_peer(tgen)["remoteAs"]


def _upstream_of(asn):
    return next(name for name, a in UPSTREAM_AS.items() if a == asn)


def _warnings(tgen):
    with open(os.path.join(tgen.logdir, "srv", "bgpd.log")) as f:
        return [
            line
            for line in f
            if "Multi-access interface srv-eth0:" in line
            and "neighbors passed remote-as" in line
        ]


def test_one_neighbor_is_not_ambiguous():
    """srv establishes with one upstream; one match is not ambiguous."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("srv establishes with either upstream")
    _wait_established(tgen, list(UPSTREAM_AS.values()), 60)

    p = _srv_peer(tgen)
    assert "multiAccessAmbiguous" not in p, p.get("remoteAsMatchedNeighbors")
    assert "remoteAsMatchedNeighbors" not in p
    assert not _warnings(tgen), _warnings(tgen)


def test_second_neighbor_is_ambiguous():
    """Once the session moves to the other upstream, both passed remote-as:
    srv warns and lists both with their AS."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    first = _upstream_of(_srv_peer(tgen)["remoteAs"])
    second = next(name for name in UPSTREAM_AS if name != first)

    step("{} shuts its session; srv moves to {}".format(first, second))
    tgen.gears[first].vtysh_cmd(
        "configure terminal\nrouter bgp {}\nneighbor {} shutdown".format(
            UPSTREAM_AS[first], LINK_LOCALS["srv"]
        )
    )
    _wait_established(tgen, [UPSTREAM_AS[second]], 60)

    step("JSON: multiAccessAmbiguous and both neighbors with their AS")
    p = _srv_peer(tgen)
    assert p.get("multiAccessAmbiguous") is True, p
    matched = {
        m["neighbor"]: m["remoteAs"] for m in p.get("remoteAsMatchedNeighbors", [])
    }
    want = {LINK_LOCALS[name]: asn for name, asn in UPSTREAM_AS.items()}
    assert matched == want, matched

    step("Text output lists them")
    out = tgen.gears["srv"].vtysh_cmd("show bgp neighbors srv-eth0")
    assert "Multi-access: 2 neighbors passed remote-as:" in out, out
    for name, asn in UPSTREAM_AS.items():
        assert "{} (AS {})".format(LINK_LOCALS[name], asn) in out, out

    step("One warning naming both neighbors and their AS")
    warnings = _warnings(tgen)
    assert len(warnings) == 1, warnings
    for name, asn in UPSTREAM_AS.items():
        assert "{} (AS {})".format(LINK_LOCALS[name], asn) in warnings[0], warnings
    assert "set a numeric remote-as" in warnings[0], warnings


def test_numeric_remote_as_clears_it():
    """A numeric remote-as singles out the peer: the list is cleared and
    not refilled."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    asn = _srv_peer(tgen)["remoteAs"]

    step("remote-as {} on srv".format(asn))
    tgen.gears["srv"].vtysh_cmd(
        "configure terminal\nrouter bgp {}\nneighbor srv-eth0 interface remote-as {}".format(
            SRV_AS, asn
        )
    )
    _wait_established(tgen, [asn], 60)

    p = _srv_peer(tgen)
    assert "multiAccessAmbiguous" not in p, p.get("remoteAsMatchedNeighbors")
    assert "remoteAsMatchedNeighbors" not in p
    assert len(_warnings(tgen)) == 1, _warnings(tgen)


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
