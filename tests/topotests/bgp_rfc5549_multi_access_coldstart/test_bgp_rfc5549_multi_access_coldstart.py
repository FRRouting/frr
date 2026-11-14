#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
RFC 5549 BGP unnumbered on a multi-access segment: cold start with many
active BGP speakers.

bgp_rfc5549_multi_access/ covers one host searching while the other
same-ASN speaker on the segment is passive. Real shared VLANs (e.g. a ToR
SVI that trunks one peering VLAN to every server) have every server running
the same unnumbered config and searching at the same time. A server's
attempt to another server then fails with whatever that server does to an
unexpected connection (Bad Peer AS, or a TCP reset while it is mid-search
itself), and every server must still find the ToR.

A host that has seen Bad Peer AS from another host must not keep retrying
it: the ToR-outage test shuts the ToR's sessions so the hosts can only
reach each other for a while, then checks that each host rejected each other
host only a bounded number of times and still finds the ToR afterwards.

Topology (N hosts, default 6; TOPOTEST_RFC5549_HOSTS overrides):

    h1..hN (AS 65001, active) ---+--- switch s1 (shared L2 segment)
    tor    (AS 65002)         ---+

Every host: "ipv6 nd multi-access" on the segment interface, "neighbor
hX-eth0 interface remote-as external", allowas-in 1 (hosts share one ASN),
RAs every second. The ToR holds one session per host,
as a ToR does with "neighbor interface VlanN peer-group": FRR has no
equivalent (a listen range cannot be link-local), so the ToR is configured
with each host's link-local address on tor-eth0.
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

NHOSTS = int(os.environ.get("TOPOTEST_RFC5549_HOSTS", "6"))
HOSTS = ["h{}".format(i) for i in range(1, NHOSTS + 1)]
HOST_AS = 65001
TOR_AS = 65002
LINK_LOCALS = {}

HOST_CONF = """frr defaults traditional
hostname {name}
log stdout debugging
debug bgp neighbor-events
!
interface {name}-eth0
 ipv6 nd multi-access
 ipv6 nd ra-interval 1
 no ipv6 nd suppress-ra
!
interface lo
 ip address 10.0.0.{idx}/32
!
router bgp {asn}
 no bgp ebgp-requires-policy
 timers bgp 3 9
 neighbor {name}-eth0 interface remote-as external
 !
 address-family ipv4 unicast
  redistribute connected
  neighbor {name}-eth0 activate
  neighbor {name}-eth0 allowas-in 1
 exit-address-family
!
"""

TOR_CONF = """frr defaults traditional
hostname tor
log stdout debugging
debug bgp neighbor-events
!
interface tor-eth0
 ipv6 nd multi-access
 ipv6 nd ra-interval 1
 no ipv6 nd suppress-ra
!
interface lo
 ip address 10.0.255.1/32
!
router bgp {asn}
 no bgp ebgp-requires-policy
 timers bgp 3 9
 neighbor HOSTS peer-group
 neighbor HOSTS remote-as external
 neighbor HOSTS capability extended-nexthop
{neighbors} !
 address-family ipv4 unicast
  redistribute connected
  neighbor HOSTS activate
 exit-address-family
!
"""


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in HOSTS + ["tor"]:
        tgen.add_router(name)
        switch.add_link(tgen.gears[name])


def _link_local(router, iface):
    for _ in range(10):
        out = json.loads(router.cmd("ip -6 -j addr show dev {} scope link".format(iface)))
        addrs = out[0].get("addr_info", []) if out else []
        if addrs:
            return addrs[0]["local"]
        time.sleep(1)
    raise RuntimeError("{} has no link-local address on {}".format(router.name, iface))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name in HOSTS + ["tor"]:
        LINK_LOCALS[name] = _link_local(tgen.gears[name], "{}-eth0".format(name))
    neighbors = "".join(
        " neighbor {0} peer-group HOSTS\n neighbor {0} interface tor-eth0\n".format(
            LINK_LOCALS[name]
        )
        for name in HOSTS
    )

    for idx, name in enumerate(HOSTS, 1):
        conf = os.path.join(tgen.logdir, "{}.frr.conf".format(name))
        with open(conf, "w") as f:
            f.write(HOST_CONF.format(name=name, idx=idx, asn=HOST_AS))
        tgen.gears[name].load_frr_config(conf)
    conf = os.path.join(tgen.logdir, "tor.frr.conf")
    with open(conf, "w") as f:
        f.write(TOR_CONF.format(asn=TOR_AS, neighbors=neighbors))
    tgen.gears["tor"].load_frr_config(conf)

    # All routers start together: the cold-start case.
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _peer(router, iface):
    output = json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(iface)))
    return output.get(iface, {})


def _stuck_hosts(tgen):
    stuck = {}
    for name in HOSTS:
        p = _peer(tgen.gears[name], "{}-eth0".format(name))
        if p.get("bgpState") != "Established" or p.get("remoteAs") != TOR_AS:
            stuck[name] = "{} remoteAs={} peer={} connectionsEstablished={} lastReset={}".format(
                p.get("bgpState"),
                p.get("remoteAs"),
                p.get("hostForeign"),
                p.get("connectionsEstablished"),
                p.get("lastResetDueTo"),
            )
    return stuck


def _wait_all_established(tgen, seconds):
    _, result = topotest.run_and_expect(
        functools.partial(lambda: _stuck_hosts(tgen) or None), None, count=seconds, wait=1
    )
    assert result is None, "Hosts not Established with the ToR after {}s: {}".format(
        seconds, json.dumps(result, indent=2)
    )


def _bad_peer_as_sent(tgen, name):
    with open(os.path.join(tgen.logdir, name, "bgpd.log")) as f:
        return sum(
            1
            for line in f
            if "NOTIFICATION: sent to neighbor" in line and "Bad Peer AS" in line
        )


def test_every_host_reaches_the_tor():
    """Every host establishes eBGP with the ToR (AS 65002), not with another host."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for all {} hosts to establish with the ToR".format(NHOSTS))
    _wait_all_established(tgen, 120)


def test_tor_has_every_host():
    """The ToR holds one Established dynamic peer per host."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check():
        output = json.loads(tgen.gears["tor"].vtysh_cmd("show bgp summary json"))
        peers = output.get("ipv4Unicast", {}).get("peers", {})
        up = [k for k, v in peers.items() if v.get("state") == "Established"]
        return None if len(up) == NHOSTS else "{} of {} established: {}".format(
            len(up), NHOSTS, sorted(up)
        )

    _, result = topotest.run_and_expect(functools.partial(_check), None, count=30, wait=1)
    assert result is None, "ToR peers: {}".format(result)


def test_hosts_learn_each_other():
    """Every host learns every other host's loopback through the ToR."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check():
        missing = {}
        for idx, name in enumerate(HOSTS, 1):
            routes = json.loads(
                tgen.gears[name].vtysh_cmd("show ip route bgp json")
            )
            want = {
                "10.0.0.{}/32".format(j) for j in range(1, NHOSTS + 1) if j != idx
            }
            lacking = sorted(want - set(routes))
            if lacking:
                missing[name] = lacking
        return missing or None

    _, result = topotest.run_and_expect(functools.partial(_check), None, count=30, wait=1)
    assert result is None, "Missing host loopbacks: {}".format(result)


def test_hosts_forward_to_each_other():
    """Traffic between hosts' loopbacks goes through the ToR: IPv4 routes
    via the ToR's IPv6 link-local, no per-neighbor IPv4 link-local needed."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    failed = []
    for idx, name in enumerate(HOSTS, 1):
        dst = "10.0.0.{}".format(idx % NHOSTS + 1)
        out = tgen.gears[name].cmd(
            "ping -c 3 -W 1 -I 10.0.0.{} {} >/dev/null && echo ok".format(idx, dst)
        )
        if "ok" not in out:
            failed.append("{} -> {}".format(name, dst))
    assert not failed, "No forwarding: {}".format(failed)


def test_tor_outage_bad_peer_as_bounded():
    """While the ToR is unreachable, hosts reject each other only a bounded
    number of times, never skip the ToR, and all find it again afterwards."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    before = {name: _bad_peer_as_sent(tgen, name) for name in HOSTS}

    step("Shut the ToR's sessions; hosts can only reach each other")
    tgen.gears["tor"].vtysh_cmd(
        "configure terminal\nrouter bgp {}\nneighbor HOSTS shutdown".format(TOR_AS)
    )
    time.sleep(30)

    step("Each host sent Bad Peer AS at most twice per other host")
    # Twice: when two hosts target each other, each rejects the other on
    # both its own connection and the one it accepted.
    limit = 2 * (NHOSTS - 1)
    sent = {name: _bad_peer_as_sent(tgen, name) - before[name] for name in HOSTS}
    assert all(n <= limit for n in sent.values()), (
        "Bad Peer AS sent during the outage (limit {}): {}".format(limit, sent)
    )

    step("No host skips the ToR")
    for name in HOSTS:
        bad = _peer(tgen.gears[name], "{}-eth0".format(name)).get("badPeerAsNeighbors", [])
        assert LINK_LOCALS["tor"] not in bad, "{} skips the ToR: {}".format(name, bad)
        hosts = {LINK_LOCALS[h] for h in HOSTS if h != name}
        assert set(bad) <= hosts, "{} skips non-hosts: {}".format(name, bad)

    step("Re-enable the ToR's sessions; every host re-establishes")
    tgen.gears["tor"].vtysh_cmd(
        "configure terminal\nrouter bgp {}\nno neighbor HOSTS shutdown".format(TOR_AS)
    )
    _wait_all_established(tgen, 60)


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
