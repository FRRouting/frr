#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
RFC 5549 BGP unnumbered on a multi-access segment: the ToR connects.

The servers' unnumbered peers are passive, so every session has to come
from the ToR connecting to each server.  A server targets one neighbor at a
time; with "ipv6 nd multi-access" it must still accept the ToR's connection
when it is not the neighbor the server is pointed at, and must not need its
own search to reach the ToR.

Topology (N hosts, default 6; TOPOTEST_RFC5549_HOSTS overrides):

    h1..hN (AS 65001, passive) ---+--- switch s1 (shared L2 segment)
    tor    (AS 65002, active)  ---+
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
 neighbor {name}-eth0 passive
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
 neighbor HOSTS timers connect 1
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

    neighbors = "".join(
        " neighbor {0} peer-group HOSTS\n neighbor {0} interface tor-eth0\n".format(
            _link_local(tgen.gears[name], "{}-eth0".format(name))
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

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _stuck_hosts(tgen):
    stuck = {}
    for name in HOSTS:
        iface = "{}-eth0".format(name)
        output = json.loads(tgen.gears[name].vtysh_cmd("show bgp neighbors {} json".format(iface)))
        p = output.get(iface, {})
        if p.get("bgpState") != "Established" or p.get("remoteAs") != TOR_AS:
            stuck[name] = "{} remoteAs={} peer={}".format(
                p.get("bgpState"), p.get("remoteAs"), p.get("hostForeign")
            )
    return stuck or None


def test_tor_reaches_every_passive_host():
    """Every passive host accepts the ToR's connection and establishes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for the ToR to establish with all {} passive hosts".format(NHOSTS))
    _, result = topotest.run_and_expect(functools.partial(_stuck_hosts, tgen), None, count=60, wait=1)
    assert result is None, "Hosts not Established with the ToR after 60s: {}".format(
        json.dumps(result, indent=2)
    )


def test_passive_hosts_do_not_search():
    """A passive peer never connects out, so it must not run the
    round-robin (which would spin on its no-op connect attempts)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    searched = {}
    for name in HOSTS:
        with open(os.path.join(tgen.logdir, name, "bgpd.log")) as f:
            n = sum(1 for line in f if "[RR] bgp_stop" in line)
        if n:
            searched[name] = n
    assert not searched, "Passive hosts ran the round-robin: {}".format(searched)


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
