#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nexthop AI
# Authored by Kalash Nainwal <kalash@nexthop.ai>
#
# BMP route-monitoring silently truncated to a slow collector.
#
#   +----------+
#   | bmp_fast |\
#   +----------+ \        +------+          +------+
#                  s1 --- |  R1  |----------|  R2  |
#   +----------+ /        +------+          +------+
#   | bmp_slow |/       (-M bmp, monitors   (sharpd injects N IPv4
#   +----------+         pre+post+loc         + N IPv6 routes,
#                        on IPv4 AND IPv6)     redistributed to R1)
#
# R1 monitors both address-families to TWO collectors on one target: bmp_fast
# drains at line rate; bmp_slow is throttled (small SO_RCVBUF + paced reads) so
# it holds R1 receive-window-blocked. The bug: R1's per-target, shared
# `bgp_request_sync[afi][safi]` flag is cleared by whichever session finishes
# an address-family first (bmp_fast), so bmp_slow -- which only reaches the 2nd
# address-family (IPv6) afterwards -- silently skips the entire IPv6 walk.
# Observed on R1 via `show bmp`: bmp_slow's MonSent plateaus at the IPv4
# portion with ByteQ 0 (drained, "Up"/healthy) while bmp_fast gets IPv4+IPv6.
#
# This test asserts BOTH collectors receive the same number of route-monitoring
# messages. It FAILS while the bug is present (slow < fast) and PASSES once the
# fix lands.

import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
from lib import topotest
from lib.checkping import check_ping
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

FAST_IP = "192.0.2.10"
SLOW_IP = "192.0.2.11"
BMP_PORT = 1789
NROUTES = 3000

BMP_TARGET_CFG = """
configure terminal
router bgp 65001
 bmp targets bt1
  bmp monitor ipv4 unicast pre-policy
  bmp monitor ipv4 unicast post-policy
  bmp monitor ipv4 unicast loc-rib
  bmp monitor ipv6 unicast pre-policy
  bmp monitor ipv6 unicast post-policy
  bmp monitor ipv6 unicast loc-rib
  bmp connect 192.0.2.10 port 1789 min-retry 1000 max-retry 30000
  bmp connect 192.0.2.11 port 1789 min-retry 1000 max-retry 30000
 exit
exit
"""


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_bmp_server("bmp_fast", ip=FAST_IP, defaultRoute="via 192.0.2.1", port=BMP_PORT)
    tgen.add_bmp_server("bmp_slow", ip=SLOW_IP, defaultRoute="via 192.0.2.1", port=BMP_PORT)

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["bmp_fast"])
    s1.add_link(tgen.gears["bmp_slow"])

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth1", "r2-eth0")


def _start_collector(tgen, name, slow):
    node = tgen.gears[name]
    logdir = os.path.join(tgen.logdir, name)
    node.run("chmod 777 {}".format(logdir))
    logf = os.path.join(logdir, "col.log")
    pidf = os.path.join(logdir, "col.pid")
    extra = "--slow --rcvbuf 16384 --read-size 4096 --read-delay 0.03" if slow else ""
    node.run(
        "python3 {}/collector.py -a {} -p {} -r {} -l {} {} &".format(
            CWD, node.ip, BMP_PORT, pidf, logf, extra
        ),
        stdout=None,
    )
    # so TopoBMPCollector.stop() (teardown) can find the pid
    node.pid_file = pidf


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
    )
    tgen.gears["r2"].load_frr_config(
        os.path.join(CWD, "r2/frr.conf"),
        [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_SHARP, None), (TopoRouter.RD_BGP, None)],
    )

    tgen.start_router()

    # Inject scale on r2 with sharpd; `redistribute sharp` advertises them to r1.
    # A route is only redistributed once it is actually FIB-installed, which needs
    # a nexthop that resolves to a real, installable next hop. IPv4 uses r2's own
    # loopback. IPv6 uses r1's link address (a local address is refused by the
    # kernel as a v6 gateway, and an unused on-link address never resolves); r2's
    # `next-hop-self force` keeps r1 from seeing its own address as the nexthop.
    def _installed(cmd):
        out = tgen.gears["r2"].vtysh_cmd(cmd, isjson=True)
        n = next(
            (e.get("fib", 0) for e in out.get("routes", []) if e.get("type") == "sharp"), 0
        )
        logger.info("r2 sharp routes installed (%s): %d" % (cmd, n))
        return n >= NROUTES

    # sharpd uses a single global install continuation (struct buffer_delay);
    # firing the second large `sharp install routes` before the first has drained
    # clobbers it and silently drops routes from the in-flight family. Wait for
    # each family to finish installing on r2 before injecting the next.
    tgen.gears["r2"].vtysh_cmd(
        "sharp install routes 100.64.0.0 nexthop 172.16.255.2 {}".format(NROUTES)
    )
    _, ok = topotest.run_and_expect(
        lambda: _installed("show ip route summary json"), True, count=90, wait=2
    )
    assert ok, "r2 did not install all injected IPv4 sharp routes"

    # Make sure the v6 nexthop is reachable before injecting, so the routes install active.
    check_ping("r2", "192:168::1", True, 10, 1)
    tgen.gears["r2"].vtysh_cmd(
        "sharp install routes 2001:db8:1:: nexthop 192:168::1 {}".format(NROUTES)
    )
    _, ok = topotest.run_and_expect(
        lambda: _installed("show ipv6 route summary json"), True, count=90, wait=2
    )
    assert ok, "r2 did not install all injected IPv6 sharp routes"

    logger.info("starting fast + slow BMP collectors")
    _start_collector(tgen, "bmp_fast", slow=False)
    _start_collector(tgen, "bmp_slow", slow=True)


def teardown_module(_mod):
    get_topogen().stop_topology()


def _parse_bmp_clients(r1):
    """Parse `show bmp` connected-client lines -> {ip: {monsent, byteq}}."""
    out = r1.vtysh_cmd("show bmp")
    res = {}
    for line in out.splitlines():
        f = line.split()
        # data line: "<ip>:<port> <uptime> <MonSent> <MirrSent> <MirrLost> <ByteSent> <ByteQ> <ByteQKernel>"
        if len(f) >= 8 and ":" in f[0] and re.match(r"^\d+:\d+", f[1]):
            ip = f[0].rsplit(":", 1)[0]
            try:
                res[ip] = {"monsent": int(f[2]), "byteq": int(f[6])}
            except ValueError:
                continue
    return res


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _rcvd():
        v4 = tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
        v6 = tgen.gears["r1"].vtysh_cmd("show bgp ipv6 unicast json", isjson=True)
        n4 = len(v4.get("routes", {}))
        n6 = len(v6.get("routes", {}))
        logger.info("r1 prefixes: v4=%d v6=%d" % (n4, n6))
        return n4 >= NROUTES and n6 >= NROUTES

    _, ok = topotest.run_and_expect(_rcvd, True, count=60, wait=2)
    assert ok, "r1 did not learn the injected v4+v6 routes from r2"


def test_no_route_monitoring_truncation():
    """
    Configure the BMP target now that the RIB is fully populated (this triggers
    the initial table walk to both collectors), wait for the dump to settle,
    then assert the slow collector received the SAME number of route-monitoring
    messages as the fast one. FAILS (slow < fast) while the bug is present.
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    # populated RIB -> configuring the target walks the whole thing
    r1.vtysh_cmd(BMP_TARGET_CFG)

    def _two_clients():
        c = _parse_bmp_clients(r1)
        return FAST_IP in c and SLOW_IP in c

    _, ok = topotest.run_and_expect(_two_clients, True, count=60, wait=2)
    assert ok, "both BMP collectors did not connect"

    # Wait until both sessions have drained (ByteQ==0) and MonSent is stable.
    stable = {"fast": (-1, 0), "slow": (-1, 0)}  # key -> (last_monsent, stable_count)

    def _settled():
        c = _parse_bmp_clients(r1)
        if FAST_IP not in c or SLOW_IP not in c:
            return False
        done = True
        for key, ip in (("fast", FAST_IP), ("slow", SLOW_IP)):
            last, cnt = stable[key]
            ms, bq = c[ip]["monsent"], c[ip]["byteq"]
            cnt = cnt + 1 if (ms == last and bq == 0) else 0
            stable[key] = (ms, cnt)
            if cnt < 3:
                done = False
        logger.info("settle check: fast=%s slow=%s" % (c[FAST_IP], c[SLOW_IP]))
        return done

    _, ok = topotest.run_and_expect(_settled, True, count=90, wait=2)
    assert ok, "BMP collectors did not drain and stabilize"

    c = _parse_bmp_clients(r1)
    fast = c[FAST_IP]["monsent"]
    slow = c[SLOW_IP]["monsent"]
    logger.info("FINAL MonSent: fast=%d slow=%d (missing %d)" % (fast, slow, fast - slow))

    assert slow == fast, (
        "route-monitoring truncated: slow collector received only %d of %d "
        "route-monitoring messages (missing %d, ~the IPv6 walk) while the fast "
        "collector got the full dump; slow session drained to ByteQ=0 and reports "
        "Up (silent truncation)." % (slow, fast, fast - slow)
    )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
