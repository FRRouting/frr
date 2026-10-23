#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_rip_interface_peer_lifetime.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_rip_interface_peer_lifetime.py
===================================

Regression for ripd keeping a dangling peer->ri after a real local
interface deletion.

A RIP peer created by remote packets holds a borrowed pointer to the
struct rip_interface of the interface it was learned on
(ripd/rip_peer.c:85).  When zebra reports an interface deletion,
lib/if.c::if_destroy_via_zapi() runs the daemon's if_unreal hook and
then frees the struct interface unless it is retained in the daemon's
own configuration.  ripd's if_del hook (rip_interface_delete_hook)
reset and freed the struct rip_interface without touching the peer
list, so the peer stayed in rip->peer_list with peer->ri dangling.
RIP_PEER_TIMER_DEFAULT (180s) after the last update, rip_peer_timeout()
reads peer->ri->ifp->name for the log-neighbor-changes message, a
heap-use-after-free that ASan turns into a ripd abort.

The deletion must hit an interface that ripd does not consider
configured.  ifp->configured is set only by the northbound
/frr-interface create callback (lib/if.c:1612); in the mgmtd-based
config path used here, an `interface` stanza for the target interface
in zebra.conf is enough to mark ripd's ifp->configured (observed with
an instrumented build: with the stanza, ripd retains the object and
the peer times out cleanly; without it, the object is freed and the
timeout reads freed memory).  The test therefore assigns every
interface and loopback address through the kernel in setup_module and
keeps all FRR config files free of `interface` stanzas, exactly like
the runtime reproduction.  The link-down/up control exercises the
retained path where the object (and the peer's ri) stays valid.

Topology
--------

    r3 ---- sw1 ---- r1 ---- sw2 ---- r2

r1-eth1 (towards r2) is deleted with `ip link del` while a RIP peer
and an installed route are bound to it.  r1-eth0 (towards r3) carries
the control peer and control route, which must survive.

Checks after the deletion:
  - the peer bound to the deleted interface is gone from
    `show ip rip status` while ripd stays alive (on the unpatched
    build the peer lingers and ripd dies on the peer timeout with an
    ASan heap-use-after-free in rip_peer_timeout);
  - the route via r2 is gone, the route via r3 is still installed;
  - r3 still sees r1 as a peer (control plane keeps running);
  - a peer on a merely link-down interface still times out normally
    after the real 180s RIP_PEER_TIMER_DEFAULT with the
    log-neighbor-changes "RIP Peer down" record, and the control
    session recovers afterwards.
"""

import os
import re
import sys
import time

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ripd]

P_R2 = "10.99.1.1/32"  # loopback redistributed by r2, via r1-eth1
P_R3 = "10.99.3.1/32"  # loopback redistributed by r3, via r1-eth0
PEER_R2 = "10.13.1.2"
PEER_R3 = "10.13.0.3"
PEER_TIMEOUT = 180  # RIP_PEER_TIMER_DEFAULT; the test waits the real timer

PEER_RE = re.compile(
    r"^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$"
)

# kernel-assigned addresses: no `interface` stanza may exist for the
# interface under test in any FRR config file (see module docstring)
ADDRESSES = [
    ("r1", "r1-eth0", "10.13.0.1/24"),
    ("r1", "r1-eth1", "10.13.1.1/24"),
    ("r2", "r2-eth0", "10.13.1.2/24"),
    ("r2", "lo", "10.99.1.1/32"),
    ("r3", "r3-eth0", "10.13.0.3/24"),
    ("r3", "lo", "10.99.3.1/32"),
]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(r1)
    sw1.add_link(r3)

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Interface addresses are assigned through the kernel, not through
    # FRR configuration files: an `interface` stanza for the target
    # interface in zebra.conf is enough to mark ripd's ifp->configured
    # (see module docstring), and lib then retains the object on
    # deletion instead of freeing it.  skip_remove_ips keeps the
    # framework's startRouter() from flushing these kernel addresses.
    for rname in ("r1", "r2", "r3"):
        tgen.gears[rname].net.skip_remove_ips = True
    for rname, dev, addr in ADDRESSES:
        r = tgen.gears[rname]
        r.cmd("ip link set lo up")
        r.cmd("ip addr add {} dev {}".format(addr, dev))
        if dev != "lo":
            r.cmd("ip link set {} up".format(dev))

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_RIP, os.path.join(CWD, "{}/ripd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _peers(router):
    """Parse `show ip rip status` peer table into {addr: (badpkts, badroutes)}."""
    out = router.vtysh_cmd("show ip rip status", raises=True)
    if "Routing Information Sources:" not in out:
        # a dead or wedged daemon must never be mistaken for "no peers"
        raise RuntimeError(
            "unexpected 'show ip rip status' output: {!r}".format(out[:200])
        )
    peers = {}
    in_sources = False
    for line in out.splitlines():
        if "Routing Information Sources:" in line:
            in_sources = True
            continue
        if in_sources:
            m = PEER_RE.match(line)
            if m:
                peers[m.group(1)] = (int(m.group(2)), int(m.group(3)))
            elif line.strip() and not line.startswith(" "):
                in_sources = False
    return peers


def _route_installed(router, pfx):
    return pfx in router.vtysh_cmd("show ip rip")


def _ripd_alive(router):
    return bool(router.cmd("pgrep -x ripd").strip())


def _asan_tail(router):
    """Return AddressSanitizer evidence from the router's log dir, if any."""
    out = router.cmd(
        "grep -rl 'AddressSanitizer' {}/ 2>/dev/null".format(router.logdir)
    )
    evidence = []
    for fname in out.split():
        head = router.cmd("grep -A 12 'AddressSanitizer' {} | head -30".format(fname))
        evidence.append("{}:\n{}".format(fname, head))
    return "\n".join(evidence)


def _expect_peer(router, addr, present=True, count=60, wait=1):
    def check():
        got = addr in _peers(router)
        if got != present:
            return "peer {} present={} (expected {})".format(addr, got, present)
        return None

    _, result = topotest.run_and_expect(check, None, count=count, wait=wait)
    return result


def _expect_route(router, pfx, installed=True, count=30, wait=1):
    def check():
        got = _route_installed(router, pfx)
        if got != installed:
            return "route {} installed={} (expected {})".format(pfx, got, installed)
        return None

    _, result = topotest.run_and_expect(check, None, count=count, wait=wait)
    return result


def test_converge():
    "Baseline: two peers and two installed routes on r1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    result = _expect_peer(r1, PEER_R2)
    assert result is None, "r2 peer missing: {}".format(result)
    result = _expect_peer(r1, PEER_R3)
    assert result is None, "r3 peer missing: {}".format(result)
    result = _expect_route(r1, P_R2)
    assert result is None, "route via r2 not installed: {}".format(result)
    result = _expect_route(r1, P_R3)
    assert result is None, "route via r3 not installed: {}".format(result)


def test_link_down_up_control():
    "A mere link down/up keeps the interface: no crash, session recovers"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.cmd("ip link set r1-eth1 down")
    # the interface object is retained, the peer entry may linger, but
    # the daemon must stay up and answer
    try:
        _peers(r1)
    except Exception as exc:
        pytest.fail("show ip rip status failed after link down: {}".format(exc))
    assert _ripd_alive(r1), "ripd died after link down"

    r1.cmd("ip link set r1-eth1 up")
    result = _expect_peer(r1, PEER_R2)
    assert result is None, "r2 peer did not recover: {}".format(result)
    result = _expect_route(r1, P_R2)
    assert result is None, "route via r2 did not recover: {}".format(result)


def test_interface_delete_unconfigured():
    "Deleting an unconfigured interface must not leave a dangling peer->ri"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    r1.cmd("ip link del r1-eth1")

    # Wait for either the fixed behaviour (peer flushed with the
    # interface, ripd alive) or the bug (peer lingers; ripd aborts on
    # the 180s peer timeout reading the freed ri).  The peer timer was
    # last refreshed at most one update interval (5s) before the
    # deletion, so the crash, when present, happens by delete+185s.
    deadline_ok = False
    crash = None
    for _ in range(200):
        if not _ripd_alive(r1):
            crash = "ripd died after interface delete"
            break
        try:
            if PEER_R2 not in _peers(r1):
                deadline_ok = True
                break
        except Exception as exc:
            crash = "show ip rip status failed: {}".format(exc)
            break
        time.sleep(1)

    if crash:
        asan = _asan_tail(r1)
        pytest.fail(
            "{}\nAddressSanitizer evidence:\n{}".format(crash, asan or "(none)")
        )

    assert deadline_ok, (
        "peer {} still bound to the deleted interface 200s after the "
        "delete (180s peer timeout elapsed)".format(PEER_R2)
    )
    assert _ripd_alive(r1), "ripd died after interface delete"

    result = _expect_route(r1, P_R2, installed=False, count=10, wait=0.5)
    assert result is None, "route via r2 survived the delete: {}".format(result)
    result = _expect_route(r1, P_R3, installed=True, count=10, wait=0.5)
    assert result is None, "route via r3 lost: {}".format(result)
    result = _expect_peer(r1, PEER_R3, present=True, count=10, wait=0.5)
    assert result is None, "control peer lost: {}".format(result)

    # control plane keeps running: r3 must still see r1
    result = _expect_peer(r3, "10.13.0.1", present=True, count=30, wait=1)
    assert result is None, "r3 lost r1 after the delete: {}".format(result)


def test_peer_timeout_normal():
    "A peer on a retained (link-down) interface still times out cleanly"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    if not _ripd_alive(r1):
        pytest.skip("ripd already dead from the unfixed interface-delete bug")

    r1.cmd("ip link set r1-eth0 down")

    # the interface object is retained, so the 180s timeout must remove
    # the peer with a clean log-neighbor-changes record, no crash
    result = _expect_peer(r1, PEER_R3, present=False,
                          count=PEER_TIMEOUT + 30, wait=1)
    assert result is None, "control peer did not time out: {}".format(result)
    assert _ripd_alive(r1), "ripd died on the normal peer timeout"

    log = r1.cmd(
        "grep -rh 'RIP Peer down: {}' {}/ 2>/dev/null".format(
            PEER_R3, r1.logdir)
    )
    assert "r1-eth0" in log, (
        "no clean 'RIP Peer down' record for the control peer:\n{}".format(log)
    )

    r1.cmd("ip link set r1-eth0 up")
    result = _expect_peer(r1, PEER_R3)
    assert result is None, "control peer did not recover: {}".format(result)
    result = _expect_route(r1, P_R3)
    assert result is None, "control route did not recover: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
