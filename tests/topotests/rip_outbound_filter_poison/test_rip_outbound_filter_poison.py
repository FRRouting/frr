#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_outbound_filter_poison.py
#
# Copyright (c) 2026 by
# Shbinging
#

"""
test_rip_outbound_filter_poison.py: RIP must poison a previously advertised
route when an outbound filter change starts denying it, instead of leaving
the stale route installed at the neighbor until its own route timeout
expires.

Topology:

    r1-eth1 (stub: 198.51.100.44/32 and 198.51.100.45/32)
       |
    [ r1 ] --- r1-eth0 --- sw1 --- r2-eth0 --- [ r2 ]

r1 redistributes both connected stub prefixes into RIPv2 (update interval
2s, route timeout 90s):

  198.51.100.44/32 (TARGET) is permitted by the initial outbound filter and
      learned by r2.  Once an outbound filter starts denying it, ripd must
      emit a metric-16 poison so r2 withdraws it within a few update
      intervals, instead of keeping it until the 90s route timeout.
  198.51.100.45/32 (NEVER) is denied from birth by every filter used here
      (control).  It must never show up on r2, and the poison logic must
      never turn a never-advertised route into a metric-16 advertisement.

The test exercises the outbound filter paths of rip_output_process():
the outbound distribute-list (prefix-list form and access-list form) and
the per-interface `route-map ... out`.  Each deny is checked on the wire,
not only in the RIB: a pcap on r2-eth0 must contain exactly one RIP
RESPONSE carrying TARGET with metric 16, no TARGET with a normal metric
after the deny, and no NEVER at all.  The RIB withdrawal assertion window
(42s) is far shorter than the 90s route timeout, so a natural timeout
cannot be mistaken for the fix, and a periodic update still advertising
TARGET fails the wire assertions.  After each deny the filter is relaxed
again to check the route is re-advertised.  Finally r2 is restarted while
the deny is in place: once its ripd is ready it must stay ignorant of
TARGET for several update intervals (and the wire stays silent), and
lifting the deny afterwards must still let it learn, proving the silence
was the filter and not a broken RIP session.
"""

import os
import struct
import subprocess
import sys
import time
import pytest
from functools import partial

pytestmark = [pytest.mark.ripd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

TARGET = "198.51.100.44/32"
TARGET_ADDR = "198.51.100.44"
NEVER = "198.51.100.45/32"
NEVER_ADDR = "198.51.100.45"
R1_SRC = "10.4.12.1"
RIP_PORT = 520
UPDATE_INTERVAL = 2

# The route timeout is 90s; the withdrawal assertions below allow at most
# 42s, so passing them cannot be a natural timeout.  (topotest.run_and_expect
# enforces a 15s minimum wait and otherwise bumps count/wait to 20x3, so the
# window must be spelled as 14x3 rather than a shorter 1s-interval poll.)
WITHDRAW_COUNT = 14
WITHDRAW_WAIT = 3
LEARN_COUNT = 30
LEARN_WAIT = 1
# How long a fresh neighbor must stay ignorant of the denied prefixes,
# in update intervals.
FRESH_IGNORE_INTERVALS = 4

PREFIX_ALLOW = "distribute-list prefix PFX_ALLOW out r1-eth0"
PREFIX_BLOCK = "distribute-list prefix PFX_BLOCK out r1-eth0"
ACL_ALLOW = "distribute-list ACL_ALLOW out r1-eth0"
ACL_BLOCK = "distribute-list ACL_BLOCK out r1-eth0"
RMAP_ALLOW = "route-map RMAP_ALLOW out r1-eth0"
RMAP_BLOCK = "route-map RMAP_BLOCK out r1-eth0"

# Every outbound filter reference the test can leave on r1-eth0, used to
# normalize the configuration before each variant.
ALL_FILTER_REFS = [
    PREFIX_ALLOW,
    PREFIX_BLOCK,
    ACL_ALLOW,
    ACL_BLOCK,
    RMAP_ALLOW,
    RMAP_BLOCK,
]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # RIP link: r1-eth0 <-> r2-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    # Stub on r1 carrying the originated prefixes: r1-eth1
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
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


def _vtysh_rip(r1, cmds):
    "Apply configuration commands inside the `router rip` node."
    r1.vtysh_cmd("configure terminal\nrouter rip\n" + "\n".join(cmds) + "\n")


def _normalize_filter(r1, allow_cmd):
    "Remove any filter left on r1-eth0, then apply the variant's ALLOW."
    running = r1.vtysh_cmd("show running-config")
    cmds = ["no " + ref for ref in ALL_FILTER_REFS if ref in running]
    cmds.append(allow_cmd)
    _vtysh_rip(r1, cmds)


def _rip_route_present(router, prefix):
    "Return True when PREFIX is installed in the Zebra RIB via RIP."
    output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    if not output or prefix not in output:
        return False
    for entry in output[prefix]:
        if entry.get("protocol") == "rip":
            return True
    return False


def _rip_route_absent(router, prefix):
    "Return True when PREFIX is gone from the Zebra RIB (or is not a RIP route)."
    return not _rip_route_present(router, prefix)


def _rip_rib_has(router, addr):
    "Return True when ADDR shows up in ripd's own RIB."
    return addr in router.vtysh_cmd("show ip rip")


def _expect(router, prefix, present, count, wait, what):
    "Wait until PREFIX presence on ROUTER matches PRESENT; assert on timeout."
    check = _rip_route_present if present else _rip_route_absent
    _, result = topotest.run_and_expect(
        partial(check, router, prefix), True, count=count, wait=wait
    )
    state = "learn" if present else "withdraw"
    assert result is True, "r2 did not {} {} {}".format(state, prefix, what)


def _expect_learn(router, prefix, what):
    _expect(router, prefix, True, LEARN_COUNT, LEARN_WAIT, what)


def _expect_withdraw(router, prefix, what):
    _expect(router, prefix, False, WITHDRAW_COUNT, WITHDRAW_WAIT, what)


def _start_capture(tgen, router, ifname, name):
    "Start tcpdump on IFNAME inside ROUTER's namespace; return (proc, log, pcap)."
    pcap = os.path.join(tgen.logdir, name + ".pcap")
    log = open(os.path.join(tgen.logdir, name + ".tcpdump.log"), "w")
    proc = router.net.popen(
        [
            "tcpdump",
            "-i",
            ifname,
            "-nn",
            "-s0",
            "-w",
            pcap,
            "udp",
            "port",
            str(RIP_PORT),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    time.sleep(1)
    if proc.poll() is not None:
        raise RuntimeError(
            "tcpdump on {} exited early with {}".format(ifname, proc.returncode)
        )
    return proc, log, pcap


def _stop_capture(proc, log):
    "Terminate the tcpdump started by _start_capture and close its log."
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if log is not None:
        log.close()


def _parse_rip_pcap(path):
    "Parse a classic pcap; return RIPv2 RESPONSE packets as {ts, src, entries}."
    with open(path, "rb") as fp:
        data = fp.read()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        return []
    off = 24
    packets = []
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkt = data[off : off + incl]
        off += incl
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        if len(pkt) < 14 + 20 + 8 + 4:
            continue
        if pkt[12:14] != b"\x08\x00":  # IPv4
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:  # UDP
            continue
        udp = ip[ihl:]
        sport, dport = struct.unpack_from(">HH", udp, 0)
        if sport != RIP_PORT and dport != RIP_PORT:
            continue
        rip = udp[8:]
        if len(rip) < 4 or rip[0] != 2:  # RESPONSE only
            continue
        src = ".".join(str(b) for b in ip[12:16])
        entries = []
        rte = rip[4:]
        while len(rte) >= 20:
            family, _tag, addr, _mask, _nh, metric = struct.unpack_from(
                ">HH4s4s4sI", rte, 0
            )
            if family == 2:  # AF_INET; skip auth (0xFFFF) entries
                entries.append((".".join(str(b) for b in addr), metric))
            rte = rte[20:]
        packets.append({"ts": ts, "src": src, "entries": entries})
    return packets


def _metrics_for(packets, addr):
    "Return (ts, metric) pairs for ADDR in packets sent by r1."
    return [
        (pkt["ts"], metric)
        for pkt in packets
        if pkt["src"] == R1_SRC
        for a, metric in pkt["entries"]
        if a == addr
    ]


def _assert_poison_evidence(packets, expect_poison):
    """Assert the wire evidence for the outbound-filter deny.

    With EXPECT_POISON True (a previously advertised route just denied):
    exactly one metric-16 RESPONSE for TARGET, and no normal-metric
    TARGET advertisement after that poison (the poison is the reference
    point; a periodic update that fires while the deny is being applied
    may still carry the route normally before the poison).  With
    EXPECT_POISON False (a neighbor that never had the route): no TARGET
    and no NEVER on the wire at all.  NEVER must never appear in either
    mode.
    """
    target = _metrics_for(packets, TARGET_ADDR)
    never = _metrics_for(packets, NEVER_ADDR)
    assert not never, "NEVER prefix appeared on the wire: {}".format(never)
    if expect_poison:
        poison = [ts for ts, metric in target if metric == 16]
        assert (
            len(poison) == 1
        ), "expected exactly one metric-16 poison for TARGET, got {}".format(target)
        late_normal = [ts for ts, metric in target if metric != 16 and ts > poison[0]]
        assert not late_normal, (
            "TARGET still advertised with a normal metric after the poison: "
            "{}".format(late_normal)
        )
    else:
        assert not target, "denied-from-birth TARGET appeared on the wire: {}".format(
            target
        )


def _deny_poison_withdraws(tgen, variant, block_cmd):
    "Deny TARGET with the variant's filter; check wire poison and RIB withdrawal."
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _expect_learn(r2, TARGET, "before {} deny".format(variant))

    proc = log = None
    pcap = os.path.join(tgen.logdir, variant + "_deny.pcap")
    try:
        proc, log, pcap = _start_capture(tgen, r2, "r2-eth0", variant + "_deny")
        logger.info("Applying %s", block_cmd)
        _vtysh_rip(r1, [block_cmd])
        # Give r1 several update intervals to emit the poison.
        time.sleep(4 * UPDATE_INTERVAL)
    finally:
        _stop_capture(proc, log)

    packets = _parse_rip_pcap(pcap)
    _assert_poison_evidence(packets, expect_poison=True)
    # The neighbor must actually withdraw far inside the 90s route timeout.
    _expect_withdraw(r2, TARGET, "after {} deny".format(variant))


def test_converge_protocols():
    "Wait for r2 to learn TARGET over RIP; NEVER must stay absent."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _expect_learn(r2, TARGET, "after startup")

    output = r2.vtysh_cmd("show ip rip")
    assert TARGET in output, "TARGET missing from r2's RIP RIB after learning"
    assert NEVER_ADDR not in output, "NEVER leaked into r2's RIP RIB"


def test_distribute_list_prefix_deny_poison_withdraws():
    "Denying TARGET with an outbound prefix-list must poison it on the wire and r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _normalize_filter(tgen.gears["r1"], PREFIX_ALLOW)
    _deny_poison_withdraws(tgen, "prefix", PREFIX_BLOCK)


def test_distribute_list_prefix_permit_recover():
    "Permitting TARGET again must re-advertise it to r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Restoring %s", PREFIX_ALLOW)
    _vtysh_rip(r1, [PREFIX_ALLOW])
    _expect_learn(r2, TARGET, "after prefix-list permit restore")


def test_distribute_list_acl_deny_poison_withdraws():
    "Denying TARGET with an outbound access-list must poison it on the wire and r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _normalize_filter(tgen.gears["r1"], ACL_ALLOW)
    _deny_poison_withdraws(tgen, "acl", ACL_BLOCK)


def test_distribute_list_acl_permit_recover():
    "Permitting TARGET again must re-advertise it to r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Restoring %s", ACL_ALLOW)
    _vtysh_rip(r1, [ACL_ALLOW])
    _expect_learn(r2, TARGET, "after access-list permit restore")


def test_route_map_out_deny_poison_withdraws():
    "Denying TARGET with a per-interface route-map out must poison it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _normalize_filter(tgen.gears["r1"], RMAP_ALLOW)
    _deny_poison_withdraws(tgen, "routemap", RMAP_BLOCK)


def test_route_map_out_permit_recover():
    "Removing the route-map out must re-advertise TARGET to r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Restoring %s", RMAP_ALLOW)
    _vtysh_rip(r1, [RMAP_ALLOW])
    _expect_learn(r2, TARGET, "after route-map out permit restore")


def test_denied_from_birth_fresh_neighbor():
    "A fresh r2 must never learn TARGET while the deny stays in place."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _expect_learn(r2, TARGET, "before final deny")

    logger.info("Applying %s", PREFIX_BLOCK)
    _vtysh_rip(r1, [PREFIX_BLOCK])
    _expect_withdraw(r2, TARGET, "after final deny")

    # Restart r2 so it observes r1 with the deny already in place, exactly
    # like a neighbor that was never exposed to the permitted trajectory.
    logger.info("Restarting r2 with the deny in place")
    r2.stop()
    r2.start()

    # Wait until the fresh ripd is actually up and RIP is active on
    # r2-eth0; otherwise the ignorance assertions below would pass
    # trivially on a not-yet-converged daemon.
    def r2_rip_ready():
        output = r2.vtysh_cmd("show ip rip status")
        if not output or "Sending updates every" not in output:
            return "fresh r2 ripd is not sending updates yet"
        if "r2-eth0" not in output:
            return "r2-eth0 is not rip-enabled yet"
        return None

    _, result = topotest.run_and_expect(
        r2_rip_ready, None, count=LEARN_COUNT, wait=LEARN_WAIT
    )
    assert result is None, "fresh r2 ripd never became ready"

    # Observe several full update intervals: r2 must stay ignorant of both
    # prefixes the whole time, and r1 must stay silent for them on the wire
    # (skip, not poison, towards a neighbor that never had the route).
    proc = log = None
    pcap = os.path.join(tgen.logdir, "fresh_neighbor.pcap")
    try:
        proc, log, pcap = _start_capture(tgen, r2, "r2-eth0", "fresh_neighbor")
        deadline = time.time() + FRESH_IGNORE_INTERVALS * UPDATE_INTERVAL
        while time.time() < deadline:
            assert _rip_route_absent(
                r2, TARGET
            ), "fresh r2 learned TARGET although it is denied from birth"
            assert _rip_route_absent(
                r2, NEVER
            ), "fresh r2 learned NEVER although it is denied from birth"
            time.sleep(1)
    finally:
        _stop_capture(proc, log)

    assert not _rip_rib_has(
        r2, TARGET_ADDR
    ), "TARGET in fresh r2's RIP RIB (denied from birth)"
    assert not _rip_rib_has(
        r2, NEVER_ADDR
    ), "NEVER in fresh r2's RIP RIB (denied from birth)"

    packets = _parse_rip_pcap(pcap)
    _assert_poison_evidence(packets, expect_poison=False)

    # Anti-false-positive control: once the deny is lifted the fresh r2
    # must learn TARGET, proving the silence above was caused by the filter
    # and not by a broken RIP session.
    logger.info("Restoring %s on the fresh neighbor", PREFIX_ALLOW)
    _vtysh_rip(r1, [PREFIX_ALLOW])
    _expect_learn(r2, TARGET, "after lifting the deny on the fresh neighbor")


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["ripd", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
