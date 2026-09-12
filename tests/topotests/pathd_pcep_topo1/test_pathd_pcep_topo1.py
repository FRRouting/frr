#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pathd_pcep_topo1.py
#
# Topotest for the FRR pathd PCEP (PCC) implementation and the
# standalone pcep_pcc binary shipped in pceplib/.
#
# Topology:
#
#                  +---------+
#                  |   pce   |   non-FRR Linux node
#                  |         |   - runs pce_sim.py (Python PCE)
#                  |         |   - also runs pcep_pcc (pceplib client)
#                  +----+----+
#                       | pce-eth0  10.10.10.100/24
#                       |
#                       sw1
#                       |
#                       | r1-eth0  10.10.10.1/24
#                  +----+----+
#                  |    r1   |   FRR with zebra + pathd (-M pathd_pcep)
#                  |   PCC   |
#                  +---------+
#
# What the test checks:
#
#   1. The basic FRR daemons are running on r1.
#   2. The PCEP session between FRR pathd (PCC) on r1 and the Python
#      PCE simulator running on the "pce" node reaches the operational
#      ("UP") state, exercising:
#         - pceplib (Open / Keepalive encoding & decoding, session FSM,
#           socket comm, timers)
#         - pathd's path_pcep_lib / path_pcep_controller / path_pcep_pcc
#           glue in FRR.
#   3. The standalone "pcep_pcc" binary built from pceplib/ also opens
#      a PCEP session against the same simulator (this exercises the
#      pcep_pcc.c code path and a second, independent flow through
#      pceplib).
#   4. The PCEP message counters reported by FRR are non-zero, proving
#      that real PCEP traffic flowed.
#   5. Tearing down the simulator brings the FRR session out of "UP"
#      state, exercising the dead-timer / disconnect paths.
#
# This test was added to drive coverage of FRR's PCEP / pceplib code,
# which is otherwise almost completely untested by the topotest suite.

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pathd]

# Where to find the pcep_pcc binary in a normal in-tree build.  The
# topotest framework runs FRR straight out of the build directory, so
# we look there first.
PCEP_PCC_PATH_CANDIDATES = [
    os.path.join(CWD, "../../../pceplib/pcep_pcc"),
    "/usr/lib/frr/pcep_pcc",
    "/usr/local/bin/pcep_pcc",
]

PCE_ADDR = "10.10.10.100"
R1_ADDR = "10.10.10.1"
PCE_PORT = 4189

# Globals used to plumb popen handles between setup_module and
# teardown_module.
pce_proc = None
pcep_pcc_proc = None
pce_log_path = None


def _find_pcep_pcc():
    for candidate in PCEP_PCC_PATH_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    return None


def build_topo(tgen):
    "Build the test topology."
    tgen.add_router("r1")
    tgen.add_router("pce")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["pce"])


def setup_module(mod):
    global pce_proc, pcep_pcc_proc, pce_log_path

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Load FRR's integrated configuration on r1 only.  pathd is auto-
    # detected (frr.conf carries a `candidate-path ...` line) but needs
    # the PCEP module loaded; pass that as an extra_daemons override so
    # the framework starts pathd with `-M pathd_pcep`.
    r1 = tgen.gears["r1"]
    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        extra_daemons=[(TopoRouter.RD_PATH, " -M pathd_pcep")],
    )

    # Set the IP/IPv6 addresses on the pce node *after* loading r1's
    # config but *before* tgen.start_router(), because start_router
    # actually flushes addresses on every gear (including non-FRR ones)
    # right before applying zebra.conf.  Wait, since "pce" has no zebra,
    # any addresses set before start_router() get flushed and never
    # restored.  So we configure pce *after* start_router() instead.
    tgen.start_router()

    tgen.gears["pce"].cmd("ip link set pce-eth0 up")
    tgen.gears["pce"].cmd("ip address add %s/24 dev pce-eth0" % PCE_ADDR)
    tgen.gears["pce"].cmd("ip -6 address add fd00:cafe::100/64 dev pce-eth0")

    # Pre-warm the ARP / ND caches between r1 and pce.  pceplib's TCP
    # connect uses a 250 ms timeout, which is too tight for a fresh
    # network namespace where the first packet has to wait for ARP.
    tgen.gears["r1"].cmd("ping -c 2 -W 1 -I r1-eth0 %s" % PCE_ADDR)
    tgen.gears["pce"].cmd("ping -c 2 -W 1 -I pce-eth0 %s" % R1_ADDR)

    # Now start the PCE simulator on the pce node.
    pce_log_path = os.path.join(tgen.logdir, "pce", "pce_sim.log")
    os.makedirs(os.path.dirname(pce_log_path), exist_ok=True)
    # Make sure the file exists before the PCE simulator (running as
    # root inside the namespace) writes to it.
    open(pce_log_path, "a").close()

    pce_sim = os.path.join(CWD, "pce", "pce_sim.py")
    tgen.gears["pce"].cmd("chmod u+x %s" % pce_sim)
    pce_proc = tgen.gears["pce"].popen(
        ["python3", pce_sim, "-p", str(PCE_PORT), "-k", "5", pce_log_path]
    )
    logger.info(
        "pce: pce_sim.py started, pid=%s, logging to %s",
        getattr(pce_proc, "pid", "?"),
        pce_log_path,
    )

    def _pce_listening():
        out = tgen.gears["pce"].cmd("ss -ltn 'sport = :%d'" % PCE_PORT)
        return ":%d" % PCE_PORT in out

    _, ok = topotest.run_and_expect(_pce_listening, True, count=20, wait=0.5)
    assert ok, "pce_sim did not start listening on port %d" % PCE_PORT


def teardown_module(mod):
    global pce_proc, pcep_pcc_proc

    tgen = get_topogen()

    for label, proc in (("pcep_pcc", pcep_pcc_proc), ("pce_sim", pce_proc)):
        if proc is None:
            continue
        logger.info("%s: terminating pid=%s", label, getattr(proc, "pid", "?"))
        try:
            proc.kill()
        except OSError:
            pass

    # Gracefully remove the pcep configuration so pathd has a chance to
    # free its PCEP / pceplib allocations before being killed.  Without
    # this, killing pathd while a PCEP session is up triggers more
    # "showing active allocations" memstats dumps than necessary.
    if "r1" in tgen.gears:
        try:
            tgen.gears["r1"].vtysh_cmd(
                "configure terminal\n"
                "segment-routing\n"
                " traffic-eng\n"
                "  no pcep\n"
                "  no policy color 1 endpoint 10.10.10.100\n"
                "  no segment-list SL1\n"
                "  no traffic-eng\n"
            )
        except Exception as e:
            logger.info("teardown: vtysh cleanup failed: %s", e)

    tgen.stop_topology()


def _show_pcep_session_json(rname):
    """Run 'show sr-te pcep session json' on `rname` and return the
    parsed JSON document, or {} if it did not parse."""
    tgen = get_topogen()
    out = tgen.gears[rname].vtysh_cmd("show sr-te pcep session json")
    try:
        return json.loads(out)
    except (ValueError, TypeError):
        return {}


def test_router_running():
    """Quick sanity check that all configured FRR daemons came up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    daemons = r1.vtysh_cmd("show daemons")
    assert "zebra" in daemons, "zebra not reported running on r1"
    assert "pathd" in daemons, "pathd not reported running on r1"


def test_pcep_session_pathd_up():
    """Wait for FRR pathd PCC to bring the PCEP session UP."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "pcepSessionsConfigured": 1,
        "pcepSessionsConnected": 1,
        "pcepSessions": [{"pceName": "PCE_SIM", "sessionStatus": "UP"}],
    }

    def _check():
        got = _show_pcep_session_json("r1")
        return topotest.json_cmp(got, expected)

    # FRR pathd retries with backoff (1s, 2s, 5s, 15s, 24s, ...).  In
    # the worst case the first successful TCP connect can be on the 5th
    # attempt at ~23s, plus a few more seconds for the Open exchange.
    # Allow up to 90s.
    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, "PCEP session did not reach UP state on r1: %s" % result


def test_pce_saw_session_from_pathd():
    """Verify the PCE simulator's log shows it received an Open from
    r1 and acknowledged it with a Keepalive."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check():
        try:
            with open(pce_log_path, "r") as fh:
                contents = fh.read()
        except (IOError, OSError) as e:
            return "Cannot read pce log %s: %s" % (pce_log_path, e)

        if "rx Open" not in contents:
            return "PCE never logged an incoming Open"
        if "tx Keepalive (ack PCC Open)" not in contents:
            return "PCE never logged sending the ack-Keepalive"
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


def test_pcep_pcc_binary():
    """Run the standalone pcep_pcc binary against the PCE simulator,
    and verify the simulator logs a second incoming session."""
    global pcep_pcc_proc

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pcep_pcc = _find_pcep_pcc()
    if pcep_pcc is None:
        pytest.skip(
            "pcep_pcc binary not found; was FRR built with "
            "--enable-pathd PCEP support?"
        )

    # Snapshot the log so we can detect *new* connections after we
    # launch pcep_pcc.
    try:
        with open(pce_log_path, "r") as fh:
            before = fh.read()
    except (IOError, OSError):
        before = ""

    # The pcep_pcc binary in pceplib/ defaults to source port 4999 and
    # destination port 4189.  We just point it at the simulator's
    # address on the pce node itself (loopback would also work but
    # going across the namespace's lo wouldn't be representative).
    cmd = [
        pcep_pcc,
        "-destip",
        PCE_ADDR,
        "-srcip",
        PCE_ADDR,
        "-srcport",
        "4999",
        "-destport",
        str(PCE_PORT),
    ]
    logger.info("pce: launching pcep_pcc: %s", " ".join(cmd))
    pcep_pcc_proc = tgen.gears["pce"].popen(cmd)

    def _pce_saw_pcc_binary():
        try:
            with open(pce_log_path, "r") as fh:
                contents = fh.read()
        except (IOError, OSError) as e:
            return "Cannot read pce log: %s" % e

        new = contents[len(before) :]
        if "accept from" not in new:
            return "PCE simulator did not log a new accept after pcep_pcc"
        if "rx Open" not in new:
            return (
                "PCE simulator did not see an Open from pcep_pcc "
                "(new log:\n%s)" % new
            )
        return None

    _, result = topotest.run_and_expect(_pce_saw_pcc_binary, None, count=60, wait=1)
    assert result is None, result


def test_pcep_counters_nonzero():
    """The PCEP session info reported by FRR should reflect real
    Open / Keepalive traffic having flowed.

    NOTE: we deliberately do *not* invoke ``show sr-te pcep counters``
    here.  When run against a live PCEP session that command currently
    crashes pathd in `mt_count_free()` (lib/memory.c) on FRR's
    development build (asan-style memory accounting): a separate,
    pre-existing bug in pathd / pceplib's counters copy/free path.
    See `path_pcep_cli.c::path_pcep_cli_show_srte_pcep_counters` and
    `path_pcep_lib.c::copy_counter_group()`.  Once that is fixed we
    should switch this test to inspect that command's output directly.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check():
        # Use the per-PCE textual 'show sr-te pcep session' which
        # reports message statistics next to the session state -- this
        # path does not exercise the buggy counter copy/free.
        out = tgen.gears["r1"].vtysh_cmd("show sr-te pcep session PCE_SIM")
        if "Session Status UP" not in out:
            return "session not UP yet, output:\n%s" % out

        # The textual report includes a "Total" row for tx/rx
        # message counts.  We only need to see a positive number
        # somewhere on a line containing a known message-name
        # keyword like Open or KeepAlive.
        for line in out.splitlines():
            ll = line.strip()
            lower = ll.lower()
            if "open" in lower or "keepalive" in lower or "keep alive" in lower:
                for tok in ll.replace(":", " ").split():
                    if tok.isdigit() and int(tok) > 0:
                        return None
        return "No non-zero Open/KeepAlive counter found in:\n%s" % out

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


def test_pcep_session_goes_down_when_pce_dies():
    """Kill the PCE simulator and confirm the FRR side notices the
    session is no longer UP (exercise dead-timer / disconnect paths
    in pathd_pcep and pceplib)."""
    global pce_proc, pcep_pcc_proc

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if pcep_pcc_proc is not None:
        try:
            pcep_pcc_proc.kill()
        except OSError:
            pass
        pcep_pcc_proc = None

    if pce_proc is not None:
        logger.info("Killing pce_sim to force session teardown")
        try:
            pce_proc.kill()
        except OSError:
            pass
        pce_proc = None

    # Also nuke any lingering python3 (the sim) on the pce node, in
    # case popen.kill() only killed the wrapper.
    tgen.gears["pce"].cmd("pkill -9 -f pce_sim.py || true")

    expected = {"pcepSessionsConnected": 0}

    def _check():
        got = _show_pcep_session_json("r1")
        return topotest.json_cmp(got, expected)

    # FRR's default dead-timer is several seconds; configured to 20s
    # in our pathd.conf.  Allow up to 60s for the session to drop.
    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "PCEP session did not drop after PCE was killed: %s" % result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
