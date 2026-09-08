#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_auth_replay_topo1.py
# Part of NetDEF Topology Tests
#

"""
test_bfd_auth_replay_topo1.py: sequence number validation for keyed SHA1
authentication (RFC 5880 Section 6.7.4).

        +---------+                        +---------+
        |         | eth-rt2        eth-rt1 |         |
        |   RT1   +------------------------+   RT2   |
        | 10.0.1.1|           s1           |10.0.1.2 |
        +---------+                        +---------+

RT1 runs bfdd with keyed SHA1 authentication. RT2 runs no BFD; it is the
namespace the scripted peer speaks from.

Two conforming implementations cannot exercise this, because neither will
emit a sequence number outside the window. The peer is therefore scripted
so that it can hold, rewind, or advance its sequence number, which is the
only way to tell a working replay window from one that never runs.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

KEY = "bfdauthkey123"
RT1_ADDR = "10.0.1.1"
RT2_ADDR = "10.0.1.2"

SEQ_ERROR = "rx-pkt-authentication-keyed-sha1-sequence-error"
SEQ_ERROR_METICULOUS = "rx-pkt-authentication-keyed-sha1-sequence-meticulous-error"


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt2", "rt2:eth-rt1"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def counters():
    "Authentication counters for the single session on rt1."
    rt1 = get_topogen().gears["rt1"]
    output = json.loads(rt1.vtysh_cmd("show bfd peers counters json"))
    return output[0] if output else {}


def counter(name):
    return counters().get(name, 0)


def peer_state():
    rt1 = get_topogen().gears["rt1"]
    output = json.loads(rt1.vtysh_cmd("show bfd peers json"))
    return output[0].get("status") if output else None


def run_peer(after_up="none", meticulous=False, by=400000, seconds=20,
             seq_start=None, hold_until_up=False):
    """Speak BFD from rt2 for `seconds`, misbehaving as asked once up."""
    rt2 = get_topogen().gears["rt2"]
    cmd = [
        sys.executable,
        os.path.join(CWD, "bfd_replay_peer.py"),
        "--local", RT2_ADDR,
        "--peer", RT1_ADDR,
        "--key", KEY,
        "--after-up", after_up,
        "--by", str(by),
        "--seconds", str(seconds),
    ]
    if seq_start is not None:
        cmd += ["--seq-start", str(seq_start)]
    if hold_until_up:
        cmd.append("--hold-until-up")
    if meticulous:
        cmd.append("--meticulous")
    logger.info("running scripted peer: %s", " ".join(cmd))
    return rt2.popen(cmd)


def expect_state(want, count=40, wait=0.5):
    test_func = lambda: peer_state() == want
    _, result = topotest.run_and_expect(test_func, True, count=count, wait=wait)
    assert result is True, "rt1 session did not reach {}, it is {}".format(
        want, peer_state()
    )


def expect_counter_above(name, floor, count=40, wait=0.5):
    test_func = lambda: counter(name) > floor
    _, result = topotest.run_and_expect(test_func, True, count=count, wait=wait)
    assert result is True, "{} did not rise above {}, it is {}".format(
        name, floor, counter(name)
    )


def skip_unless_ready():
    """Keyed SHA1 needs a build with crypto-openssl.

    Sequence numbers only exist in the cryptographic authentication
    types, so there is nothing here that a build without them can run.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled, skipping keyed SHA1 test")


def test_bfd_auth_session_comes_up():
    "A well behaved authenticated peer brings the session up."
    skip_unless_ready()

    peer = run_peer(after_up="none", seconds=25)
    expect_state("up")
    assert counter(SEQ_ERROR) == 0, "a conforming peer was refused on sequence"
    peer.terminate()
    peer.wait()


def test_bfd_auth_held_sequence_is_accepted():
    """A repeated sequence number is inside the keyed SHA1 window.

    RFC 5880 Section 6.7.4 makes the window bfd.RcvAuthSeq to
    bfd.RcvAuthSeq+(3*Detect Mult) inclusive, so a distance of zero is
    acceptable for the plain variant.
    """
    skip_unless_ready()

    before = counter(SEQ_ERROR)
    peer = run_peer(after_up="hold", seconds=25)
    expect_state("up")
    assert counter(SEQ_ERROR) == before, "a held sequence number was refused"
    peer.terminate()
    peer.wait()


def test_bfd_auth_rewound_sequence_is_refused():
    "A sequence number far behind the window is a replay and must be dropped."
    skip_unless_ready()

    expect_state("down", count=60)
    before = counter(SEQ_ERROR)
    peer = run_peer(after_up="rewind", by=400000, seconds=30)
    expect_state("up")
    expect_counter_above(SEQ_ERROR, before)
    # Nothing is being accepted any more, so detection expires.
    expect_state("down", count=60)
    peer.terminate()
    peer.wait()


def test_bfd_auth_advanced_sequence_is_refused():
    """A sequence number far past the window must be dropped too.

    Without the upper bound almost the whole number space is acceptable,
    and a peer that wraps is then refused for good.
    """
    skip_unless_ready()

    expect_state("down", count=60)
    before = counter(SEQ_ERROR)
    peer = run_peer(after_up="advance", by=2000000, seconds=30)
    expect_state("up")
    expect_counter_above(SEQ_ERROR, before)
    peer.terminate()
    peer.wait()


def test_bfd_auth_sequence_resynchronises():
    """The window is forgotten after twice the detection time.

    RFC 5880 Section 6.8.1 requires bfd.AuthSeqKnown to be cleared once
    nothing has been received for that long, so that a peer which
    restarted with a fresh sequence number is not locked out.
    """
    skip_unless_ready()

    expect_state("down", count=60)
    # A fresh peer picks an unrelated starting sequence, exactly as a
    # restarted implementation would.
    peer = run_peer(after_up="none", seconds=25)
    expect_state("up")
    peer.terminate()
    peer.wait()


def test_bfd_auth_sequence_may_wrap():
    """A sequence number that wraps past 2^32 is still inside the window.

    The window is an unsigned 32 bit circular space, so the step from
    0xffffffff to 0 is a distance of one and not a jump backwards. A
    linear comparison would refuse everything from here on.
    """
    skip_unless_ready()

    expect_state("down", count=60)
    # Held at six short of the wrap until something is accepted, so the
    # window is established there and the wrap falls inside the session
    # rather than while the previous window is still ageing out.
    peer = run_peer(after_up="none", seconds=40, seq_start=0xFFFFFFFA,
                    hold_until_up=True)
    expect_state("up")

    before = counter(SEQ_ERROR)
    accepted = counter("control-packet-input")
    # Wait on packets being accepted rather than on the clock, so the
    # session is known to have carried on well past the wrap.
    expect_counter_above("control-packet-input", accepted + 20)
    assert peer_state() == "up", "session dropped as the sequence number wrapped"
    assert counter(SEQ_ERROR) == before, "a wrapped sequence number was refused"
    peer.terminate()
    peer.wait()


def test_bfd_auth_meticulous_refuses_a_repeat():
    """Meticulous keyed SHA1 starts the window one past the last sequence.

    RFC 5880 Section 6.7.4 gives the meticulous variants a window of
    bfd.RcvAuthSeq+1 to bfd.RcvAuthSeq+(3*Detect Mult), so the repeat
    that the plain variant accepts must be refused here.
    """
    skip_unless_ready()

    expect_state("down", count=60)
    get_topogen().gears["rt1"].vtysh_cmd(
        """
        configure terminal
        key chain kc1
        key 1
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        bfd
        peer {} local-address {} interface eth-rt2
        authentication algorithm meticulous
        exit
        exit
        """.format(RT2_ADDR, RT1_ADDR)
    )

    before = counter(SEQ_ERROR_METICULOUS)
    peer = run_peer(after_up="hold", meticulous=True, seconds=30)
    expect_state("up")
    expect_counter_above(SEQ_ERROR_METICULOUS, before)
    expect_state("down", count=60)
    peer.terminate()
    peer.wait()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
