#!/usr/bin/env python
#
# test_bfd_zapi_sbfd_topo1.py
#
# Verifies the ZAPI wire-payload extension: a ZEBRA_BFD_DEST_REGISTER
# message that carries the appended SBFD/SRv6 tail (bfd_mode, remote_discr,
# srv6_source_ipv6, seg_num, seg_list[], bfd_name) is decoded by bfdd and the
# resulting bfd_session reflects those fields. A second register without the
# SBFD tail acts as a back-compatibility regression check that the previous wire format
# senders are still accepted.
#
# Topology: single router r1 running zebra + bfdd. The test process opens
# zebra's ZAPI socket from inside r1's namespace via r1.popen("python3 -c"),
# performs the ZEBRA_HELLO + ZEBRA_BFD_CLIENT_REGISTER + ZEBRA_BFD_DEST_REGISTER
# handshake, and then asserts the bfdd-side session state via vtysh.

import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.common_config import required_linux_kernel_version
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]


# ZAPI wire-protocol constants — mirror lib/zclient.h / lib/route_types.txt.
ZSERV_PATH = "/var/run/frr/zserv.api"
ZEBRA_HEADER_MARKER = 254
ZSERV_VERSION = 6
ZEBRA_HEADER_SIZE = 10  # length(2)+marker(1)+version(1)+vrf(4)+command(2)

# enum bfd_mode_type from bfdd/bfd.h.
BFD_MODE_TYPE_BFD = 0
BFD_MODE_TYPE_SBFD_INIT = 2

VRF_DEFAULT = 0


# Parse ZAPI opcode + route-protocol values from the in-tree FRR headers
# when available, falling back to known-good hardcoded values otherwise.
#
# The FRR topotest container runs from a layout where the source headers
# aren't present at runtime (only the built binaries + topotests dir are
# shipped), so auto-derive is best-effort. When run from a source tree
# (developer workstation or a CI variant that mounts the source), the
# parsers self-heal across upstream opcode insertions that would otherwise
# silently shift positional values. The hardcoded fallbacks must stay in
# sync with FRR master and need a manual bump on the next upstream rebase
# — verify with:
#     grep -nE '^\s+ZEBRA_(HELLO|BFD_DEST_REGISTER|BFD_CLIENT_REGISTER),' \
#          lib/zclient.h
#     grep -E '^#define ZEBRA_ROUTE_SHARP' lib/route_types.h
_HARDCODED_OPCODES = {
    "ZEBRA_HELLO": 19,
    "ZEBRA_BFD_DEST_REGISTER": 27,
    "ZEBRA_BFD_CLIENT_REGISTER": 36,
    "ZEBRA_ROUTE_SHARP": 24,
}


def _frr_header(rel_path):
    return os.path.normpath(os.path.join(CWD, "..", "..", "..", rel_path))


def _parse_zapi_opcode(name):
    """Position of ``name`` in the (unnamed) ``typedef enum`` body in
    ``lib/zclient.h``.  Returns the hardcoded fallback if the header is
    not accessible at runtime (e.g. inside the topotest container).
    """
    try:
        with open(_frr_header("lib/zclient.h")) as fh:
            src = fh.read()
    except (FileNotFoundError, OSError):
        return _HARDCODED_OPCODES[name]
    m = re.search(r"typedef enum\s*\{(.*?)\}\s*;", src, re.DOTALL)
    if not m:
        return _HARDCODED_OPCODES[name]
    pos = 0
    for raw in m.group(1).splitlines():
        line = re.sub(r"/\*.*?\*/", "", raw).split("//")[0].strip().rstrip(",").strip()
        if not line:
            continue
        if "=" in line:
            entry, val = (x.strip() for x in line.split("=", 1))
            pos = int(val, 0)
        else:
            entry = line
        if entry == name:
            return pos
        pos += 1
    return _HARDCODED_OPCODES[name]


def _parse_route_type(name):
    """Value of a ``#define ZEBRA_ROUTE_xxx N`` line in ``lib/route_types.h``.
    Returns the hardcoded fallback if the header is not accessible.
    """
    pattern = re.compile(r"^#define\s+" + re.escape(name) + r"\s+(\d+)", re.MULTILINE)
    try:
        with open(_frr_header("lib/route_types.h")) as fh:
            m = pattern.search(fh.read())
    except (FileNotFoundError, OSError):
        return _HARDCODED_OPCODES[name]
    if not m:
        return _HARDCODED_OPCODES[name]
    return int(m.group(1))


ZEBRA_HELLO = _parse_zapi_opcode("ZEBRA_HELLO")
ZEBRA_BFD_DEST_REGISTER = _parse_zapi_opcode("ZEBRA_BFD_DEST_REGISTER")
ZEBRA_BFD_CLIENT_REGISTER = _parse_zapi_opcode("ZEBRA_BFD_CLIENT_REGISTER")
ZEBRA_ROUTE_SHARP = _parse_route_type("ZEBRA_ROUTE_SHARP")


def build_topo(tgen):
    tgen.add_router("r1")
    sw = tgen.add_switch("s1")
    sw.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)],
        )
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


# Inline Python script that runs inside r1's namespace, opens the ZAPI
# socket, performs the BFD client handshake, and emits one
# ZEBRA_BFD_DEST_REGISTER. Two forms are exercised, selected by argv[1]:
#   "sbfd"      — appends the SBFD tail (bfd_mode/seg_num/bfd_name).
#   "classical" — omits the tail entirely, mimicking a sender without the SBFD tail.
# Exit code 0 indicates the socket exchange succeeded; non-zero plus a
# diagnostic on stderr indicates a wire-level failure.
ZAPI_CLIENT_SCRIPT = r"""
import os, socket, struct, sys, time

ZSERV_PATH = "/var/run/frr/zserv.api"
ZEBRA_HEADER_MARKER = 254
ZSERV_VERSION = 6
ZEBRA_HEADER_SIZE = 10

ZEBRA_HELLO = __ZEBRA_HELLO__
ZEBRA_BFD_DEST_REGISTER = __ZEBRA_BFD_DEST_REGISTER__
ZEBRA_BFD_CLIENT_REGISTER = __ZEBRA_BFD_CLIENT_REGISTER__

BFD_MODE_TYPE_SBFD_INIT = 2
ZEBRA_ROUTE_SHARP = __ZEBRA_ROUTE_SHARP__
VRF_DEFAULT = 0


def header(command, vrf_id=VRF_DEFAULT):
    return struct.pack(
        "!HBBIH", ZEBRA_HEADER_SIZE, ZEBRA_HEADER_MARKER, ZSERV_VERSION,
        vrf_id, command,
    )


def finalize(buf):
    # length prefix at offset 0 covers the whole frame
    return struct.pack("!H", len(buf)) + buf[2:]


def send(sock, buf):
    sock.sendall(finalize(buf))


def hello(sock):
    buf = bytearray(header(ZEBRA_HELLO))
    buf += struct.pack("!B", ZEBRA_ROUTE_SHARP)     # redist_default
    buf += struct.pack("!H", 0)                     # instance
    buf += struct.pack("!I", 0)                     # session_id
    buf += struct.pack("!B", 0)                     # synchronous=false
    send(sock, buf)


def bfd_client_register(sock):
    buf = bytearray(header(ZEBRA_BFD_CLIENT_REGISTER))
    buf += struct.pack("!I", os.getpid())
    send(sock, buf)


def bfd_dest_register(sock, kind, dst_addr):
    # Mirrors lib/bfd.c::zclient_bfd_command, HAVE_BFDD path. Encodes a
    # multihop IPv6 register so the body length is identical between the
    # SBFD and classical variants up to the appended tail.
    buf = bytearray(header(ZEBRA_BFD_DEST_REGISTER))
    buf += struct.pack("!I", os.getpid())

    dst = socket.inet_pton(socket.AF_INET6, dst_addr)
    src = socket.inet_pton(socket.AF_INET6, "2001:db8:1::1")

    # Layout per lib/bfd.c::zclient_bfd_command (HAVE_BFDD path).
    # min_rx/min_tx are uint32; detection_multiplier, mhop, hops, ifname_len,
    # cbit and profile_len are each uint8. The stream_putc/stream_putl mix
    # is easy to misencode from Python; keep the sizes lined up below.
    buf += struct.pack("!H", socket.AF_INET6) + dst       # dst family + addr
    buf += struct.pack("!II", 300000, 300000)             # min_rx, min_tx
    buf += struct.pack("!B", 3)                           # det_mult
    buf += struct.pack("!B", 1)                           # is_multihop = 1
    buf += struct.pack("!H", socket.AF_INET6) + src       # src family + addr
    buf += struct.pack("!B", 1)                           # hops/ttl
    buf += struct.pack("!B", 0)                           # ifname_len = 0 (mhop)
    buf += struct.pack("!B", 0)                           # cbit
    buf += struct.pack("!B", 0)                           # profile_len = 0

    if kind == "sbfd":
        # Optional-field tail with BFD_REGEXT_FLAG_* indicating which fields
        # follow. Mirrors the encoder in lib/bfd.c::zclient_bfd_command.
        BFD_REGEXT_FLAG_BFD_MODE     = 0x0001
        BFD_REGEXT_FLAG_REMOTE_DISCR = 0x0002
        BFD_REGEXT_FLAG_SRV6_SOURCE  = 0x0004
        BFD_REGEXT_FLAG_SEG_LIST     = 0x0008
        BFD_REGEXT_FLAG_BFD_NAME     = 0x0010

        seg_list = [
            socket.inet_pton(socket.AF_INET6, "2001:db8:a::100"),
            socket.inet_pton(socket.AF_INET6, "2001:db8:a::200"),
        ]
        bfd_name = b"zapi-sbfd-test"

        flags = (BFD_REGEXT_FLAG_BFD_MODE
                 | BFD_REGEXT_FLAG_REMOTE_DISCR
                 | BFD_REGEXT_FLAG_SRV6_SOURCE
                 | BFD_REGEXT_FLAG_SEG_LIST
                 | BFD_REGEXT_FLAG_BFD_NAME)
        buf += struct.pack("!H", flags)                     # bfd_regext_flags
        buf += struct.pack("!B", BFD_MODE_TYPE_SBFD_INIT)   # bfd_mode
        buf += struct.pack("!I", 0x000186A0)                # remote_discr = 100000
        buf += src                                          # srv6_source_ipv6
        buf += struct.pack("!B", len(seg_list))             # seg_num
        for sid in seg_list:
            buf += sid
        buf += struct.pack("!B", len(bfd_name)) + bfd_name
    elif kind == "classical":
        # A sender without the optional tail: no tail bytes at all.
        pass
    else:
        raise SystemExit("unknown kind {!r}".format(kind))

    send(sock, buf)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: {} sbfd|classical <dst-ipv6>".format(sys.argv[0]))
    kind = sys.argv[1]
    dst_addr = sys.argv[2]

    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(ZSERV_PATH)
            break
        except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
            last_err = exc
            time.sleep(0.2)
    else:
        raise SystemExit("zserv connect failed: {}".format(last_err))

    try:
        hello(sock)
        bfd_client_register(sock)
        bfd_dest_register(sock, kind, dst_addr)
        # Give zebra a beat to forward the register to bfdd before we close.
        time.sleep(0.5)
    finally:
        sock.close()


main()
"""


# Substitute the wire-protocol constants the embedded script needs.
# Done as a string-replace (rather than .format()) because the script
# body contains literal "{}" inside its own format() calls.
for _ph, _val in (
    ("__ZEBRA_HELLO__", ZEBRA_HELLO),
    ("__ZEBRA_BFD_DEST_REGISTER__", ZEBRA_BFD_DEST_REGISTER),
    ("__ZEBRA_BFD_CLIENT_REGISTER__", ZEBRA_BFD_CLIENT_REGISTER),
    ("__ZEBRA_ROUTE_SHARP__", ZEBRA_ROUTE_SHARP),
):
    ZAPI_CLIENT_SCRIPT = ZAPI_CLIENT_SCRIPT.replace(_ph, str(_val))


def _run_zapi_client(net_node, kind, dst_addr):
    """Run the inline ZAPI client inside `net_node`'s network namespace.

    `net_node` is the mininet Router (tgen.net[name]) — it exposes `cmd`
    without the higher-level TopoRouter wrappers. The inline script
    raises SystemExit on ZAPI handshake failure, but `cmd()` swallows
    the exit code; we append a sentinel echo so the caller can surface
    a real diagnostic instead of silently timing out at `_wait_for_peer`.
    """
    script = ZAPI_CLIENT_SCRIPT.replace("'", "'\\''")
    output = net_node.cmd(
        "python3 -c '{}' {} {} 2>&1; echo __ZAPI_EXIT__=$?".format(
            script, kind, dst_addr))
    assert "__ZAPI_EXIT__=0" in output, (
        "ZAPI client ({} -> {}) failed; output:\n{}".format(
            kind, dst_addr, output))
    return output


def _show_bfd_peers(net_node):
    """Read bfdd's session table as JSON; return list of peer dicts."""
    raw = net_node.cmd("vtysh -c 'show bfd peers json'")
    raw = raw.strip()
    if not raw:
        return []
    return json.loads(raw)


def _wait_for_peer(net_node, predicate, timeout=10.0):
    """Poll `show bfd peers json` until predicate matches one peer."""
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        last = _show_bfd_peers(net_node)
        for peer in last:
            if predicate(peer):
                return peer
        time.sleep(0.3)
    raise AssertionError(
        "no bfd peer matched predicate within {}s; last seen: {}".format(
            timeout, last))


SBFD_DST = "2001:db8:2::1"
CLASSICAL_DST = "2001:db8:2::2"


def test_zapi_sbfd_register_creates_session():
    """
    Drive the new ZAPI tail end-to-end: a ZEBRA_BFD_DEST_REGISTER with
    `bfd_mode=SBFD_INIT` + a non-empty `bfd_name` + a 2-SID seg_list
    materialises as a bfdd session whose peer/source addresses match
    what was sent. `bfd_name` being preserved through the tail is the
    load-bearing assertion — it is the only new field already
    surfaced by `show bfd peers json` without bfdd-side debug counters.
    """
    if required_linux_kernel_version("4.5") is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net["r1"]
    _run_zapi_client(r1, "sbfd", SBFD_DST)

    peer = _wait_for_peer(
        r1, lambda p: p.get("peer") == SBFD_DST,
    )
    assert peer.get("bfd-name") == "zapi-sbfd-test", (
        "bfd_name from ZAPI SBFD tail not preserved: {!r}".format(peer))


def test_zapi_classical_register_still_accepted():
    """
    Back-compat: a register frame without the SBFD tail (the previous wire
    format, and the extended wire format that classical-BFD callers like
    BGP/OSPF continue to produce) must still create a
    working bfdd session. The decoder's `STREAM_READABLE > 0` gate is
    what enables this; the encoder's matching gate is what keeps
    classical-BFD wire bytes byte-for-byte unchanged.
    """
    if required_linux_kernel_version("4.5") is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net["r1"]
    _run_zapi_client(r1, "classical", CLASSICAL_DST)

    peer = _wait_for_peer(
        r1, lambda p: p.get("peer") == CLASSICAL_DST,
    )
    # Classical-BFD register: bfd_name was not carried, so the session
    # comes up without one. (Default formatting may omit the key
    # entirely or emit an empty string; accept both.)
    assert not peer.get("bfd-name"), (
        "classical register unexpectedly carries bfd-name: {!r}".format(peer))


def test_zapi_sbfd_register_deduplicates_by_bfd_name():
    """
    Re-registering the *same* SBFD session — same peer/local/vrf/bfd_name
    — must reuse the existing `bfd_session`. The load-bearing piece is
    that `bs_peer_find` uses `bpc->bfd_name` in the key; for that lookup
    to match the previously-inserted session, `ptm_bfd_sess_new` must
    also have populated `bs->key.bfdname` (set by the SBFD register path). Without
    that, a re-register would silently create a duplicate session and
    bfdd's peer count would grow on every flap.

    Self-contained: uses a distinct destination address so the test
    does not depend on other tests' session state and can be reordered
    or run in isolation.
    """
    if required_linux_kernel_version("4.5") is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net["r1"]
    dedupe_dst = "2001:db8:2::3"

    def count_with_dst(dst):
        return sum(1 for p in _show_bfd_peers(r1) if p.get("peer") == dst)

    # Issue two back-to-back identical SBFD registers; expect exactly
    # one session afterwards.
    _run_zapi_client(r1, "sbfd", dedupe_dst)
    _wait_for_peer(r1, lambda p: p.get("peer") == dedupe_dst)
    after_first = count_with_dst(dedupe_dst)
    assert after_first == 1, (
        "first SBFD register did not produce exactly one session "
        "(got {})".format(after_first))

    _run_zapi_client(r1, "sbfd", dedupe_dst)
    # Negative-test timing window: we're asserting that the count
    # *did not grow*, so there's no event to poll for. The inline
    # client already sleeps 0.5s post-send, and we add another 0.5s
    # here; on a loaded CI runner this can be bumped if the dedupe
    # assertion ever flakes.
    time.sleep(0.5)
    after_second = count_with_dst(dedupe_dst)
    assert after_second == 1, (
        "duplicate SBFD session created on same-name re-register "
        "(after_first={}, after_second={})".format(
            after_first, after_second))
