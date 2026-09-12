#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test RIPng source address selection per RFC 2080 sections 2.4.1 and 2.5.2.

- Periodic Responses must use a designated link-local source address of
  the sending interface: neighbors store that address as the next hop
  of the advertised routes (section 2.5.2).
- A reply to a unicast Request from a port other than the RIPng port
  must use a globally valid source address, because the requestor may
  not reside on the directly attached network (section 2.4.1).  When
  the interface has no globally valid address, such a reply must be
  refused instead of falling back to a link-local source.
"""

import glob
import os
import sys
import json

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripngd]

# Python snippet run inside r2: send a RIPng Request for the whole
# routing table (one RTE with prefix ::/0 and metric infinity) from a
# non-RIPng source port and print the source address of the reply, or
# TIMEOUT when no reply arrives.
_SEND_REQUEST_PY = r"""
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("2001:db8:2::1", 0))
s.settimeout(5)
rte = b"\x00" * 16 + b"\x00\x00" + b"\x00" + b"\x10"
s.sendto(b"\x01\x01\x00\x00" + rte, ("2001:db8:1::1", 521))
try:
    data, src = s.recvfrom(2048)
    print(src[0])
except socket.timeout:
    print("TIMEOUT")
"""


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _send_request_and_get_reply_source(r2):
    """Run the request snippet in r2 and return the reply source or TIMEOUT."""
    return r2.cmd(
        "cat > /tmp/ripng_request.py <<'PYEOF'\n%sPYEOF\n"
        "python3 /tmp/ripng_request.py" % _SEND_REQUEST_PY
    ).strip()


def test_ripng_periodic_update_uses_linklocal_source():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _dump_diagnostics():
        print("r1 interface addresses:")
        print(r1.vtysh_cmd("show interface r1-eth0"))
        print("r2 interface addresses:")
        print(r2.vtysh_cmd("show interface r2-eth0"))
        print("r2 RIPng table:")
        print(r2.vtysh_cmd("show ipv6 ripng"))
        print("r2 route 2001:db8:1::/64 json:")
        print(r2.vtysh_cmd("show ipv6 route 2001:db8:1::/64 json"))
        for router in (r1, r2):
            for log in glob.glob("%s/ripngd.log" % router.gearlogdir):
                print("%s ripngd log tail:" % router.name)
                print(open(log).read()[-3000:])

    def _check_ripng_running():
        # RIPng is only enabled on interfaces that have a link-local
        # address (ripng_if_ipv6_lladdress_check), and the kernel
        # generates that address asynchronously after the veth comes
        # up.  Wait until r2's own interface prefix appears in its
        # RIPng table before checking what it learned from r1.
        out = r2.vtysh_cmd("show ipv6 ripng")
        if "2001:db8:2::/64" in out:
            return None
        return "r2 RIPng table has no interface prefix yet"

    _, result = topotest.run_and_expect(
        _check_ripng_running, None, count=120, wait=1
    )
    if result is not None:
        _dump_diagnostics()
    assert result is None, (
        "r2 never enabled RIPng on r2-eth0: %s" % result
    )

    def _check_nexthop():
        output = json.loads(r2.vtysh_cmd("show ipv6 route json"))
        for route in output.get("2001:db8:1::/64", []):
            if route.get("protocol") != "ripng":
                continue
            for nexthop in route.get("nexthops", []):
                if nexthop.get("ip", "").startswith("fe80:"):
                    return None
        return "no RIPng route with a link-local next hop"

    _, result = topotest.run_and_expect(_check_nexthop, None, count=180, wait=1)
    if result is not None:
        _dump_diagnostics()
    assert result is None, (
        "the next hop of the RIPng route 2001:db8:1::/64 is not the "
        "link-local source address of r1's periodic update: %s" % result
    )


def test_ripng_unicast_request_uses_global_source():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step(
        "Send a Request from a non-RIPng port: r1 must reply with the "
        "globally valid source address 2001:db8:1::1 (RFC 2080 section 2.4.1)"
    )
    reply_source = _send_request_and_get_reply_source(r2)
    assert reply_source == "2001:db8:1::1", (
        "expected the reply source to be the global address 2001:db8:1::1, "
        "got %r" % reply_source
    )


def test_ripng_unicast_request_refused_without_global_source():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Remove the global address of r1-eth0: no globally valid source remains")
    r1.vtysh_cmd(
        """
configure terminal
    interface r1-eth0
        no ipv6 address 2001:db8:1::1/64
"""
    )

    try:
        step(
            "A Request from a non-RIPng port must not be answered with a "
            "link-local source: r1 refuses to reply"
        )
        reply_source = _send_request_and_get_reply_source(r2)
        assert reply_source == "TIMEOUT", (
            "expected r1 to refuse the reply when no globally valid source "
            "address exists, got reply from %r" % reply_source
        )
    finally:
        r1.vtysh_cmd(
            """
configure terminal
    interface r1-eth0
        ipv6 address 2001:db8:1::1/64
"""
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
