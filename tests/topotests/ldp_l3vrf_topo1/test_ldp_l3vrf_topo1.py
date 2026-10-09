#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ldp_l3vrf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by 6WIND
#

r"""
test_ldp_l3vrf_topo1.py: Test that ldpd ignores interfaces belonging to an
L3VRF.

      +----+ eth0 (default VRF, 10.0.1.0/24) +----+ 
      |    |---------------------------------|    |
      |    | eth1 (VRF vrf1, 10.0.2.0/24)    |    |
      | r1 |---------------------------------| r2 |
      |    | eth2 (default VRF, then         |    |
      |    | moved to vrf1, 10.0.3.0/24)     |    | 
      |    |---------------------------------|    |
      +----+                                 +----+

LDP is configured on eth0, eth1 and eth2 on each router.

zebra notifies ldpd of the interfaces and addresses of every VRF, at startup
and at runtime. 
ldpd only supports the default VRF and must ignore the other ones:
- eth1 is in vrf1 from startup: ldpd must never activate it, nor send LDP
  hellos on it;
- eth2 starts in the default VRF and forms an LDP adjacency, then is moved to
  vrf1: ldpd must deactivate it and never reactivate it.

Note that an LDP adjacency can never be formed over an L3VRF interface, even
when ldpd wrongly activates it: the LDP discovery socket belongs to the
default VRF and does not receive the packets from the L3VRF interfaces
(net.ipv4.udp_l3mdev_accept=0). Checking the adjacencies and neighbors is not
enough, the tests check the ldpd interface state and the packets actually
sent on the L3VRF segments.
"""

import os
import re
import sys
import json
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ldpd]

# router: remote LSR-ID
ROUTERS = {"r1": "2.2.2.2", "r2": "1.1.1.1"}

# LDP hello interval is 5s: a capture of this duration sees several hellos
HELLO_CAPTURE_TIME = 12


def build_topo(tgen):
    for rname in ROUTERS:
        tgen.add_router(rname)

    # default-VRF link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # L3VRF link
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # default-VRF link, moved to the L3VRF at runtime
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.net.add_l3vrf("vrf1", 10)
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "vrf1")

    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


#
# Helpers
#


def _vtysh_json(router, cmd):
    output = router.vtysh_cmd(cmd)
    try:
        return json.loads(output)
    except ValueError:
        logger.info("%s: invalid JSON output for '%s':\n%s", router.name, cmd, output)
        return {}


def _ldp_iface_state(router, ifname):
    "State of an interface in ldpd, None if ldpd has no such LDP interface."
    output = _vtysh_json(router, "show mpls ldp interface json")
    return output.get("{}: ipv4".format(ifname), {}).get("state")


def _ldp_hello_ifaces(router):
    "Interfaces on which ldpd sends LDP link hellos."
    output = _vtysh_json(router, "show mpls ldp discovery detail json")
    return set(output.get("interfaces", {}))


def _ldp_adj_ifaces(router):
    "Interfaces on which ldpd has an LDP link adjacency."
    output = _vtysh_json(router, "show mpls ldp discovery json")
    return {adj.get("interface") for adj in output.get("adjacencies", [])}


def _capture_ldp_packets(router, ifname):
    "Capture the LDP packets seen on an interface for HELLO_CAPTURE_TIME."
    rc, output, error = router.net.cmd_status(
        "timeout {} tcpdump -nnq -l -i {} udp port 646".format(
            HELLO_CAPTURE_TIME, ifname
        ),
        warn=False,
    )
    # timeout exits with 124 when it stops a capture that ran for the whole
    # duration: any other status, or no "listening on" banner, means that
    # tcpdump failed and the segment has not been checked.
    assert rc == 124 and "listening on {}".format(ifname) in error, (
        "{}: LDP packet capture on {} failed (exit status {}):\n{}".format(
            router.name, ifname, rc, error
        )
    )
    return [line for line in output.splitlines() if "UDP" in line]


def _check_l3vrf_iface_ignored(router, ifname):
    "ldpd must not activate an L3VRF interface, nor send hellos on it."
    state = _ldp_iface_state(router, ifname)
    if state == "ACTIVE":
        return "{}: L3VRF interface {} is ACTIVE in ldpd".format(router.name, ifname)
    if ifname in _ldp_hello_ifaces(router):
        return "{}: ldpd sends LDP hellos on L3VRF interface {}".format(
            router.name, ifname
        )
    if ifname in _ldp_adj_ifaces(router):
        return "{}: LDP adjacency over L3VRF interface {}".format(router.name, ifname)
    return None


def _check_no_ldp_on_segment(ifname_suffix):
    "No LDP packet may be seen on an L3VRF segment, from any of its ends."
    tgen = get_topogen()
    if not tgen.gears["r1"].cmd("which tcpdump").strip():
        logger.info("tcpdump not available, skipping the LDP packet capture")
        return
    for rname, router in tgen.routers().items():
        ifname = rname + ifname_suffix
        packets = _capture_ldp_packets(router, ifname)
        assert not packets, "{}: LDP packets seen on L3VRF interface {}:\n{}".format(
            rname, ifname, "\n".join(packets)
        )


def _check_neighbor_operational(router, remote_id):
    output = router.vtysh_cmd("show mpls ldp neighbor")
    if re.search(r"ipv4\s+{}\s+OPERATIONAL".format(re.escape(remote_id)), output):
        return None
    return "waiting for {} <-> {} LDP neighbor".format(router.name, remote_id)


def _check_adjacency(router, ifname, expected):
    present = ifname in _ldp_adj_ifaces(router)
    if present == expected:
        return None
    return "{}: LDP adjacency over {} {}".format(
        router.name, ifname, "missing" if expected else "still present"
    )


#
# Tests
#


def test_mpls_ldp_neighbor_establish():
    "Sanity check: the default-VRF links must establish an LDP session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, remote_id in ROUTERS.items():
        router = tgen.gears[rname]
        test_func = partial(_check_neighbor_operational, router, remote_id)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result

        # both default-VRF links carry an adjacency
        for ifname in (rname + "-eth0", rname + "-eth2"):
            test_func = partial(_check_adjacency, router, ifname, True)
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, result


def test_ldp_l3vrf_interface_ignored():
    "eth1 (VRF vrf1 from startup) must be ignored by ldpd, on both routers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        result = _check_l3vrf_iface_ignored(router, rname + "-eth1")
        assert result is None, result

    # With frr.conf, the LDP configuration is applied after ldpd has received
    # the initial interface dump from zebra, and the resync of the newly
    # configured interfaces only covers the default VRF: eth1 is never
    # activated at startup, even without L3VRF filtering. Flap eth1 so that
    # zebra sends runtime interface and address notifications for it.
    for rname, router in tgen.routers().items():
        router.cmd_raises("ip link set dev {}-eth1 down".format(rname))
    for rname, router in tgen.routers().items():
        router.cmd_raises("ip link set dev {}-eth1 up".format(rname))

    topotest.sleep(5, "waiting after flapping eth1")
    for rname, router in tgen.routers().items():
        result = _check_l3vrf_iface_ignored(router, rname + "-eth1")
        assert result is None, result

    _check_no_ldp_on_segment("-eth1")


def test_ldp_interface_moved_to_l3vrf():
    "eth2 moved from the default VRF to vrf1 must be deactivated by ldpd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # precondition: eth2 is an active LDP interface of the default VRF
    for rname, router in tgen.routers().items():
        ifname = rname + "-eth2"
        state = _ldp_iface_state(router, ifname)
        assert state == "ACTIVE", "{}: {} is {} in ldpd, expected ACTIVE".format(
            rname, ifname, state
        )

    # move eth2 to vrf1, keeping its IPv4 address
    for rname, router in tgen.routers().items():
        ifname = rname + "-eth2"
        addr = "10.0.3.{}/24".format(rname[1:])
        router.cmd_raises("ip link set dev {} master vrf1".format(ifname))
        router.cmd_raises("ip addr replace {} dev {}".format(addr, ifname))

    for rname, router in tgen.routers().items():
        ifname = rname + "-eth2"
        test_func = partial(_check_l3vrf_iface_ignored, router, ifname)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, result

    # let any late interface/address notification from zebra be processed,
    # then check that eth2 has not been reactivated
    topotest.sleep(HELLO_CAPTURE_TIME, "waiting after moving eth2 to vrf1")
    for rname, router in tgen.routers().items():
        result = _check_l3vrf_iface_ignored(router, rname + "-eth2")
        assert result is None, result

    _check_no_ldp_on_segment("-eth2")

    # the LDP session is still up through eth0
    for rname, remote_id in ROUTERS.items():
        result = _check_neighbor_operational(tgen.gears[rname], remote_id)
        assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
