#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
test_nhrp_unique.py: Test the NHRP U-bit (uniqueness qualifier).

RFC 2332 section 5.2.3 requires the NHS to reject a Registration
Request that carries the uniqueness qualifier (U-bit) when the cache
already holds a unique binding for the same protocol address from
another peer, with Code 14 (Unique Internetworking Layer Address
Already Registered).  The rejected request must not update the cache.

The test runs two clients that register the same protocol address
172.16.1.4/32 with the same NHS.  The first registration wins; the
second one is rejected with Code 14 and its registration retries must
never displace the winning binding.
"""

import os
import sys
import json
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.nhrpd]

TOPOLOGY = """
                        nhc1 (172.16.1.4/32)      nhc2 (172.16.1.4/32)
                                | 10.2.1.2                | 10.2.1.3
                                +----+        +-----------+
                                     |        |
                                +-----+-------+----+
                                |       s1        |
                                |   10.2.1.0/24   |
                                +--------+--------+
                                         | 10.2.1.1
                                   nhs1 (172.16.1.1/32)
"""


def build_topo(tgen):
    "Build function"

    # Create 3 routers.
    for rname in ("nhs1", "nhc1", "nhc2"):
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["nhs1"])
    switch.add_link(tgen.gears["nhc1"])
    switch.add_link(tgen.gears["nhc2"])


def _populate_iface():
    tgen = get_topogen()
    cmds_tot = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.2.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for rname, addr in (("nhs1", "1"), ("nhc1", "2"), ("nhc2", "3")):
        for cmd in cmds_tot:
            input = cmd.format(rname, addr)
            logger.info("input: " + input)
            output = tgen.net[rname].cmd(input)
            logger.info("output: " + output)


def setup_module(mod):
    result = required_linux_kernel_version("4.18")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _populate_iface()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _cache_table(router):
    """Return the table of show ip nhrp cache json, or [] on failure."""
    try:
        return json.loads(router.vtysh_cmd("show ip nhrp cache json")).get(
            "table", []
        )
    except (ValueError, TypeError):
        return []


def test_unique_registration_conflict():
    """
    Two clients register the same protocol address with the NHS.

    The first registration wins and its binding must stay in the NHS
    cache.  The second client's registration carries the U-bit and must
    be rejected (Code 14): its retries must not displace the winning
    binding, and it must never obtain an NHS cache entry of its own.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    nhs1 = tgen.gears["nhs1"]
    nhc1 = tgen.gears["nhc1"]
    nhc2 = tgen.gears["nhc2"]

    # Convergence: the NHS must hold exactly one dynamic binding for
    # the shared protocol address 172.16.1.4.
    def _check_converged():
        dyn = [
            e
            for e in _cache_table(nhs1)
            if e.get("type") == "dynamic" and e.get("protocol") == "172.16.1.4"
        ]
        if len(dyn) == 1:
            return None
        return "NHS has %d dynamic entries for 172.16.1.4" % len(dyn)

    _, result = topotest.run_and_expect(_check_converged, None, count=60, wait=1)
    assert result is None, "NHS cache did not converge: %s" % result

    # The registration that won first is bound to one of the clients.
    winner_nbma = None
    for e in _cache_table(nhs1):
        if e.get("type") == "dynamic" and e.get("protocol") == "172.16.1.4":
            winner_nbma = e.get("nbma")
            break
    assert winner_nbma is not None, "NHS lost the binding for 172.16.1.4"
    assert winner_nbma in ("10.2.1.2", "10.2.1.3"), "unexpected NBMA %r" % (
        winner_nbma,
    )
    winner = nhc1 if winner_nbma == "10.2.1.2" else nhc2
    loser = nhc2 if winner is nhc1 else nhc1
    logger.info(
        "registration won by %s (NBMA %s), %s is rejected",
        winner.name,
        winner_nbma,
        loser.name,
    )

    # The winning client refreshes its unique registration every
    # holdtime/3 seconds; the losing client's conflicting registrations
    # must be rejected with Code 14 each time.  Watch for two holdtimes
    # so several refresh and retry cycles have happened.
    def _check_stable():
        dyn = [
            e
            for e in _cache_table(nhs1)
            if e.get("type") == "dynamic" and e.get("protocol") == "172.16.1.4"
        ]
        if len(dyn) != 1:
            return "NHS has %d dynamic entries for 172.16.1.4" % len(dyn)
        if dyn[0]["nbma"] != winner_nbma:
            return "binding moved from %s to %s" % (winner_nbma, dyn[0]["nbma"])
        return None

    _, result = topotest.run_and_expect(_check_stable, None, count=25, wait=1)
    assert result is None, "NHS binding did not stay unique: %s" % result

    # The winning client has registered the NHS in its own cache; the
    # losing client must not have obtained any NHS cache entry.
    win_nhs = [
        e
        for e in _cache_table(winner)
        if e.get("type") == "nhs" and e.get("protocol") == "172.16.1.1"
    ]
    assert win_nhs, "%s did not register the NHS" % winner.name

    lose_nhs = [e for e in _cache_table(loser) if e.get("type") == "nhs"]
    assert not lose_nhs, (
        "%s unexpectedly registered the NHS: %r" % (loser.name, lose_nhs)
    )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
