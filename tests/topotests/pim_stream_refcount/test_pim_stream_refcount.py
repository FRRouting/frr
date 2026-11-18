#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_stream_refcount.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_stream_refcount.py: test the (S,G) upstream stream reference.

The keepalive timer expiry releases one upstream reference for the source
stream. These tests check that the kernel upcalls handling a stream take
exactly one reference for it:

- WRONGVIF realigning the input interface of an upstream created by a join
  (no stream reference yet) must take it, otherwise the expiry releases the
  join reference and deletes the upstream while it is still joined.
- Repeated NOCACHE upcalls for an existing upstream must not take more than
  one, otherwise the upstream is never deleted. On a non-DR of the source
  LAN they must not take any (the upstream already has an owner).

Taking the stream reference (on WRONGVIF) must also set up the register
state, otherwise it waits for the keepalive timer expiry.

Topology:

    r2 (source) ---- r1-eth0
    r2 (source) ---- r1-eth1 (PIM passive, alternate ingress)
                     r1-eth2 ---- r3 (receiver, no PIM)
    r2 (source) ---- r1-eth3 (not DR)
                 |
                 r4 (PIM DR, RP)
"""

import os
import re
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

app_helper = McastTesterHelper()


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r2"),
        "s3": ("r1", "r3"),
        "s4": ("r1", "r2", "r4"),
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # `ip mroute` doesn't make the config loader start staticd.
    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config(extra_daemons=["staticd"])

    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def expect_upstream(router, group, source, state, count=30, wait=2):
    "Wait for the (S,G) upstream to match `state` (`None` means removed)."

    def check_upstream():
        output = router.vtysh_cmd("show ip pim upstream json", isjson=True)
        upstream = output.get(group, {}).get(source)
        if state is None:
            return upstream
        if upstream is None:
            return f"({source},{group}) upstream not found"
        return topotest.json_cmp(upstream, state)

    _, result = topotest.run_and_expect(check_upstream, None, count=count, wait=wait)
    assert result is None, f"Router {router.name} ({source},{group}) upstream: {result}"


def watch_nocache_upcalls(router, ifname, group, source, start, max_refcount):
    """
    Call `start` (to send the stream) and check the (S,G) upstream reference
    count doesn't exceed `max_refcount` until the kernel repeats the NOCACHE
    upcall (every 10 seconds) on `ifname`. The upcalls are only visible in
    the debug log: read what is logged from now on.
    """
    upcall = re.compile(
        r"pim kernel upcall NOCACHE .* for \(S,G\)="
        rf"\({re.escape(source)},{re.escape(group)}\) on {re.escape(ifname)} "
    )
    log_path = os.path.join(router.net.logdir, router.name, "pimd.log")
    upcalls = 0
    with open(log_path, errors="replace") as log:
        log.seek(0, os.SEEK_END)
        router.vtysh_cmd("debug mroute")
        try:
            start()
            partial = ""
            for _ in range(30):
                # Read the log first: pimd answers vtysh after handling
                # the upcalls it logged.
                lines = (partial + log.read()).split("\n")
                partial = lines.pop()
                upcalls += sum(1 for line in lines if upcall.search(line))

                output = router.vtysh_cmd("show ip pim upstream json", isjson=True)
                upstream = output.get(group, {}).get(source)
                assert upstream is not None, f"({source},{group}) upstream not found"
                assert (
                    upstream["refCount"] <= max_refcount
                ), f"({source},{group}) reference leak: {upstream['refCount']}"
                if upcalls >= 2:
                    break
                time.sleep(1)
        finally:
            router.vtysh_cmd("no debug mroute")

    assert upcalls >= 2, f"({source},{group}) NOCACHE upcalls seen: {upcalls}"


def test_wrongvif_stream_reference():
    """
    The receiver joins (S,G) before data, so the upstream exists without a
    stream reference. Data then arrives on the alternate ingress (also
    connected to the source) and WRONGVIF realigns the input interface:
    it must take the stream reference so the keepalive timer expiry
    doesn't release the join reference.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "232.1.1.1"
    source = "10.20.1.4"

    app_helper.run("r3", [f"--source={source}", group, "r3-eth0"])
    expect_upstream(r1, group, source, {"inboundInterface": "r1-eth0", "refCount": 1})

    app_helper.run("r2", ["--send=0.5", group, "r2-eth1"])
    expect_upstream(r1, group, source, {"inboundInterface": "r1-eth1", "refCount": 2})

    # Stream stopped: the keepalive timer expiry must only release the
    # stream reference, the join keeps the upstream.
    app_helper.stop_host("r2")
    expect_upstream(
        r1,
        group,
        source,
        {"refCount": 1, "keepaliveTimer": "--:--:--"},
        count=60,
    )

    app_helper.stop_host("r3")
    expect_upstream(r1, group, source, None)


def test_wrongvif_register():
    """
    The (S,G) upstream of an ASM group is joined before data (connected
    source), so it has neither a stream reference nor register state. Data
    then arrives on the alternate ingress and WRONGVIF realigns the input
    interface: taking the stream reference must also set up the register
    state, not leave it to the keepalive timer expiry or the upstream scan.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "239.1.1.1"
    source = "10.20.1.4"

    # IGMPv3 (S,G) reports in the ASM range don't create PIM state.
    r1.vtysh_cmd(
        f"""
        configure terminal
         interface r1-eth2
          ip igmp static-group {group} {source}
        """
    )
    expect_upstream(
        r1,
        group,
        source,
        {"inboundInterface": "r1-eth0", "joinState": "Joined", "regState": "RegNoInfo"},
    )

    app_helper.run("r2", ["--send=0.5", group, "r2-eth1"])

    # The upstream scan (every 31 seconds) would set up the register state
    # later too: check the first state seen after the realignment, which
    # handles the register state in the same upcall.
    upstream = None
    for _ in range(60):
        output = r1.vtysh_cmd("show ip pim upstream json", isjson=True)
        upstream = output.get(group, {}).get(source)
        assert upstream is not None, f"({source},{group}) upstream not found"
        if upstream["inboundInterface"] == "r1-eth1":
            break
        time.sleep(0.5)

    # The RP (no receivers) answers with a Register-Stop.
    if upstream["regState"] == "RegPrune":
        upstream["regState"] = "RegJoined"
    result = topotest.json_cmp(
        upstream,
        {
            "inboundInterface": "r1-eth1",
            "firstHopRouter": True,
            "regState": "RegJoined",
        },
    )
    assert result is None, f"Router r1 ({source},{group}) upstream: {result}"

    app_helper.stop_host("r2")
    r1.vtysh_cmd(
        f"""
        configure terminal
         interface r1-eth2
          no ip igmp static-group {group} {source}
        """
    )
    # Waits for the keepalive timer expiry to release the stream reference.
    expect_upstream(r1, group, source, None, count=60)


def test_nocache_stream_reference():
    """
    The receiver joins (S,G) before data and the source MRIB route points
    to the receiver interface (no PIM neighbor): the upstream has no RPF
    interface so the MFC is never installed and the kernel repeats the
    NOCACHE upcall (every 10 seconds) for the connected source. Only the
    first one must take the stream reference, otherwise the upstream is
    never deleted.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "232.1.1.2"
    source = "192.168.1.2"

    app_helper.run("r3", [f"--source={source}", group, "r3-eth0"])
    expect_upstream(r1, group, source, {"inboundInterface": "Unknown", "refCount": 1})

    # A late upcall lets the keepalive timer expire and release the
    # reference (until the next upcall), a leak takes more than one.
    watch_nocache_upcalls(
        r1,
        "r1-eth0",
        group,
        source,
        lambda: app_helper.run("r2", ["--send=0.5", group, "r2-eth0"]),
        max_refcount=2,
    )
    expect_upstream(r1, group, source, {"firstHopRouter": True, "refCount": 2})

    app_helper.stop_host("r2")
    expect_upstream(
        r1,
        group,
        source,
        {"refCount": 1, "keepaliveTimer": "--:--:--"},
        count=60,
    )

    app_helper.stop_host("r3")
    expect_upstream(r1, group, source, None)


def test_nocache_non_dr_stream_reference():
    """
    Same as the NOCACHE test above, but r1 isn't the DR of the source LAN:
    the upstream already has an owner (the join), so the repeated NOCACHE
    upcalls must not take any reference: nothing would release them.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "232.1.1.3"
    source = "192.168.4.2"

    def check_dr():
        output = r1.vtysh_cmd("show ip pim interface r1-eth3 json", isjson=True)
        return topotest.json_cmp(output, {"r1-eth3": {"drAddress": "192.168.4.4"}})

    _, result = topotest.run_and_expect(check_dr, None, count=30, wait=2)
    assert result is None, f"r4 is not the DR of r1-eth3: {result}"

    app_helper.run("r3", [f"--source={source}", group, "r3-eth0"])
    expect_upstream(r1, group, source, {"inboundInterface": "Unknown", "refCount": 1})

    watch_nocache_upcalls(
        r1,
        "r1-eth3",
        group,
        source,
        lambda: app_helper.run("r2", ["--send=0.5", group, "r2-eth2"]),
        max_refcount=1,
    )

    app_helper.stop_host("r2")
    app_helper.stop_host("r3")
    expect_upstream(r1, group, source, None)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
