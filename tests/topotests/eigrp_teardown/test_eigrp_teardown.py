#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_eigrp_teardown.py
#
# Copyright (c) 2026 by
# Lee Clements
#

"""
test_eigrp_teardown.py: eigrpd must survive having EIGRP stopped underneath it.

r1 and r2 are joined by two links, so r2 advertises each link's subnet to r1
over the other link as well, and r2 has a stub subnet, 10.0.5.0/24, which r1
learns over both links.  r1 also has r1-eth2, which gets its address only
after the link is down, and r1-eth3, which no network statement covers at all.

Each test changes some running EIGRP state -- removes a whole process or a
network statement, resets neighbours, sets a filter, or stops the daemon --
and checks that eigrpd is still alive afterwards.
"""

import os
import re
import sys
import functools
import pytest

pytestmark = [pytest.mark.eigrpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

PEERS = {"10.0.1.2", "10.0.2.2"}

ROUTER_EIGRP = """
configure terminal
 router eigrp 1
  network 10.0.1.0/24
  network 10.0.2.0/24
"""


def build_topo(tgen):
    for name in ("r1", "r2"):
        tgen.add_router(name)

    # r1-eth0 <-> r2-eth0 and r1-eth1 <-> r2-eth1
    for name in ("s1", "s2"):
        switch = tgen.add_switch(name)
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

    # r1-eth2 and r1-eth3 are stubs
    for name in ("s3", "s4"):
        tgen.add_switch(name).add_link(tgen.gears["r1"])

    # r2-eth2 is the stub r1 learns over both links
    tgen.add_switch("s5").add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(daemons=["zebra", "eigrpd"])

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def assert_alive(router, after):
    result = router.check_router_running()
    assert result == "", "eigrpd on %s died after %s:\n%s" % (
        router.name,
        after,
        result,
    )


def neighbours(router):
    output = router.vtysh_cmd("show ip eigrp neighbors")
    return set(re.findall(r"^\d+\s+(\d+\.\d+\.\d+\.\d+)\s", output, re.M))


def wait_for_neighbours(router):
    test_func = functools.partial(neighbours, router)
    _, result = topotest.run_and_expect(test_func, PEERS, count=30, wait=1)
    assert result == PEERS, "%s has neighbours %r, expected %r" % (
        router.name,
        result,
        PEERS,
    )


def paths(router, prefix):
    """The 'via' lines listed for a prefix in show ip eigrp topology all-links."""
    output = router.vtysh_cmd("show ip eigrp topology all-links")
    vias, current = [], None
    for line in output.splitlines():
        match = re.match(r"^[PA]\s+(\S+),", line)
        if match:
            current = match.group(1)
            continue
        if current == prefix and "via " in line:
            vias.append(line.strip())
    return vias


def wait_for_both_paths(router):
    """r1 learns r2's stub subnet from r2 over each of the two links."""

    def _check():
        vias = paths(router, "10.0.5.0/24")
        return all(any(peer in v for v in vias) for peer in PEERS)

    _, result = topotest.run_and_expect(_check, True, count=30, wait=1)
    assert result is True, "%s does not learn 10.0.5.0/24 over both links: %r" % (
        router.name,
        paths(router, "10.0.5.0/24"),
    )


def instance_on(router, ifname):
    return ifname in router.vtysh_cmd("show ip eigrp interfaces")


def start_never_up_instance(r1):
    """
    Create an instance on r1-eth2 that is never brought up.

    Two details matter.  zebra withdraws an interface's addresses from the
    daemons when the interface goes down, but passes on an address added to
    one that is already down -- so the link goes down first and the address
    arrives afterwards.  And the address is added in the kernel, not through
    vtysh: configuring it in zebra brings the interface back up.
    """
    r1.run("ip link set r1-eth2 down")
    r1.run("ip addr replace 10.0.9.1/24 dev r1-eth2")
    r1.vtysh_cmd(
        """
        configure terminal
         router eigrp 1
          network 10.0.9.0/24
        """
    )
    test_func = functools.partial(instance_on, r1, "r1-eth2")
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert "r1-eth2 is down" in r1.vtysh_cmd(
        "show interface r1-eth2"
    ), "r1-eth2 came back up, so the instance on it is not a never-up one"
    assert result is True, (
        "no instance was created on the down r1-eth2\n"
        "--- show interface r1-eth2 ---\n%s\n"
        "--- show ip eigrp interfaces ---\n%s\n"
        "--- kernel ---\n%s"
        % (
            r1.vtysh_cmd("show interface r1-eth2"),
            r1.vtysh_cmd("show ip eigrp interfaces"),
            r1.run("ip -4 addr show dev r1-eth2"),
        )
    )


def test_premise_adjacency_on_both_links():
    "r1 peers with r2 over both links."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    wait_for_neighbours(tgen.gears["r1"])


def test_distribute_list_on_interface_without_eigrp():
    "A filter naming an interface EIGRP does not run on must not abort eigrpd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    assert not instance_on(r1, "r1-eth3"), "premise: EIGRP must not run on r1-eth3"

    r1.vtysh_cmd(
        """
        configure terminal
         router eigrp 1
          distribute-list prefix FILTER in r1-eth3
        """
    )
    assert_alive(r1, "distribute-list on an interface EIGRP does not run on")

    # Editing the prefix-list re-runs the same lookup from the filter hook.
    r1.vtysh_cmd(
        """
        configure terminal
         ip prefix-list FILTER seq 10 deny 10.98.0.0/16
        """
    )
    assert_alive(r1, "editing a prefix-list such a filter uses")

    r1.vtysh_cmd(
        """
        configure terminal
         router eigrp 1
          no distribute-list prefix FILTER in r1-eth3
        """
    )
    assert_alive(r1, "removing that distribute-list")


def test_clear_neighbors_with_never_up_instance():
    """
    Resetting adjacencies must cope with an instance that was never up.

    This names the interface rather than clearing every neighbour.  Both
    forms send a goodbye hello on the never-up instance, which is what this
    tests, but clearing every neighbour would also delete both of r2's
    adjacencies, and deleting the second runs DUAL over 10.0.5.0/24 while
    it still holds a descriptor naming the first, already freed -- issue
    #3530, a separate use-after-free that AddressSanitizer reports.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    start_never_up_instance(r1)

    r1.vtysh_cmd("clear ip eigrp neighbors r1-eth2")
    assert_alive(r1, "clear ip eigrp neighbors on an instance that was never up")


def test_no_network_on_never_up_instance():
    "Removing the network statement must free a never-up instance safely."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    start_never_up_instance(r1)

    r1.vtysh_cmd(
        """
        configure terminal
         router eigrp 1
          no network 10.0.9.0/24
        """
    )
    assert_alive(r1, "no network covering an instance that was never up")


def test_no_router_eigrp_with_live_adjacencies():
    """
    Removing the process must leave nothing behind that still fires or reads.

    The hello timer fires every second here, so a few seconds is many chances
    for one left armed on a freed instance to run.  Removing the process also
    deletes the neighbour on one link after the instance on the other link is
    freed, and that must not re-run DUAL over routes still pointing at the
    freed instance -- r2 advertises each link's subnet over the other link,
    and 10.0.5.0/24 over both, so there are such routes once r1 knows
    10.0.5.0/24 over both links.  The removal is repeated so that a process
    re-created on the same interfaces is torn down cleanly too.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for attempt in range(1, 4):
        wait_for_neighbours(r1)
        wait_for_both_paths(r1)

        r1.vtysh_cmd(
            """
            configure terminal
             no router eigrp 1
            """
        )
        topotest.sleep(4, "letting any timer left on a freed instance fire")
        assert_alive(r1, "no router eigrp (attempt %d)" % attempt)

        r1.vtysh_cmd(ROUTER_EIGRP)


def test_no_router_eigrp_with_pending_filter_timer():
    """
    Removing the process must also stop an interface's distribute-list timer.

    Setting a filter on an interface EIGRP runs on arms a timer that resends
    the interface's routes ten seconds later.  Removing the process inside
    those ten seconds frees the instance with that timer still armed.  The
    filter permits everything, so it changes nothing else.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    wait_for_neighbours(r1)

    r1.vtysh_cmd(
        """
        configure terminal
         router eigrp 1
          distribute-list prefix PERMIT in r1-eth0
        """
    )
    r1.vtysh_cmd(
        """
        configure terminal
         no router eigrp 1
        """
    )
    topotest.sleep(12, "letting the distribute-list timer come due")
    assert_alive(r1, "no router eigrp with an interface filter timer pending")

    r1.vtysh_cmd(ROUTER_EIGRP)


def test_shutdown_with_never_up_instance():
    "Stopping eigrpd must free a never-up instance safely."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    wait_for_neighbours(r1)
    start_never_up_instance(r1)

    errors = r1.net.stopRouter(assertOnError=False)
    assert not errors, "r1 did not stop cleanly with a never-up instance:\n%s" % errors


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
