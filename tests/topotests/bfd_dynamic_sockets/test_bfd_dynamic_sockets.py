#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_dynamic_sockets.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bfd_dynamic_sockets.py: Verify that BFD listening sockets are created
dynamically when the first BFD session is configured and closed when the
last session is removed.

Topology:

    +----+    +----+
    | r1 |----| r2 |
    +----+    +----+

Both routers start with bfdd running but no BFD peers configured.
The test verifies:
 1. No BFD sockets are open at startup (no sessions configured).
 2. Adding a BFD peer causes single-hop and multi-hop sockets to be created.
 3. The BFD session comes up successfully.
 4. Enabling echo mode causes echo sockets to be created.
 5. Adding a second peer in the same VRF does not change the sockets.
 6. Removing the BFD peer causes all sockets to be closed.
 7. Re-adding a peer with echo mode re-opens all socket types.
"""

import os
import re
import sys
import time
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

# BFD well-known UDP ports
BFD_SINGLE_HOP_PORT = 3784
BFD_MULTI_HOP_PORT = 4784
BFD_ECHO_PORT = 3785


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("r1", "r2"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def bfd_socket_count(router, port):
    """Count the number of UDP sockets bound to the given port.

    Runs 'ss -ulpn' inside the router namespace and counts occurrences
    of the specified port in the output.
    """
    output = router.cmd("ss -ulpn sport = :{}".format(port))
    logger.info("ss output for port %d on %s:\n%s", port, router.name, output)
    # Count lines containing the port (skip the header line)
    count = 0
    for line in output.strip().splitlines():
        if ":{}".format(port) in line:
            count += 1
    return count


def get_socket_fds(router, port):
    """Return the sorted list of fd numbers for BFD UDP sockets on the given port.

    Parses 'ss -ulpn' output looking for entries like:
        users:(("bfdd",pid=12345,fd=15))
    and extracts the fd values.
    """
    output = router.cmd("ss -ulpn sport = :{}".format(port))
    fds = []
    for line in output.strip().splitlines():
        if ":{}".format(port) not in line:
            continue
        match = re.search(r"fd=(\d+)", line)
        if match:
            fds.append(int(match.group(1)))
    return sorted(fds)


def check_all_sockets_closed(router):
    """Check function for run_and_expect: returns None when all BFD sockets
    (single-hop, multi-hop, and echo) are closed."""
    shop = bfd_socket_count(router, BFD_SINGLE_HOP_PORT)
    mhop = bfd_socket_count(router, BFD_MULTI_HOP_PORT)
    echo = bfd_socket_count(router, BFD_ECHO_PORT)
    if shop == 0 and mhop == 0 and echo == 0:
        return None
    return "single-hop={}, multi-hop={}, echo={}".format(shop, mhop, echo)


def check_base_sockets_open(router):
    """Check function for run_and_expect: returns None when single-hop and
    multi-hop sockets are open."""
    shop = bfd_socket_count(router, BFD_SINGLE_HOP_PORT)
    mhop = bfd_socket_count(router, BFD_MULTI_HOP_PORT)
    if shop > 0 and mhop > 0:
        return None
    return "single-hop={}, multi-hop={}".format(shop, mhop)


def check_all_sockets_open(router):
    """Check function for run_and_expect: returns None when single-hop,
    multi-hop, and echo sockets are all open."""
    shop = bfd_socket_count(router, BFD_SINGLE_HOP_PORT)
    mhop = bfd_socket_count(router, BFD_MULTI_HOP_PORT)
    echo = bfd_socket_count(router, BFD_ECHO_PORT)
    if shop > 0 and mhop > 0 and echo > 0:
        return None
    return "single-hop={}, multi-hop={}, echo={}".format(shop, mhop, echo)


def test_no_sockets_at_startup():
    """Step 1: Assert no BFD sockets exist when no peers are configured."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that no BFD listening sockets exist at startup")

    for router in tgen.routers().values():
        shop = bfd_socket_count(router, BFD_SINGLE_HOP_PORT)
        mhop = bfd_socket_count(router, BFD_MULTI_HOP_PORT)
        echo = bfd_socket_count(router, BFD_ECHO_PORT)
        assertmsg = (
            '"{}" should have no BFD sockets but found single-hop={}, '
            "multi-hop={}, echo={}".format(router.name, shop, mhop, echo)
        )
        assert shop == 0 and mhop == 0 and echo == 0, assertmsg


def test_sockets_created_on_peer_add():
    """Step 2: Add a BFD peer and verify single-hop and multi-hop sockets
    are dynamically created."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding BFD peer on r1 and r2")

    # Configure BFD peer on r1 (no echo mode yet)
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.2
  no shutdown
 !
!
"""
    )

    # Configure BFD peer on r2 (no echo mode yet)
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.1
  no shutdown
 !
!
"""
    )

    logger.info("Verifying single-hop and multi-hop sockets are open on r1")
    test_func = partial(check_base_sockets_open, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" BFD base sockets not created after adding peer'
    assert result is None, assertmsg

    logger.info("Verifying single-hop and multi-hop sockets are open on r2")
    test_func = partial(check_base_sockets_open, tgen.gears["r2"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r2" BFD base sockets not created after adding peer'
    assert result is None, assertmsg

    # Echo sockets should NOT be open yet (echo mode not enabled)
    echo_r1 = bfd_socket_count(tgen.gears["r1"], BFD_ECHO_PORT)
    assertmsg = (
        '"r1" should have no echo sockets without echo-mode but found {}'.format(
            echo_r1
        )
    )
    assert echo_r1 == 0, assertmsg


def test_bfd_session_comes_up():
    """Step 3: Verify the BFD session comes up between r1 and r2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Waiting for BFD session to come up")

    expected = [{"peer": "192.168.0.2", "status": "up"}]
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show bfd peers json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" BFD session did not come up'
    assert result is None, assertmsg


def test_echo_sockets_created():
    """Step 4: Enable echo mode and verify echo sockets are created."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling echo-mode on r1 and r2")

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.2
  echo-mode
 !
!
"""
    )

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.1
  echo-mode
 !
!
"""
    )

    logger.info("Verifying echo sockets are now open on r1")
    test_func = partial(check_all_sockets_open, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" echo sockets not created after enabling echo-mode'
    assert result is None, assertmsg

    logger.info("Verifying echo sockets are now open on r2")
    test_func = partial(check_all_sockets_open, tgen.gears["r2"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r2" echo sockets not created after enabling echo-mode'
    assert result is None, assertmsg


def test_sockets_unchanged_on_second_session():
    """Step 5: Add a second BFD peer in the same VRF and verify the
    listening socket file descriptors are not changed (sockets are reused,
    not recreated)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Record current socket fds before adding the second peer.
    shop_fds_before = get_socket_fds(r1, BFD_SINGLE_HOP_PORT)
    mhop_fds_before = get_socket_fds(r1, BFD_MULTI_HOP_PORT)
    echo_fds_before = get_socket_fds(r1, BFD_ECHO_PORT)

    logger.info(
        "Socket fds before second peer: shop=%s mhop=%s echo=%s",
        shop_fds_before,
        mhop_fds_before,
        echo_fds_before,
    )

    # Add a second single-hop peer on r1 (peer address does not need to
    # respond -- the session will stay down, but the session_count will
    # increase and sockets must remain unchanged).
    logger.info("Adding second BFD peer (192.168.0.3) on r1")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.3
  no shutdown
 !
!
"""
    )

    # Give the daemon a moment to process.
    time.sleep(1)

    # Record socket fds after adding the second peer.
    shop_fds_after = get_socket_fds(r1, BFD_SINGLE_HOP_PORT)
    mhop_fds_after = get_socket_fds(r1, BFD_MULTI_HOP_PORT)
    echo_fds_after = get_socket_fds(r1, BFD_ECHO_PORT)

    logger.info(
        "Socket fds after second peer: shop=%s mhop=%s echo=%s",
        shop_fds_after,
        mhop_fds_after,
        echo_fds_after,
    )

    assertmsg = (
        "Single-hop socket fds changed after adding second peer: "
        "before={} after={}".format(shop_fds_before, shop_fds_after)
    )
    assert shop_fds_before == shop_fds_after, assertmsg

    assertmsg = (
        "Multi-hop socket fds changed after adding second peer: "
        "before={} after={}".format(mhop_fds_before, mhop_fds_after)
    )
    assert mhop_fds_before == mhop_fds_after, assertmsg

    assertmsg = (
        "Echo socket fds changed after adding second peer: "
        "before={} after={}".format(echo_fds_before, echo_fds_after)
    )
    assert echo_fds_before == echo_fds_after, assertmsg

    # Now remove the second peer -- first peer is still active so sockets
    # must stay open.
    logger.info("Removing second BFD peer (192.168.0.3) on r1")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 no peer 192.168.0.3
!
"""
    )

    time.sleep(1)

    # Sockets must still be open because the original peer remains.
    shop_fds_final = get_socket_fds(r1, BFD_SINGLE_HOP_PORT)
    mhop_fds_final = get_socket_fds(r1, BFD_MULTI_HOP_PORT)
    echo_fds_final = get_socket_fds(r1, BFD_ECHO_PORT)

    logger.info(
        "Socket fds after removing second peer: shop=%s mhop=%s echo=%s",
        shop_fds_final,
        mhop_fds_final,
        echo_fds_final,
    )

    assertmsg = (
        "Sockets should still be open after removing second peer "
        "(first peer still active): shop={} mhop={} echo={}".format(
            shop_fds_final, mhop_fds_final, echo_fds_final
        )
    )
    assert (
        shop_fds_final == shop_fds_before
        and mhop_fds_final == mhop_fds_before
        and echo_fds_final == echo_fds_before
    ), assertmsg


def test_all_sockets_closed_on_peer_remove():
    """Step 6: Remove the BFD peer and verify all sockets (single-hop,
    multi-hop, and echo) are closed."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing BFD peer on r1 and r2")

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
bfd
 no peer 192.168.0.2
!
"""
    )

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
bfd
 no peer 192.168.0.1
!
"""
    )

    logger.info("Verifying all BFD sockets are closed on r1")
    test_func = partial(check_all_sockets_closed, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" BFD sockets still open after removing all peers'
    assert result is None, assertmsg

    logger.info("Verifying all BFD sockets are closed on r2")
    test_func = partial(check_all_sockets_closed, tgen.gears["r2"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r2" BFD sockets still open after removing all peers'
    assert result is None, assertmsg


def test_all_sockets_reopen_on_new_peer():
    """Step 7: Re-add a BFD peer with echo mode and verify all socket types
    (single-hop, multi-hop, echo) re-open correctly."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-adding BFD peer with echo-mode on r1 and r2")

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.2
  echo-mode
  no shutdown
 !
!
"""
    )

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.1
  echo-mode
  no shutdown
 !
!
"""
    )

    logger.info("Verifying all socket types re-open on r1")
    test_func = partial(check_all_sockets_open, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" BFD sockets not re-created after adding peer with echo'
    assert result is None, assertmsg

    logger.info("Verifying BFD session comes up again")
    expected = [{"peer": "192.168.0.2", "status": "up"}]
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show bfd peers json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" BFD session did not come up on re-add'
    assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
