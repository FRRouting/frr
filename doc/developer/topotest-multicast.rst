.. _topotest-multicast:

Multicast Testing in Topotests
===============================

FRR topotests provide several methods for generating multicast traffic and
simulating IGMP/MLD joins in test scenarios. This guide explains the different
approaches available, when to use each method, and provides examples.

Overview
--------

Multicast testing in FRR topotests involves two main operations:

1. **Sending multicast traffic** - Simulating a multicast source that sends
   UDP packets to a multicast group address
2. **Receiving multicast traffic (IGMP/MLD join)** - Simulating a host that
   joins a multicast group, which triggers IGMP/MLD JOIN messages

There are three main approaches available:

- **Direct script usage** - Using ``mcast-tx.py`` and ``mcast-rx.py`` scripts
  directly
- **Unified tester script** - Using ``mcast-tester.py`` directly
- **Helper class** - Using ``McastTesterHelper`` class (recommended for new tests)

Method 1: Direct Script Usage (mcast-tx.py / mcast-rx.py)
----------------------------------------------------------

The simplest approach uses two separate scripts:

- ``mcast-tx.py`` - Sends multicast UDP packets
- ``mcast-rx.py`` - Joins a multicast group (triggers IGMP JOIN)

**When to use:**
- Simple test cases with basic multicast send/receive needs
- Tests that need fine-grained control over packet timing and count
- Legacy tests or when you need minimal dependencies

**Example: Sending Multicast Traffic**

.. code-block:: python

    from lib.topogen import get_topogen

    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    CWD = os.path.dirname(os.path.realpath(__file__))

    # Send 40 multicast packets with TTL=5, interval=2ms
    r2.run(
        "{}/mcast-tx.py --ttl 5 --count 40 --interval 2 229.1.1.1 r2-eth0".format(CWD)
    )

**Example: Joining Multicast Group (IGMP Join)**

.. code-block:: python

    import os
    from lib.topogen import get_topogen

    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    CWD = os.path.dirname(os.path.realpath(__file__))

    # Join multicast group 229.1.1.2 on interface r2-eth0
    cmd = [os.path.join(CWD, "mcast-rx.py"), "229.1.1.2", "r2-eth0"]
    p = r2.popen(cmd)
    try:
        # ... perform test assertions ...
        pass
    finally:
        if p:
            p.terminate()
            p.wait()

**mcast-tx.py Options:**

- ``group`` - Multicast IP address (required)
- ``ifname`` - Interface name (required)
- ``--port`` - UDP port number (default: 1000)
- ``--ttl`` - Time-to-live (default: 20)
- ``--count`` - Number of packets to send (default: 1)
- ``--interval`` - Milliseconds between packets (default: 100)

**mcast-rx.py Options:**

- ``group`` - Multicast IP address (required)
- ``ifname`` - Interface name (required)
- ``--port`` - UDP port (default: 1000)
- ``--sleep`` - Time to sleep before stopping (default: 5)

**Reference Examples:**

- ``tests/topotests/pim_basic/test_pim.py::test_pim_send_mcast_stream()`` -
  Demonstrates sending multicast traffic
- ``tests/topotests/pim_basic/test_pim.py::test_pim_igmp_report()`` -
  Demonstrates IGMP join using mcast-rx.py

Method 2: Unified Tester Script (mcast-tester.py)
---------------------------------------------------

The ``mcast-tester.py`` script can act as both a sender and receiver,
supporting both IPv4 and IPv6.

**When to use:**
- Tests requiring IPv6 multicast (MLD)
- Tests needing source-specific multicast (SSM)
- Tests that need more advanced features than basic scripts

**Example: Using mcast-tester.py Directly**

.. code-block:: python

    import os
    from lib.topogen import get_topogen

    tgen = get_topogen()
    CWD = os.path.dirname(os.path.realpath(__file__))
    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")

    # Start multicast receiver
    cmd_r4 = [mcast_tester, "229.1.1.1", "r4-eth1"]
    p1 = tgen.gears["r4"].popen(cmd_r4)

    # Start multicast sender (sends every 0.7 seconds)
    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    cmd_tx = [mcast_tx, "--ttl", "10", "--count", "1000", "--interval", "1",
              "229.1.1.1", "r2-eth0"]
    p2 = tgen.gears["r2"].popen(cmd_tx)

    try:
        # ... perform test assertions ...
        pass
    finally:
        if p1:
            p1.terminate()
            p1.wait()
        if p2:
            p2.terminate()
            p2.wait()

**mcast-tester.py Options:**

- ``group`` - Multicast IP address (required)
- ``interface`` - Interface name (required)
- ``--port`` - UDP port (default: 1000)
- ``--ttl`` - TTL/hops for sending packets (default: 16)
- ``--send=<interval>`` - Transmit instead of join, with interval in seconds
- ``--source`` - Source address for multicast (SSM support)
- ``--socket`` - Point to topotest UNIX socket (for synchronization)

**Reference Examples:**

- ``tests/topotests/pim_override_behavior/test_pim_override_behavior.py`` -
  Uses mcast-tester.py for both receiver and sender

Method 3: McastTesterHelper Class (Recommended)
-------------------------------------------------

The ``McastTesterHelper`` class provides a high-level interface that manages
process lifecycle and cleanup automatically. This is the recommended approach
for new tests.

**When to use:**
- New test development (recommended)
- Tests requiring multiple hosts with joins/traffic
- Tests needing automatic cleanup
- Complex test scenarios with multiple multicast groups

**Example: Basic Usage**

.. code-block:: python

    from lib.pim import McastTesterHelper
    from lib.topogen import get_topogen

    tgen = get_topogen()

    # Initialize helper
    app_helper = McastTesterHelper(tgen)

    # Start IGMP join (receiver)
    result = app_helper.run_join("i1", "225.1.1.1", join_intf="l1-i1-eth1")
    assert result is True

    # Start multicast traffic (sender)
    result = app_helper.run_traffic("i2", "225.1.1.1", bind_intf="f1-i2-eth1")
    assert result is True

    # ... perform test assertions ...

    # Cleanup (stops all processes)
    app_helper.stop_all_hosts()

**Example: Using Context Manager**

.. code-block:: python

    from lib.pim import McastTesterHelper
    from lib.topogen import get_topogen

    tgen = get_topogen()

    with McastTesterHelper(tgen) as helper:
        # Start receiver
        helper.run("h1", ["239.100.0.1", "h1-eth0"])

        # Start sender
        helper.run("h2", ["--send=0.7", "239.100.0.1", "h2-eth0"])

        # ... perform test assertions ...
        # Processes are automatically cleaned up when exiting the context

**Example: Multiple Groups**

.. code-block:: python

    app_helper = McastTesterHelper(tgen)

    # Join multiple groups
    app_helper.run_join("i1", ["225.1.1.1", "225.1.1.2", "225.1.1.3"], "l1")

    # Send traffic to multiple groups
    app_helper.run_traffic("i2", ["225.1.1.1", "225.1.1.2"], "f1")

**McastTesterHelper Methods:**

- ``run_join(host, join_addrs, join_towards=None, join_intf=None)`` -
  Join multicast group(s). One of ``join_towards`` or ``join_intf`` must be set.
- ``run_traffic(host, send_to_addrs, bind_towards=None, bind_intf=None)`` -
  Send multicast traffic. One of ``bind_towards`` or ``bind_intf`` must be set.
- ``stop_all_hosts()`` - Stop all multicast processes
- ``stop_traffic_senders()`` - Stop only traffic senders, keep joins running

**Reference Examples:**

- ``tests/topotests/multicast_pim_sm_topo1/test_multicast_pim_sm_topo1.py`` -
  Comprehensive example using McastTesterHelper with multiple test cases
- ``tests/topotests/pim_igmp_vrf/test_pim_vrf.py`` -
  Uses McastTesterHelper with context manager for VRF testing

Comparison and Recommendations
--------------------------------

+----------------------+------------------+------------------+------------------+
| Feature              | Direct Scripts   | mcast-tester.py  | Helper Class     |
+======================+==================+==================+==================+
| IPv4 Support         | Yes              | Yes              | Yes              |
+----------------------+------------------+------------------+------------------+
| IPv6 Support         | No               | Yes              | Yes              |
+----------------------+------------------+------------------+------------------+
| SSM Support          | No               | Yes              | Yes              |
+----------------------+------------------+------------------+------------------+
| Process Management   | Manual           | Manual           | Automatic        |
+----------------------+------------------+------------------+------------------+
| Cleanup Handling     | Manual           | Manual           | Automatic        |
+----------------------+------------------+------------------+------------------+
| Multiple Groups      | Multiple calls   | Multiple calls   | Single call      |
+----------------------+------------------+------------------+------------------+
| Ease of Use          | Medium           | Medium           | High             |
+----------------------+------------------+------------------+------------------+

**Recommendations:**

1. **Use McastTesterHelper** for new tests - It provides automatic cleanup,
   better error handling, and supports all features
2. **Use direct scripts** only for simple, one-off scenarios or when you need
   very specific control over packet timing
3. **Use mcast-tester.py directly** when you need IPv6 or SSM support but
   prefer manual process management

Best Practices
--------------

1. **Always cleanup processes** - Use context managers or ensure proper cleanup
   in ``teardown_module()`` or test ``finally`` blocks

2. **Use appropriate TTL values** - Set TTL high enough to reach all routers
   in your topology (typically 5-10 hops)

3. **Wait for convergence** - After starting joins/traffic, use
   ``topotest.run_and_expect()`` to wait for PIM state to converge

4. **Use descriptive group addresses** - Use different multicast addresses for
   different test scenarios to avoid interference

5. **Handle process failures** - Check return values and handle process
   termination errors gracefully

6. **Root privileges required** - All multicast scripts require root privileges
   for socket operations. Topotests run with appropriate permissions.

Example: Complete Test Case
----------------------------

This example demonstrates a complete multicast test case that verifies PIM
functionality. The test scenario involves:

**Test Setup:**
- **Receiver (h1)**: A host that joins multicast group ``225.1.1.1``, which triggers
  an IGMP JOIN message to be sent upstream to the PIM router
- **Sender (h2)**: A host that sends multicast UDP traffic to group ``225.1.1.1``
- **Router (r1)**: A PIM router that should establish multicast forwarding state
  when it receives both the IGMP JOIN from the receiver and the multicast traffic
  from the sender

**Expected Behavior:**
1. When h1 joins the multicast group, it sends an IGMP JOIN message to r1
2. When h2 starts sending multicast traffic, r1 receives it and creates (S,G)
   or (*,G) state
3. PIM should establish forwarding state on r1, creating a multicast distribution
   tree that allows traffic from h2 to reach h1
4. The test verifies that r1 shows the correct PIM upstream state with
   ``joinState: "Joined"``

Here's the complete example showing best practices:

.. code-block:: python

    import os
    import sys
    import pytest
    from functools import partial

    # Mark this test module as requiring PIM daemon
    pytestmark = [pytest.mark.pimd]

    # Get the current working directory for locating test files
    CWD = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.join(CWD, "../"))

    from lib import topotest
    from lib.topogen import Topogen, get_topogen
    from lib.topolog import logger
    from lib.pim import McastTesterHelper

    def setup_module(mod):
        """
        Initialize the test topology and load router configurations.
        This function is called once before all tests in the module.
        """
        # Create topology from build_topo function
        tgen = Topogen(build_topo, mod.__name__)
        tgen.start_topology()

        # Load FRR configuration files for each router
        for rname, router in tgen.routers().items():
            router.load_frr_config("frr.conf")

        # Start FRR daemons on all routers
        tgen.start_router()

    def teardown_module():
        """
        Clean up test resources after all tests complete.
        This function is called once after all tests in the module.
        """
        tgen = get_topogen()
        # Clean up any multicast helper processes if they exist
        if hasattr(tgen, "app_helper"):
            tgen.app_helper.cleanup()
        # Stop the topology and clean up
        tgen.stop_topology()

    def test_multicast_basic():
        """
        Test basic multicast join and traffic forwarding.

        This test verifies that:
        1. A receiver can join a multicast group (IGMP JOIN)
        2. A sender can send multicast traffic
        3. PIM establishes the correct forwarding state
        """
        tgen = get_topogen()

        # Skip test if any routers failed to start
        if tgen.routers_have_failure():
            pytest.skip(tgen.errors)

        # Initialize multicast test helper
        app_helper = McastTesterHelper(tgen)

        # Step 1: Start receiver on h1
        # This causes h1 to join multicast group 225.1.1.1, which sends an
        # IGMP JOIN message to the connected router (r1)
        result = app_helper.run_join("h1", "225.1.1.1", join_intf="h1-eth0")
        assert result is True, "Failed to start multicast receiver on h1"

        # Step 2: Start sender on h2
        # This causes h2 to send UDP multicast packets to group 225.1.1.1
        # The packets will be forwarded by PIM routers toward receivers
        result = app_helper.run_traffic("h2", "225.1.1.1", bind_intf="h2-eth0")
        assert result is True, "Failed to start multicast sender on h2"

        # Step 3: Wait for PIM state to converge
        # Verify that router r1 has established the correct PIM upstream state
        # This state indicates that r1 knows about the multicast group and
        # has joined the distribution tree
        r1 = tgen.gears["r1"]
        expected = {
            "225.1.1.1": {
                "*": {
                    "joinState": "Joined",  # r1 should show joined state
                }
            }
        }

        # Create a test function that compares actual vs expected PIM state
        test_func = partial(
            topotest.router_json_cmp, r1, "show ip pim upstream json", expected
        )
        # Poll r1's PIM state up to 30 times, waiting 1 second between checks
        # This allows time for PIM to converge after the join and traffic start
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "PIM state did not converge - expected joinState 'Joined'"

        # Step 4: Cleanup
        # Stop all multicast processes (both sender and receiver)
        app_helper.stop_all_hosts()

Additional Resources
---------------------

- ``tests/topotests/pim_basic/test_pim.py`` - Basic PIM tests using direct scripts
- ``tests/topotests/multicast_pim_sm_topo1/test_multicast_pim_sm_topo1.py`` -
  Comprehensive multicast tests using McastTesterHelper
- ``tests/topotests/pim_igmp_vrf/test_pim_vrf.py`` - VRF multicast testing
- ``tests/topotests/lib/pim.py`` - Source code for McastTesterHelper class
- ``tests/topotests/lib/mcast-tester.py`` - Unified multicast tester script
- ``tests/topotests/pim_basic/mcast-tx.py`` - Multicast sender script
- ``tests/topotests/pim_basic/mcast-rx.py`` - Multicast receiver script
