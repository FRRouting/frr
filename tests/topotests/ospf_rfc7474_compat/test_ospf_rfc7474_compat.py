#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Test OSPF RFC 7474 compatibility switch.

Verifies that the 'compatible rfc7474' global and per-interface commands
work correctly and that toggling them during active sessions does not
disrupt OSPF adjacencies.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import verify_ospf_neighbor, config_ospf_interface

pytestmark = [pytest.mark.ospfd]

# Global variables
topo = None
"""
TOPOLOGY:
    Please view in a fixed-width font such as Courier.

         +--------+                    +--------+
         |        | r1-r2-eth0         |        |
         |   R1   +--------------------+   R2   |
         |        | .1  10.0.0.0/24 .2 |        |
         +--------+                    +--------+
     Router-ID: 100.1.1.1          Router-ID: 100.1.1.2
     Area: 0.0.0.0                 Area: 0.0.0.0
     Auth: MD5 (key 1)             Auth: MD5 (key 1)

TESTCASES:
1. Default: global=strict, per-iface=none. Adjacency up.
2. Global strict -> legacy, per-iface=none. Adjacency survives.
3. Global legacy -> strict, per-iface=none. Adjacency survives.
4. Global=strict, set per-iface=strict. Adjacency survives.
5. Global strict -> legacy, per-iface=strict stays. Adjacency survives (override).
6. Global=strict, per-iface=legacy forces legacy. Adjacency survives (override).
7. Per-iface legacy -> strict restores strict. Adjacency survives.
8. Config persistence: global=legacy + per-iface=legacy/strict in write terminal.
"""


def setup_module(mod):
    """Set up topology: 2 routers with MD5 authentication."""
    logger.info("Running setup_module to create topology")

    json_file = "{}/ospf_rfc7474_compat.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Configure MD5 authentication on the link between r1 and r2
    for rtr in ["r1", "r2"]:
        other = "r2" if rtr == "r1" else "r1"
        auth_cfg = {
            rtr: {
                "links": {
                    other: {
                        "ospf": {
                            "authentication": "message-digest",
                            "message-digest-key": "1",
                            "authentication-key": "ospfkey",
                        }
                    }
                }
            }
        }
        result = config_ospf_interface(tgen, topo, auth_cfg)
        assert result is True, "setup_module: auth config failed on {}".format(rtr)

    # Verify adjacency forms with authentication
    ospf_converged = verify_ospf_neighbor(tgen, topo)
    assert (
        ospf_converged is True
    ), "setup_module: OSPF adjacency not established: {}".format(ospf_converged)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown topology."""
    logger.info("Running teardown_module to delete topology")
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_rfc7474_default_adjacency(request):
    """Verify adjacency is up with default strict mode."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    step("Verify adjacency is Full with default strict RFC 7474 mode")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    # Verify the default config does not show 'no compatible rfc7474'
    step("Verify default running-config has no rfc7474 override")
    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" not in output
    ), "{} Failed: 'no compatible rfc7474' found in default config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_global_strict_to_legacy(request):
    """Toggle global setting from strict (default) to legacy. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    step("Disable strict RFC 7474 globally on both routers")
    for rtr in ["r1", "r2"]:
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               router ospf
                 no compatible rfc7474""")

    step("Verify adjacency remains Full after switching to legacy mode")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config shows 'no compatible rfc7474'")
    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" in output
    ), "{} Failed: 'no compatible rfc7474' not in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_global_legacy_to_strict(request):
    """Toggle global setting from legacy back to strict. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    step("Re-enable strict RFC 7474 globally on both routers")
    for rtr in ["r1", "r2"]:
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               router ospf
                 compatible rfc7474""")

    step("Verify adjacency remains Full after switching back to strict mode")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config no longer shows 'no compatible rfc7474'")
    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" not in output
    ), "{} Failed: 'no compatible rfc7474' still in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_per_interface_override_with_global_strict(request):
    """Global=strict + per-iface=strict. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # State entering: global=strict (from test 3), per-iface=none
    step("Set per-interface strict override on both routers")
    for rtr in ["r1", "r2"]:
        other = "r2" if rtr == "r1" else "r1"
        intf = topo["routers"][rtr]["links"][other]["interface"]
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               interface {}
                 ip ospf compatible rfc7474 enable""".format(intf))

    step("Verify adjacency remains Full (global=strict, per-iface=strict)")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config shows per-interface setting")
    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        "ip ospf compatible rfc7474 enable" in output
    ), "{} Failed: per-interface setting not in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_per_interface_overrides_global_legacy(request):
    """Global=legacy + per-iface=strict: per-iface must override. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # State entering: global=strict, per-iface=strict (from test 4)
    step("Switch global to legacy while per-interface stays strict")
    for rtr in ["r1", "r2"]:
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               router ospf
                 no compatible rfc7474""")

    step("Verify adjacency remains Full (per-iface=strict overrides global=legacy)")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config shows both settings")
    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" in output
    ), "{} Failed: global legacy not in running-config".format(tc_name)
    assert (
        "ip ospf compatible rfc7474 enable" in output
    ), "{} Failed: per-interface strict not in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_per_interface_legacy_overrides_global_strict(request):
    """Global=strict + per-iface=legacy: per-iface forces legacy. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # State entering: global=legacy, per-iface=strict (from test 5)
    # First restore global to strict
    step("Restore global to strict on both routers")
    for rtr in ["r1", "r2"]:
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               router ospf
                 compatible rfc7474""")

    step("Set per-interface to legacy on both routers")
    for rtr in ["r1", "r2"]:
        other = "r2" if rtr == "r1" else "r1"
        intf = topo["routers"][rtr]["links"][other]["interface"]
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               interface {}
                 ip ospf compatible rfc7474 disable""".format(intf))

    step("Verify adjacency remains Full (per-iface=legacy overrides global=strict)")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config shows per-interface legacy override")
    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        "ip ospf compatible rfc7474 disable" in output
    ), "{} Failed: per-interface legacy not in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_restore_global_strict(request):
    """Restore to clean state: global=strict, per-iface=strict. Adjacency must survive."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # State entering: global=strict, per-iface=legacy (from test 6)
    step("Set per-interface back to strict on both routers")
    for rtr in ["r1", "r2"]:
        other = "r2" if rtr == "r1" else "r1"
        intf = topo["routers"][rtr]["links"][other]["interface"]
        tgen.gears[rtr].vtysh_cmd("""configure terminal
               interface {}
                 ip ospf compatible rfc7474 enable""".format(intf))

    step("Verify adjacency remains Full (global=strict, per-iface=strict)")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    step("Verify running-config shows per-interface strict")
    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" not in output
    ), "{} Failed: global legacy still in running-config".format(tc_name)
    assert (
        "ip ospf compatible rfc7474 disable" not in output
    ), "{} Failed: per-interface legacy still in running-config".format(tc_name)
    assert (
        "ip ospf compatible rfc7474 enable" in output
    ), "{} Failed: per-interface strict not in running-config".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_rfc7474_config_persistence(request):
    """Verify settings persist via write terminal."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # State entering: global=strict, per-iface=strict (from test 7)
    step("Set global legacy and per-interface legacy on r1")
    r1 = tgen.gears["r1"]
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    r1.vtysh_cmd("""configure terminal
           router ospf
             no compatible rfc7474""")
    r1.vtysh_cmd("""configure terminal
           interface {}
             ip ospf compatible rfc7474 disable""".format(intf))

    step("Verify write terminal output includes both settings")
    output = r1.vtysh_cmd("write terminal")
    assert (
        "no compatible rfc7474" in output
    ), "{} Failed: global 'no compatible rfc7474' not in write terminal output".format(
        tc_name
    )
    assert (
        "ip ospf compatible rfc7474 disable" in output
    ), "{} Failed: per-interface config not in write terminal output".format(tc_name)

    step("Now set per-interface to strict and verify mixed config")
    r1.vtysh_cmd("""configure terminal
           interface {}
             ip ospf compatible rfc7474 enable""".format(intf))
    output = r1.vtysh_cmd("write terminal")
    assert (
        "no compatible rfc7474" in output
    ), "{} Failed: global legacy not in write terminal output".format(tc_name)
    assert (
        "ip ospf compatible rfc7474 enable" in output
    ), "{} Failed: per-interface strict not correctly shown in write terminal output".format(
        tc_name
    )

    step("Verify adjacency is still up")
    ospf_converged = verify_ospf_neighbor(tgen, topo, dut="r1")
    assert ospf_converged is True, "{} Failed: {}".format(tc_name, ospf_converged)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
