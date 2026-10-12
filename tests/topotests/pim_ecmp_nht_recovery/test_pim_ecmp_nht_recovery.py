#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Regression for ECMP PIM NHT recovery after PIM neighbor loss."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.pim import McastTesterHelper
from lib.topogen import Topogen, get_topogen


pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

GROUP = "239.1.1.1"
SOURCE = "198.51.100.2"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("h1", "203.0.113.2/24", "via 203.0.113.1")
    tgen.add_host("h2", "198.51.100.2/24", "via 198.51.100.1")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth1", "r2-eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["h1"], "r1-eth2", "h1-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["h2"], "r2-eth2", "h2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.routers()["r1"]
    r2 = tgen.routers()["r2"]
    r1.load_frr_config(os.path.join(CWD, "r1", "frr.conf"))
    r2.load_frr_config(os.path.join(CWD, "r2", "frr.conf"))

    tgen.start_router()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global app_helper
    app_helper = McastTesterHelper()
    app_helper.init(tgen)


def teardown_module():
    app_helper.cleanup()
    get_topogen().stop_topology()


def _wait_for(check, description):
    result, value = topotest.run_and_expect(check, None, count=90, wait=1)
    assert result, "{}: {}".format(description, value)


def _upstream_is_resolved():
    output = get_topogen().routers()["r1"].vtysh_cmd("show ip pim upstream")
    for line in output.splitlines():
        if SOURCE in line and GROUP in line:
            if "Unknown" not in line and ("r1-eth0" in line or "r1-eth1" in line):
                return None
    return output


def _pim_neighbors_are_present():
    output = get_topogen().routers()["r1"].vtysh_cmd("show ip pim neighbor")
    if "r1-eth0" in output and "r1-eth1" in output:
        return None
    return output


def _pim_neighbors_are_absent():
    output = get_topogen().routers()["r1"].vtysh_cmd("show ip pim neighbor")
    if "r1-eth0" not in output and "r1-eth1" not in output:
        return None
    return output


def _source_gate_is_unresolved():
    output = get_topogen().routers()["r1"].vtysh_cmd("show ip pim nexthop")
    unresolved_interfaces = set()
    for line in output.splitlines():
        fields = line.split()
        if (
            len(fields) == 4
            and fields[0] == SOURCE
            and fields[2] == "0.0.0.0"
            and fields[3] == "URIB"
        ):
            unresolved_interfaces.add(fields[1])

    if {"r1-eth0", "r1-eth1"} <= unresolved_interfaces:
        return None
    return output


def test_pim_ecmp_nht_recovers_after_neighbor_comes_up():
    """Recover a cached RFC 5549 source nexthop after PIM neighbor-up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.routers()["r1"]
    r2 = tgen.routers()["r2"]

    _wait_for(_pim_neighbors_are_present, "PIM neighbors did not establish")

    # This is a programmatically built topology, so give McastTesterHelper
    # the host interface explicitly instead of using its JSON-topology lookup.
    app_helper.run_join("h1", GROUP, join_intf="h1-eth0")
    app_helper.run_traffic("h2", GROUP, bind_intf="h2-eth0")
    _wait_for(_upstream_is_resolved, "initial source RPF was not resolved")

    # Keep the BGP sessions up, but remove both remote PIM neighbors. A BGP
    # reconnect now delivers IPv4-over-IPv6-link-local nexthops while PIM has
    # no neighbor from which to resolve the IPv4 gateway.
    r2.vtysh_cmd(
        """
        configure terminal
         interface r2-eth0
          no ip pim
         exit
         interface r2-eth1
          no ip pim
         exit
        end
        """
    )
    _wait_for(_pim_neighbors_are_absent, "PIM neighbors did not clear")

    r1.vtysh_cmd("clear bgp *")
    _wait_for(_source_gate_is_unresolved, "RFC 5549 source nexthop was not poisoned")

    r2.vtysh_cmd(
        """
        configure terminal
         interface r2-eth0
          ip pim
         exit
         interface r2-eth1
          ip pim
         exit
        end
        """
    )
    _wait_for(_pim_neighbors_are_present, "PIM neighbors did not recover")
    _wait_for(_upstream_is_resolved, "cached source RPF did not recover")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
