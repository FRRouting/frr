#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import functools, json, os, pytest, re, sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_table_map():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(
            r1.vtysh_cmd( "show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "10.255.0.2": {
                    "remoteAs": 65002,
                    "state": "Established",
                    "peerState": "OK",
                },
            },
            "totalPeers": 1,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initial state"

    def _bgp_with_table_map():
        output = json.loads(r1.vtysh_cmd("show ip fib json"))
        expected = {
            "10.0.0.1/32": [],
            "10.0.0.2/32": None,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_with_table_map,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Should contain only one of two shared networks"

    #
    # Unset table-map
    #
    r1.vtysh_cmd(
        """
        configure terminal
          router bgp 65001
            address-family ipv4 unicast
              no table-map TableMap
    """
    )

    def _bgp_without_table_map():
        output = json.loads(r1.vtysh_cmd("show ip fib json"))
        expected = {
            "10.0.0.1/32": [],
            "10.0.0.2/32": [],
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_without_table_map,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Shouldn't contain both shared routes"

    #
    # Reset table-map
    #
    r1.vtysh_cmd(
        """
        configure terminal
          router bgp 65001
            address-family ipv4 unicast
              table-map TableMap
        """
    )

    test_func = functools.partial(
        _bgp_with_table_map,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Should contain only one of two shared networks"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
