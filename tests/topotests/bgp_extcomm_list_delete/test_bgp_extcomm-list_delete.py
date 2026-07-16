#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#

"""
bgp_extcomm_list-delete.py:

Test the following commands:
route-map test permit 10
  set extended-comm-list delete <arg>
"""

import functools
import json
import os
import pytest
import re
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib import topotest


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 6,
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initially"


def _set_extcomm_list(gear, ecom_t, ecom):
    "Set the extended community for deletion."
    cmd = [
        "con t\n",
        f"bgp extcommunity-list standard r1-{ecom_t} permit {ecom_t} {ecom}\n",
        f"route-map r1-in permit 10\n",
        f"set extended-comm-list delete r1-{ecom_t}\n",
    ]
    gear.vtysh_cmd("".join(cmd))


def _unset_extcomm_list(gear, ecom_t, ecom):
    "Unset the extended community for deletion."

    gear.vtysh_cmd(
        f"""
        configure t
         no bgp extcommunity-list standard r1-{ecom_t} permit {ecom_t} {ecom}
         route-map r1-in permit 10
          no set extended-comm-list delete r1-{ecom_t}
        """
    )


def _set_extcomm_list_regex(gear, ecom_t, ecom):
    "Set the extended community with regex for deletion."

    gear.vtysh_cmd(
        f"""
         configure t
          bgp extcommunity-list expanded r1-{ecom_t} permit {ecom}
          route-map r1-in permit 10
           set extended-comm-list delete r1-{ecom_t}
         """
    )


def _set_expanded_extcomm_list_entries(gear, name, regexes):
    "Set expanded extended community-list entries for deletion."
    cmd = ["con t\n"]
    for seq, regex in enumerate(regexes, 1):
        cmd.append(
            f"bgp extcommunity-list expanded {name} seq {seq * 5} permit {regex}\n"
        )
    cmd.extend(
        [
            "route-map r1-in permit 10\n",
            f"set extended-comm-list delete {name}\n",
        ]
    )
    gear.vtysh_cmd("".join(cmd))


def _bgp_extcomm_list_del_check(gear, prefix, ecom):
    """
    Check the non-presense of the extended community for the given prefix.
    """
    # get the extended community list attribute for the given prefix
    output = json.loads(gear.vtysh_cmd(f"show ip bgp {prefix} json"))
    ecoms = output.get("paths", [])[0].get("extendedCommunity", {})
    ecoms = ecoms.get("string")

    # ecoms might be None at the first time
    if not ecoms:
        return False
    return re.search(ecom, ecoms) is None


def _bgp_extcomm_deleted_and_preserved_check(gear, prefix, deleted, preserved):
    """
    Check one extended community was deleted while another one remains.
    """
    output = json.loads(gear.vtysh_cmd(f"show ip bgp {prefix} json"))
    ecoms = output.get("paths", [])[0].get("extendedCommunity", {})
    ecoms = ecoms.get("string")

    if not ecoms:
        return False
    return re.search(deleted, ecoms) is None and re.search(preserved, ecoms) is not None


def _bgp_extcomm_list_all_del_check(gear, prefix, ecoms):
    """
    Check the absence of all listed extended communities for the given prefix.
    """
    output = json.loads(gear.vtysh_cmd(f"show ip bgp {prefix} json"))
    route_ecoms = output.get("paths", [])[0].get("extendedCommunity", {})
    route_ecoms = route_ecoms.get("string")

    if not route_ecoms:
        return True
    return all(re.search(ecom, route_ecoms) is None for ecom in ecoms)


def test_rt_extcomm_list_delete():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    # set the extended community for deletion
    _set_extcomm_list(r2, "rt", "1.1.1.1:1")

    # check for the deletion of the extended community
    test_func = functools.partial(
        _bgp_extcomm_list_del_check, r2, "10.10.10.1/32", r"1.1.1.1:1"
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "RT extended community 1.1.1.1:1 was not stripped."


def test_soo_extcomm_list_delete():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    # set the extended community for deletion
    _set_extcomm_list(r2, "soo", "2.2.2.2:2")

    # check for the deletion of the extended community
    test_func = functools.partial(
        _bgp_extcomm_list_del_check, r2, "10.10.10.2/32", r"2.2.2.2:2"
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "SoO extended community 2.2.2.2:2 was not stripped."


def test_nt_extcomm_list_delete():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    # set the extended community for deletion
    _set_extcomm_list(r2, "nt", "3.3.3.3:0")

    # check for the deletion of the extended community
    test_func = functools.partial(
        _bgp_extcomm_list_del_check, r2, "10.10.10.3/32", r"3.3.3.3"
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "NT extended community 3.3.3.3:0 was not stripped."


def test_rt_extcomm_list_expanded_delete():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    # unset previous extended community
    _unset_extcomm_list(r2, "rt", "1.1.1.1:1")

    # set the extended community with regex for deletion
    _set_extcomm_list_regex(r2, "rt", "1.1.1.[1-2]:1")

    # check for the deletion of the extended community
    test_func = functools.partial(
        _bgp_extcomm_list_del_check, r2, "10.10.10.1/32", r"1.1.1.1:1"
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "RT extended community 1.1.1.1:1 was not stripped."


def test_expanded_soo_extcomm_list_delete_preserves_lb():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    # Delete the matching SoO with an expanded regex. Other extended
    # communities on the same route, such as link-bandwidth, must remain.
    _set_expanded_extcomm_list_entries(
        r2, "r1-expanded-soo", [r"SoO:51\.1\.1\.1:[0-9]+"]
    )

    test_func = functools.partial(
        _bgp_extcomm_deleted_and_preserved_check,
        r2,
        "10.10.10.4/32",
        r"SoO:51\.1\.1\.1:11",
        r"LB:",
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "Expanded SoO delete stripped LB or left the matching SoO."


def test_expanded_soo_and_lb_extcomm_list_delete():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    _set_expanded_extcomm_list_entries(
        r2,
        "r1-expanded-soo-lb",
        [r"LB:.*", r"SoO:([0-9]{1,3}[.]){3}[0-9]{1,3}:[0-9]+"],
    )

    test_func = functools.partial(
        _bgp_extcomm_list_all_del_check,
        r2,
        "10.10.10.5/32",
        [r"LB:", r"SoO:51\.1\.1\.1:11"],
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "Expanded wildcard delete left LB or the matching SoO."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
