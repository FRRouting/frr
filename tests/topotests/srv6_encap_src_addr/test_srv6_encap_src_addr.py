#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_srv6_encap_src_addr.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by
# University of Rome Tor Vergata, Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#

"""
test_srv6_encap_src_addr.py:
Test for SRv6 encap source address on zebra
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_srv6_encap_src_addr(tgen):
    "Test SRv6 encapsulation source address."
    logger.info("Test SRv6 encapsulation source address.")
    r1 = tgen.gears["r1"]

    # Generate expected results
    json_file = "{}/r1/expected_srv6_encap_src_addr.json".format(CWD)
    expected = json.loads(open(json_file).read())

    ok = topotest.router_json_cmp_retry(
        r1, "show segment-routing srv6 manager json", expected
    )
    assert ok, '"r1" JSON output mismatches'

    output = r1.cmd("ip sr tunsrc show")
    assert output == "tunsrc addr fc00:0:1::1\n"


def test_zebra_srv6_encap_src_addr_unset(tgen):
    "Test SRv6 encapsulation source address unset."
    logger.info("Test SRv6 encapsulation source address unset.")
    r1 = tgen.gears["r1"]

    # Unset SRv6 encapsulation source address
    r1.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           encapsulation
            no source-address
        """
    )

    # Generate expected results
    json_file = "{}/r1/expected_srv6_encap_src_addr_unset.json".format(CWD)
    expected = json.loads(open(json_file).read())

    ok = topotest.router_json_cmp_retry(
        r1, "show segment-routing srv6 manager json", expected
    )
    assert ok, '"r1" JSON output mismatches'

    output = r1.cmd("ip sr tunsrc show")
    assert output == "tunsrc addr ::\n"


def test_zebra_srv6_encap_src_addr_set(tgen):
    "Test SRv6 encapsulation source address set."
    logger.info("Test SRv6 encapsulation source address set.")
    r1 = tgen.gears["r1"]

    # Set SRv6 encapsulation source address
    r1.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           encapsulation
            source-address fc00:0:1::1
        """
    )

    # Generate expected results
    json_file = "{}/r1/expected_srv6_encap_src_addr_set.json".format(CWD)
    expected = json.loads(open(json_file).read())

    ok = topotest.router_json_cmp_retry(
        r1, "show segment-routing srv6 manager json", expected
    )
    assert ok, '"r1" JSON output mismatches'

    output = r1.cmd("ip sr tunsrc show")
    assert output == "tunsrc addr fc00:0:1::1\n"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
