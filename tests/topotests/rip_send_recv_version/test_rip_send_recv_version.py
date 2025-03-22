#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
Test if RIP `ip rip send version` and `ip rip receive version` 
works as expected.
"""

import os
import sys
import json
import pytest
import functools
import re

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripd]


def setup_module(mod):
    topodef = {"s1": ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def get_conf_of_interface(i_name, text):
    pattern = f'!\ninterface {i_name}(.*?)!'

    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        return match.strip()
    
    return None

def test_rip_version():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    st = r1.vtysh_cmd("show running-config")
    r1_eth0 = get_conf_of_interface("r1-eth0", st)
    assert r1_eth0 != None
    assert "ip rip send version 1 2" not in r1_eth0
    assert "ip rip receive version 1 2" not in r1_eth0
    r1_eth1 = get_conf_of_interface("r1-eth1", st)
    assert r1_eth1 != None
    assert "ip rip send version 1 2" in r1_eth1
    assert "ip rip receive version 1 2" in r1_eth1

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
