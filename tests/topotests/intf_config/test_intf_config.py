#!/usr/bin/env python
# SPDX-License-Identifier: ISC


import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


#
# Simple topology pe1 and ce1 connected with two links; v4 and v6 addresses
# configured on the pe1 side, just v6 on the ce1 side.
#
def build_topo(tgen):
    tgen.add_router("pe1")
    tgen.add_router("ce1")

    tgen.add_link(tgen.gears["pe1"], tgen.gears["ce1"], "eth0", "eth0")
    tgen.add_link(tgen.gears["pe1"], tgen.gears["ce1"], "eth1", "eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # For debugging
    # tgen.cli()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(path)


def check_intf_addrs(output):

    expected = open_json_file("%s/pe1/results/eth1_addrs.json" % CWD)

    actual = json.loads(output)

    res = topotest.json_cmp(actual, expected)
    if res != None:
        logger.info("check_intf_addrs res: {}".format(res))

    return res


def check(name, command, checker):
    tgen = get_topogen()
    router = tgen.gears[name]

    def _check():
        try:
            return checker(router.vtysh_cmd(command))
        except:
            return False

    logger.info('[+] check {} "{}"'.format(name, command))
    _, result = topotest.run_and_expect(_check, None, count=10, wait=0.5)
    assert result is None, "Failed"


def test_addrs():
    logger.info("Checking interface address config")

    check("pe1", "show interface json", check_intf_addrs)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
