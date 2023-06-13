# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# May 28 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#

import ipaddress
import math
import re

import pytest
from lib.common_config import retry, step
from lib.topolog import logger
from munet.base import proc_error


@retry(retry_timeout=30)
def check_vtysh_up(router):
    rc, o, e = router.net.cmd_status("vtysh -c 'show version'")
    return None if not rc else proc_error(rc, o, e)


@retry(retry_timeout=3, initial_wait=0.1)
def check_kernel(r1, prefix, expected=True):
    net = ipaddress.ip_network(prefix)
    if net.version == 6:
        kernel = r1.net.cmd_nostatus("ip -6 route show", warn=not expected)
    else:
        kernel = r1.net.cmd_nostatus("ip -4 route show", warn=not expected)

    logger.debug("checking kernel routing table:\n%0.1920s", kernel)
    route = f"{str(net)}(?: nhid [0-9]+)?.*proto (static|196)"
    m = re.search(route, kernel)
    if expected and not m:
        return f"Failed to find \n'{route}'\n in \n'{kernel:.1920}'"
    elif not expected and m:
        return f"Failed found \n'{route}'\n in \n'{kernel:.1920}'"
    return None


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def write_big_route_conf(super_prefix, count, confpath, prologue=""):
    start = None
    end = None

    with open(confpath, "w+", encoding="ascii") as f:
        if prologue:
            f.write(prologue + "\n")
        for net in get_ip_networks(super_prefix, count):
            end = net
            if not start:
                start = net
            f.write(f"ip route {net} lo\n")

    return start, end


def _test_staticd_late_start(tgen, router):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # for x in ["r1"]:
    #     tgen.gears[x].net.cmd_nostatus(
    #         "vtysh -c 'debug mgmt client frontend' "
    #         "-c 'debug mgmt client backend' "
    #         "-c 'debug mgmt backend frontend datastore transaction'"
    #     )

    step("Verifying startup route is not present w/o staticd running")
    result = check_kernel(router, "12.0.0.0/24", expected=False)
    assert result is not None

    step("Configure another static route verify is not present w/o staticd running")
    router.net.cmd_nostatus("vtysh -c 'config t' -c 'ip route 12.1.0.0/24 101.0.0.2'")
    result = check_kernel(router, "12.0.0.0/24", expected=False)
    assert result is not None
    result = check_kernel(router, "12.1.0.0/24", expected=False)
    assert result is not None

    step("Starting staticd")
    router.startDaemons(["staticd"])

    step("Verifying both routes are present")
    result = check_kernel(router, "12.0.0.0/24")
    assert result is None
    result = check_kernel(router, "12.1.0.0/24")
    assert result is None
