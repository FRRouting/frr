#!/usr/bin/env python

# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Test if default-originate works with ONLY match operations.
"""

import datetime
import ipaddress
import math
import os
import sys

import pytest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.staticd]
CWD = os.path.dirname(os.path.realpath(__file__))


def setup_module(mod):
    topodef = {
        # "s1": ("r1", "r2", "r3"),
        "s1": "r1"
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def enable_debug(router):
    router.vtysh_cmd("debug northbound callbacks configuration")


def disable_debug(router):
    router.vtysh_cmd("no debug northbound callbacks configuration")


def do_config(count, add=True, do_ipv6=False, super_prefix=None, via=None, vrf=None, use_cli=False):
    rname = "r1"
    router = get_topogen().routers()[rname]

    optype = "adding" if add else "removing"
    iptype = "IPv6" if do_ipv6 else "IPv4"

    if super_prefix is None:
        super_prefix = u"2001::/48" if do_ipv6 else u"10.0.0.0/8"

    if via is None:
        via = u"2100::1" if do_ipv6 else u"100.0.0.1"

    vrfdbg = " in vrf {}".format(vrf) if vrf else ""
    router.logger.info("{} {} static {} routes{}".format(
        optype, count, iptype, vrfdbg)
    )

    # Generate config file in a retrievable place
    config_file = os.path.join(
        router.logdir, rname, "{}-routes-{}.conf".format(
            iptype.lower(), optype
        )
    )
    with open(config_file, "w") as f:
        if use_cli:
            f.write("configure terminal\n")
        if vrf:
            f.write("vrf {}\n".format(vrf))

        for i, net in enumerate(get_ip_networks(super_prefix, count)):
            if add:
                f.write("ip route {} {}\n".format(net, via))
            else:
                f.write("no ip route {} {}\n".format(net, via))

    # Load config file.
    if use_cli:
        load_command = 'vtysh < "{}"'.format(config_file)
    else:
        load_command = 'vtysh -f "{}"'.format(config_file)
    tstamp = datetime.datetime.now()
    output = router.run(load_command)
    delta = (datetime.datetime.now() - tstamp).total_seconds()

    optyped = "added" if add else "removed"
    logger.info(
        "{} {} {} static routes under {}{} in {}s".format(
            optyped, count, iptype.lower(), super_prefix, vrfdbg, delta
        )
    )
    router.logger.info(
        "\nvtysh command => {}\nvtysh output <= {}\nin {}s".format(
            load_command, output, delta
        )
    )


def guts(vrf=None, use_cli=False):
    # via an IP gateway
    do_config(1, True, False, vrf=vrf, use_cli=use_cli)
    do_config(1, False, False, vrf=vrf, use_cli=use_cli)

    # via loopback
    do_config(1, True, False, via="lo", vrf=vrf, use_cli=use_cli)
    do_config(1, False, False, via="lo", vrf=vrf, use_cli=use_cli)

    # via blackhole
    do_config(1, True, False, via="blackhole", vrf=vrf, use_cli=use_cli)
    do_config(1, False, False, via="blackhole", vrf=vrf, use_cli=use_cli)


def test_static_no_vrf_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    guts(vrf=None, use_cli=False)


def test_static_no_vrf_cli():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    guts(vrf=None, use_cli=True)


def test_static_vrf_file():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    guts(vrf="red", use_cli=False)


def test_static_vrf_cli():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    guts(vrf="red", use_cli=True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
