#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# June 2 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test the timing of config operations.

The initial add of 10k routes is used as a baseline for timing and all future
operations are expected to complete in under 2 times that baseline. This is a
lot of slop; however, the pre-batching code some of these operations (e.g.,
adding the same set of 10k routes) would take 100 times longer, so the intention
is to catch those types of regressions.
"""

import datetime
import ipaddress
import math
import os
import sys
import pytest
from lib import topotest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_ip_networks(super_prefix, base_count, count):
    count_log2 = math.log(base_count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def test_static_timing():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def do_config(
        base_count,
        count,
        bad_indices,
        base_delta,
        d_multiplier,
        add=True,
        do_ipv6=False,
        super_prefix=None,
        en_dbg=False,
    ):
        router_list = tgen.routers()
        tot_delta = float(0)

        optype = "adding" if add else "removing"
        iptype = "IPv6" if do_ipv6 else "IPv4"
        if super_prefix is None:
            super_prefix = u"2001::/48" if do_ipv6 else u"10.0.0.0/8"
        via = u"lo"
        optyped = "added" if add else "removed"

        for rname, router in router_list.items():
            router.logger.info("{} {} static {} routes".format(optype, count, iptype))

            # Generate config file.
            config_file = os.path.join(
                router.logdir, rname, "{}-routes-{}.conf".format(iptype.lower(), optype)
            )
            with open(config_file, "w") as f:
                for i, net in enumerate(
                    get_ip_networks(super_prefix, base_count, count)
                ):
                    if i in bad_indices:
                        if add:
                            f.write("ip route {} {} bad_input\n".format(net, via))
                        else:
                            f.write("no ip route {} {} bad_input\n".format(net, via))
                    elif add:
                        f.write("ip route {} {}\n".format(net, via))
                    else:
                        f.write("no ip route {} {}\n".format(net, via))

            # Enable debug
            if en_dbg:
                router.vtysh_cmd("debug northbound callbacks configuration")

            # Load config file.
            load_command = 'vtysh -f "{}"'.format(config_file)
            tstamp = datetime.datetime.now()
            output = router.run(load_command)
            delta = (datetime.datetime.now() - tstamp).total_seconds()
            tot_delta += delta

            router.logger.info(
                "\nvtysh command => {}\nvtysh output <= {}\nin {}s".format(
                    load_command, output, delta
                )
            )

        limit_delta = base_delta * d_multiplier
        logger.info(
            "{} {} {} static routes under {} in {}s (limit: {}s)".format(
                optyped, count, iptype.lower(), super_prefix, tot_delta, limit_delta
            )
        )
        if limit_delta:
            assert tot_delta <= limit_delta

        return tot_delta


    # Number of static routes
    router = tgen.gears["r1"]
    output = router.run("vtysh -h | grep address-sanitizer")
    if output == "":
        logger.info("No Address Sanitizer, generating 10000 routes")
        prefix_count = 10000
    else:
        logger.info("Address Sanitizer build, only testing 50 routes")
        prefix_count = 50

    prefix_base = [
        [u"10.0.0.0/8", u"11.0.0.0/8"],
        [u"2100:1111:2220::/44", u"2100:3333:4440::/44"],
    ]

    topotest.sleep(5)

    bad_indices = []
    for ipv6 in [False, True]:
        base_delta = do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            0,
            0,
            True,
            ipv6,
            prefix_base[ipv6][0],
        )

        # Another set of same number of prefixes
        do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            base_delta,
            3,
            True,
            ipv6,
            prefix_base[ipv6][1],
        )

        # Duplicate config
        do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            base_delta,
            3,
            True,
            ipv6,
            prefix_base[ipv6][0],
        )

        # Remove 1/2 of duplicate
        do_config(
            prefix_count,
            prefix_count // 2,
            bad_indices,
            base_delta,
            3,
            False,
            ipv6,
            prefix_base[ipv6][0],
        )

        # Add all back in so 1/2 replicate 1/2 new
        do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            base_delta,
            3,
            True,
            ipv6,
            prefix_base[ipv6][0],
        )

        # remove all
        delta = do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            base_delta,
            3,
            False,
            ipv6,
            prefix_base[ipv6][0],
        )
        delta += do_config(
            prefix_count,
            prefix_count,
            bad_indices,
            base_delta,
            3,
            False,
            ipv6,
            prefix_base[ipv6][1],
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
