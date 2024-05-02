# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# October 29 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#

import datetime
import ipaddress
import json
import logging
import math
import os
import pprint
import re

from lib.common_config import retry, step
from lib.topolog import logger
from lib.topotest import json_cmp as tt_json_cmp

try:
    from deepdiff import DeepDiff as dd_json_cmp
except ImportError:
    dd_json_cmp = None


def json_cmp(got, expect, exact_match):
    if dd_json_cmp:
        if exact_match:
            deep_diff = dd_json_cmp(expect, got)
            # Convert DeepDiff completely into dicts or lists at all levels
            json_diff = json.loads(deep_diff.to_json())
        else:
            json_diff = dd_json_cmp(expect, got, ignore_order=True)
            # Convert DeepDiff completely into dicts or lists at all levels
            # json_diff = json.loads(deep_diff.to_json())
            # Remove new fields in json object from diff
            if json_diff.get("dictionary_item_added") is not None:
                del json_diff["dictionary_item_added"]
            # Remove new json objects in json array from diff
            if (new_items := json_diff.get("iterable_item_added")) is not None:
                new_item_paths = list(new_items.keys())
                for path in new_item_paths:
                    if type(new_items[path]) is dict:
                        del new_items[path]
                if len(new_items) == 0:
                    del json_diff["iterable_item_added"]
        if not json_diff:
            json_diff = None
    else:
        json_diff = tt_json_cmp(got, expect, exact_match)
        json_diff = str(json_diff)
    return json_diff


def enable_debug(router):
    router.vtysh_cmd("debug northbound callbacks configuration")


def disable_debug(router):
    router.vtysh_cmd("no debug northbound callbacks configuration")


@retry(retry_timeout=30, initial_wait=1)
def _do_oper_test(tgen, qr):
    r1 = tgen.gears["r1"].net

    qcmd = (
        r"vtysh -c 'show mgmt get-data {} {}' "
        r"""| sed -e 's/"phy-address": ".*"/"phy-address": "rubout"/'"""
        r"""| sed -e 's/"uptime": ".*"/"uptime": "rubout"/'"""
        r"""| sed -e 's/"vrf": "[0-9]*"/"vrf": "rubout"/'"""
        r"""| sed -e 's/"if-index": [0-9][0-9]*/"if-index": "rubout"/'"""
        r"""| sed -e 's/"id": [0-9][0-9]*/"id": "rubout"/'"""
    )
    # Don't use this for now.
    dd_json_cmp = None

    expected = open(qr[1], encoding="ascii").read()
    output = r1.cmd_nostatus(qcmd.format(qr[0], qr[2] if len(qr) > 2 else ""))

    try:
        ojson = json.loads(output)
    except json.decoder.JSONDecodeError as error:
        logging.error("Error decoding json: %s\noutput:\n%s", error, output)
        raise

    try:
        ejson = json.loads(expected)
    except json.decoder.JSONDecodeError as error:
        logging.error(
            "Error decoding json exp result: %s\noutput:\n%s", error, expected
        )
        raise

    if dd_json_cmp:
        cmpout = json_cmp(ojson, ejson, exact_match=True)
        if cmpout:
            logging.warning(
                "-------DIFF---------\n%s\n---------DIFF----------",
                pprint.pformat(cmpout),
            )
    else:
        cmpout = tt_json_cmp(ojson, ejson, exact=True)
        if cmpout:
            logging.warning(
                "-------EXPECT--------\n%s\n------END-EXPECT------",
                json.dumps(ejson, indent=4),
            )
            logging.warning(
                "--------GOT----------\n%s\n-------END-GOT--------",
                json.dumps(ojson, indent=4),
            )

    assert cmpout is None


def do_oper_test(tgen, query_results):
    reset = True
    for qr in query_results:
        step(f"Perform query '{qr[0]}'", reset=reset)
        if reset:
            reset = False
        _do_oper_test(tgen, qr)


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


@retry(retry_timeout=30, initial_wait=0.1)
def check_kernel(r1, super_prefix, count, add, is_blackhole, vrf, matchvia):
    network = ipaddress.ip_network(super_prefix)
    vrfstr = f" vrf {vrf}" if vrf else ""
    if network.version == 6:
        kernel = r1.cmd_raises(f"ip -6 route show{vrfstr}")
    else:
        kernel = r1.cmd_raises(f"ip -4 route show{vrfstr}")

    # logger.debug("checking kernel routing table%s:\n%s", vrfstr, kernel)

    for i, net in enumerate(get_ip_networks(super_prefix, count)):
        if not add:
            assert str(net) not in kernel
            continue

        if is_blackhole:
            route = f"blackhole {str(net)} proto (static|196) metric 20"
        else:
            route = (
                f"{str(net)}(?: nhid [0-9]+)? {matchvia} "
                "proto (static|196) metric 20"
            )
        assert re.search(route, kernel), f"Failed to find \n'{route}'\n in \n'{kernel}'"


def addrgen(a, count, step=1):
    for _ in range(0, count, step):
        yield a
        a += step


@retry(retry_timeout=30, initial_wait=0.1)
def check_kernel_32(r1, start_addr, count, vrf, step=1):
    start = ipaddress.ip_address(start_addr)
    vrfstr = f" vrf {vrf}" if vrf else ""
    if start.version == 6:
        kernel = r1.cmd_raises(f"ip -6 route show{vrfstr}")
    else:
        kernel = r1.cmd_raises(f"ip -4 route show{vrfstr}")

    nentries = len(re.findall("\n", kernel))
    logging.info("checking kernel routing table%s: (%s entries)", vrfstr, nentries)

    for addr in addrgen(start, count, step):
        assert str(addr) in kernel, f"Failed to find '{addr}' in {nentries} entries"


def do_config(
    r1,
    count,
    add=True,
    do_ipv6=False,
    via=None,
    vrf=None,
    use_cli=False,
):
    optype = "adding" if add else "removing"
    iptype = "IPv6" if do_ipv6 else "IPv4"

    #
    # Set the route details
    #

    if vrf:
        super_prefix = "2111::/48" if do_ipv6 else "111.0.0.0/8"
    else:
        super_prefix = "2055::/48" if do_ipv6 else "55.0.0.0/8"

    matchvia = ""
    if via == "blackhole":
        pass
    elif via:
        matchvia = f"dev {via}"
    else:
        if vrf:
            via = "2102::2" if do_ipv6 else "3.3.3.2"
            matchvia = f"via {via} dev r1-eth1"
        else:
            via = "2101::2" if do_ipv6 else "1.1.1.2"
            matchvia = f"via {via} dev r1-eth0"

    vrfdbg = " in vrf {}".format(vrf) if vrf else ""
    logger.debug("{} {} static {} routes{}".format(optype, count, iptype, vrfdbg))

    #
    # Generate config file in a retrievable place
    #

    config_file = os.path.join(
        r1.logdir, r1.name, "{}-routes-{}.conf".format(iptype.lower(), optype)
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

    #
    # Load config file.
    #

    if use_cli:
        load_command = 'vtysh < "{}"'.format(config_file)
    else:
        load_command = 'vtysh -f "{}"'.format(config_file)
    tstamp = datetime.datetime.now()
    output = r1.cmd_raises(load_command)
    delta = (datetime.datetime.now() - tstamp).total_seconds()

    #
    # Verify the results are in the kernel
    #
    check_kernel(r1, super_prefix, count, add, via == "blackhole", vrf, matchvia)

    optyped = "added" if add else "removed"
    logger.debug(
        "{} {} {} static routes under {}{} in {}s".format(
            optyped, count, iptype.lower(), super_prefix, vrfdbg, delta
        )
    )
