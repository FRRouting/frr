# SPDX-License-Identifier: ISC
#
# Copyright (C) 2023 NVIDIA Corporation
# Copyright (C) 2023 6WIND
#
import re
from time import sleep

from lib.topogen import get_topogen, topotest
import functools


def route_get_nhg_id(route_str, rname):
    global fatal_error

    def get_func(route_str, rname):
        net = get_topogen().net
        output = net[rname].cmd(
            'vtysh -c "show ip route {} nexthop-group"'.format(route_str)
        )
        match = re.search(r"Nexthop Group ID: (\d+)", output)
        if match is not None:
            nhg_id = int(match.group(1))
            return nhg_id
        else:
            return None

    test_func = functools.partial(get_func, route_str, rname)
    _, nhg_id = topotest.run_and_expect_type(test_func, int, count=30, wait=1)
    if nhg_id == None:
        fatal_error = "Nexthop Group ID not found for route {}".format(route_str)
        assert nhg_id != None, fatal_error
    else:
        return nhg_id


def verify_nexthop_group(nhg_id, rname, recursive=False, ecmp=0):
    net = get_topogen().net
    count = 0
    valid = None
    ecmpcount = None
    depends = None
    resolved_id = None
    installed = None
    found = False

    while not found and count < 10:
        count += 1
        # Verify NHG is valid/installed
        output = net[rname].cmd('vtysh -c "show nexthop-group rib {}"'.format(nhg_id))
        valid = re.search(r"Valid", output)
        if valid is None:
            found = False
            sleep(1)
            continue

        if ecmp or recursive:
            ecmpcount = re.search(r"Depends:.*\n", output)
            if ecmpcount is None:
                found = False
                sleep(1)
                continue

            # list of IDs in group
            depends = re.findall(r"\((\d+)\)", ecmpcount.group(0))

            if ecmp:
                if len(depends) != ecmp:
                    found = False
                    sleep(1)
                    continue
            else:
                # If recursive, we need to look at its resolved group
                if len(depends) != 1:
                    found = False
                    sleep(1)
                    continue

                resolved_id = int(depends[0])
                verify_nexthop_group(resolved_id, rname, False)
        else:
            installed = re.search(r"Installed", output)
            if installed is None:
                found = False
                sleep(1)
                continue
        found = True

    assert valid is not None, "Nexthop Group ID={} not marked Valid".format(nhg_id)
    if ecmp or recursive:
        assert ecmpcount is not None, "Nexthop Group ID={} has no depends".format(
            nhg_id
        )
        if ecmp:
            assert (
                len(depends) == ecmp
            ), "Nexthop Group ID={} doesn't match ecmp size".format(nhg_id)
        else:
            assert (
                len(depends) == 1
            ), "Nexthop Group ID={} should only have one recursive depend".format(
                nhg_id
            )
    else:
        assert installed is not None, "Nexthop Group ID={} not marked Installed".format(
            nhg_id
        )


def verify_route_nexthop_group(route_str, rname, recursive=False, ecmp=0):
    # Verify route and that zebra created NHGs for and they are valid/installed
    nhg_id = route_get_nhg_id(route_str, rname)
    verify_nexthop_group(nhg_id, rname, recursive, ecmp)
