# SPDX-License-Identifier: ISC
#
# Copyright (C) 2023 NVIDIA Corporation
# Copyright (C) 2023 6WIND
#
import re
from time import sleep

from lib.topogen import get_topogen


def route_get_nhg_id(route_str, rname):
    tgen = get_topogen()
    output = tgen.gears[rname].vtysh_cmd("show ip route %s nexthop-group" % route_str)
    match = re.search(r"Nexthop Group ID: (\d+)", output)
    assert match is not None, (
        "Nexthop Group ID not found for sharpd route %s" % route_str
    )

    nhg_id = int(match.group(1))
    return nhg_id


def verify_nexthop_group(
    nhg_id, rname, recursive=False, ecmp=0, recursive_again=False
):
    tgen = get_topogen()
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
        output = tgen.gears[rname].vtysh_cmd("show nexthop-group rib %d" % nhg_id)
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
                verify_nexthop_group(resolved_id, rname, recursive=recursive_again)
        else:
            installed = re.search(r"Installed", output)
            if installed is None:
                found = False
                sleep(1)
                continue
        found = True

    assert valid is not None, "Nexthop Group ID=%d not marked Valid" % nhg_id
    if ecmp or recursive:
        assert ecmpcount is not None, "Nexthop Group ID=%d has no depends" % nhg_id
        if ecmp:
            assert len(depends) == ecmp, (
                "Nexthop Group ID=%d doesn't match ecmp size" % nhg_id
            )
        else:
            assert len(depends) == 1, (
                "Nexthop Group ID=%d should only have one recursive depend" % nhg_id
            )
    else:
        assert installed is not None, (
            "Nexthop Group ID=%d not marked Installed" % nhg_id
        )


def verify_route_nexthop_group(route_str, rname, recursive=False, ecmp=0):
    # Verify route and that zebra created NHGs for and they are valid/installed
    nhg_id = route_get_nhg_id(route_str, rname)
    verify_nexthop_group(nhg_id, rname, recursive, ecmp)
