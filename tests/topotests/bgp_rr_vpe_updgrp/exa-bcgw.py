#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by 6WIND S.A.
#

"""
exa-bcgw.py: ExaBGP API process of a BCGW peer.

Announces a VPNv4 table of ROUTES /32 prefixes spread over VRFS customers
(one RD, route target and label per customer), then executes the command
files /etc/exabgp/cmd-<seq> (private to the exabgp node) in order, and
renames each one to cmd-<seq>.done once executed:

    wave <med>              re-announce the whole table with this MED
    withdraw                withdraw the whole table
    announce                announce the whole table again (MED 0)
    churn <start> <count> <med>
                            re-announce <count> routes starting at <start>
                            (wrapping around the table) with this MED: a
                            small, rotating slice of the table, to mimic
                            the low-rate ambient route churn seen in the
                            field (as opposed to a full-table wave)

usage: exa-bcgw.py <name> <next-hop> <routes> <vrfs>
"""

import os
import sys
import time

NAME = sys.argv[1]
NEXT_HOP = sys.argv[2]
ROUTES = int(sys.argv[3])
VRFS = int(sys.argv[4])

AS = 65100
# 10.128.0.0/9: away from the link addresses
BASE = (10 << 24) | (128 << 16)
CMD_DIR = "/etc/exabgp"


def prefix(index):
    addr = BASE + index
    return "{}.{}.{}.{}/32".format(
        (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF
    )


def route_line(index, action, med=0):
    vrf = index % VRFS + 1
    if action == "withdraw":
        return "withdraw route {} rd {}:{} next-hop {} label [{}]".format(
            prefix(index), AS, vrf, NEXT_HOP, 1000 + vrf
        )
    return (
        "announce route {} rd {}:{} next-hop {} label [{}] med {}"
        " extended-community [ target:{}:{} ]".format(
            prefix(index), AS, vrf, NEXT_HOP, 1000 + vrf, med, AS, vrf
        )
    )


def table(action, med=0):
    for index in range(ROUTES):
        sys.stdout.write(route_line(index, action, med) + "\n")
    sys.stdout.flush()


def churn(start, count, med):
    for i in range(count):
        index = (start + i) % ROUTES
        sys.stdout.write(route_line(index, "announce", med) + "\n")
    sys.stdout.flush()


def log(message):
    sys.stderr.write("exa-bcgw {}: {}\n".format(NAME, message))
    sys.stderr.flush()


# let the session come up
time.sleep(5)
table("announce")
log("announced {} routes in {} vrfs".format(ROUTES, VRFS))



def execute(command):
    words = command.split()
    if len(words) == 2 and words[0] == "wave":
        table("announce", int(words[1]))
    elif words == ["withdraw"]:
        table("withdraw")
    elif words == ["announce"]:
        table("announce")
    elif len(words) == 4 and words[0] == "churn":
        churn(int(words[1]), int(words[2]), int(words[3]))
    else:
        log("unknown command: {}".format(command))
        return
    log("done: {}".format(command))


while True:
    commands = sorted(
        f
        for f in os.listdir(CMD_DIR)
        if f.startswith("cmd-") and not f.endswith((".done", ".tmp"))
    )
    for name in commands:
        path = os.path.join(CMD_DIR, name)
        with open(path) as f:
            execute(f.read().strip())
        os.rename(path, path + ".done")
    time.sleep(0.5)
