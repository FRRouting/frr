#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_pim6_hello_send_counters.py: successful IPv6 PIM hello transmissions
must be counted as SENT, not as failed.

Regression test for the pim_msg_send() return-value mismatch: the IPv4 frame
sender returns 0 on success, the IPv6 one returned sendmsg()'s byte count,
and every caller tests the result as a boolean -- so on IPv6 every
successful transmission was taken for a failure.  The visible symptoms are
`helloSend 0` / `hellosendFailed N` on an interface whose hellos are plainly
going out, and a "could not send PIM message on interface ..." warning for
every periodic Join/Prune.

The same symptom was reported and closed once before (FRRouting/frr issue
regarding hello Tx counts on pim6d), so this asserts on the counters to keep
it from coming back.

A single router suffices: hellos are sent to ff02::d regardless of whether
any neighbor exists, and the send/sendFailed split is decided entirely by
the local return-value handling.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pim6d]

IFNAME = "r1-eth0"


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config("frr.conf", daemons=["zebra", "pim6d"])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_hello_send_counted_as_sent():
    """helloSend must accumulate; before the fix it stayed at 0 forever
    while hellosendFailed counted every SUCCESSFUL transmission."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _hellos_sent():
        out = tgen.gears["r1"].vtysh_cmd(
            "show ipv6 pim interface {} json".format(IFNAME)
        )
        try:
            data = json.loads(out)
        except ValueError:
            return "r1: unparseable pim interface JSON (pim6d dead?)"
        row = data.get(IFNAME)
        if row is None:
            return "r1: no pim interface data for {}: {}".format(IFNAME, data)
        sent = row.get("helloSend", 0)
        failed = row.get("hellosendFailed", 0)
        # Two accumulated hellos separate the fixed accounting from a lucky
        # startup race; a small failed allowance covers the genuine
        # first-send failure while the interface address is still settling.
        if sent < 2:
            return "helloSend={} hellosendFailed={}: successful hellos are " "not being counted as sent".format(sent, failed)
        if failed > sent:
            return "hellosendFailed={} exceeds helloSend={}: successes are " "still being booked as failures".format(failed, sent)
        return None

    # hello period is 5s; 40s covers many periods with margin.
    _, result = topotest.run_and_expect(_hellos_sent, None, count=40, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
