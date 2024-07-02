#!/usr/bin/env python

#
# Copyright 2022 6WIND S.A.
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
Check if fec nexthop resolution works correctly.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """
    r1 ---- r2 ---- r3 ---- r4 ----- r5 ---- r6 ---- r7
     <--- ospf ----> <---- isis -----> <--- ospf ---->
    """
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    switch1 = tgen.add_switch("s1")
    switch1.add_link(tgen.gears["r1"])
    switch1.add_link(tgen.gears["r2"])

    switch2 = tgen.add_switch("s2")
    switch2.add_link(tgen.gears["r2"])
    switch2.add_link(tgen.gears["r3"])

    switch3 = tgen.add_switch("s3")
    switch3.add_link(tgen.gears["r3"])
    switch3.add_link(tgen.gears["r4"])

    switch4 = tgen.add_switch("s4")
    switch4.add_link(tgen.gears["r4"])
    switch4.add_link(tgen.gears["r5"])

    switch5 = tgen.add_switch("s5")
    switch5.add_link(tgen.gears["r5"])
    switch5.add_link(tgen.gears["r6"])

    switch6 = tgen.add_switch("s6")
    switch6.add_link(tgen.gears["r6"])
    switch6.add_link(tgen.gears["r7"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    def _enable_mpls_misc(router):
        router.run("modprobe mpls_router")
        router.run("echo 100000 > /proc/sys/net/mpls/platform_labels")
        router.run("echo 1 > /proc/sys/net/mpls/conf/lo/input")

    router = tgen.gears["r1"]
    _enable_mpls_misc(router)

    router = tgen.gears["r2"]
    _enable_mpls_misc(router)

    router = tgen.gears["r3"]
    _enable_mpls_misc(router)

    router = tgen.gears["r4"]
    _enable_mpls_misc(router)

    router = tgen.gears["r5"]
    _enable_mpls_misc(router)

    router = tgen.gears["r6"]
    _enable_mpls_misc(router)

    router = tgen.gears["r7"]
    _enable_mpls_misc(router)

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if rname in ("r1", "r3", "r5", "r7"):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
        if rname in ("r3", "r4", "r5"):
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
        if rname in ("r1", "r2", "r3", "r5", "r6", "r7"):
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# There are some startup issued when initialising OSPF
# To avoid those issues, load the ospf configuration after zebra started
def test_zebra_fec_nexthop_resolution_finalise_ospf_config():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(2)

    tgen.net["r1"].cmd("vtysh -f {}/r1/ospfd.conf.after".format(CWD))
    tgen.net["r2"].cmd("vtysh -f {}/r2/ospfd.conf.after".format(CWD))
    tgen.net["r3"].cmd("vtysh -f {}/r3/ospfd.conf.after".format(CWD))
    tgen.net["r5"].cmd("vtysh -f {}/r5/ospfd.conf.after".format(CWD))
    tgen.net["r6"].cmd("vtysh -f {}/r6/ospfd.conf.after".format(CWD))
    tgen.net["r7"].cmd("vtysh -f {}/r7/ospfd.conf.after".format(CWD))


def test_zebra_fec_nexthop_resolution_bgp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_bgp_session():
        r1 = tgen.gears["r1"]

        tgen.gears["r3"].vtysh_cmd("config \n no mpls fec nexthop-resolution \n end")
        tgen.gears["r3"].vtysh_cmd("config \n mpls fec nexthop-resolution \n end")
        tgen.gears["r5"].vtysh_cmd("config \n no mpls fec nexthop-resolution \n end")
        tgen.gears["r5"].vtysh_cmd("config \n mpls fec nexthop-resolution \n end")
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))

        if output["ipv4Unicast"]["peers"]["192.0.2.7"]["state"] == "Established":
            return None
        return False

    test_func1 = functools.partial(_check_bgp_session)
    _, result1 = topotest.run_and_expect(test_func1, None, count=60, wait=0.5)
    assert result1 is None, "Failed to verify the fec_nexthop_resolution: bgp session"


def test_zebra_fec_nexthop_resolution_ping():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ping_launch():
        r1 = tgen.gears["r1"]

        ping_launch = "ping 192.0.2.7 -I 192.0.2.1 -c 1"
        selected_lines = r1.run(ping_launch).splitlines()[-2:-1]
        rtx_stats = "".join(selected_lines[0].split(",")[0:3])
        current = topotest.normalize_text(rtx_stats)

        expected_stats = "1 packets transmitted 1 received 0% packet loss"
        expected = topotest.normalize_text(expected_stats)

        if current == expected:
            return None

        return False

    test_func2 = functools.partial(_check_ping_launch)
    _, result2 = topotest.run_and_expect(test_func2, None, count=60, wait=1)
    assert result2 is None, "Failed to verify the fec_nexthop_resolution: ping"


def test_zebra_fec_nexthop_resolution_table():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _zebra_check_mpls_table():
        r3 = tgen.gears["r3"]
        inLabel = 0
        outLabels = 0

        """
        Retrieve inLabel from MPLS FEC table
        """
        mpls_fec = r3.vtysh_cmd("show mpls fec 192.0.2.7/32")
        lines = mpls_fec.split("\n")
        for line in lines:
            if "Label" in line:
                inLabel = line.split(": ", 1)[1]

        """
        Retrieve outLabel from BGP
        """
        output = json.loads(r3.vtysh_cmd("show ip route 192.0.2.7/32 json"))

        outLabels = output["192.0.2.7/32"][0]["nexthops"][1]["labels"]

        if (inLabel == 0) or (outLabels == 0):
            return True

        """
        Compare expected data with real data
        """
        output = json.loads(r3.vtysh_cmd("show mpls table " + str(inLabel) + " json"))

        expected = {
            "inLabel": int(inLabel),
            "installed": True,
            "nexthops": [
                {
                    "type": "BGP",
                    "outLabel": outLabels[0],
                    "outLabelStack": outLabels,
                    "distance": 20,
                    "installed": True,
                    "nexthop": "192.168.3.4",
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func3 = functools.partial(_zebra_check_mpls_table)
    _, result3 = topotest.run_and_expect(test_func3, None, count=60, wait=0.5)
    assert result3 is None, "Failed to verify the fec_nexthop_resolution: mpls table"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
