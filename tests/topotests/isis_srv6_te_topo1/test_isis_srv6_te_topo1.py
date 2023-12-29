#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2023 6WIND S.A.
# Dmytro Shytyi <dmytro.shytyi@6wind.com>
#


"""
test_isis_srv6_te_topo1.py:


                         +---------+
                         |         |
                         |   SRC   |
                         |         |
                         +---------+
                              |eth-rt1
                              |
                              |10.8.0.0/24
                              |
                              |eth-src
                         +---------+
                         |         |
                         |   RT1   |
                         |         |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         |         +----------+----------+         |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         |         +---------------------+         |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+         +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.10.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         |         |
                         +---------+

"""

import os
import re
import sys
import json
import functools
import pytest
import subprocess

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    create_interface_in_kernel,
)
from multiprocessing import Process

pytestmark = [pytest.mark.isisd, pytest.mark.bgpd]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    tgen.add_router("rt4")
    tgen.add_router("rt5")
    tgen.add_router("rt6")
    tgen.add_router("dst")
    tgen.add_router("src")

    # Define connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-src")
    switch.add_link(tgen.gears["src"], nodeif="eth-rt1")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
        netmask="128",
        create=True,
    )


def setup_module(mod):
    """Sets up the pytest environment"""

    # Verify if kernel requirements are satisfied
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # Build the topology
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra and isis configuration files
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if os.path.exists("{}/isisd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
        if os.path.exists("{}/bgpd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
        if os.path.exists("{}/pathd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
            )
        if os.path.exists("{}/staticd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
            )

    tgen.gears["rt1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["rt1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt1"].run("ip link set vrf10 up")
    tgen.gears["rt1"].run("ip link set eth-src master vrf10")

    tgen.gears["rt6"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["rt6"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt6"].run("ip link set vrf10 up")
    tgen.gears["rt6"].run("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
    tgen.gears["rt6"].run("sysctl -w net.ipv6.conf.default.seg6_enabled=1")
    tgen.gears["rt6"].run("sysctl -w net.ipv6.conf.eth-rt4.seg6_enabled=1")
    tgen.gears["rt6"].run("sysctl -w net.ipv6.conf.eth-rt5.seg6_enabled=1")

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    # Teardown the topology
    tgen = get_topogen()
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = functools.partial(
        topotest.router_json_cmp, tgen.gears[rname], command, expected
    )
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step1/show_yang_interface_isis_adjacencies.ref",
        )


def test_configure_srv6_locators():
    tgen = get_topogen()
    tgen.gears["rt1"].vtysh_cmd(
        "configure \n \
         segment-routing \n \
         traffic-eng \n \
         segment-list srv6-header \n \
         index 1 ipv6-address fc00:0:3:: \n \
         index 2 ipv6-address fc00:0:5:: \n \
         index 3 ipv6-address fc00:0:6:: \n \
         exit \n \
         exit \n \
         srv6 \n \
         locators \n \
         locator loc1 \n \
         prefix fc00:0:1::/48 block-len 32 node-len 16 func-bits 16 \n \
         exit \n \
         locator loc2 \n \
         prefix fc00:0:1b::/48 block-len 32 node-len 16 func-bits 16 \n \
         exit \n \
         exit \n \
         exit \n \
         exit"
    )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step1/show_ipv6_route.ref"
        )


def test_srv6_locator_step1():
    logger.info("Test (step 1): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step1/show_srv6_locator_table.ref",
        )


#
# Step 2
#
# Test SRv6 TE Policy activted
#


def test_srv6_te_policy_activated():
    logger.info("Test (step 2): verify SRv6 TE policy activated")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        "configure \n \
        ipv6 route 2001:db8:10::/64 fc00:0:6:: color 1 \n \
        segment-routing \n \
        traffic-eng \n \
        policy color 1 endpoint fc00:0:6:: \n \
        candidate-path preference 1 name srv6 explicit segment-list srv6-header \n \
        exit \
        exit \
        exit \
        !"
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route static json",
            "step2/show_srv6_route.ref",
        )


#
# Step 3
#
# Test SRv6 additional srv6 route.
#


def test_srv6_te_policy_additional_route():
    logger.info("Test (step 3): verify SRv6 TE additional route")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        "configure \n \
        no ipv6 route 2001:db8:10::/64 fc00:0:6:: color 1 \n \
        ipv6 route fc00:0:6b::/48 fc00:0:6:: color 1 \n \
        exit \
        !"
    )

    # Add this to use 'eth-dst' if for BGP tests.
    tgen.gears["rt6"].run("ip link set eth-dst master vrf10")

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route static json",
            "step3/show_srv6_additional_route.ref",
        )


#
# Step 4
#
# Test SRv6 TE Policy removed
#


def test_srv6_te_policy_removed():
    logger.info("Test (step 4): verify SRv6 TE policy removed")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        "configure \n \
        no ipv6 route fc00:0:6b::/48 fc00:0:6:: color 1 \n \
        segment-routing \n \
        traffic-eng \n \
        no policy color 1 endpoint fc00:0:6:: \n \
        exit \
        exit \
        exit \
        !"
    )

    # for rname in ["rt1"]:
    #    router_compare_json_output(
    #        rname,
    #        "show ipv6 route static json",
    #        "step4/show_ipv6_route.ref",
    #    )


#
# Step 5
#
# Test SRv6 End.B6.Encaps
#


def test_srv6_end_b6_encaps():
    logger.info("Test (step 5): verify SRv6 END.B6.Encaps")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        "configure \n \
         ipv6 route fc00:0:6b::/48 fc00:0:6:: color 1 \n \
		 segment-routing \n \
		 traffic-eng \n \
 		 segment-list srv6 \n \
		  index 1 ipv6-address fc00:0:2:: \n \
		  index 2 ipv6-address fc00:0:6:: \n \
		  exit \n \
		  policy color 1 endpoint fc00:0:6:: \n \
		   candidate-path preference 1 name srv6 explicit segment-list srv6 \n \
		 exit \n \
		exit \n \
		!"
    )

    tgen.gears["rt2"].vtysh_cmd(
        "configure \n \
		 segment-routing \n \
		 traffic-eng \n \
		  segment-list srv6-header \n \
		   index 1 ipv6-address fc00:0:4:: \n \
		   index 2 ipv6-address fc00:0:5:: \n \
		  exit \n \
		  policy color 1 endpoint fc00:0:6:: \n \
		   srv6-binding-sid fc00:0:2:: \n \
		   candidate-path preference 1 name srv6 explicit segment-list srv6-header \n \
		 exit \n \
		exit \n \
		!"
    )

    tgen.gears["rt5"].vtysh_cmd(
        "configure \n \
          interface sr0 \n \
           ipv6 address fc00:0:5::/48 \n \
          exit"
    )

    tgen.gears["rt5"].run("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
    tgen.gears["rt5"].run("sysctl -w net.ipv6.conf.default.seg6_enabled=1")
    tgen.gears["rt5"].run("sysctl -w net.ipv6.conf.eth-rt4.seg6_enabled=1")

    subprocess.check_call(["apt", "install", "-y", "tcpdump"])
    if not os.path.isdir("/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/scapy-latest"):
        subprocess.check_call(
            ["git", "clone", "https://github.com/secdev/scapy.git", "/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/scapy-latest"]
        )
    if not os.path.isdir("/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/python_packages"):
        subprocess.check_call(
            ["pip", "download", "--dest", "/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/python_packages/", "setuptools==62.0.0"]
        )
        subprocess.check_call(
            ["pip", "download", "--dest", "/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/python_packages/", "wheel"]
        )
    tgen.gears["rt2"].run(
        "python3 -m venv /tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/; source /tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/venv/bin/activate; pip3 install --no-index --force-reinstall --find-links=/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/python_packages/ setuptools==62.0.0; pip3 install --no-index --find-links=/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/python_packages /tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/scapy-latest/"
    )

    def ping_func():
        tgen = get_topogen()
        tgen.gears["src"].run("ping 10.0.10.2 -c 128 -i 0.1")

    p1 = Process(target=ping_func)
    p1.start()
    # tgen.gears["rt2"].run("tcpdump -i any -q -w ./rt2-dump.pcap & ping 10.0.10.2 -c 5; killall tcpdump")
    tgen.gears["rt2"].run("touch ./rt2-dump.pcap && chmod oug+rwx ./rt2-dump.pcap")
    tgen.gears["rt2"].run("tcpdump -i any -w ./rt2-dump.pcap -c 64")

    # tgen.gears["rt2"].run("tshark -ni any -w /tmp/rt2-dump.pcap -c 64")
    p1.join()

    file_content = """\
from scapy.all import rdpcap, IPv6, IPv6ExtHdrSegmentRouting
scapy_cap = rdpcap(
    "/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/rt2-dump.pcap"
)
# scapy_cap = rdpcap('/tmp/rt2-dump.pcap')
output_pkt_flag = False
outer_srh = -1
outer_srhl = -1
inner_srh = -1
inner_srhl = -1
inner_most_srh = -1
inner_most_srhl = -1
for packet in scapy_cap:
    if "echo-request" in str(packet):
        print(packet)
        if packet.haslayer(IPv6) and packet.haslayer(IPv6ExtHdrSegmentRouting):
            outer_srh = packet[IPv6][IPv6ExtHdrSegmentRouting].addresses
            outer_srhl = packet[IPv6][IPv6ExtHdrSegmentRouting].segleft
            encap = packet[IPv6][IPv6ExtHdrSegmentRouting]
            if encap.haslayer(IPv6) and encap.haslayer(IPv6ExtHdrSegmentRouting):
                inner_srh = encap[IPv6][IPv6ExtHdrSegmentRouting].addresses
                inner_srhl = encap[IPv6][IPv6ExtHdrSegmentRouting].segleft
                bgp_encap = encap[IPv6][IPv6ExtHdrSegmentRouting]
                if bgp_encap.haslayer(IPv6) and bgp_encap.haslayer(
                    IPv6ExtHdrSegmentRouting
                ):
                    inner_most_srh = bgp_encap[IPv6][
                        IPv6ExtHdrSegmentRouting
                    ].addresses
                    inner_most_srhl = bgp_encap[IPv6][
                        IPv6ExtHdrSegmentRouting
                    ].segleft

                if (
                    ("fc00:0:6::" in inner_srh)
                    and ("fc00:0:2::" in inner_srh)
                    and (inner_srhl == 0)
                    and ("fc00:0:5::" in outer_srh)
                    and ("fc00:0:4::" in outer_srh)
                    and (outer_srhl == 1)
                    and ("fc00:0:6b:1::" in inner_most_srh)
                    and (inner_most_srhl == 0)
                ):
                    output_pkt_flag = True
                else:
                    print(
                        "Observed: outer srh: {}, segleft={}, inner srh: {}, segleft={}, inner_most_srh: {}, segleft={}".format(
                            outer_srh,
                            outer_srhl,
                            inner_srh,
                            inner_srhl,
                            inner_most_srh,
                            inner_most_srhl,
                        )
                    )

if output_pkt_flag == False:
    assertmsg = ('Unexpected SRH in the captured packet in rt2'
                 'Expected outer srh: [fc00:0:5::, fc00:0:4::], segleft=1, inner srh: [fc00:0:6::, fc00:0:2::], segleft=0, inner_most_srh: [fc00:0:6b:1::], segleft=0')
    assert False, assertmsg
    """

    file_path = (
        "/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/scapy_test_srv6.py"
    )
    with open(file_path, "w") as file:
        file.write(file_content)

    activate_cmd = f"source {os.path.join('/tmp/topotests/isis_srv6_te_topo1.test_isis_srv6_te_topo1/rt2/venv', 'bin', 'activate')}"
    subprocess.run(
        [activate_cmd, ";", "python3", file_path], shell=True, executable="/bin/bash"
    )



#
# Step 6
#
# Test SRv6 End.B6.Encaps removal
#


def test_srv6_end_b6_encaps_removal():
    logger.info("Test (step 6): verify SRv6 END.B6.Encaps removal")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt2"].vtysh_cmd(
        "configure \n \
		 segment-routing \n \
		 traffic-eng \n \
		  policy color 1 endpoint fc00:0:6:: \n \
		   no srv6-binding-sid fc00:0:2:: \n \
         exit \n \
		exit \n \
		!"
    )

    for rname in ["rt2"]:
        router_compare_json_output(
            rname,
            "show ipv6 route fc00:0:2:: json",
            "step6/show_ipv6_route.ref",
        )


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
