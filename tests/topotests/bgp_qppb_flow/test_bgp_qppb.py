#!/usr/bin/env python
#
# SPDX-License-Identifier: ISC
#
# test_bgp_qppb.py
#
# Copyright (c) 2023 VyOS Inc.
# Volodymyr Huti <v.huti@vyos.io>
#

"""
Test QPPB plugin functionality:
- verify bpf map manipulations affect xdp processing properly
- dscp tag is displayed for nexthop entry
- QOS setup balances the traffic throughput via plugin
- LPM overlapping setup

TODO:
- redirection to different l3 iface based on configured marking
- layer 3 devices are functional
- fragmentation/scalability
"""

import pytest

pytestmark = [pytest.mark.bgpd]

"""
test_bgp_qppb.py:

       20...1
       +------+    20...2
       |  h1  |----------+  AS30          AS10          AS10
       +------+          ++------+      +------+      +------+
                          |      |      |      |      |      |
       +------+   20..1.2 |  R1  |      |  R2  |      |  R3  |
       |  h2  |-----------|      |------|      |------|      |
       +------+           +------+      +------+      +------+
       20..1.1           lo:1.0.1.17   lo:1.0.2.17     | lo:1.0.3.17
                         QPPB Router                   |
                                                       |
                                        lo:           +------+
                                        |  1.0.4.17   |      |
                                        | 10.61.0.1   |  R4  |
                                        |   *****     |      |
                                        | 10.66.0.1   +------+
                                                        AS60
"""

import os
import re
import sys
import time
import functools
import subprocess

from lib import topotest
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.bgp import verify_bgp_convergence
from lib.common_config import (
    create_debug_log_config,
    apply_raw_config,
    start_topology,
    TcpDumpHelper,
    IPerfHelper,
    step,
)

from bgp_qppb_flow import *
from lib.topotest import version_cmp, interface_to_ifindex
import ctypes


xdp_ifindex = lambda host, iface: c_uint(interface_to_ifindex(host, iface))
af21_tag = c_ubyte(0x12)
af12_tag = c_ubyte(0x0C)
zero_tag = c_ubyte(0)


# Helpers
# -------------------------------------------------------
def setup_test_hosts(tgen, router):
    """
    Setup client hosts to test traffic forwarding
    NOTE, networks are overlaping for the purpose of lpm_overlap TC
          privateDirs empty, so you can str(host)
    """
    h1 = tgen.add_host("h1", "20.0.0.1", "dev h1-eth0", private_mounts="")
    h2 = tgen.add_host("h2", "20.0.1.1", "dev h2-eth0", private_mounts="")
    router.add_link(h1)
    router.add_link(h2)
    tgen.net.configure_hosts()

    ip_cmd = "ip addr add {} {}"
    # XXX: will be used for overlap testing
    router.cmd_raises(ip_cmd.format("20.0.0.2/16", "dev " + router.name + "-eth0"))
    router.cmd_raises(ip_cmd.format("20.0.1.2/24", "dev " + router.name + "-eth1"))
    # XXX: do we really need this?
    router.cmd_raises("sysctl -w net.ipv4.conf.all.proxy_arp=1")


def check_ping4(rnode, dst, connected=True, src=None, tos=None, count=10, timeout=0):
    ping = ""
    if timeout:
        ping = "timeout {} ".format(timeout)
    ping += "ping {} -c{}".format(dst, count)
    if src:
        ping = "{} -I{}".format(ping, src)
    if tos:
        ping = "{} -Q{}".format(ping, src)

    match = ", {} packet loss".format("100%" if connected else "0%")
    logger.info(
        "[+] {} ping -> {}, connection expected -> {}".format(
            rnode, dst, "up" if connected else "down"
        )
    )
    logger.debug("Executing the ping -> {}".format(ping))

    def _match_missing(rnode, dst, match):
        output = rnode.run(ping)
        logger.info(output)
        return match not in output

    func = functools.partial(_match_missing, rnode, dst, match)
    success, result = topotest.run_and_expect(func, True, count, wait=1)
    assert result is True


# Module
# -------------------------------------------------------
def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()
    # iperf_helper.cleanup()
    # tcpdumpf_helper.cleanup()


def setup_module(mod):
    # XXX: write down [ requirement:verion, ... ]
    # result |= required_linux_kernel_version("5+")
    # result |= required_linux_kernel_features("BPF")
    # result |= required_package_version(bcc, dev)
    #       ...
    # if result is not True:
    #     pytest.skip("Kernel requirements are not met")
    # XXX(?): verify that user XPD env doesn't overlap with test

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    json_file = f"{CWD}/topo_cisco.json"
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # Extra setup steps
    # -----------------------------------------------------------------------
    r4 = tgen.gears["r4"]
    r1 = tgen.gears["r1"]

    debug_rmap_dict = {"r1": {"raw_config": ["end", "debug route-map"]}}
    debug_config_dict = {
        "r1": {"debug": {"log_file": "debug.log", "enable": ["bgpd", "zebra"]}}
    }
    if DEV_DEBUG:
        create_debug_log_config(tgen, debug_config_dict)
        apply_raw_config(tgen, debug_rmap_dict)

    setup_test_hosts(tgen, r1)
    r1.vtysh_cmd(
        """
          configure
            router bgp 30
              table-map QPPB
    """
    )
    # each address will receive different marking (tier of preference)
    lo_ip_add = "ip address add dev lo 10.6{0}.0.1/32"
    [r4.cmd_raises(lo_ip_add.format(n)) for n in range(1, 7)]

    # Initializing BPF objects
    # -----------------------------------------------------------------------
    # NOTE: we need to switch mnt namespace to instantiate BPF mappings
    # XXX: python3.12 introduces os.setns, for now use libc directly
    ns = "/proc/%d/ns/mnt" % r1.net.pid
    nsfd = os.open(ns, os.O_RDONLY)

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.setns(nsfd, 0)

    r1.cmd_raises(
        """
        mkdir -p /sys/fs/bpf
        mount -t bpf bpf /sys/fs/bpf
    """
    )
    load_qppb_plugin(tgen, r1)


# Test Cases
# -------------------------------------------------------
# @pytest.mark.skip
def test_xdp_lpm(tgen):
    """
    Manually setup the XDP mappings, without route destribution
    Assume that H1 is pinging the managment interface on R4 [lo(1.0.4.17)]
    The R1 is marking/forwarding based on QPPB mappings:
             qppb_router
        h1 ->  [ R1 ] -> .... -> R4
            eth0      r1-r2-eth0
    The packet marking happens as follows:
    -----------------------------------------
    xdp_qppb(xdp_md *skb):
        switch qppb_map[iif]:  // idx for eth0
            BgpPolicy.Src: mark = dscp_map[(skb.src, 32)]
            BgpPolicy.Dst: mark = dscp_map[(skb.dst, 32)]
                     NONE: return pass

        if MARK_SKB:  skb->tos = mark
        if MARK_META: skb->classid = mark
        return pass
    -----------------------------------------
    """
    h1 = tgen.gears["h1"]
    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    qppb_map = r1.bpf[b"qppb_mode_map"]
    dscp_map = r1.bpf[b"dscp_map"]

    r1_eth0_idx = xdp_ifindex(r1, "r1-eth0")
    qppb_map[r1_eth0_idx] = BgpPolicy.Dst.value
    router_attach_xdp(r1, b"r1-eth0")

    # --------------------------------------------------------------------------------
    tcpdump = TcpDumpHelper(tgen, "icmp[0] == 8")  # ICMP Echo requst
    r4_lo_key = KeyV4(32, (1, 0, 4, 17))
    h1_key = KeyV4(32, (20, 0, 0, 1))
    r4_lo_ip = "1.0.4.17"
    PINGS = 10

    def _check(sender, receiver, dst, cap_iface, tos, src=None, ping_tos=None):
        p1 = tcpdump.capture_start(receiver, cap_iface, background=True, timeout=PINGS)
        assert p1, "Failed to run tcpdump on {}:\n{}".format(sender.name, p1)

        check_ping4(sender, dst, src=src, count=PINGS, timeout=PINGS, tos=ping_tos)
        time.sleep(1.5)
        return tcpdump.find_msg(receiver, "tos 0x%x" % tos.value)

    check_connection = functools.partial(_check, h1, r4, r4_lo_ip, "r4-r3-eth0")
    h1.run("ping -c 3 -w 3 " + r4_lo_ip)  # refresh arp cache, etc ...
    time.sleep(2)
    # --------------------------------------------------------------------------------
    dscp_map[r4_lo_key] = af21_tag
    found, matches = check_connection(af21_tag)
    assert found and matches >= (
        PINGS - 1  # XXX: first packet is not tagged - caching issues?
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    # --------------------------------------------------------------------------------
    dscp_map[r4_lo_key] = af12_tag
    found, matches = check_connection(af12_tag)
    assert found and matches >= (
        PINGS - 1
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    # ---------------------------------------------------------------------------------
    dscp_map[h1_key] = af12_tag
    dscp_map[r4_lo_key] = zero_tag
    qppb_map[r1_eth0_idx] = BgpPolicy.Src.value
    found, matches = check_connection(af12_tag)
    assert found and matches >= (
        PINGS - 1
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    # --------------------------------------------------------------------------------
    # XXX: Run some flows into opposite directions
    # XXX: Use ping with custom tos ...
    # XXX: Try using invalid values, i.e. tos > 64
    #      ...
    # --------------------------------------------------------------------------------
    qppb_map.clear()
    dscp_map[h1_key] = af21_tag
    dscp_map[r4_lo_key] = af12_tag
    found, _ = check_connection(af12_tag)
    assert not found, "LPM misbehaviour, markings not expected after clearing dscp map"

    # cleanup used resources
    router_remove_xdp(r1, b"r1-eth0")
    dscp_map.pop(h1_key)
    dscp_map.pop(r4_lo_key)
    # XXX dscp_map.clear() - clears the initial config, used by the following test
    # bpf_print_trace(bpf)
    # breakpoint()
    # --------------------------------------------------------------------------------


def test_nh_dscp_displayed(tgen):
    """
    Verify that QoS group is displayed for the marked prefix
    """
    nhFile = "{}/bgp_ipv4_nh.ref".format(CWD)
    expected = open(nhFile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()

    def check_dscp_displayed():
        r1 = tgen.gears["r1"]
        actual = r1.vtysh_cmd("show bgp ipv4 10.61.0.1")
        actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
        actual = re.sub(r" version [0-9]+", " version XX", actual)
        actual = re.sub(r"Last update: .*", "Last update: XXXX", actual)
        return topotest.get_textdiff(
            actual, expected, title1="Actual bgp nh show", title2="Expected bgp nh show"
        )

    ok, result = topotest.run_and_expect(check_dscp_displayed, "", count=5, wait=1)
    assert ok, result


def test_qos_topo(tgen):
    """
    Setup QOS topology and verify traffic prioritization works as expected

    Steps:
    ---------------------------------------------
    - setup tc on qppb router (r1)
      * 10Mbit htb queue
      * bandwidth classes
    - setup iperf servers
    - choose processing mode SKB / META
      * attach tc filters
        - for SKB, use tc binary
        - for META, use pyroute tc func
      * run traffic in Dst mode
      * run traffic with custom tos
        verify, it is respected
      * run traffic in Src mode
      * flood link with different prio traffic
        verify rebalancing works

          dscp | bw Mbytes
         ------+------------
           10  |   7.5
           20  |   5.0
           30  |   2.5
           40  |   2.5
            *  |   1
    ---------------------------------------------
    Refences:
    - ipmininet/tests/test_tc.py
    - mininet/examples/test/test_simpleperf.py
    - mininet/examples/test/test_intfoptions.py
    - mininet/examples/test/test_walkthrough.py
    - mininet/mininet/link.py -> class TCIntf
    - http://luxik.cdi.cz/~devik/qos/htb/manual/userg.htm
    ---------------------------------------------
    """
    xdp_dscp = lambda x: c_ubyte(dscp_tos(x))
    dscp_tos = lambda x: x << 2
    h1 = tgen.gears["h1"]
    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    tc_egress_idx = interface_to_ifindex(r1, "r1-r2-eth0")
    r1_eth0_idx = xdp_ifindex(r1, "r1-eth0")
    qppb_map = r1.bpf[b"qppb_mode_map"]
    dscp_map = r1.bpf[b"dscp_map"]
    h1_key = KeyV4(24, (20, 0, 0, 1))
    R4_L0_61 = "10.61.0.1"
    tolerance = 0.20  # 20% slippage, for short lived connection
    TIME_OUT = 8
    bw = 7.5

    # TC setup
    # ---------------------------------------------------------------
    _class = "class add dev r1-r2-eth0 parent 1:1 "
    _filter = "filter add dev r1-r2-eth0 parent 1:0 "
    u32_fmt = "prio %d protocol ip u32 match ip tos %d 0xff classid %s"
    tc_setup = [
        "qdisc replace dev r1-r2-eth0 root handle 1:0 htb default 50",
        "class add dev r1-r2-eth0 parent 1:0 classid 1:1 htb rate 10Mbps",
        _class + "classid 1:10 htb rate 7.5Mbps",
        _class + "classid 1:20 htb rate 5.0Mbps",
        _class + "classid 1:30 htb rate 2.5Mbps",
        _class + "classid 1:40 htb rate 0.5Mbps",
        _class + "classid 1:50 htb rate 100kbps",
    ]
    tc_filters = [
        _filter + u32_fmt % (1, dscp_tos(10), "1:10"),
        _filter + u32_fmt % (2, dscp_tos(20), "1:20"),
        _filter + u32_fmt % (3, dscp_tos(30), "1:30"),
        _filter + u32_fmt % (4, dscp_tos(40), "1:40"),
    ]

    # Setup iperf server/client helpers
    # ---------------------------------------------------------------
    servers = clients = []
    iph = IPerfHelper(tgen)
    start_client = functools.partial(iph.iperf, json=True, length=TIME_OUT)
    start_server = functools.partial(iph.iperf, server=True, background=True)
    for i in range(1, 7):
        server = start_server(r4, bind_addr="10.6%d.0.1" % i, port=5200 + i)
        servers.append(server)

    tc_check(r1, tc_setup)
    for mode in [XdpMode.META, XdpMode.SKB]:
        # reset tc filters/ xdp handlers
        r1.run("tc filter del dev r1-r2-eth0")
        router_remove_xdp(r1, b"r1-eth0")
        load_qppb_plugin(tgen, r1, mode=mode)
        router_attach_xdp(r1, b"r1-eth0")

        if mode == XdpMode.SKB:
            tc_check(r1, tc_filters)
        elif mode == XdpMode.META:
            tc_bpf_filter(r1, tc_egress_idx)
        # refresh arp cache, etc ...
        h1.run("ping -c 3 " + R4_L0_61)
        time.sleep(1)
        # breakpoint()
        # TC1: BGP_POLICT_DST
        # -----------------------------------------------------------------
        tc_log_stats(r1, "r1-r2-eth0")
        qppb_map[r1_eth0_idx] = BgpPolicy.Dst.value
        client = start_client(h1, dst=R4_L0_61)
        tc_log_stats(r1, "r1-r2-eth0")

        out, err = client.communicate()
        assert_bw(out, bw, tolerance, time=TIME_OUT)

        # TC2: Respect TOS
        # -----------------------------------------------------------------
        tc_log_stats(r1, "r1-r2-eth0")
        client = start_client(h1, dst=R4_L0_61, dscp=20)
        tc_log_stats(r1, "r1-r2-eth0")
        # bpf_print_trace(r1.bpf)

        bw = 5
        out, err = client.communicate()
        assert_bw(out, bw, tolerance, time=TIME_OUT)

        # TC3: BGP_POLICT_SRC, swap host roles
        # -----------------------------------------------------------------
        qppb_map[r1_eth0_idx] = BgpPolicy.Src.value
        dscp_map[h1_key] = xdp_dscp(10)
        tc_log_stats(r1, "r1-r2-eth0")
        client = start_client(h1, dst=R4_L0_61)
        tc_log_stats(r1, "r1-r2-eth0")

        bw = 7.5
        out, err = client.communicate()
        assert_bw(out, bw, tolerance, time=TIME_OUT)
        dscp_map[h1_key] = zero_tag

        # TC4: verify bw rebalancing
        # - setup all without max prio (10)
        # - start max prio
        #   - verify BW is realocated -> max prio takes full link
        #   - verify lowest prio gets no BW
        # -----------------------------------------------------------------
        # breakpoint()
        qppb_map[r1_eth0_idx] = BgpPolicy.Dst.value
        for i in range(2, 7):
            client = start_client(
                h1, dst="10.6%d.0.1" % i, port=5200 + i, timeout=10, background=True
            )
            clients.append(client)

        # kill the second highest prio
        high_prio = clients[0]
        high_prio.kill()

        # max prio flow, should receive the best treatment
        client = start_client(h1, dst=R4_L0_61)
        out, err = client.communicate()
        assert_bw(out, bw, tolerance, time=TIME_OUT)

        time.sleep(5)  # XXX:
        # iph.stop_host("h1")  # does not work with background processes
        iperf_json = "%s/iperf_h1_10.66.0.1_client.json" % tgen.logdir
        with open(iperf_json) as file:
            out = file.read()
            # the lowest prio should be ~0.5mbps
            assert_bw(out, 0.25, 1, time=TIME_OUT)

    # XXX: swap priority on the fly
    #  + swap filter priorty
    #  + swap lpm entries
    #  + swap direction
    # ....


@pytest.mark.skip
def test_xdp_network_overlap(tgen):
    """
    The feature configuration involves many steps making it quite easy to messup
    and accidentally leak traffic, apply wrong preference, etc ..
    I`m assuming the following scenarios that may require special handling on xdp side
       * configuration mistakes, network loops
       * delays during (re)convergance (I guess?)
       * using overlaping network ranges (router cascading ?)
       * external events (malformed update packets / fail in processing ...?)
       * sidefects of admin involvment ...
       # XXX(?): how this would work with different kinds of NAT
       # XXX: overlaping vs router cascading scenario
    Topo:
       20.0.0.0/16   h1-eth1, learned (dscp af22)
         h1 <-----++
                     r2 <-- r3 <-- r4
         h2 <-----++
       20.0.1.0/24   h2-eth2, installed by admin

    Admin should be aware that subnetwork 20..1. will receive the QOS treatment from 20.../16,
    even though it was not explicitly configured for the new network segment
    """
    # XXX,TBD: not sure how common/critical such issues would be
    # XXX: likely, there will be many ways to acidentally leak traffic (;
    #      any tools to detect leaks? i.e. some packet processing stats to look at
    r1 = tgen.gears["r1"]
    qppb_map = r1.bpf[b"qppb_mode_map"]
    dscp_map = r1.bpf[b"dscp_map"]

    r1_eth0_idx = xdp_ifindex(r1, "r1-r2-eth0")
    qppb_map[r1_eth0_idx] = BgpPolicy.Dst.value
    h1_key = KeyV4(16, (20, 0, 0, 0))
    dscp_map[h1_key] = af21_tag
    router_attach_xdp(r1, b"r1-r2-eth0")

    r4 = tgen.gears["r4"]
    r4.run("ping -c 3 20.0.0.1")  # is tagged with 0x12
    r4.run("ping -c 3 20.0.1.1")  # is tagged as well

    # Admin can dissable marking/processing by manually inserting prefix without policy
    # The LPM will lookup the more specific prefix and ignore it
    h2_key = KeyV4(24, (20, 0, 1, 0))
    dscp_map[h2_key] = zero_tag
    r4.run("ping -c 3 20.0.1.1")  # should not be tagged any more

    # ::TBD::
    breakpoint()


@pytest.mark.skip
def test_get_version(tgen):
    "Sanity testing, triggers breapoint"
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    version = r1.vtysh_cmd("show version")
    logger.info("FRR version is: " + version)

    for host in ["h1", "r1", "r4"]:
        tgen.net.hosts[host].run_in_window("bash")

    bpf_print_trace(r1.bpf)
    breakpoint()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
