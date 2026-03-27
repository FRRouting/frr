#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_specific_query_frag.py
#
# Copyright (c) 2026 by
# Vitaliy Guschin <guschin108@gmail.com>
#

"""
Test suite for IGMPv3 Group-and-Source-Specific Query fragmentation:

1. Verify IGMPv3 state creation with a large number of sources (5000+).
2. Validate the generation of Group-and-Source-Specific Queries upon
   receiving BLOCK_OLD_SOURCES reports.
3. Verify that the number of transmitted specific queries matches the
   configured Last Member Query Count (LMQT).
"""

import os
import sys
import time
import pytest
import json

from scapy.utils import rdpcap
from scapy.main import load_contrib
from scapy.config import conf

# pylint: disable=C0413
load_contrib("igmpv3")
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topotest import json_cmp
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

HOST_IP="192.168.10.2"
IGMP_GROUP="232.1.1.12"
TOTAL_SOURCES = 5000
SOURCE_PREFIX = "10.0"
STEP = 250

@pytest.fixture
def sources_db():
    db = {
        f"{SOURCE_PREFIX}.{(i // 256) % 256}.{i % 256}": {
            "query_count": 0
        }
        for i in range(1, TOTAL_SOURCES + 1)
    }
    return db

def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    tgen.add_host("h1", f"{HOST_IP}/24", "via 192.168.10.1")

    s1 = tgen.add_switch("s1")

    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["h1"])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears['r1']
    r1.load_config(TopoRouter.RD_ZEBRA, f"{CWD}/r1/frr.conf")
    r1.load_config(TopoRouter.RD_PIM, f"{CWD}/r1/frr.conf")

    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def igmpv3_sources_save_to_json(tgen, sources_db):
    sources_list = list(sources_db.keys())
    sources_file = os.path.join(tgen.logdir, "sources.json")

    with open(sources_file, "w") as f:
        json.dump(sources_list, f)

def igmpv3_send_membership_reports(tgen, mode):
    sources_file_path = os.path.join(tgen.logdir, "sources.json")

    cmd = (
        f"python3 {CWD}/igmp_send.py "
        f"--mode {mode} "
        f"--group {IGMP_GROUP} "
        f"--src {HOST_IP} "
        f"--json {sources_file_path} "
        f"--iface h1-eth0 "
        f"--step {STEP}"
    )

    h1 = tgen.gears['h1']
    output = h1.run(cmd)

    assert "Success" in output, f"Script failed. Output: {output}"

def igmpv3_send_membership_reports_include(tgen):
    logger.info("Send IGMPv3 Membership Reports (MODE_IS_INCLUDE)")

    igmpv3_send_membership_reports(tgen, "include")

def igmpv3_send_membership_reports_block(tgen):
    logger.info("Send IGMPv3 Membership Reports (BLOCK_OLD_SOURCES)")

    igmpv3_send_membership_reports(tgen, "block")

def igmpv3_verify_group(tgen):
    expected = {
        "r1-eth0": {
            "groups": [
                {
                    "group": IGMP_GROUP,
                    "sourcesCount": TOTAL_SOURCES
                }
            ]
        }
    }

    def verify_group():
        r1 = tgen.gears["r1"]
        data = r1.vtysh_cmd("show ip igmp groups json", isjson=True)
        return json_cmp(data, expected)

    success, result = topotest.run_and_expect(verify_group, None, count=60, wait=1)
    assert success, f"IGMP group did not converge! Last output:\n{result}"

def igmpv3_verify_group_sources(tgen, sources_db):
    r1 = tgen.gears["r1"]
    data = r1.vtysh_cmd("show ip igmp sources json", isjson=True)

    sources_list = data["r1-eth0"][IGMP_GROUP]["sources"]
    actual_ips = {item["source"] for item in sources_list}
    expected_ips = set(sources_db.keys())

    missing = expected_ips - actual_ips
    extra = actual_ips - expected_ips

    error_msg = ""
    if missing:
        error_msg += f"Missing {len(missing)} sources!"
    if extra:
        error_msg += f"Found {len(extra)} unexpected sources!"

    assert not error_msg, f"IGMP Sources mismatch."

def igmpv3_verify_group_and_sources(tgen, sources_db):
    logger.info("Verify IGMPv3 Group and Source States")

    igmpv3_verify_group(tgen)
    igmpv3_verify_group_sources(tgen, sources_db)

def igmpv3_start_traffic_capture(tgen):
    logger.info("Start IGMPv3 traffic capture")

    pcap_file = os.path.join(tgen.logdir, "h1/dump.pcap")
    pid_file = os.path.join(tgen.logdir, "h1/tshark.pid")
    h1 = tgen.gears["h1"]
    cmd = (
        f"(tshark -n -s 9200 -Q -i h1-eth0 -f 'igmp' -w {pcap_file} > /dev/null 2>&1 & "
        f"echo $! > {pid_file})"
    )
    h1.run(cmd)
    time.sleep(2)

def igmpv3_wait_for_expiration(tgen):
    logger.info("Wait for expiration of IGMPv3 sources")

    expected = {'totalGroups': 0 }

    def verify_group():
        r1 = tgen.gears["r1"]
        data = r1.vtysh_cmd("show ip igmp groups json", isjson=True)
        return json_cmp(data, expected)

    success, result = topotest.run_and_expect(verify_group, None, count=60, wait=1)
    assert success, f"IGMP group did not converge! Last output:\n{result}"

def igmpv3_stop_traffic_capture(tgen):
    logger.info("Stop IGMPv3 traffic capture")

    h1 = tgen.gears["h1"]

    pid_file = os.path.join(tgen.logdir, "h1/tshark.pid")
    cmd = (
        f"PID=$(cat {pid_file}); "
        f"kill -SIGINT $PID; "
        f"wait $PID 2>/dev/null; "
        f"rm {pid_file}"
    )

    h1.run(cmd)
    time.sleep(2)

def igmpv3_verify_specific_query(tgen, sources_db):
    logger.info("Verify processing of IGMPv3 Group and Source Specific Queries")

    pcap_file = os.path.join(tgen.logdir, "h1/dump.pcap")
    if not os.path.exists(pcap_file):
        assert False, f"Pcap file {pcap_file} not found"

    conf.max_list_count = 10000

    packets = rdpcap(pcap_file)
    for pkt in packets:
        if pkt.haslayer(IGMPv3mq):
            query = pkt[IGMPv3mq]
            if query.gaddr == IGMP_GROUP and query.numsrc > 0:
                for src_ip in query.srcaddrs:
                    if src_ip in sources_db:
                        sources_db[src_ip]["query_count"] += 1

    r1 = tgen.gears["r1"]
    data = r1.vtysh_cmd("show ip igmp interface r1-eth0 json", isjson=True)
    lmqc = data["r1-eth0"]["lastMemberQueryCount"]

    for src, stats in sources_db.items():
        count = stats['query_count']
        assert count == lmqc, (
            f"Source {src} mismatch! "
            f"Expected {lmqc} Specific Queries, "
            f"but captured {count} in pcap."
        )

    logger.info(
        f"Verified: All {TOTAL_SOURCES} source(s) received {lmqc} Group and Source Specific Queries "
        f"(matches LMQC in config)"
    )

def test_igmpv3_specific_query_frag(tgen, sources_db):
    "Tests IGMP specefic query fragmentation"

    logger.info(f"Starting IGMPv3 fragmentation test ({TOTAL_SOURCES} sources)")
    igmpv3_sources_save_to_json(tgen, sources_db)
    igmpv3_send_membership_reports_include(tgen)
    igmpv3_verify_group_and_sources(tgen, sources_db)
    igmpv3_start_traffic_capture(tgen)
    igmpv3_send_membership_reports_block(tgen)
    igmpv3_wait_for_expiration(tgen)
    igmpv3_stop_traffic_capture(tgen)
    igmpv3_verify_specific_query(tgen, sources_db)
    logger.info(f"Success!")

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
