#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
IPv4-specific redirect counter tests for EVPN MH ARP/ND failover behavior.
"""

import os
import sys
import time
from functools import partial

import pytest

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
TOPOTEST_DIR = os.path.dirname(THIS_DIR)
sys.path.append(TOPOTEST_DIR)

import test_evpn_mh_v4_v6_num as evpn_mh_base

pytestmark = [pytest.mark.bgpd, pytest.mark.pim6d, pytest.mark.evpn]

# Reuse the shared topology fixture from the base EVPN MH v4/v6 test module.
tgen_and_ip_version = evpn_mh_base.tgen_and_ip_version


def _check_arp_counter_progress_any(duts_before):
    """
    Return success if IPv4 ARP accounting progresses on any DUT.
    """
    details = {}
    for dut, before in duts_before:
        after = evpn_mh_base.get_arp_nd_redirect_stats(dut)
        details[dut.name] = {"before": before, "after": after}
        if after["ipv4_arp"] > before["ipv4_arp"]:
            return None

    return "IPv4 ARP counter did not progress on any DUT: {}".format(details)


def test_evpn_arp_redirect_counters_ipv4(tgen_and_ip_version):
    """
    Validate IPv4 ARP redirect accounting path by generating ARP churn
    from dual-attached hosts and verifying counters progress.
    """
    tgen, ip_version = tgen_and_ip_version

    if ip_version != "ipv4":
        pytest.skip("IPv4-specific redirect test")

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Depending on ECMP/hash, ingress can be observed on either rack-1 ToR.
    duts = [tgen.gears["torm11"], tgen.gears["torm12"]]
    duts_before = []
    for dut in duts:
        summary = dut.vtysh_cmd("show evpn arp-nd-redirect")
        assert "EVPN ARP-reply/NA redirect:" in summary
        before_stats = evpn_mh_base.get_arp_nd_redirect_stats(dut)
        duts_before.append((dut, before_stats))
        evpn_mh_base.logger.info(
            "%s arp-nd redirect counters before (v4): %s", dut.name, before_stats
        )

    host_if = {}
    for host_name in ("hostd11", "hostd12", "hostd21", "hostd22"):
        host_if[host_name] = evpn_mh_base._detect_host_bond_if(tgen.gears[host_name])

    peer_targets = {
        "hostd11": "45.0.0.12",
        "hostd12": "45.0.0.11",
        "hostd21": "45.0.0.22",
        "hostd22": "45.0.0.21",
    }
    gw_ip = "45.0.0.1"
    injected = 0

    for _ in range(10):
        for host_name in ("hostd11", "hostd12", "hostd21", "hostd22"):
            host = tgen.gears[host_name]
            intf = host_if[host_name]
            host.run("ip neigh flush dev {} 2>/dev/null || true".format(intf))
            host.run("ping -I {} -c 1 {} >/dev/null 2>&1 || true".format(intf, gw_ip))
            host.run(
                "ping -I {} -c 1 {} >/dev/null 2>&1 || true".format(
                    intf, peer_targets[host_name]
                )
            )
            src_ip = evpn_mh_base._get_global_ipv4_on_intf(
                host, intf
            ) or evpn_mh_base._fallback_host_ipv4(host_name)
            _, peer_mac = evpn_mh_base.compute_host_ip_mac(
                "hostd12"
                if host_name == "hostd11"
                else "hostd11"
                if host_name == "hostd12"
                else "hostd22"
                if host_name == "hostd21"
                else "hostd21"
            )
            evpn_mh_base._send_unicast_arp_reply(
                host, intf, src_ip, peer_targets[host_name], peer_mac
            )
            injected += 1
        time.sleep(1)

    assert injected > 0, "No unicast ARP-reply injections were generated"

    test_fn = partial(_check_arp_counter_progress_any, duts_before)
    _, result = evpn_mh_base.topotest.run_and_expect(test_fn, None, count=40, wait=1)

    for dut, _ in duts_before:
        after_stats = evpn_mh_base.get_arp_nd_redirect_stats(dut)
        evpn_mh_base.logger.info(
            "%s arp-nd redirect counters after (v4): %s", dut.name, after_stats
        )

    assert result is None, result


def test_evpn_arp_redirected_counter_ipv4(tgen_and_ip_version):
    """
    Strict IPv4 redirect validation:
    - force local ES-down + peer-up condition
    - send targeted ARP traffic
    - verify Redirected packets increments.
    """
    tgen, ip_version = tgen_and_ip_version

    if ip_version != "ipv4":
        pytest.skip("IPv4-specific redirect test")

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    duts = [tgen.gears["torm11"], tgen.gears["torm12"]]
    redirect_before = []
    for dut in duts:
        summary = dut.vtysh_cmd("show evpn arp-nd-redirect")
        assert "EVPN ARP-reply/NA redirect:" in summary
        stats = evpn_mh_base.get_arp_nd_redirect_stats(dut)
        redirect_before.append((dut, stats))
        evpn_mh_base.logger.info(
            "%s redirected-before strict check (v4): %s", dut.name, stats
        )

    # Force ingress to torm11 and create ES-down only on torm11.
    torm11 = tgen.gears["torm11"]
    torm12 = tgen.gears["torm12"]
    src_host = tgen.gears["hostd12"]
    strict_esi = evpn_mh_base.host_es_map.get("hostd11")
    precheck_count = int(os.environ.get("TOPOTEST_STRICT_PRECHECK_COUNT", "45"))
    precheck_wait = float(os.environ.get("TOPOTEST_STRICT_PRECHECK_WAIT", "1"))
    evpn_mh_base.logger.info(
        "strict redirect precheck (v4): waiting up to %.1fs for ES %s peer set readiness",
        precheck_count * precheck_wait,
        strict_esi,
    )
    es_precheck = evpn_mh_base.wait_for_es_peer_set_ready(
        torm11, strict_esi, [], count=precheck_count, wait=precheck_wait
    )
    if es_precheck is not None:
        pytest.skip(
            "strict redirect precheck failed (v4, ES peer set not ready after {:.1f}s) for {}: {}".format(
                precheck_count * precheck_wait, strict_esi, es_precheck
            )
        )

    torm11.run("ip link set dev torm11-eth2 down 2>/dev/null || true")
    src_host.run("ip link set dev hostd12-eth1 down 2>/dev/null || true")
    down_check_fn = partial(evpn_mh_base.check_link_oper_down, torm11, "hostbond1")
    _, down_result = evpn_mh_base.topotest.run_and_expect(
        down_check_fn, None, count=20, wait=1
    )
    assert down_result is None, "torm11 hostbond1 did not transition down: {}".format(
        down_result
    )

    # Put hostd12 ingress (hostbond2) into VLAN1000 temporarily.
    torm11.run("bridge vlan del vid 1 dev hostbond2 2>/dev/null || true")
    torm11.run("bridge vlan del vid 1 pvid untagged dev hostbond2 2>/dev/null || true")
    torm11.run("bridge vlan del vid 1001 dev hostbond2 2>/dev/null || true")
    torm11.run(
        "bridge vlan del vid 1001 pvid untagged dev hostbond2 2>/dev/null || true"
    )
    torm11.run("bridge vlan add vid 1000 dev hostbond2 2>/dev/null || true")
    torm11.run(
        "bridge vlan add vid 1000 pvid untagged dev hostbond2 2>/dev/null || true"
    )
    pvid_check_fn = partial(evpn_mh_base.check_port_vlan_pvid, torm11, "hostbond2", 1000)
    _, pvid_result = evpn_mh_base.topotest.run_and_expect(
        pvid_check_fn, None, count=10, wait=1
    )
    assert pvid_result is None, pvid_result

    peer_rx_before = evpn_mh_base.get_link_rx_packets(torm12, "vxlan48")
    evpn_mh_base.logger.info(
        "%s strict-check peer-rx-before (v4) %s: %d",
        torm12.name,
        "vxlan48",
        peer_rx_before,
    )
    peer_rx_result = None
    peer_rx_after = peer_rx_before
    try:
        src_if = evpn_mh_base._detect_host_bond_if(src_host)
        src_ip4 = evpn_mh_base._get_global_ipv4_on_intf(
            src_host, src_if
        ) or evpn_mh_base._fallback_host_ipv4(src_host.name)
        dst_ip4, dst_mac = evpn_mh_base.compute_host_ip_mac("hostd11")
        dst_ip4 = dst_ip4.split("/")[0]
        for dbg_dut in duts:
            dbg_es = dbg_dut.vtysh_cmd("show evpn es {} json".format(strict_esi))
            dbg_mac = dbg_dut.vtysh_cmd(
                "show evpn mac vni 1000 mac {} json".format(dst_mac)
            )
            dbg_redirect = dbg_dut.vtysh_cmd("show evpn arp-nd-redirect")
            dbg_link = dbg_dut.run(
                "ip -d link show dev hostbond2; bridge link show dev hostbond2; "
                "bridge vlan show dev hostbond2"
            )
            evpn_mh_base.logger.info(
                "%s strict-debug es(%s): %s", dbg_dut.name, strict_esi, dbg_es
            )
            evpn_mh_base.logger.info(
                "%s strict-debug mac(%s): %s", dbg_dut.name, dst_mac, dbg_mac
            )
            evpn_mh_base.logger.info(
                "%s strict-debug redirect:\n%s", dbg_dut.name, dbg_redirect
            )
            evpn_mh_base.logger.info(
                "%s strict-debug hostbond2:\n%s", dbg_dut.name, dbg_link
            )

        for _ in range(12):
            src_host.run("ip neigh flush dev {} 2>/dev/null || true".format(src_if))
            src_host.run(
                "ping -I {} -c 1 {} >/dev/null 2>&1 || true".format(src_if, dst_ip4)
            )
            evpn_mh_base._send_unicast_arp_reply(src_host, src_if, src_ip4, dst_ip4, dst_mac)
            time.sleep(1)

        redirect_fn = partial(evpn_mh_base.check_arp_redirect_progress_any, redirect_before)
        _, redirect_result = evpn_mh_base.topotest.run_and_expect(
            redirect_fn, None, count=40, wait=1
        )
        peer_rx_check = partial(
            evpn_mh_base.check_link_rx_progress, torm12, "vxlan48", peer_rx_before
        )
        _, peer_rx_result = evpn_mh_base.topotest.run_and_expect(
            peer_rx_check, None, count=20, wait=1
        )
        peer_rx_after = evpn_mh_base.get_link_rx_packets(torm12, "vxlan48")
    finally:
        # Restore hostbond2 VLAN mapping back to VLAN1001.
        torm11.run("bridge vlan del vid 1000 dev hostbond2 2>/dev/null || true")
        torm11.run(
            "bridge vlan del vid 1000 pvid untagged dev hostbond2 2>/dev/null || true"
        )
        torm11.run("bridge vlan add vid 1 dev hostbond2 2>/dev/null || true")
        torm11.run("bridge vlan add vid 1001 dev hostbond2 2>/dev/null || true")
        torm11.run(
            "bridge vlan add vid 1001 pvid untagged dev hostbond2 2>/dev/null || true"
        )
        src_host.run("ip link set dev hostd12-eth1 up 2>/dev/null || true")
        torm11.run("ip link set dev torm11-eth2 up 2>/dev/null || true")

    for dut, _ in redirect_before:
        stats = evpn_mh_base.get_arp_nd_redirect_stats(dut)
        evpn_mh_base.logger.info(
            "%s redirected-after strict check (v4): %s", dut.name, stats
        )
    evpn_mh_base.logger.info(
        "%s strict-check peer-rx-after (v4) %s: %d (delta=%d)",
        torm12.name,
        "vxlan48",
        peer_rx_after,
        peer_rx_after - peer_rx_before,
    )

    assert redirect_result is None, redirect_result
    assert peer_rx_result is None, peer_rx_result
