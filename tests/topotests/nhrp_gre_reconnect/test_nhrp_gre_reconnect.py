#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_nhrp_gre_reconnect.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Zoran Peričić <zpericic@netst.org>
#

"""
test_nhrp_gre_reconnect.py:

Verify NHRP tunnels re-establish after the GRE source interface is
deleted and recreated, simulating a PPPoE disconnect/reconnect cycle.

The spoke (r1) uses a macvlan interface (r1-ppp0) on top of r1-eth0 as the
GRE tunnel source.  Deleting r1-ppp0 simulates a PPPoE disconnect; recreating
it simulates a reconnect.
"""

import os
import sys
import json
import time
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version, retry

pytestmark = [pytest.mark.nhrpd]

TOPOLOGY = """
    r1 (spoke/NHC) ---[s1 10.1.1.0/24]--- r2 (hub/NHS)

    r1-eth0: L2 only (macvlan parent)
    r1-ppp0: macvlan on r1-eth0, 10.1.1.100/24  (GRE source, deletable)
    r2-eth0: 10.1.1.2/24

    r1-gre0: 10.255.255.1/32  (mode gre, key 42, ttl 64, dev r1-ppp0)
    r2-gre0: 10.255.255.2/32  (mode gre, key 42, ttl 64, dev r2-eth0)
"""


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def _populate_iface():
    """Create macvlan source interface on r1 and GRE tunnels on both routers."""
    tgen = get_topogen()

    # r1: create macvlan r1-ppp0 on top of r1-eth0 (simulates PPPoE interface)
    for cmd in [
        "ip link set dev r1-eth0 up",
        "ip link add r1-ppp0 link r1-eth0 type macvlan mode bridge",
        "ip addr add 10.1.1.100/24 dev r1-ppp0",
        "ip link set dev r1-ppp0 up",
        "ip tunnel add r1-gre0 mode gre ttl 64 key 42 dev r1-ppp0 local 10.1.1.100 remote 0.0.0.0",
        "ip link set dev r1-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/r1-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/r1-gre0/disable_ipv6",
    ]:
        logger.info("r1: %s", cmd)
        tgen.net["r1"].cmd(cmd)

    # r2: standard GRE setup (hub)
    for cmd in [
        "ip tunnel add r2-gre0 mode gre ttl 64 key 42 dev r2-eth0 local 10.1.1.2 remote 0.0.0.0",
        "ip link set dev r2-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/r2-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/r2-gre0/disable_ipv6",
        "iptables -A FORWARD -i r2-gre0 -o r2-gre0"
        " -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1"
        " --hashlimit-mode srcip,dstip --hashlimit-srcmask 24"
        " --hashlimit-dstmask 24 --hashlimit-name loglimit-0"
        " -j NFLOG --nflog-group 1 --nflog-range 128",
    ]:
        logger.info("r2: %s", cmd)
        tgen.net["r2"].cmd(cmd)


def _delete_source():
    """Delete the spoke's macvlan source interface (simulates PPPoE disconnect)."""
    tgen = get_topogen()
    logger.info("Deleting r1-ppp0 (simulating PPPoE disconnect)")
    tgen.net["r1"].cmd("ip link del r1-ppp0")


def _recreate_source(ip="10.1.1.100"):
    """Recreate the spoke's macvlan source + GRE tunnel (simulates PPPoE reconnect)."""
    tgen = get_topogen()
    logger.info("Recreating r1-ppp0 with IP %s (simulating PPPoE reconnect)", ip)

    # Recreate macvlan
    tgen.net["r1"].cmd("ip link set dev r1-eth0 up")
    tgen.net["r1"].cmd(
        "ip link add r1-ppp0 link r1-eth0 type macvlan mode bridge"
    )
    tgen.net["r1"].cmd("ip addr add {}/24 dev r1-ppp0".format(ip))
    tgen.net["r1"].cmd("ip link set dev r1-ppp0 up")

    # Always recreate the GRE tunnel: even if the kernel kept it alive after
    # the macvlan deletion, its local address and dev binding are stale.
    # This matches real PPPoE behaviour where NetworkManager recreates the
    # GRE tunnel on every reconnect.
    tgen.net["r1"].cmd("ip tunnel del r1-gre0 2>/dev/null; true")
    tgen.net["r1"].cmd(
        "ip tunnel add r1-gre0 mode gre ttl 64 key 42"
        " dev r1-ppp0 local {} remote 0.0.0.0".format(ip)
    )
    tgen.net["r1"].cmd("ip link set dev r1-gre0 up")
    # Re-apply the GRE interface address via vtysh since zebra lost it
    tgen.gears["r1"].vtysh_cmd(
        """
        configure
            interface r1-gre0
                ip address 10.255.255.1/32
        """
    )


def _recreate_source_only(ip="10.1.1.100"):
    """Recreate only the macvlan source, leaving the GRE tunnel intact.

    This forces nhrpd to trigger ZEBRA_GRE_SOURCE_SET on the existing
    GRE tunnel, exercising the zebra encoder path (bugs #5-9).
    """
    tgen = get_topogen()
    logger.info(
        "Recreating r1-ppp0 with IP %s (GRE tunnel kept alive)", ip
    )

    tgen.net["r1"].cmd("ip link set dev r1-eth0 up")
    tgen.net["r1"].cmd(
        "ip link add r1-ppp0 link r1-eth0 type macvlan mode bridge"
    )
    tgen.net["r1"].cmd("ip addr add {}/24 dev r1-ppp0".format(ip))
    tgen.net["r1"].cmd("ip link set dev r1-ppp0 up")


def _check_nhrp_cache(router, json_file, count=40, wait=0.5):
    """Poll NHRP cache until it matches the expected JSON."""
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, router, "show ip nhrp cache json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)

    output = router.vtysh_cmd("show ip nhrp cache")
    logger.info("%s NHRP cache:\n%s", router.name, output)

    return result


def _check_nhrp_cache_inline(router, expected, count=40, wait=0.5):
    """Poll NHRP cache until it matches an inline expected dict."""
    test_func = partial(
        topotest.router_json_cmp, router, "show ip nhrp cache json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)

    output = router.vtysh_cmd("show ip nhrp cache")
    logger.info("%s NHRP cache:\n%s", router.name, output)

    return result


def setup_module(mod):
    logger.info("NHRP GRE Reconnect Topology:\n%s", TOPOLOGY)
    result = required_linux_kernel_version("4.18")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _populate_iface()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_NHRP,
            os.path.join(CWD, "{}/nhrpd.conf".format(rname)),
        )

    logger.info("Launching NHRP")
    for name in router_list:
        tgen.gears[name].start()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_nhrp_initial():
    """Verify NHRP converges: spoke registers with hub, cache entries correct."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Check r1 cache (nhs + local)
    result = _check_nhrp_cache(
        r1, "{}/r1/nhrp4_cache.json".format(CWD), count=40, wait=0.5
    )
    assert result is None, '"r1" NHRP cache mismatch on initial convergence'

    # Check r2 cache (dynamic + local)
    result = _check_nhrp_cache(
        r2, "{}/r2/nhrp4_cache.json".format(CWD), count=40, wait=0.5
    )
    assert result is None, '"r2" NHRP cache mismatch on initial convergence'

    # Verify data path
    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2:\n%s", output)
    assert " 0% packet loss" in output, "Initial ping r1 -> r2 failed"


def test_nhrp_source_disconnect():
    """Delete the source interface and verify NHRP detects the loss."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _delete_source()

    # r2's dynamic entry for r1 should eventually expire (holdtime=10s)
    expected_down = {
        "attr": {"entriesCount": 1},
        "table": [
            {
                "interface": "r2-gre0",
                "type": "local",
                "protocol": "10.255.255.2",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_down, count=60, wait=1)
    assert result is None, '"r2" NHRP cache still has r1 after source disconnect'


def test_nhrp_source_reconnect():
    """Recreate the source interface and verify NHRP re-establishes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _recreate_source(ip="10.1.1.100")

    # Check both caches converge back to initial state
    result = _check_nhrp_cache(
        r1, "{}/r1/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r1" NHRP cache mismatch after source reconnect'

    result = _check_nhrp_cache(
        r2, "{}/r2/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r2" NHRP cache mismatch after source reconnect'

    # Verify data path
    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2 after reconnect:\n%s", output)
    assert " 0% packet loss" in output, "Ping r1 -> r2 failed after source reconnect"


def test_nhrp_source_survives_reconnect():
    """Recreate only the source interface, keeping the GRE tunnel alive.

    This forces nhrpd to trigger ZEBRA_GRE_SOURCE_SET on the existing GRE
    tunnel (rather than a freshly created one), exercising the zebra encoder
    path where bugs #5-9 manifest.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Delete the source interface (GRE tunnel stays in kernel)
    _delete_source()

    # Wait for r2 to drop r1's dynamic entry
    expected_down = {
        "attr": {"entriesCount": 1},
        "table": [
            {
                "interface": "r2-gre0",
                "type": "local",
                "protocol": "10.255.255.2",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_down, count=60, wait=1)
    assert result is None, '"r2" cache still has r1 before source-only reconnect'

    # Recreate only the macvlan — GRE tunnel is NOT recreated.
    # nhrpd detects the new source interface and calls dplane_gre_set()
    # on the existing r1-gre0, exercising the zebra GRE encoder path.
    _recreate_source_only(ip="10.1.1.100")

    # Verify NHRP re-establishes through the surviving tunnel
    result = _check_nhrp_cache(
        r1, "{}/r1/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r1" NHRP cache mismatch after source-only reconnect'

    result = _check_nhrp_cache(
        r2, "{}/r2/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r2" NHRP cache mismatch after source-only reconnect'

    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2 after source-only reconnect:\n%s", output)
    assert " 0% packet loss" in output, "Ping failed after source-only reconnect"


def test_nhrp_gre_params_preserved():
    """Verify GRE tunnel parameters (key, TTL, flags) after dplane_gre_set on existing tunnel.

    Runs after test_nhrp_source_survives_reconnect where the GRE tunnel was NOT
    recreated, so these params were set by zebra's GRE encoder (bugs #5-6, #8).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.net["r1"].cmd("ip tunnel show r1-gre0")
    logger.info("GRE tunnel params after source-only reconnect:\n%s", output)

    assert "key 42" in output, "GRE key not preserved after source-only reconnect"
    assert "ttl 64" in output, "GRE TTL not preserved after source-only reconnect"


def test_nhrp_gre_stays_up():
    """Verify the GRE interface has UP flag after dplane_gre_set on existing tunnel.

    Runs after test_nhrp_source_survives_reconnect — exercises fix #9 where
    ifi_change no longer clears IFF_UP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    expected = {
        "r1-gre0": {
            "flags": "<UP,LOWER_UP,RUNNING>",
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show interface r1-gre0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)

    assert result is None, "r1-gre0 interface flags incorrect (missing UP?)"


def test_nhrp_gre_bounce_reconnect():
    """Delete source, recreate source, then bounce GRE (down+up).

    Models the original bug scenario: ppp0 dies unexpectedly, ppp0 comes
    back, and the GRE tunnel is bounced (down then up) on reconnect.
    FRR would never reconnect NHRP after this sequence.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # ppp0 dies
    _delete_source()

    # Wait for r2 to drop r1's dynamic entry
    expected_down = {
        "attr": {"entriesCount": 1},
        "table": [
            {
                "interface": "r2-gre0",
                "type": "local",
                "protocol": "10.255.255.2",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_down, count=60, wait=1)
    assert result is None, '"r2" cache still has r1 before GRE bounce reconnect'

    # ppp0 comes back
    _recreate_source_only(ip="10.1.1.100")

    # Bounce the GRE tunnel (simulates "nmcli con down nhrp0; nmcli con up nhrp0")
    logger.info("Bouncing r1-gre0 (down + up)")
    tgen.net["r1"].cmd("ip link set dev r1-gre0 down")
    tgen.net["r1"].cmd("ip link set dev r1-gre0 up")

    # Verify NHRP reconnects — this is where FRR originally failed
    result = _check_nhrp_cache(
        r1, "{}/r1/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r1" NHRP cache mismatch after GRE bounce reconnect'

    result = _check_nhrp_cache(
        r2, "{}/r2/nhrp4_cache.json".format(CWD), count=60, wait=1
    )
    assert result is None, '"r2" NHRP cache mismatch after GRE bounce reconnect'

    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2 after GRE bounce reconnect:\n%s", output)
    assert " 0% packet loss" in output, "Ping failed after GRE bounce reconnect"


def test_nhrp_reconnect_new_ip():
    """Reconnect with a different source IP and verify NHRP updates NBMA address."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Disconnect
    _delete_source()

    # Wait for r2 to drop r1
    expected_down = {
        "attr": {"entriesCount": 1},
        "table": [
            {
                "interface": "r2-gre0",
                "type": "local",
                "protocol": "10.255.255.2",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_down, count=60, wait=1)
    assert result is None, '"r2" cache still has r1 before new-IP reconnect'

    # Reconnect with new IP
    _recreate_source(ip="10.1.1.200")

    # r1 local entry should show new NBMA
    expected_r1 = {
        "table": [
            {
                "interface": "r1-gre0",
                "type": "local",
                "nbma": "10.1.1.200",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r1, expected_r1, count=60, wait=1)
    assert result is None, '"r1" local NBMA not updated to 10.1.1.200'

    # r2 dynamic entry should show new NBMA
    expected_r2 = {
        "table": [
            {
                "interface": "r2-gre0",
                "type": "dynamic",
                "protocol": "10.255.255.1",
                "nbma": "10.1.1.200",
            }
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_r2, count=60, wait=1)
    assert result is None, '"r2" dynamic NBMA not updated to 10.1.1.200'

    # Verify data path with new IP
    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2 after new-IP reconnect:\n%s", output)
    assert " 0% packet loss" in output, "Ping failed after new-IP reconnect"


def test_nhrp_rapid_flap():
    """Rapidly flap the source interface and verify NHRP converges."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Rapid flap: delete + recreate 3 times with short intervals
    for i in range(3):
        logger.info("Rapid flap iteration %d", i + 1)
        _delete_source()
        time.sleep(1)
        _recreate_source(ip="10.1.1.100")
        time.sleep(1)

    # After flapping, verify convergence
    # Build inline expectations (same as initial but with 10.1.1.100)
    expected_r1 = {
        "attr": {"entriesCount": 2},
        "table": [
            {
                "interface": "r1-gre0",
                "type": "nhs",
                "protocol": "10.255.255.2",
                "nbma": "10.1.1.2",
            },
            {
                "interface": "r1-gre0",
                "type": "local",
                "protocol": "10.255.255.1",
                "nbma": "10.1.1.100",
            },
        ],
    }
    result = _check_nhrp_cache_inline(r1, expected_r1, count=60, wait=1)
    assert result is None, '"r1" NHRP cache mismatch after rapid flap'

    expected_r2 = {
        "attr": {"entriesCount": 2},
        "table": [
            {
                "interface": "r2-gre0",
                "type": "local",
                "protocol": "10.255.255.2",
                "nbma": "10.1.1.2",
            },
            {
                "interface": "r2-gre0",
                "type": "dynamic",
                "protocol": "10.255.255.1",
                "nbma": "10.1.1.100",
            },
        ],
    }
    result = _check_nhrp_cache_inline(r2, expected_r2, count=60, wait=1)
    assert result is None, '"r2" NHRP cache mismatch after rapid flap'

    # Verify data path
    output = r1.run("ping 10.255.255.2 -c 5 -w 10")
    logger.info("Ping r1 -> r2 after rapid flap:\n%s", output)
    assert " 0% packet loss" in output, "Ping failed after rapid flap"


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
