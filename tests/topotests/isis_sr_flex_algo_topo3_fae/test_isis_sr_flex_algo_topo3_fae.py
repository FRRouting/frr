#!/usr/bin/env python


#
# test_isis_flex_algo_topo3_fae.py
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
test_isis_sr_flex_algo_topo3_fae.py:

            +--------+                  +--------+
            |        |                  |        |
            |  RT1   |------------------|  RT2   |
            |        |                  |        |
            +--------+                  +--------+
           /     |    \\                     |    \\
          /      |     \\                    |     \\
+--------+       |      \\                   |      \\
|        |       |       +--------+          |       +--------+  +--------+
|  RT0   |       |       |        |          |       |        |  |        |
|        |       |       |  RT4   |------------------|  RT3   |  |  H9    |
+--------+       |       |        |          |       |        |  |        |
    |     \\     |       +--------+          |       +--------+  +--------+
    |      \\    |           |               |            |    \\     |
+--------+  +--------+       |          +--------+        |     \\    |
|        |  |        |       |          |        |        |      +--------+
|  H0    |  |  RT5   |-------|----------|  RT6   |        |      |        |
|        |  |        |       |          |        |        |      |  RT9   |
+--------+  +--------+       |          +--------+        |      |        |
                      \\     |                    \\      |      +--------+
                       \\    |                     \\     |     /
                        \\   |                      \\    |    /
                         +--------+                  +--------+
                         |        |                  |        |
                         |  RT8   |------------------|  RT7   |
                         |        |                  |        |
                         +--------+                  +--------+
"""

import os
import sys
import pytest
import json
import tempfile
import re
import subprocess
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import kill_router_daemons, start_router_daemons
import isis_sr_flex_algo_topo3_fae.lib.flexalgo_config as faconfig


pytestmark = [pytest.mark.isisd, pytest.mark.bgpd, pytest.mark.pathd]
zebra_conf_head = """\
log file zebra.log
!
hostname rt1
!
log stdout notifications
log monitor notifications
log commands
!
!debug zebra packet
!debug zebra dplane
!debug zebra kernel
!
"""

zebra_conf_tail = """\
ip forwarding
ipv6 forwarding
!
line vty
!
"""

isisd_conf_itf = """\
 ip router isis 1
 ipv6 router isis 1
 isis hello-multiplier 3
 isis network point-to-point
"""

isisd_conf_area_fmt = """\
router isis {}
 lsp-gen-interval 2
 net 49.0000.0000.0000.00{}.00
 is-type level-1
 topology ipv6-unicast
 !
 affinity-map red bit-position 0
 affinity-map green bit-position 1
 affinity-map blue bit-position 2
 affinity-map purple bit-position 3
 !"""

isisd_conf_area_sr_fmt = """\
 segment-routing on
 segment-routing global-block {} {}
 segment-routing node-msd 8"""

bgpd_conf_fmt = """\
router bgp 1
 neighbor {} remote-as 1
 neighbor {} update-source lo
 !
 address-family ipv4 unicast
  network {}
  neighbor {} route-map sr-te in
 exit-address-family
exit
!
route-map sr-te permit 10
 set sr-te color 1
exit
!"""

# Segment routing policies will be created as the tests run.
pathd_conf_fmt = """\
segment-routing
 traffic-eng
  mpls-te on
  mpls-te import isis
  flex-algo igp-defaults protocol isis area-tag {}
 exit
exit

!"""

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}

isis_area = "1"
sr_global_block = (20000, 23999)
sr_flex_algos = range(128, 132)
sr_flex_algos_cnt = len(list(sr_flex_algos))
sr_flex_algo_participation = (
    # Flex-Algo
    # 128    129     130     131
    (True, True, True, True),  # rt0
    (True, False, True, True),  # rt1
    (True, False, True, True),  # rt2
    (True, False, True, True),  # rt3
    (True, False, False, True),  # rt4
    (False, True, True, True),  # rt5
    (False, True, True, True),  # rt6
    (False, True, True, True),  # rt7
    (False, True, False, True),  # rt8
    (True, True, True, True),  # rt9
)
sr_flex_algos_affinity = (
    "include-any green",  # algo 128
    "include-any red",  # algo 129
    "include-any blue",  # algo 130
    "include-any purple",  # algo 131
)
advertise_flex_algos = (
    False,  # rt0
    True,  # rt1
    False,  # rt2
    False,  # rt3
    False,  # rt4
    False,  # rt5
    False,  # rt6
    False,  # rt7
    True,  # rt8
    False,  # rt9
)
ipv4_indices = (
    range(100, sr_flex_algos_cnt * 100 + 0 + 1, 100),  # rt0
    range(101, sr_flex_algos_cnt * 100 + 1 + 1, 100),  # rt1
    range(102, sr_flex_algos_cnt * 100 + 2 + 1, 100),  # rt2
    range(103, sr_flex_algos_cnt * 100 + 3 + 1, 100),  # rt3
    range(104, sr_flex_algos_cnt * 100 + 4 + 1, 100),  # rt4
    range(105, sr_flex_algos_cnt * 100 + 5 + 1, 100),  # rt5
    range(106, sr_flex_algos_cnt * 100 + 6 + 1, 100),  # rt6
    range(107, sr_flex_algos_cnt * 100 + 7 + 1, 100),  # rt7
    range(108, sr_flex_algos_cnt * 100 + 8 + 1, 100),  # rt8
    range(109, sr_flex_algos_cnt * 100 + 9 + 1, 100),  # rt9
)
ipv6_indices = (
    range(1100, 1000 + sr_flex_algos_cnt * 100 + 0 + 1, 100),
    range(1101, 1000 + sr_flex_algos_cnt * 100 + 1 + 1, 100),
    range(1102, 1000 + sr_flex_algos_cnt * 100 + 2 + 1, 100),
    range(1103, 1000 + sr_flex_algos_cnt * 100 + 3 + 1, 100),
    range(1104, 1000 + sr_flex_algos_cnt * 100 + 4 + 1, 100),
    range(1105, 1000 + sr_flex_algos_cnt * 100 + 5 + 1, 100),
    range(1106, 1000 + sr_flex_algos_cnt * 100 + 6 + 1, 100),
    range(1107, 1000 + sr_flex_algos_cnt * 100 + 7 + 1, 100),
    range(1108, 1000 + sr_flex_algos_cnt * 100 + 8 + 1, 100),
    range(1109, 1000 + sr_flex_algos_cnt * 100 + 9 + 1, 100),
)

router_names = tuple([f"rt{x}" for x in range(0, 10)])
num_routers = len(router_names)
router_links = (
    (
        0,
        1,
        ip_network("10.1.0.0/24"),
        ip_network("2001:db8:0:1::/64"),
        ["green", "blue", "purple"],
    ),
    (0, 5, ip_network("10.5.0.0/24"), ip_network("2001:db8:0:5::/64"), ["red", "blue"]),
    (
        1,
        2,
        ip_network("10.12.0.0/24"),
        ip_network("2001:db8:1:2::/64"),
        ["green", "blue", "purple"],
    ),
    (1, 4, ip_network("10.14.0.0/24"), ip_network("2001:db8:1:4::/64"), ["green"]),
    (1, 5, ip_network("10.15.0.0/24"), ip_network("2001:db8:1:5::/64"), []),
    (
        2,
        3,
        ip_network("10.23.0.0/24"),
        ip_network("2001:db8:2:3::/64"),
        ["green", "blue", "purple"],
    ),
    (2, 6, ip_network("10.26.0.0/24"), ip_network("2001:db8:2:6::/64"), []),
    (
        3,
        4,
        ip_network("10.34.0.0/24"),
        ip_network("2001:db8:3:4::/64"),
        ["green", "purple"],
    ),
    (3, 7, ip_network("10.37.0.0/24"), ip_network("2001:db8:3:7::/64"), []),
    (
        3,
        9,
        ip_network("10.39.0.0/24"),
        ip_network("2001:db8:3:9::/64"),
        ["green", "blue"],
    ),
    (4, 8, ip_network("10.48.0.0/24"), ip_network("2001:db8:4:8::/64"), ["purple"]),
    (
        5,
        6,
        ip_network("10.56.0.0/24"),
        ip_network("2001:db8:5:6::/64"),
        ["red", "blue", "purple"],
    ),
    (
        5,
        8,
        ip_network("10.58.0.0/24"),
        ip_network("2001:db8:5:8::/64"),
        ["red", "purple"],
    ),
    (
        6,
        7,
        ip_network("10.67.0.0/24"),
        ip_network("2001:db8:6:7::/64"),
        ["red", "blue", "purple"],
    ),
    (7, 8, ip_network("10.78.0.0/24"), ip_network("2001:db8:7:8::/64"), ["red"]),
    (
        7,
        9,
        ip_network("10.79.0.0/24"),
        ip_network("2001:db8:7:9::/64"),
        ["red", "blue", "purple"],
    ),
)
lo_v4_base = ip_network("10.254.0.0/32")
lo_v6_base = ip_network("2001:db8:f::0/128")
network_v4_base = ip_network("10.255.0.0/24")
network_v6_base = ip_network("2001:db8:ff00::/64")

switch_names = ("sw0", "sw9")
router_switch_links = (
    # sw, rtr, v4-subnet, v6-subnet
    (0, 0, network_v4_base, network_v6_base),
    (1, 9, network_v4_base, network_v6_base),
)

host_names = ("h0", "h9")
host_links = (
    # host, switch, v4-address, v4-gateway, v6-address, v6-gateway
    (
        0,
        0,
        faconfig.v4net(0, network_v4_base, host=True, offset=2),
        faconfig.v4net(0, network_v4_base, 1).split("/")[0],
        faconfig.v6net(0, network_v6_base, host=True, offset=2),
        faconfig.v6net(0, network_v6_base, 1).split("/")[0],
    ),
    (
        1,
        1,
        faconfig.v4net(9, network_v4_base, host=True, offset=2),
        faconfig.v4net(9, network_v4_base, 1).split("/")[0],
        faconfig.v6net(9, network_v6_base, host=True, offset=2),
        faconfig.v6net(9, network_v6_base, 1).split("/")[0],
    ),
)

_nft_links = [[car, f"eth-{cadr}"] for car, cadr, *cdr in router_links] + [
    [cadr, f"eth-{car}"] for car, cadr, *cdr in router_links
]


def _num_mpls_nexthops(router):
    routes = tgen.gears[router].vtysh_cmd("show ip route bgp json", isjson=True)
    route_prefixes_infos = sorted(routes.items())

    counts = []
    for rp, ri in route_prefixes_infos:
        nexthops = [nh for nh in ri.get("nexthops", []) if "labels" in nh]
        counts.append(len(nexthops))
    return counts


def _expect_num_nexthops(router, expected_num_nexthops, count=20):
    "Wait until number of nexthops for routes matches expectation"
    logger.info(f"waiting for BGP router {router} nexthops {expected_num_nexthops}")
    test_func = partial(_num_mpls_nexthops, router)
    _, result = topotest.run_and_expect(
        test_func, expected_num_nexthops, count=count, wait=3
    )
    assert (
        result == expected_num_nexthops
    ), "'{}' wrong number of route nexthops".format(router)


def _ping(tgen, hidx, addr, count=5):
    """Ping address from (non-router) host

    Returns True if all echo requests were answered.  Returns False
    otherwise."""
    # root@h0:/home/ekinzie/frr/tests/topotests# ping -c 5 -n -W 1  10.255.9.2
    # PING 10.255.9.2 (10.255.9.2) 56(84) bytes of data.
    # 64 bytes from 10.255.9.2: icmp_seq=1 ttl=59 time=0.155 ms
    # 64 bytes from 10.255.9.2: icmp_seq=2 ttl=59 time=0.089 ms
    # 64 bytes from 10.255.9.2: icmp_seq=3 ttl=59 time=0.077 ms
    # 64 bytes from 10.255.9.2: icmp_seq=4 ttl=59 time=0.077 ms
    # 64 bytes from 10.255.9.2: icmp_seq=5 ttl=59 time=0.093 ms
    #
    # --- 10.255.9.2 ping statistics ---
    # 5 packets transmitted, 5 received, 0% packet loss, time 4100ms
    # rtt min/avg/max/mdev = 0.077/0.098/0.155/0.029 ms

    hostname = host_names[hidx]
    host = tgen.gears[hostname]
    cmd = f"ping -c {count} -n -W 1 {addr}"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: ping returned {rc}")
        return False

    success = False
    stats = False
    for line in out.splitlines():
        if stats:
            tokens = re.split(r"\W+", line)
            tx = tokens[0]
            rx = tokens[3]
            success = True if tx == rx else False
            break
        if line.startswith("---"):
            stats = True
            continue

    if not success:
        logger.info(out)
    return success


#
# Check version of nftables against known minimum level for
# syntax compatibility. Cache result.
#
_nft_version_is_good = None


def _nft_version_ok():
    global _nft_version_is_good

    def versiontuple(v):
        return tuple(map(int, (v.split("."))))

    def _docheck():
        global _nft_version_is_good
        _nft_version_is_good = False
        logger.info("checking nftables version")
        try:
            vstr = subprocess.check_output(
                ["nft", "--version"], universal_newlines=True
            )
        except Exception as err:
            logger.warning(err)
            return
        m = re.search(r"nftables v([\d\.]+)", vstr)
        if m:
            actual = versiontuple(m.group(1))
            # We know 0.8.2 is too old (syntax errors on our filter cmds).
            # Not sure what is the real minimum version.
            minimum = versiontuple("0.9.7")
            if actual >= minimum:
                _nft_version_is_good = True

    if _nft_version_is_good is not None:
        return _nft_version_is_good

    _docheck()
    return _nft_version_is_good


#
# List of labels we'll look for in traffic filters below
#
_traf_labels_of_interest = [20109, 20209, 20309, 20409, 20509]


def _add_nft_counter(tgen, hostname, device, addr):
    "Add nftables entry that matches addr so we can count packets"

    # Need "sudo apt install nftables"
    if not _nft_version_ok():
        return True

    host = tgen.gears[hostname]
    devparam = ""
    if device != "":
        devparam = f"device {device}"

    # need a different chain name per-device
    n_chain = f"c-fa1-{device}"

    cmd = f"nft add table netdev t-fa1"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: nft returned {rc}")
        return False

    cmd = f"nft add chain netdev t-fa1 {n_chain} '{{type filter hook ingress device {device} priority -500;}}'"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: nft returned {rc}")
        return False

    #
    # despite "nft describe ether_type" output listing ip == 0x0008,
    # the correct symbolic value to use here is not byte-swapped
    #
    cmd = f"nft add rule netdev t-fa1 {n_chain} ether type 0x8847 counter"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: nft returned {rc}")
        return False

    #
    # We have to left-shift the labels 4 bits for alignment on 8-bit boundary,
    # then mask top 20 bits.
    #
    # nftables raw matching offset and length are expressed in bits
    #
    for v in _traf_labels_of_interest:
        vs = v << 4
        cmd = f"nft add rule netdev t-fa1 {n_chain} ether type 0x8847 @ll,112,24 '&' 0xfffff0 {vs} counter"
        logger.info(f"{hostname}: {cmd}")
        rc, out, err = host.net.cmd_status(cmd)
        if rc != 0:
            logger.info(f"{hostname}: nft returned {rc}")
            return False

    cmd = f"nft add rule netdev t-fa1 {n_chain} ip daddr {addr} counter"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: nft returned {rc}")
        return False

    return True


#
# Returns a dict keyed by numeric mpls label and/or string ip address
#
# Each value is a dict with keys p and b (for packets and bytes)
#
def _read_nft_counter(tgen, hostname, device, addr=None):
    "Get the value of an nftables counter for address addr"

    counters = {}

    host = tgen.gears[hostname]

    # need a different chain name per-device
    n_chain = f"c-fa1-{device}"

    cmd = f"nft list chain netdev t-fa1 {n_chain}"
    logger.info(f"{hostname}: {cmd}")
    rc, out, err = host.net.cmd_status(cmd)
    if rc != 0:
        logger.info(f"{hostname}: nft list returned {rc}")
        return ""

    logger.info(f'{hostname}: nft list output: "{out}"')

    if addr:
        for line in out.splitlines():
            m = re.search(
                re.escape(addr) + r"\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)", line
            )
            if m:
                logger.info(f'{hostname}: match: "{line}"')
                # count = line.split()[0]
                counters[addr] = {"p": int(m.group(1)), "b": int(m.group(2))}
                break

    #
    # extract packet counts for all labels of interest
    #
    for v in _traf_labels_of_interest:
        # shifted value used in rule
        vs = v << 4
        pat = (
            r"ether\s+type\s+0x8847\s+@ll,112,24\s+&\s+16777200\s+==\s+"
            + re.escape(f"{vs}")
            + r"\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)"
        )
        for line in out.splitlines():
            m = re.search(pat, line)
            if m:
                count_p = m.group(1)
                count_b = m.group(2)
                counters[v] = {"p": int(m.group(1)), "b": int(m.group(2))}
                logger.info(f"{hostname}: mlabel {v} packets: {m.group(1)}")
                break

    return counters


def add_nft_all_counters(tgen, addr):
    if not _nft_version_ok():
        return True

    for i in _nft_links:
        hostname = router_names[i[0]]
        _add_nft_counter(tgen, hostname, i[1], addr)


def read_nft_all_counters(tgen, addr):
    c = {}

    if not _nft_version_ok():
        return c

    for i in _nft_links:
        hostname = router_names[i[0]]
        if not hostname in c:
            c[hostname] = {}
        c[hostname][i[1]] = _read_nft_counter(tgen, hostname, i[1], addr)

    return c


def diff_nft_all_counters(before, after):
    diff = {}

    if not _nft_version_ok():
        return diff

    for hostname in before.keys():
        diff[hostname] = {}
        for itf in before[hostname].keys():
            diff[hostname][itf] = {}
            for item in before[hostname][itf].keys():
                tmp = {}
                tmp["p"] = (
                    after[hostname][itf][item]["p"] - before[hostname][itf][item]["p"]
                )
                tmp["b"] = (
                    after[hostname][itf][item]["b"] - before[hostname][itf][item]["b"]
                )
                diff[hostname][itf][item] = tmp
    return diff


def check_nft_counters_by_link_affinity(counters, affinities, packets, label):
    """Check that packets are incremented only links with particular affinities

    `counters`   - a dictionary as returned by diff_nft_all_counters()
    `affinities` - a list of link affinities ("green", "red", etc.)
    `packets`    - the expected number of packets counted on any link
    `label`      - the expected MPLS label in the counted packets

    Return True if the expected number of packets was sampled only on
    links with the specified affinities.  Return False if a packet count
    is wrong, if a link with an incorrect affinity was used or if no
    packets were found on any of the links with the desired affinities.
    """

    tot_pkts = 0
    for rtr in counters:
        idx_a = router_names.index(rtr)
        for itf in counters[rtr]:
            idx_b = int(itf[4:])
            if label not in counters[rtr][itf]:
                logger.error(
                    f"router {rtr} interface {itf} has no label {label}: {counters[rtr][itf]}"
                )
                continue
            label_packets = counters[rtr][itf][label]["p"]
            if label_packets == 0:
                continue
            if label_packets != packets:
                return False
            tot_pkts += label_packets

            # Find the link attached to router `rtr` interface `itf`
            # and get its affinities.
            idx = sorted([idx_a, idx_b])
            links = [
                link[-1]
                for link in router_links
                if link[0] == idx[0] and link[1] == idx[1]
            ]
            link = links[0]
            match = False
            for aff in affinities:
                if aff in link:
                    match = True
                    break

            if not match:
                logger.error(
                    f"Found packets with MPLS label {label} on a "
                    + f'link with none of these affinities: {",".join(affinities)}'
                )
                return False
            logger.info(
                f"OK - {packets} packets on router {rtr} interface {itf} label {label}"
            )

    if tot_pkts == 0:
        logger.error(
            f'No packets found on links with affinity for {",".join(affinities)}'
        )
        return False
    return True


def build_topo(tgen):
    "Build function"

    def connect_routers(tgen, left_idx, right_idx):
        left = "rt{}".format(left_idx)
        right = "rt{}".format(right_idx)
        tgen.gears[left].add_link(
            tgen.gears[right], myif=f"eth-{right_idx}", nodeif=f"eth-{left_idx}"
        )
        l_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, left_idx)
        tgen.gears[left].run("ip link set eth-{} down".format(right_idx))
        tgen.gears[left].run("ip link set eth-{} address {}".format(right_idx, l_addr))
        tgen.gears[left].run("ip link set eth-{} up".format(right_idx))
        r_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, right_idx)
        tgen.gears[right].run("ip link set eth-{} down".format(left_idx))
        tgen.gears[right].run("ip link set eth-{} address {}".format(left_idx, r_addr))
        tgen.gears[right].run("ip link set eth-{} up".format(left_idx))

    def connect_switch(tgen, swidx, ridx, v4base, v6base):
        sw = switch_names[swidx]
        rtr = router_names[ridx]
        tgen.gears[sw].add_link(tgen.gears[rtr], nodeif=f"eth-{sw}")

    def connect_host(tgen, swidx, hidx):
        sw = switch_names[swidx]
        host = host_names[hidx]
        tgen.gears[sw].add_link(tgen.gears[host], nodeif=f"eth-{sw}")

    def zebra_conf_itfs(tgen, idx):
        cfg = (
            "interface lo\n"
            + f" ip address {faconfig.v4addr(idx, lo_v4_base)}\n"
            + f" ipv6 address {faconfig.v6addr(idx, lo_v6_base)}\n"
            + "!\n"
        )
        for link in (ll for ll in router_links if ll[0] == idx):
            cfg += (
                f"interface eth-{link[1]}\n"
                + f" ip address {faconfig.v4addr(idx, link[2])}\n"
                + f" ipv6 address {faconfig.v6addr(idx, link[3])}\n"
                + "!\n"
            )
        for link in (ll for ll in router_links if ll[1] == idx):
            cfg += (
                f"interface eth-{link[0]}\n"
                + f" ip address {faconfig.v4addr(idx, link[2])}\n"
                + f" ipv6 address {faconfig.v6addr(idx, link[3])}\n"
                + "!\n"
            )
        for link in (ll for ll in router_switch_links if ll[1] == idx):
            # only ipv4 for now
            sw = switch_names[link[0]]
            cfg += (
                f"interface eth-{sw}\n"
                + f" ip address {faconfig.v4net(idx, link[2], 1)}\n"
                + "!\n"
            )
        return cfg[:-2]  # drop the trailing newline

    def isisd_conf_itfs(tgen, idx):
        cfg = (
            "interface lo\n"
            + " ip router isis 1\n"
            + " ipv6 router isis 1\n"
            + " isis passive\n!\n"
        )
        for link in (ll for ll in router_links if ll[0] == idx):
            cfg += f"interface eth-{link[1]}\n" + isisd_conf_itf
            if len(link[4]) > 0:
                cfg += f' isis affinity flex-algo {" ".join(link[4])}\n'
            cfg += "!\n"
        for link in (ll for ll in router_links if ll[1] == idx):
            cfg += f"interface eth-{link[0]}\n" + isisd_conf_itf
            if len(link[4]) > 0:
                cfg += f' isis affinity flex-algo {" ".join(link[4])}\n'
            cfg += "!\n"
        return cfg[:-2]  # drop the trailing newline

    def write_zebra_conf(tgen, idx, filename):
        with open(filename, "w") as _fp:
            print(zebra_conf_head, file=_fp)
            print(zebra_conf_itfs(tgen, idx), file=_fp)
            print(zebra_conf_tail, file=_fp)
        return

    def write_isisd_conf(tgen, idx, filename):
        idx_02x = f"{idx:02x}" if idx > 0 else f"{num_routers:02x}"
        with open(filename, "w") as _fp:
            print(isisd_conf_itfs(tgen, idx), file=_fp)
            print(isisd_conf_area_fmt.format(isis_area, idx_02x), file=_fp)
            for _fa, aff, part in zip(
                sr_flex_algos, sr_flex_algos_affinity, sr_flex_algo_participation[idx]
            ):
                if not part:
                    continue
                print(f" flex-algo {_fa}", file=_fp)
                if advertise_flex_algos[idx]:
                    print(f"  advertise-definition", file=_fp)
                    if aff is not None:
                        print(f"  affinity {aff}", file=_fp)
                print(" !", file=_fp)
            print(isisd_conf_area_sr_fmt.format(*sr_global_block), file=_fp)
            lov4 = faconfig.v4addr(idx, lo_v4_base)
            lov6 = faconfig.v6addr(idx, lo_v6_base)
            for _fa, v4sid, v6sid, part in zip(
                sr_flex_algos,
                ipv4_indices[idx],
                ipv6_indices[idx],
                sr_flex_algo_participation[idx],
            ):
                if not part:
                    continue
                print(
                    f" segment-routing prefix {lov4} algorithm {_fa} index {v4sid}",
                    file=_fp,
                )
                print(
                    f" segment-routing prefix {lov6} algorithm {_fa} index {v6sid}",
                    file=_fp,
                )

    def write_bgpd_conf(tgen, idx, peeridx, filename):
        neighbor = faconfig.v4addr(peeridx, lo_v4_base).split("/")[0]
        network = faconfig.v4net(idx, network_v4_base)
        args = (neighbor, neighbor, network, neighbor)
        with open(filename, "w") as _fp:
            print(bgpd_conf_fmt.format(*args), file=_fp)

    def write_pathd_conf(tgen, idx, filename):
        with open(filename, "w") as _fp:
            print(pathd_conf_fmt.format(isis_area), file=_fp)

    for switch in switch_names:
        tgen.add_switch(switch)

    for rtr in router_names:
        tgen.add_router(rtr)

    for name, info in zip(host_names, host_links):
        logger.info(f"HOST {info}")
        tgen.add_host(name, info[2], "via " + info[3])
        connect_host(tgen, info[1], info[0])

    for link in router_links:
        connect_routers(tgen, *link[0:2])

    for link in router_switch_links:
        connect_switch(tgen, *link)

    for rtr in router_names:
        try:
            os.mkdir(f"{CWD}/{rtr}")
        except FileExistsError:
            pass

    for idx in range(0, num_routers):
        tgen.gears[router_names[idx]].cmd_raises("ip link add dummy0 type dummy")
        write_zebra_conf(tgen, idx, f"{CWD}/{router_names[idx]}/zebra.conf")
        write_isisd_conf(tgen, idx, f"{CWD}/{router_names[idx]}/isisd.conf")
    write_bgpd_conf(tgen, 0, num_routers - 1, f"{CWD}/{router_names[0]}/bgpd.conf")
    write_bgpd_conf(
        tgen, num_routers - 1, 0, f"{CWD}/{router_names[num_routers-1]}/bgpd.conf"
    )
    write_pathd_conf(tgen, 0, f"{CWD}/{router_names[0]}/pathd.conf")
    write_pathd_conf(
        tgen, num_routers - 1, f"{CWD}/{router_names[num_routers-1]}/pathd.conf"
    )


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built")
    tgen.start_topology()
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def setup_testcase(msg):
    logger.info(msg)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def router_compare_json_output(rname, command, reference, exact=False):
    """Compare router JSON output"""

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(
        topotest.router_json_cmp, tgen.gears[rname], command, expected, exact=exact
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

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step1/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname, "show ip route isis json", "step1/show_ip_route.ref"
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step1/show_ipv6_route.ref"
        )


def test_mpls_lib_step1():
    logger.info("Test (step 1): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname, "show mpls table json", "step1/show_mpls_table.ref"
        )

    # Try to ping the host attached to RT9 from the host attached to
    # RT0 and make sure that we CANNOT reach RT9.
    addr = host_links[1][2].split("/")[0]
    assert _ping(tgen, 0, addr) == False


# Step 2
#
# Action(s):
# - Add candidate path to RT0 for flex-algo 128.
# - Add candidate path to RT9 for flex-algo 128.
# - Check policies are active.
# - Check registration count in isis routes.
# - Check routes from BGP to ensure active candidate path is taken.
#
# Expected change(s):
# - RT0 has one endpoint registration for RT9's loopback address on
#   algo 128.
# - RT9 has one endpoint registration for RT0's loopback address on
#   algo 128.
# - New policy is active on both RT0 and RT9.
# - BGP route on RT0 to RT9's LAN takes MPLS path as determined by
#   segment-routing.

step2_policies = (
    {  # rt0
        # (color, endpoint)
        (1, ip_address("10.254.0.10")): {
            "binding-sid": 16,
            "candidate-path": [
                {"preference": 10, "name": "candidate-1", "flex-algo": 128},
            ],
        }
    },
    None,  # rt1
    None,  # rt2
    None,  # rt3
    None,  # rt4
    None,  # rt5
    None,  # rt6
    None,  # rt7
    None,  # rt8
    {  # rt9
        (1, ip_address("10.254.0.1")): {
            "binding-sid": 17,
            "candidate-path": [
                {"preference": 10, "name": "candidate-1", "flex-algo": 128},
            ],
        }
    },
)


def test_step2_create_policies():
    logger.info("Test (step 2) - create policies")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtr, policies in zip(router_names, step2_policies):
        if policies is None:
            continue
        cmd = faconfig.fmt_policies(policies, 3)
        tgen.gears[rtr].vtysh_cmd(cmd)


def test_step2_policy_active():
    logger.info("Test (step 2): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step2/show_yang_pathd.ref",
        )


def test_step2_fae_registration():
    logger.info("Test (step 2): check if pathd registered an endpoint with isisd")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show isis fae registrations json",
            "step2/show_isis_fae_registrations.ref",
        )


def test_step2_bgp_routes():
    logger.info(
        "Test (step 2): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show ip route bgp json",
            "step2/show_ip_route_bgp.ref",
        )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]

    add_nft_all_counters(tgen, addr)

    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][0]
    # The 'red' and 'green' links are mutually exclusive.
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["green"], 5, label) == True
        assert check_nft_counters_by_link_affinity(diff, ["red"], 5, label) == False


####
# step 3: add higher priority candidate path
# Actions:
#  -Add candidate path to RT0 for flex-algo 131 with higher prio than
#   existing candidate.
#  -Add candidate path to RT9 for flex-algo 131 with higher prio than
#   existing candidate.
# Expected Changes:
#  -A second endpoint registration, this time for algo 131, is added to
#   RT0 and RT9.
#  -The sr-te policy is still active with the new candidate path selected.
#  -The BGP route has been updated with the new MPLS label in the next-hop

step3_policies = (
    {  # rt0
        # (color, endpoint)
        (1, ip_address("10.254.0.10")): {
            "binding-sid": 16,
            "candidate-path": [
                {"preference": 15, "name": "candidate-2", "flex-algo": 131},
            ],
        }
    },
    None,  # rt1
    None,  # rt2
    None,  # rt3
    None,  # rt4
    None,  # rt5
    None,  # rt6
    None,  # rt7
    None,  # rt8
    {  # rt9
        (1, ip_address("10.254.0.1")): {
            "binding-sid": 17,
            "candidate-path": [
                {"preference": 15, "name": "candidate-2", "flex-algo": 131},
            ],
        }
    },
)


def test_step3_create_policies():
    logger.info("Test (step 3) - create policies")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtr, policies in zip(router_names, step3_policies):
        if policies is None:
            continue
        cmd = faconfig.fmt_policies(policies, 3)
        tgen.gears[rtr].vtysh_cmd(cmd)


def test_step3_policy_active():
    logger.info("Test (step 3): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step3/show_yang_pathd.ref",
        )


def test_step3_fae_registration():
    logger.info("Test (step 3): check if pathd registered an endpoint with isisd")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show isis fae registrations json",
            "step3/show_isis_fae_registrations.ref",
        )


def test_step3_bgp_routes():
    logger.info(
        "Test (step 3): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show ip route bgp json",
            "step3/show_ip_route_bgp.ref",
        )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][3]
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["purple"], 5, label) == True


####
# step 4: check candidate policy preferences (remove isis route)
# Actions:
#  -Withdraw the advertisements of flex-algo 131 Prefix-SIDs
# Expected changes:
#  -There is no active registration on rt0 and rt9 for endpoints in
#   algo 131.
#  -FAE registrations for algo 128 are active
#  -The SR-TE policy is still active but has switched to the algo 128 path
#  -The BGP route has been updated with the MPLS label for the algo 128
#   candidate path


def test_step4_disable_algo():
    logger.info("Test (step 4) - Delete IPv4 prefix-sids for algo 131")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for idx in range(0, num_routers):
        rtr = router_names[idx]
        cmd = f"configure terminal\n router isis {isis_area}\n"
        lov4 = faconfig.v4addr(idx, lo_v4_base)
        for _fa, v4sid, v6sid, part in zip(
            sr_flex_algos,
            ipv4_indices[idx],
            ipv6_indices[idx],
            sr_flex_algo_participation[idx],
        ):
            if _fa != 131:
                continue
            if not part:
                continue
            cmd += f"  no segment-routing prefix {lov4} algorithm {_fa} index {v4sid}\n"
        tgen.gears[rtr].vtysh_cmd(cmd)


def test_step4_policy_active():
    logger.info("Test (step 4): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step4/show_yang_pathd.ref",
        )


def test_step4_fae_registration():
    logger.info(
        "Test (step 4): check if registration for algo 131 is inactive, 128 is active"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show isis fae registrations json",
            "step4/show_isis_fae_registrations.ref",
        )


def test_step4_bgp_routes():
    logger.info(
        "Test (step 4): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show ip route bgp json",
            "step4/show_ip_route_bgp.ref",
        )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][0]
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["green"], 5, label) == True
        assert check_nft_counters_by_link_affinity(diff, ["red"], 5, label) == False


####
# step 5: check candidate policy preferences (add isis route)
def test_step5_enable_algo():
    logger.info("Test (step 5) - Add IPv4 prefix-sids for algo 131")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for idx in range(0, num_routers):
        rtr = router_names[idx]
        cmd = f"configure terminal\n router isis {isis_area}\n"
        lov4 = faconfig.v4addr(idx, lo_v4_base)
        for _fa, v4sid, v6sid, part in zip(
            sr_flex_algos,
            ipv4_indices[idx],
            ipv6_indices[idx],
            sr_flex_algo_participation[idx],
        ):
            if _fa != 131:
                continue
            if not part:
                continue
            cmd += f"  segment-routing prefix {lov4} algorithm {_fa} index {v4sid}\n"
        tgen.gears[rtr].vtysh_cmd(cmd)


def test_step5_policy_active():
    logger.info("Test (step 5): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step5/show_yang_pathd.ref",
        )


def test_step5_fae_registration():
    logger.info(
        "Test (step 5): check if registrations for algos 128 and 131 are active"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show isis fae registrations json",
            "step5/show_isis_fae_registrations.ref",
        )


def test_step5_bgp_routes():
    logger.info(
        "Test (step 5): check routes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show ip route bgp json",
            "step5/show_ip_route_bgp.ref",
        )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][3]
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["purple"], 5, label) == True


####
# step 6: remove higher priority candidate path
def test_step6_remove():
    logger.info("Test (step 6) - remove higher priority candidate path")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtr, policies in zip(router_names, step3_policies):
        if policies is None:
            continue
        cmd = faconfig.fmt_policies(policies, 3, remove_cand=True)
        tgen.gears[rtr].vtysh_cmd(cmd)


def test_step6_policy_active():
    logger.info("Test (step 6): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step6/show_yang_pathd.ref",
        )


def test_step6_fae_registration():
    logger.info("Test (step 6): check if registrations for algo 128 are inactive")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show isis fae registrations json",
            "step6/show_isis_fae_registrations.ref",
        )


def test_step6_bgp_routes():
    logger.info(
        "Test (step 6): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in router_names:
        router_compare_json_output(
            rname,
            "show ip route bgp json",
            "step6/show_ip_route_bgp.ref",
        )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][0]
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["green"], 5, label) == True
        assert check_nft_counters_by_link_affinity(diff, ["red"], 5, label) == False


####
# step 7: check reaction to withdrawal of more specific route
# Actions:
#  -From rt9, advertise a prefix-sid for a prefix that includes R9's IPv4
#    loopback address, but has a mask length < 32.
#  -From rt9, remove the /32 prefix-sid matching the loopback
# Expected results:
#  -rt0 has learned the new shorter prefix and has moved the FAE
#   registration for rt9's loopback to this prefix-sid.
#  -The SR-TE policy has activated the algo 128 candidate path.
#  -The BGP route has been updated with the MPLS label for the less
#   specific prefix-sid.


def test_step7_less_specific_route():
    logger.info(
        "Test (step 7) - check FAE registration is moved to less specific route"
    )
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    idx = 9
    rtr = router_names[idx]
    tgen.gears[rtr].cmd_raises("ip link set up dev dummy0")
    v4sid = list(ipv4_indices[idx])[0]
    new_v4sid = list(ipv4_indices[idx])[-1] + 100
    cmd = (
        "configure terminal\n interface dummy0\n"
        + "  ip address 10.254.1.1/16\n"
        + f"  ip router isis {isis_area}\n"
        + "  isis passive\n"
    )
    tgen.gears[rtr].vtysh_cmd(cmd)
    cmd = f"configure terminal\n router isis {isis_area}\n"
    lov4 = faconfig.v4addr(idx, lo_v4_base)
    for _fa, v4sid, part in zip(
        sr_flex_algos, ipv4_indices[idx], sr_flex_algo_participation[idx]
    ):
        if _fa != 128:
            continue
        if not part:
            continue
        cmd += f"  segment-routing prefix 10.254.0.0/16 algorithm {_fa} index {new_v4sid}\n"
        cmd += f"  no segment-routing prefix {lov4} algorithm {_fa} index {v4sid}\n"
    tgen.gears[rtr].vtysh_cmd(cmd)


def test_step7_policy_active():
    logger.info("Test (step 7): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step7/show_yang_pathd.ref",
    )


def test_step7_fae_registration():
    logger.info(
        "Test (step 7): check if pathd registered endpoint for two algos with isisd"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show isis fae registrations json",
        "step7/show_isis_fae_registrations.ref",
    )

    router_compare_json_output(
        "rt0", "show isis route prefix-sid json", "step7/show_isis_route_prefixsid.ref"
    )


def test_step7_bgp_routes():
    logger.info(
        "Test (step 7): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show ip route bgp json",
        "step7/show_ip_route_bgp.ref",
    )

    idx = 9
    new_v4sid = list(ipv4_indices[idx])[-1] + 100

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + new_v4sid
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["green"], 5, label) == True
        assert check_nft_counters_by_link_affinity(diff, ["red"], 5, label) == False


####
# step 8: check reaction to more specific route to endpoint
# Actions:
#  -Add the loopback interface back to the isis config.  This should
#   be sufficient.
# Excpected Changes:
#  -A prefix-SID with rt9's loopback address and a /32 mask is advertised.
#  -rt0 has learned the this longer prefix and has moved the FAE
#   registration for rt9's loopback to this prefix-sid.
#  -The SR-TE policy for the algo 128 candidate path is still active.
#  -The BGP route has been updated with the MPLS label of the longer
#   algo 128 prefix-SID


def test_step8_more_specific_route():
    logger.info(
        "Test (step 8) - check FAE registration is moved to more specific route"
    )
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    idx = 9
    rtr = router_names[idx]
    lov4 = faconfig.v4addr(idx, lo_v4_base)
    v4sid = list(ipv4_indices[idx])[0]
    cmd = f"configure terminal\n router isis {isis_area}\n"
    cmd += f"  segment-routing prefix {lov4} algorithm 128 index {v4sid}\n"
    tgen.gears[rtr].vtysh_cmd(cmd)


def test_step8_policy_active():
    logger.info("Test (step 8): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step8/show_yang_pathd.ref",
    )


def test_step8_fae_registration():
    logger.info("Test (step 8): check if isisd moved the endpoint registration")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show isis fae registrations json",
        "step8/show_isis_fae_registrations.ref",
    )

    router_compare_json_output(
        "rt0", "show isis route prefix-sid json", "step8/show_isis_route_prefixsid.ref"
    )


def test_step8_bgp_routes():
    logger.info(
        "Test (step 8): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show ip route bgp json",
        "step8/show_ip_route_bgp.ref",
    )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    assert _ping(tgen, 0, addr) == True
    read_nft_all_counters(tgen, addr)


####
# Test 9 - restart isisd
# Actions:
#  -Restart isisd
# Excpected Changes:
#  -isisd will re-establish adjacencies and notify the world that it is
#   ready for FAE registrations on area 1.
#  -pathd will send the same registrations it sent the previous isisd
#   process
#  -isisd will update pathd and the sr-te policy will be activated.
def test_step9_restart_isisd():
    logger.info("Test (step 9): restart isisd")

    # step(f'Restart isisd on router {router_names[0]}')
    tgen = get_topogen()
    kill_router_daemons(tgen, router_names[0], ["isisd"])
    start_router_daemons(tgen, router_names[0], ["isisd"])
    logger.info("isisd restarted")


def test_step9_policy_active():
    logger.info("Test (step 9): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step9/show_yang_pathd.ref",
    )


def test_step9_fae_registration():
    logger.info("Test (step 9): check if isisd moved the endpoint registration")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show isis fae registrations json",
        "step9/show_isis_fae_registrations.ref",
    )

    router_compare_json_output(
        "rt0", "show isis route prefix-sid json", "step9/show_isis_route_prefixsid.ref"
    )


def test_step9_bgp_routes():
    logger.info(
        "Test (step 9): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show ip route bgp json",
        "step9/show_ip_route_bgp.ref",
    )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    before = read_nft_all_counters(tgen, addr)
    assert _ping(tgen, 0, addr) == True
    after = read_nft_all_counters(tgen, addr)
    diff = diff_nft_all_counters(before, after)
    label = sr_global_block[0] + ipv4_indices[9][0]
    if _nft_version_ok():
        assert check_nft_counters_by_link_affinity(diff, ["green"], 5, label) == True
        assert check_nft_counters_by_link_affinity(diff, ["red"], 5, label) == False


####
# Step 10 - restart pathd
# Actions:
#  -Restart pahd
# Excpected Changes:
#  -pathd will send client-ready to isisd
#  -isisd will send ready message to pathd for area 1
#  -pathd will send the same registrations it sent the previous isisd
#   process
#  -isisd will update pathd and the sr-te policy will be activated.
def test_step10_restart_isisd():
    logger.info("Test (step 10): restart pathd")

    # step(f'Restart isisd on router {router_names[0]}')
    tgen = get_topogen()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, router_names[0], ["pathd"])
    start_router_daemons(tgen, router_names[0], ["pathd"])
    logger.info("pathd restarted")


def test_step10_policy_active():
    logger.info("Test (step 10): check if policy is active")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step10/show_yang_pathd.ref",
    )


def test_step10_fae_registration():
    logger.info("Test (step 10): check if isisd moved the endpoint registration")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show isis fae registrations json",
        "step10/show_isis_fae_registrations.ref",
    )

    router_compare_json_output(
        "rt0", "show isis route prefix-sid json", "step10/show_isis_route_prefixsid.ref"
    )


def test_step10_bgp_routes():
    logger.info(
        "Test (step 10): checkroutes from BGP to ensure active candidate path is taken"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt0",
        "show ip route bgp json",
        "step10/show_ip_route_bgp.ref",
    )

    # Try to ping the host attached to RT9 from the host attached to RT0
    addr = host_links[1][2].split("/")[0]
    assert _ping(tgen, 0, addr) == True
    read_nft_all_counters(tgen, addr)


#####
## Step 11 - Select policy by BGP route color
## This suffers from zebra/bgpd nexthop problems.
## Actions:
##  -Create four policies on RT0
##  -Observe installed BGP route
##  -Change color in route-map, one time for each configured policy color
##   and observe to installed BGP route.
##  -Change color in route-map to a value not in any policy.
## Excpected Changes:
##  -The next-hop of the installed BGP route will follow the path in the
##   matching policy.
##  -The last route-map update will result in no installed BGP route.
# step11_rt0_policies = \
#    {
#        # (color, endpoint)
#        (1, ip_address('10.254.0.10')): {
#            'binding-sid': 16,
#            'candidate-path': [
#                {'preference': 10, 'name': 'color-1', 'flex-algo': 128},
#            ]
#        },
#        (2, ip_address('10.254.0.10')): {
#            'binding-sid': 17,
#            'candidate-path': [
#                {'preference': 10, 'name': 'color-2', 'flex-algo': 129},
#            ]
#        },
#        (3, ip_address('10.254.0.10')): {
#            'binding-sid': 18,
#            'candidate-path': [
#                {'preference': 10, 'name': 'color-3', 'flex-algo': 130},
#            ]
#        },
#        (4, ip_address('10.254.0.10')): {
#            'binding-sid': 19,
#            'candidate-path': [
#                {'preference': 10, 'name': 'color-4', 'flex-algo': 131},
#            ]
#        }
#    }
#
# def test_step11_create_policies():
#    logger.info("Test (step 11) - create policies")
#    tgen = get_topogen()
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    rtr = router_names[0]
#    cmd = faconfig.fmt_policies(step11_rt0_policies, 3)
#    tgen.gears[rtr].vtysh_cmd(cmd)
#
# def test_step11_color_wheel():
#    """Change the route-map color assignment"""
#    logger.info("Test (step 11) - route-map color")
#    tgen = get_topogen()
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#    rtr = router_names[0]
#    for color in (pol[0] for pol in step11_rt0_policies.keys()):
#        cmd = f'configure terminal\n router bgp 1\n' + \
#              f' route-map sr-te permit 10\n' + \
#              f' set sr-te color {color}\n'
#        tgen.gears[rtr].vtysh_cmd(cmd)
#        #tgen.mininet_cli()
#        router_compare_json_output(
#            rtr,
#            "show ip route bgp json",
#            f"step11/color{color}_show_ip_route_bgp.ref",
#        )
#
# def test_step11_clean_up():
#    logger.info("Test (step 11) - clean up")
#    tgen = get_topogen()
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    # Delete policies
#    rtr = router_names[0]
#    cmd = faconfig.fmt_policies(step11_rt0_policies, 3, remove=True)
#    tgen.gears[rtr].vtysh_cmd(cmd)
#
#    # Put the original color back
#    cmd = f'configure terminal\n router bgp 1\n' + \
#          f' route-map sr-te permit 10\n' + \
#          f' set sr-te color 1\n'
#    tgen.gears[rtr].vtysh_cmd(cmd)
#

#####
## Step 12 - nexthop updates to BGP
## This also suffers from zebra/bgpd nexthop problems.
## Actions:
##  -On RT0 create policy for RT9, algo 130.
##  -Algo 130 includes RT1 and RT5, both of which have a link to RT0.
##   Shut down the link from 0 -> 1.
##  -Later, enable the link from 0 -> 1 and shut down the link fro 0 -> 5.
##  -Enable both links
## Excpected Changes:
##  -After shutting down the 0->1 link, the BGP route learned from RT9
##   will have a label in the nexthop pointing to RT5.
##  -After restoring 0->1 and shutting down 0->5, the BGP route learned
##   from RT9 will have a label in the nexthop pointing to RT1.
##  -When both links are enabled again, the route learned from BGP will
##   have nexthops for both RT1 and RT5.
# step12_rt0_policies = \
#    {
#        # (color, endpoint)
#        (1, ip_address('10.254.0.10')): {
#            'binding-sid': 16,
#            'candidate-path': [
#                {'preference': 10, 'name': 'candidate-1', 'flex-algo': 130},
#            ]
#        }
#    }
# def test_step12_setup():
#    logger.info("Test (step 12) - create policies")
#    tgen = get_topogen()
#
#    # Skip if previous fatal error condition is raised
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    rtr = router_names[0]
#    cmd = faconfig.fmt_policies(step12_rt0_policies, 3)
#    tgen.gears[rtr].vtysh_cmd(cmd)
#    tgen.mininet_cli()
#    _expect_num_nexthops(rtr, [2])
#    #router_compare_json_output(
#    #    'rt0',
#    #    "show ip route bgp json",
#    #    "step12/setup_show_ip_route_bgp.ref",
#    #)
#
# def test_step12_linkdown():
#    logger.info("Test (step 12) - eth-1 link down")
#    tgen = get_topogen()
#
#    # Skip if previous fatal error condition is raised
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    rtr = router_names[0]
#    tgen.gears[rtr].run("ip link set eth-1 down")
#    cmd = faconfig.fmt_policies(step12_rt0_policies, 3)
#    tgen.mininet_cli()
#    _expect_num_nexthops(rtr, [1])
#    #router_compare_json_output(
#    #    'rt0',
#    #    "show ip route bgp json",
#    #    "step12/linkdown_show_ip_route_bgp.ref",
#    #)
#    # Check nexthops pre link-down
#
#
# def test_step12_swap_links():
#    logger.info("Test (step 12) - swap links")
#    tgen = get_topogen()
#
#    # Skip if previous fatal error condition is raised
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    rtr = router_names[0]
#    tgen.gears[rtr].run("ip link set eth-1 up")
#    tgen.gears[rtr].run("ip link set eth-5 down")
#
#    tgen.mininet_cli()
#    _expect_num_nexthops(rtr, [1])
#    #router_compare_json_output(
#    #    'rt0',
#    #    "show ip route bgp json",
#    #    "step12/swaplinks_show_ip_route_bgp.ref",
#    #)
#
# def test_step12_enable_both_links():
#    logger.info("Test (step 12) - enable both links")
#    tgen = get_topogen()
#
#    # Skip if previous fatal error condition is raised
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    rtr = router_names[0]
#    tgen.gears[rtr].run("ip link set eth-5 up")
#    tgen.mininet_cli()
#    _expect_num_nexthops(rtr, [2])
#    #router_compare_json_output(
#    #    'rt0',
#    #    "show ip route bgp json",
#    #    "step12/setup_show_ip_route_bgp.ref",
#    #)


# Step 13 - pathd SID updates to zebra
# Actions:
#  -On RT0 create four policies for the RT9 endpoint, one per flex-algo
#  -For each flex algo, change the SIDs in RT9's isis configuration.
#  -After each SID on RT9 is changed, check Zebra's policy list to ensure
#   that pathd sent the new label it learned from isisd.
# Excpected Changes:
#  -Zebra will have an updated label after each change to RT9's config.

step13_rt0_policies = {
    # (color, endpoint)
    (1, ip_address(faconfig.v4addr(num_routers - 1, lo_v4_base, with_masklen=False))): {
        "binding-sid": 16,
        "candidate-path": [
            {"preference": 10, "name": "candidate-1", "flex-algo": 128},
        ],
    },
    (2, ip_address(faconfig.v4addr(num_routers - 1, lo_v4_base, with_masklen=False))): {
        "binding-sid": 17,
        "candidate-path": [
            {"preference": 10, "name": "candidate-2", "flex-algo": 129},
        ],
    },
    (3, ip_address(faconfig.v6addr(num_routers - 1, lo_v6_base, with_masklen=False))): {
        "binding-sid": 18,
        "candidate-path": [
            {"preference": 10, "name": "candidate-3", "flex-algo": 130},
        ],
    },
    (4, ip_address(faconfig.v6addr(num_routers - 1, lo_v6_base, with_masklen=False))): {
        "binding-sid": 19,
        "candidate-path": [
            {"preference": 10, "name": "candidate-4", "flex-algo": 131},
        ],
    },
}


def test_step13_setup():
    logger.info("Test (step 13) - create policies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rtr = router_names[0]
    cmd = faconfig.fmt_policies(step13_rt0_policies, 3)
    tgen.gears[rtr].vtysh_cmd(cmd)
    router_compare_json_output(
        router_names[0],
        "show zebra sr-te json",
        "step13/setup_show_zebra_srte.ref",
    )


def test_step13_update_sids():
    logger.info("Test (step 13) - update sids")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    idx = num_routers - 1
    rtr = router_names[idx]
    lov4 = faconfig.v4addr(idx, lo_v4_base)
    lov6 = faconfig.v6addr(idx, lo_v6_base)
    for _fa, v4sid, v6sid, part in zip(
        sr_flex_algos,
        ipv4_indices[idx],
        ipv6_indices[idx],
        sr_flex_algo_participation[idx],
    ):
        if not part:
            continue
        cmd = f"configure terminal\n router isis {isis_area}\n"
        cmd += f" segment-routing prefix {lov4} algorithm {_fa} index {v4sid+10}\n"
        cmd += f" segment-routing prefix {lov6} algorithm {_fa} index {v6sid+10}\n"
        tgen.gears[rtr].vtysh_cmd(cmd)
        router_compare_json_output(
            router_names[0],
            "show zebra sr-te json",
            f"step13/show_zebra_srte_algo_{_fa}.ref",
        )


def test_step13_clean_up():
    logger.info("Test (step 13) - clean up")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Delete policies
    rtr = router_names[0]
    cmd = faconfig.fmt_policies(step13_rt0_policies, 3, remove=True)
    tgen.gears[rtr].vtysh_cmd(cmd)
