
import os
import sys
import json
from functools import partial
import pytest
import sys
import re
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd, pytest.mark.bgpd]

# when VTY_OBUF_LIMIT is 20 and show_yield_limit is 1000
threshold = int(2e5)

def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r3"])
    s3 = tgen.add_switch("s3")
    s3.add_link(tgen.gears["r4"])
    s3.add_link(tgen.gears["r5"])

    peer_ip = "121.0.1.33"
    peer_route = "via 121.0.1.3"
    peer = tgen.add_exabgp_peer("r3-peer", ip=peer_ip, defaultRoute=peer_route)
    s2.add_link(peer)

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r4"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.2 nolearning
        """
    )
    tgen.net["r5"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.3 nolearning
        """
    )
    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)

def teardown_module(mod):
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.stop_topology()

def _create_rmac(router, vrf):
    """
    Creates RMAC for a given router and vrf
    """
    return "52:54:00:00:{:02x}:{:02x}".format(router, vrf)

def test_show_ip_bgp_memory():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp install routes 192.168.0.0 nexthop 121.0.1.2 100000")
    # sharp install is asynchronous; wait for a while to ensure the installation completes.
    time.sleep(5)
    r1.vtysh_cmd("show ip bgp")

    output = r1.vtysh_cmd("show memory bgpd")
    filtered_lines = [line for line in output.splitlines() if "Buffer data" in line]

    match = re.search(r"\d+$", filtered_lines[0])
    buffer_value = int(match.group())

    # Verify that the memory usage of the show command is within the expected range.
    assert buffer_value < threshold, f"Buffer data value {buffer_value} is not less than {threshold}"

def test_show_ip_bgp_ipv4_vpn_memory():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("sharp install routes 192.168.0.0 nexthop 121.0.1.1 100000")
    time.sleep(5)
    r2.vtysh_cmd("show ip bgp ipv4 vpn")

    output = r2.vtysh_cmd("show memory bgpd")
    filtered_lines = [line for line in output.splitlines() if "Buffer data" in line]

    match = re.search(r"\d+$", filtered_lines[0])
    buffer_value = int(match.group())

    assert buffer_value < threshold, f"Buffer data value {buffer_value} is not less than {threshold}"

def test_show_bgp_ipv4_flowspec_detail_memory():
    tgen = get_topogen()
    r3 = tgen.gears["r3"]

    time.sleep(5)
    r3.vtysh_cmd("show bgp ipv4 flowspec detail")

    output = r3.vtysh_cmd("show memory bgpd")
    filtered_lines = [line for line in output.splitlines() if "Buffer data" in line]

    match = re.search(r"\d+$", filtered_lines[0])
    buffer_value = int(match.group())

    assert buffer_value < threshold, f"Buffer data value {buffer_value} is not less than {threshold}"

def test_show_bgp_l2vpn_evpn_memory():
    tgen = get_topogen()
    r4 = tgen.gears["r4"]

    r4.vtysh_cmd("sharp install routes 192.168.0.0 nexthop 10.0.0.3 100000")
    time.sleep(5)
    r4.vtysh_cmd("show bgp l2vpn evpn route")

    output = r4.vtysh_cmd("show memory bgpd")
    filtered_lines = [line for line in output.splitlines() if "Buffer data" in line]

    match = re.search(r"\d+$", filtered_lines[0])
    buffer_value = int(match.group())

    assert buffer_value < threshold, f"Buffer data value {buffer_value} is not less than {threshold}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))