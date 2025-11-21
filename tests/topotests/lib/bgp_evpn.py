#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_evpn.py
# Verification utility APIs and Classes for BGP/EVPN related testing
#
# Copyright (c) 2025 by
# Cisco Systems, Inc.
# Mrinmoy Ghosh
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

import json
from lib import topotest


### Configs
def config_bond(node, bond_name, bond_members, bond_ad_sys_mac, br, vid=1000):
    """
    Used to setup bonds on the TORs and hosts for MH
    """
    node.run(f"ip link add dev {bond_name} type bond mode 802.3ad")
    node.run(f"ip link set dev {bond_name} type bond lacp_rate 1")
    node.run(f"ip link set dev {bond_name} type bond miimon 100")
    node.run(f"ip link set dev {bond_name} type bond xmit_hash_policy layer3+4")
    node.run(f"ip link set dev {bond_name} type bond min_links 1")
    node.run(f"ip link set dev {bond_name} type bond ad_actor_system {bond_ad_sys_mac}")

    for bond_member in bond_members:
        node.run(f"ip link set dev {bond_member} down")
        node.run(f"ip link set dev {bond_member} master {bond_name}")
        node.run(f"ip link set dev {bond_member} up")

    node.run(f"ip link set dev {bond_name} up")

    # if bridge is specified add the bond as a bridge member
    if br:
        node.run(f" ip link set dev {bond_name} master {br}")
        node.run(f"/sbin/bridge link set dev {bond_name} priority 8")
        node.run(f"/sbin/bridge vlan del vid 1 dev {bond_name}")
        node.run(f"/sbin/bridge vlan del vid 1 untagged pvid dev {bond_name}")
        node.run(f"/sbin/bridge vlan add vid {vid} dev {bond_name}")
        node.run(f"/sbin/bridge vlan add vid {vid} untagged pvid dev {bond_name}")


def config_host(
    host_name,
    host,
    host_ip,
    host_mac,
    bond_name="torbond",
    bond_member_suffixes=["-eth0", "-eth1"],
    bond_ad_sys_mac="00:00:00:00:00:00",
):
    """
    Create the dual-attached bond on host nodes for MH
    """
    bond_members = []

    for suffix in bond_member_suffixes:
        bond_members.append(host_name + suffix)

    config_bond(host, bond_name, bond_members, bond_ad_sys_mac, None)
    host.run(f"ip addr add {host_ip} dev {bond_name}")
    host.run(f"ip link set dev {bond_name} address {host_mac}")


def config_l3vni(tor_name, node, vtep_ip, mac_map, vni=500, vrf="vrf500", svi="br500"):
    """
    Create an L3VNI and its ip-vrf {vrf} on the TOR node.
    The VNI is associated with SVI bridge {svi}.
    The SVI is assigned a MAC address based on the tor_name using mac_map.
    """
    node.run(f"ip link add {vrf} type vrf table {vni}")
    node.run(f"ip link set {vrf} up")

    node.run(f"ip link add {svi} type bridge")
    node.run(f"ip link set {svi} master {vrf} addrgenmode none")

    node.run(f"ip link set {svi} addr {mac_map[tor_name]}")
    node.run(
        f"ip link add vni{vni} type vxlan id {vni} local {vtep_ip} dstport 4789 nolearning"
    )
    node.run(f"ip link set vni{vni} master {svi} addrgenmode none")
    # node.run("/sbin/bridge link set dev vni500 learning off")
    node.run(f"ip link set dev vni{vni} master {svi}")
    node.run(f"ip link set dev {svi} up")
    node.run(f"ip link set dev vni{vni} up")


def config_l2vni(tor_name, node, svi_ip, vtep_ip, vni=1000, vid=1000, vrf="vrf500"):
    """
    On torm1x amd torm21,
    Create a VxLAN device for VNI 1000 and add it to the bridge.
    VLAN-1000 is mapped to VNI-1000.

    On torm22, do the same + add another bridge and l2vni to create a different subnet
    """
    bridge = f"br{vid}"
    # on torm2x, there are 2 subnets. This required to different bridge domain, svi_ip and l2vni.
    # subnets are connected to same vrf. Therefore, same L3VNI can be used
    node.run(f"ip link add {bridge} type bridge")
    node.run(f"ip link set {bridge} master {vrf}")
    node.run(f"ip addr add {svi_ip}/24 dev {bridge}")
    node.run(f"/sbin/sysctl net.ipv4.conf.{bridge}.arp_accept=1")

    node.run(
        f"ip link add vni{vni} type vxlan local {vtep_ip} dstport 4789 id {vni} nolearning"
    )
    node.run(f"ip link set vni{vni} master {bridge} addrgenmode none")
    node.run(f"/sbin/bridge link set dev vni{vni} learning off")
    node.run(f"ip link set vni{vni} up")
    node.run(f"ip link set {bridge} up")

    node.run(f"/sbin/bridge vlan del vid 1 dev vni{vni}")
    node.run(f"/sbin/bridge vlan del vid 1 untagged pvid dev vni{vni}")
    node.run(f"/sbin/bridge vlan add vid {vid} dev vni{vni}")
    node.run(f"/sbin/bridge vlan add vid {vid} untagged pvid dev vni{vni}")


### Verifications
def get_bgp_evpn_vni(dut):
    """
    Check the output of 'show bgp evpn vni' command on the router
    Parse 'show evpn vni json' output and return a dict of VNI to type.
    Example return: {1000: "L2", 500: "L3"}
    :param dut: Device under test
    """

    output = json.loads(dut.vtysh_cmd("show evpn vni json"))
    vni_types = {}
    for vni_str, vni_info in output.items():
        vni = int(vni_str)
        vni_types[vni] = vni_info.get("type")
    return vni_types


def get_local_l2_vnis(dut):
    """
    Returns list of L2VNIs configured and active on the DUT
    :param dut: Device under test
    """
    return [k for k, v in get_bgp_evpn_vni(dut).items() if v == "L2"]


def check_es(dut, host_es_map, host_vni_map, local_vteps, remote_vteps):
    """
    Verify list of PEs associated all ESs, local and remote
    :param dut: Device under test
    :param host_es_map: Mapping of hosts to their Ethernet Segment Identifiers (ESIs)
    :param host_vni_map: Mapping of hosts to their Virtual Network Identifiers (VNIs)
    :param local_vteps: Set of local VTEP IPs
    :param remote_vteps: Set of remote VTEP IPs
    """
    bgp_es = dut.vtysh_cmd("show bgp l2vp evpn es json")
    bgp_es_json = json.loads(bgp_es)

    result = None

    expected_es_set = set(
        [
            v1
            for k1, v1 in host_es_map.items()
            for k2, v2 in host_vni_map.items()
            if k1 == k2 and v2 in get_local_l2_vnis(dut)
        ]
    )
    curr_es_set = []

    # check is ES content is correct
    for es in bgp_es_json:
        esi = es["esi"]
        curr_es_set.append(esi)
        types = es["type"]
        vtep_ips = set()
        for vtep in es.get("vteps", []):
            vtep_ips.add(vtep["vtep_ip"])

        if "local" in types:
            diff = local_vteps.symmetric_difference(vtep_ips)
        else:
            diff = remote_vteps.symmetric_difference(vtep_ips)
        result = (esi, diff) if diff else None
        if result:
            return result

    # check if all ESs are present
    curr_es_set = set(curr_es_set)
    result = curr_es_set.symmetric_difference(expected_es_set)

    return result if result else None


def check_df_role(dut, esi, role):
    """
    Return error string if the df role on the dut is different
    """
    es_json = dut.vtysh_cmd("show evpn es %s json" % esi)
    es = json.loads(es_json)

    if not es:
        return "esi %s not found" % esi

    flags = es.get("flags", [])
    curr_role = "nonDF" if "nonDF" in flags else "DF"

    if curr_role != role:
        return "%s is %s for %s" % (dut.name, curr_role, esi)

    return None


def check_ip_neigh(tgen, ip, mac, bridge, dut, expect=True):
    """
    checks if neighbor entry is present in kernel
    """
    output = tgen.gears[dut].run(
        f"ip neigh show | grep {ip} | grep {mac} | grep {bridge}"
    )
    if (ip in output) == expect:
        return None
    else:
        return f"{'' if expect else 'Un-'}Expected IP Neighbor Entry on {dut}: {ip} {mac} {bridge}: Got {output}"


def check_protodown_rc(dut, protodown_rc):
    """
    check if specified protodown reason code is set
    """

    out = dut.vtysh_cmd("show evpn json")

    evpn_js = json.loads(out)
    tmp_rc = evpn_js.get("protodownReasons", [])

    if protodown_rc:
        if protodown_rc not in tmp_rc:
            return "protodown %s missing in %s" % (protodown_rc, tmp_rc)
    else:
        if tmp_rc:
            return "unexpected protodown rc %s" % (tmp_rc)

    return None


def check_neigh(dut, vni, ip, mac, m_type, state, expect=True):
    """
    checks if neighbor is present and if desination matches the one provided
    """

    out = dut.vtysh_cmd("show evpn arp-cache vni %d ip %s json" % (vni, ip))

    if out == "":
        return f"Could not find neighbor ip {ip}" if expect else None
    nbr_js = json.loads(out)
    tmp_ip = nbr_js.get("ip", "")
    tmp_mac = nbr_js.get("mac", "")
    tmp_m_type = nbr_js.get("type", "")
    tmp_state = nbr_js.get("state", "")
    if tmp_ip == ip and tmp_mac == mac and tmp_m_type == m_type and tmp_state == state:
        return None if expect else f"Incorrectly found Neighbor {nbr_js}"

    return "invalid vni %d ip %s out %s" % (vni, ip, nbr_js) if expect else None


def check_mac_in_bridge(dut, mac, dev, vlan, proto=None, expect=True):
    """
    Check if a MAC entry exists in the kernel bridge FDB with specified protocol
    """
    output = dut.run(f"bridge fdb show | grep '{mac} dev {dev} vlan {vlan}'")

    # Check if MAC exists
    if (mac in output) != expect:
        return f"MAC {'not' if expect else 'unexpectedly'} found in bridge FDB: {mac} dev {dev} vlan {vlan}"

    # If MAC exists and protocol check is requested
    if expect and proto and (mac in output):
        if f"proto {proto}" not in output:
            return f"MAC {mac} found but with wrong protocol. Expected: {proto}, Got: {output}"

    return None


def check_mac_flag_in_evpn(dut, vni, mac, flag, mac_type="local", expect=True):
    """
    Check if a MAC exists in the EVPN MAC table with the specified flag and type
    """
    out = dut.vtysh_cmd(f"show evpn mac vni {vni}")

    if not out or "Number of MACs" not in out:
        return (
            None
            if not expect
            else f"MAC {mac} not found in EVPN MAC table for VNI {vni}"
        )

    found = False
    for line in out.splitlines():
        if mac in line:
            # Check both flag and type
            if flag in line and mac_type in line:
                found = True
                break

    if found == expect:
        return None
    else:
        return f"MAC {mac} {'not' if expect else 'unexpectedly'} found as {mac_type} with flag {flag} in EVPN MAC table for VNI {vni}"


def get_mac_holdtime(dut):
    """
    Get the MAC holdtime value from the 'show evpn' command
    """
    out = dut.vtysh_cmd("show evpn json")
    evpn_data = json.loads(out)
    holdtime = evpn_data.get("macHoldtime", 300)  # Default to 300 if not found

    # Convert to seconds
    return int(holdtime)


def check_mac_exists_in_evpn(dut, vni, mac, expect=True):
    """
    Check if a MAC exists in the EVPN MAC table regardless of flags or type
    """
    out = dut.vtysh_cmd(f"show evpn mac vni {vni}")

    if not out or "Number of MACs" not in out:
        return None if not expect else f"EVPN MAC output missing for VNI {vni}"

    found = False
    for line in out.splitlines():
        if mac in line:
            found = True
            break

    if found == expect:
        return None
    else:
        return f"MAC {mac} {'not' if expect else 'unexpectedly'} found in EVPN MAC table for VNI {vni}"


def check_bridge_fdb_proto_supported(dut):
    """
    Check if the bridge FDB supports 'protocol' field
    """
    out = dut.run("bridge fdb help 2>&1 | grep protocol | wc -l")
    out = int(out.strip())
    if out > 0:
        return None
    return "Bridge FDB does not support protocol"
