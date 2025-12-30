#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2023 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the GNU General
# Public License, version 2 (GPLv2). See the LICENSE file in the
# root of the source tree for details.
#

"""
Exhaustive test for the CISCO-BGP4-MIB implementation, written in the style
of FRR 8.5.4, with a dedicated VRF peering session to test cbgpPeer3Table.
"""

import os
import sys
import json
from time import sleep
import pytest
import functools
import logging
import re

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.snmptest import SnmpTester
from lib import topotest
from lib.topolog import logger  # The logger is imported from here

pytestmark = [pytest.mark.bgpd, pytest.mark.snmp]

# OID Definitions
MIB_BASE = "1.3.6.1.4.1.9.9.187.1.2"
OIDS = {
    "cbgpPeerTable": f"{MIB_BASE}.1",
    "cbgpPeerCapsTable": f"{MIB_BASE}.2",
    "cbgpPeerAddrFamilyTable": f"{MIB_BASE}.3",
    "cbgpPeerAddrFamilyPrefixTable": f"{MIB_BASE}.4",
    "cbgpPeer2Table": f"{MIB_BASE}.5",
    "cbgpPeer2AddrFamilyTable": f"{MIB_BASE}.7",
    "cbgpPeer2AddrFamilyPrefixTable": f"{MIB_BASE}.8",
    "cbgpPeer3Table": f"{MIB_BASE}.9",
}

peers_ipv4 = ["10.10.0.2", "10.10.1.2", "10.10.2.2"]
peers_ipv6 = ["253.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2", "253.0.0.1.0.0.0.0.0.0.0.0.0.0.0.2", "253.0.0.2.0.0.0.0.0.0.0.0.0.0.0.2"]
peers_ipv4_lcl = ["0A 0A 00 01", "0A 0A 01 01", "0A 0A 02 01"]
peers_ipv6_lcl = ["FD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01", "FD 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01", "FD 00 00 02 00 00 00 00 00 00 00 00 00 00 00 01"]
peers_ipv4_rmt = ["0A 0A 00 02", "0A 0A 01 02", "0A 0A 02 02"]
peers_ipv6_rmt = ["FD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02", "FD 00 00 01 00 00 00 00 00 00 00 00 00 00 00 02", "FD 00 00 02 00 00 00 00 00 00 00 00 00 00 00 02"]

ipv4_af_type = "1"
ipv6_af_type = "2"
ipv4_unicast_af_idx = "1.1"
ipv6_unicast_af_idx = "2.1"
l2vpn_evpn_af_idx = "25.70"  # AFI=25 (IANA_AFI_L2VPN), SAFI=70 (IANA_SAFI_EVPN)

cbgpPeerTableOIDs = []
cbgpPeer2TableOIDs = []
cbgpPeerAddrFamilyTableOIDs = []
cbgpPeerAddrFamilyPrefixTableOIDs = []
cbgpPeer2AddrFamilyTableOIDs = []
cbgpPeer2AddrFamilyPrefixTableOIDs = []
cbgpPeer3TableOIDs = []
cbgpPeer2TableOIDs_v4 = []
cbgpPeer2TableOIDs_v6 = []
cbgpPeer2AddrFamilyTableOIDs_v4 = []
cbgpPeer2AddrFamilyTableOIDs_v6 = []
cbgpPeer2AddrFamilyPrefixTableOIDs_v4 = []
cbgpPeer2AddrFamilyPrefixTableOIDs_v6 = []
cbgpPeer3TableOIDs_v4 = []
cbgpPeer3TableOIDs_v6 = []

for peer_ipv4, peer_ipv6, peer_ipv4_lcl, peer_ipv6_lcl, peer_ipv4_rmt, peer_ipv6_rmt in zip(peers_ipv4, peers_ipv6, peers_ipv4_lcl, peers_ipv6_lcl, peers_ipv4_rmt, peers_ipv6_rmt):
    # First peer (10.10.0.2) has route-map filter, receives 2 prefixes; others receive 4
    accepted_prefixes = '2' if peer_ipv4 == "10.10.0.2" else '4'
    denied_prefixes = '2' if peer_ipv4 == "10.10.0.2" else '0'

    cbgpPeerTableOIDs.extend([
        (rf'{OIDS["cbgpPeerTable"]}.1.7.{peer_ipv4}', '00', "cbgpPeerLastErrorTxt"),
        (rf'{OIDS["cbgpPeerTable"]}.1.8.{peer_ipv4}', '5', "cbgpPeerPrevState (idle)"),
    ])
    for i in range(1, 7):
        cbgpPeerTableOIDs.append((rf'{OIDS["cbgpPeerTable"]}.1.{i}.{peer_ipv4}', None, f"Deprecated OID .1.{i}"))

    cbgpPeerAddrFamilyTableOIDs.extend([
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.1.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeerAddrFamilyAfi"),
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.2.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeerAddrFamilySafi"),
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.3.{peer_ipv4}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeerAddrFamilyName"),
        # L2VPN EVPN entries with IANA values
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.1.{peer_ipv4}.{l2vpn_evpn_af_idx}', '25', "cbgpPeerAddrFamilyAfi L2VPN"),
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.2.{peer_ipv4}.{l2vpn_evpn_af_idx}', '70', "cbgpPeerAddrFamilySafi EVPN"),
        (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.3.{peer_ipv4}.{l2vpn_evpn_af_idx}', 'L2VPN EVPN'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeerAddrFamilyName L2VPN EVPN"),
    ])

    cbgpPeerAddrFamilyPrefixTableOIDs.extend([
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.1.{peer_ipv4}.{ipv4_unicast_af_idx}', accepted_prefixes, "cbgpPeerAcceptedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.2.{peer_ipv4}.{ipv4_unicast_af_idx}', denied_prefixes, "cbgpPeerDeniedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.3.{peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeerPrefixAdminLimit"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.4.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeerPrefixThreshold"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.6.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeerAdvertisedPrefixes"),
        # L2VPN EVPN entries
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.1.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeerAcceptedPrefixes L2VPN EVPN"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.2.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeerDeniedPrefixes L2VPN EVPN"),
    ])

    peer2_ipv4_entries = [
        (rf'{OIDS["cbgpPeer2Table"]}.1.1.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer2Type"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.2.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_rmt, "cbgpPeer2RemoteAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.3.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer2State"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.4.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer2AdminStatus"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.5.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer2NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.6.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_lcl, "cbgpPeer2LocalAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.8.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer2LocalAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.9.{ipv4_af_type}.{peer_ipv4}', 'C0 00 02 01', "cbgpPeer2LocalIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.11.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer2RemoteAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.12.{ipv4_af_type}.{peer_ipv4}', 'C0 00 02 02', "cbgpPeer2RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.17.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer2LastError"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.21.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer2HoldTime"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.22.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer2KeepAlive"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.23.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer2HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.24.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer2KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.28.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer2LastErrorTxt"),
    ]
    cbgpPeer2TableOIDs.extend(peer2_ipv4_entries)
    cbgpPeer2TableOIDs_v4.extend(peer2_ipv4_entries)

    peer2_ipv6_entries = [
        (rf'{OIDS["cbgpPeer2Table"]}.1.1.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer2Type"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.2.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_rmt, "cbgpPeer2RemoteAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.3.{ipv6_af_type}.{peer_ipv6}', '6', "cbgpPeer2State"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.4.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer2AdminStatus"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.5.{ipv6_af_type}.{peer_ipv6}', '4', "cbgpPeer2NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.6.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_lcl, "cbgpPeer2LocalAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.8.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer2LocalAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.9.{ipv6_af_type}.{peer_ipv6}', 'C0 00 02 01', "cbgpPeer2LocalIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.11.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer2RemoteAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.12.{ipv6_af_type}.{peer_ipv6}', 'C0 00 02 02', "cbgpPeer2RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.17.{ipv6_af_type}.{peer_ipv6}', '0', "cbgpPeer2LastError"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.21.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer2HoldTime"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.22.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer2KeepAlive"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.23.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer2HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.24.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer2KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.28.{ipv6_af_type}.{peer_ipv6}', '00', "cbgpPeer2LastErrorTxt"),
    ]
    cbgpPeer2TableOIDs.extend(peer2_ipv6_entries)
    cbgpPeer2TableOIDs_v6.extend(peer2_ipv6_entries)

    peer2_af_ipv4_entries = [
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
    ]
    cbgpPeer2AddrFamilyTableOIDs.extend(peer2_af_ipv4_entries)
    cbgpPeer2AddrFamilyTableOIDs_v4.extend(peer2_af_ipv4_entries)

    peer2_af_ipv6_entries = [
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '2', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', 'IPv6 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
    ]
    cbgpPeer2AddrFamilyTableOIDs.extend(peer2_af_ipv6_entries)
    cbgpPeer2AddrFamilyTableOIDs_v6.extend(peer2_af_ipv6_entries)

    # L2VPN EVPN entries added separately for IPv4 peers with IANA values
    cbgpPeer2AddrFamilyTableOIDs.extend([
        # L2VPN EVPN entries
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '25', "cbgpPeer2AddrFamilyAfi L2VPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '70', "cbgpPeer2AddrFamilySafi EVPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', 'L2VPN EVPN'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName L2VPN EVPN"),
    ])
    cbgpPeer2AddrFamilyTableOIDs_v4.extend([
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '25', "cbgpPeer2AddrFamilyAfi L2VPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '70', "cbgpPeer2AddrFamilySafi EVPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', 'L2VPN EVPN'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName L2VPN EVPN"),
    ])

    peer2_prefix_ipv4_entries = [
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', accepted_prefixes, "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', denied_prefixes, "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2PrefixAdminLimit"),
    ]
    cbgpPeer2AddrFamilyPrefixTableOIDs.extend(peer2_prefix_ipv4_entries)
    cbgpPeer2AddrFamilyPrefixTableOIDs_v4.extend(peer2_prefix_ipv4_entries)

    # IPv6 peers receive all 4 prefixes (no filter on IPv6 peers)
    peer2_prefix_ipv6_entries = [
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '4', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '0', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '75', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2PrefixAdminLimit"),
    ]
    cbgpPeer2AddrFamilyPrefixTableOIDs.extend(peer2_prefix_ipv6_entries)
    cbgpPeer2AddrFamilyPrefixTableOIDs_v6.extend(peer2_prefix_ipv6_entries)

    # L2VPN EVPN entries for IPv4 peers
    cbgpPeer2AddrFamilyPrefixTableOIDs.extend([
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeer2AcceptedPrefixes L2VPN EVPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeer2DeniedPrefixes L2VPN EVPN"),
    ])
    cbgpPeer2AddrFamilyPrefixTableOIDs_v4.extend([
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeer2AcceptedPrefixes L2VPN EVPN"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{l2vpn_evpn_af_idx}', '0', "cbgpPeer2DeniedPrefixes L2VPN EVPN"),
    ])

    peer3_ipv4_entries = [
        (rf'{OIDS["cbgpPeer3Table"]}.1.2.0.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3Type"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.3.0.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_rmt, "cbgpPeer3RemoteAddr"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.4.0.{ipv4_af_type}.{peer_ipv4}', 'VRF default'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.5.0.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer3State"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.6.0.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer3AdminStatus"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.7.0.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.8.0.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_lcl, "cbgpPeer3LocalAddr"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.10.0.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3LocalAs"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.11.0.{ipv4_af_type}.{peer_ipv4}', 'C0 00 02 01', "cbgpPeer3LocalIdentifier"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.13.0.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3RemoteAs"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.14.0.{ipv4_af_type}.{peer_ipv4}', 'C0 00 02 02', "cbgpPeer3RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.19.0.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3LastError"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.20.0.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3FsmEstablishedTransitions"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.22.0.{ipv4_af_type}.{peer_ipv4}', '30', "cbgpPeer3ConnectRetryInterval"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.23.0.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTime"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.24.0.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAlive"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.25.0.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.26.0.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.28.0.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.30.0.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer3LastErrorTxt"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.31.0.{ipv4_af_type}.{peer_ipv4}', '5', "cbgpPeer3PrevState"),
    ]
    cbgpPeer3TableOIDs.extend(peer3_ipv4_entries)
    cbgpPeer3TableOIDs_v4.extend(peer3_ipv4_entries)

    peer3_ipv6_entries = [
        (rf'{OIDS["cbgpPeer3Table"]}.1.2.0.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer3Type"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.3.0.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_rmt, "cbgpPeer3RemoteAddr"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.4.0.{ipv6_af_type}.{peer_ipv6}', 'VRF default'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.5.0.{ipv6_af_type}.{peer_ipv6}', '6', "cbgpPeer3State"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.6.0.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer3AdminStatus"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.7.0.{ipv6_af_type}.{peer_ipv6}', '4', "cbgpPeer3NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.8.0.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_lcl, "cbgpPeer3LocalAddr"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.10.0.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer3LocalAs"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.11.0.{ipv6_af_type}.{peer_ipv6}', 'C0 00 02 01', "cbgpPeer3LocalIdentifier"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.13.0.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer3RemoteAs"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.14.0.{ipv6_af_type}.{peer_ipv6}', 'C0 00 02 02', "cbgpPeer3RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.19.0.{ipv6_af_type}.{peer_ipv6}', '0', "cbgpPeer3LastError"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.20.0.{ipv6_af_type}.{peer_ipv6}', '1', "cbgpPeer3FsmEstablishedTransitions"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.22.0.{ipv6_af_type}.{peer_ipv6}', '30', "cbgpPeer3ConnectRetryInterval"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.23.0.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer3HoldTime"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.24.0.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer3KeepAlive"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.25.0.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer3HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.26.0.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer3KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.28.0.{ipv6_af_type}.{peer_ipv6}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.30.0.{ipv6_af_type}.{peer_ipv6}', '00', "cbgpPeer3LastErrorTxt"),
        (rf'{OIDS["cbgpPeer3Table"]}.1.31.0.{ipv6_af_type}.{peer_ipv6}', '5', "cbgpPeer3PrevState"),
    ]
    cbgpPeer3TableOIDs.extend(peer3_ipv6_entries)
    cbgpPeer3TableOIDs_v6.extend(peer3_ipv6_entries)

# --- Logger Configuration ---
# 1. Get a logger instance
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set the lowest level to capture

# 2. Create a formatter to define the log message format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# 3. Create a handler to write logs to a file
file_handler = logging.FileHandler('test_run.log')
file_handler.setFormatter(formatter)

# 4. Create a handler to stream logs to the console (screen)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)

# 5. Add both handlers to the logger
# This is the key step: the logger now has two destinations
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


def log_headline(identifier, description):
    """Emit a numbered headline for test progress."""
    logger.info(f"{identifier} {description}")

def build_topo(tgen):
    "Builds the topology."
    tgen.add_router("r1")
    tgen.add_router("r2")

    # THE DEFINITIVE SOLUTION: Create two dedicated links.
    # Link 1 (eth0) for default VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    # Link 1 (eth1) for default VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    # Link 1 (eth2) for default VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    # Link 2 (eth3) for RED VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    # Link 2 (eth4) for RED VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])
    # Link 2 (eth5) for RED VRF traffic.
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])

def setup_module(mod):
    snmpd = os.system("which snmpd")
    if snmpd:
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run("ip link add RED type vrf table 1001")
    r1.run("ip link set up dev RED")
    r2.run("ip link add RED type vrf table 1001")
    r2.run("ip link set up dev RED")
    r1.run("ip link set r1-eth3 master RED")
    r2.run("ip link set r2-eth3 master RED")
    r1.run("ip link set r1-eth4 master RED")
    r2.run("ip link set r2-eth4 master RED")
    r1.run("ip link set r1-eth5 master RED")
    r2.run("ip link set r2-eth5 master RED")

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, ""), (TopoRouter.RD_BGP, "-M snmp")]
        )
        router.load_config(
            TopoRouter.RD_SNMP,
            os.path.join(CWD, "{}/snmpd.conf".format(rname)),
            "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX",
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def bgp_converge_summary(device):
    json_file = os.path.join(CWD, "r1/bgp_summary.json")
    expected = json.loads(open(json_file).read())
    output = json.loads(device.vtysh_cmd("show bgp vrf all summary json"))

    # Capture the comparison result
    diff = topotest.json_cmp(output, expected)

    # If there is a difference, log it before returning
    if diff:
        logger.error("BGP summary mismatch:\n{}".format(diff))

    # Return the result (None on success, diff string on failure)
    return diff

def get_vrf_id(device, vrf_name):
    # Execute the command to show all VRFs
    output = device.vtysh_cmd("show vrf")

    # Define the regex pattern to find the VRF name and capture its ID.
    # Pattern breakdown:
    # ^vrf\s+      - Line starts with "vrf" followed by one or more spaces.
    # {vrf_name}   - The specific VRF name we are searching for.
    # \s+id\s+     - A space, the word "id", and another space.
    # (\d+)        - A capturing group for one or more digits (this is the ID).
    pattern = rf"^vrf\s+{vrf_name}\s+id\s+(\d+).*"

    # Iterate through each line of the output
    for line in output.strip().splitlines():
        match = re.search(pattern, line)
        if match:
            # If a match is found, group(1) contains the captured ID string.
            vrf_id_str = match.group(1)
            # Convert the captured string to an integer and return it.
            return int(vrf_id_str)

    # If the loop completes without finding a match, return None.
    return None


def test_cisco_bgp4_mib_walk():
    "Main test function for CISCO-BGP4-MIB."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    log_headline("1.", "CISCO-BGP4-MIB walk suite")
    test_func = functools.partial(bgp_converge_summary, r1)
    log_headline("1.1", "Waiting for all BGP sessions to establish")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"

    vrf_peers_ipv4 = ["10.10.3.2", "10.10.4.2", "10.10.5.2"]
    vrf_peers_ipv4_lcl = ["0A 0A 03 01", "0A 0A 04 01", "0A 0A 05 01"]
    vrf_peers_ipv4_rmt = ["0A 0A 03 02", "0A 0A 04 02", "0A 0A 05 02"]

    vrf_id = get_vrf_id(r1, "RED")

    for peer_ipv4, peer_ipv4_lcl, peer_ipv4_rmt in zip(vrf_peers_ipv4, vrf_peers_ipv4_lcl, vrf_peers_ipv4_rmt):

        vrf_peer3_entries = [
            (rf'{OIDS["cbgpPeer3Table"]}.1.2.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3Type"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.3.{vrf_id}.{ipv4_af_type}.{peer_ipv4}',  peer_ipv4_rmt, "cbgpPeer3RemoteAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.4.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', 'VRF RED'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.5.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer3State"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.6.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer3AdminStatus"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.7.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3NegotiatedVersion"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.8.{vrf_id}.{ipv4_af_type}.{peer_ipv4}',  peer_ipv4_lcl, "cbgpPeer3LocalAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.10.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3LocalAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.11.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '0A 0A 03 01', "cbgpPeer3LocalIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.13.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3RemoteAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.14.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '0A 0A 03 02', "cbgpPeer3RemoteIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.15.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3InUpdates"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.16.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3OutUpdates"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.19.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3LastError"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.20.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3FsmEstablishedTransitions"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.22.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '30', "cbgpPeer3ConnectRetryInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.23.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTime"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.24.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAlive"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.25.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTimeConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.26.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAliveConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.28.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.30.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer3LastErrorTxt"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.31.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '5', "cbgpPeer3PrevState"),
        ]
        cbgpPeer3TableOIDs.extend(vrf_peer3_entries)
        cbgpPeer3TableOIDs_v4.extend(vrf_peer3_entries)

    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    def _check_snmp_walk_no_errors(table_oid, table_name):
        """Check that snmpwalk completes without OID ordering errors."""
        cmd = f"snmpwalk -v2c -c public -Ln -On localhost {table_oid}"
        result = r1.cmd(cmd)

        # Check for OID ordering error
        if "OID not increasing" in result or "Error:" in result:
            logger.error(f"SNMP walk error for {table_name}:")
            logger.error(result)
            return False

        return True

    def _check_oids(snmp_output, checks):
        if not isinstance(snmp_output, dict):
            logger.error("SNMP output is not a dictionary")
            return False
        for oid_pattern, value_pattern, message in checks:
            if value_pattern is None:
                found = oid_pattern in snmp_output
                if found:
                    logger.error(f"SNMP WALK FAIL: {message} - OID {oid_pattern} should be absent but was found.")
                    return False
                logger.info(f"SNMP WALK PASS: {message}, {oid_pattern} ")
                continue
            else:
                found = oid_pattern in snmp_output and snmp_output[oid_pattern] == value_pattern
                if not found:
                    logger.error(f"SNMP WALK FAIL: {message} - Pattern not found: {snmp_output} {oid_pattern}: {value_pattern}")
                    return False
                logger.info(f"SNMP WALK PASS: {message}, {oid_pattern}, {value_pattern}")
        return True

    def _ensure_exact_keys(snmp_output, checks, label):
        expected_keys = {oid for oid, _, _ in checks}
        output_keys = set(snmp_output.keys())
        if output_keys != expected_keys:
            unexpected = sorted(output_keys - expected_keys)
            missing = sorted(expected_keys - output_keys)
            if unexpected:
                logger.error(f"{label}: unexpected OIDs returned: {unexpected}")
            if missing:
                logger.error(f"{label}: missing OIDs: {missing}")
            return False
        return True

    def _collect_columns(checks, base_oid):
        pattern = re.compile(rf"{re.escape(base_oid)}\.1\.(\d+)\.")
        columns = set()
        for oid, _, _ in checks:
            match = pattern.match(oid)
            if match:
                columns.add(int(match.group(1)))
        return sorted(columns)

    def _snmp_walk_by_af(base_oid, checks, af_type, label):
        af_pattern = re.compile(
            rf"{re.escape(base_oid)}\.1\.\d+\.{af_type}\."
        )
        af_checks = [entry for entry in checks if af_pattern.match(entry[0])]
        if not af_checks:
            logger.warning(f"{label}: no expected OIDs for AF {af_type}")
            return True
        # Walk the full table once and then filter rows that match the AF index.
        output, _ = snmp.walk(base_oid)
        filtered_output = {
            oid: value for oid, value in output.items() if af_pattern.match(oid)
        }
        if not filtered_output:
            sample_keys = sorted(output.keys())[:5]
            logger.error(
                f"{label}: no SNMP results matched AF {af_type} (sample keys={sample_keys})"
            )
            return False
        expected_keys = {oid for oid, _, _ in af_checks}
        filtered_output = {
            oid: value for oid, value in filtered_output.items() if oid in expected_keys
        }
        if not _check_oids(filtered_output, af_checks):
            return False
        if not _ensure_exact_keys(filtered_output, af_checks, label):
            return False
        return True

    # 4. Test IPv4 Peer Tables
    def _snmp_check_cbgpPeerTable():

        # Check cbgpPeerTable
        output, _ = snmp.walk(OIDS["cbgpPeerTable"])
        for i in range(1, 7):
            cbgpPeerTableOIDs.append((rf'{OIDS["cbgpPeerTable"]}.1.{i}.{peer_ipv4}', None, f"Deprecated OID .1.{i}"))
        if not _check_oids(output, cbgpPeerTableOIDs): return False

        # Check cbgpPeerAddrFamilyTable - explicitly check for OID ordering errors
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeerAddrFamilyTable"], "cbgpPeerAddrFamilyTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeerAddrFamilyTable"])
        if not _check_oids(output, cbgpPeerAddrFamilyTableOIDs): return False

        # Check cbgpPeerAddrFamilyPrefixTable - explicitly check for OID ordering errors
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeerAddrFamilyPrefixTable"], "cbgpPeerAddrFamilyPrefixTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeerAddrFamilyPrefixTable"])
        if not _check_oids(output, cbgpPeerAddrFamilyPrefixTableOIDs): return False

        return True

    log_headline("1.2", "Walking cbgpPeer tables (combined)")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeerTable, True, count=3, wait=5)
    assert result, "SNMP checks for cbgpPeerTable failed"

    # 5. Test IPv6 Peer Tables
    def _snmp_check_cbgpPeer2Table():

        # Check cbgpPeer2Table
        output, _ = snmp.walk(OIDS["cbgpPeer2Table"])
        if not _check_oids(output, cbgpPeer2TableOIDs): return False

        # Check cbgpPeer2AddrFamilyTable - explicitly check for OID ordering errors
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeer2AddrFamilyTable"], "cbgpPeer2AddrFamilyTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeer2AddrFamilyTable"])
        if not _check_oids(output, cbgpPeer2AddrFamilyTableOIDs): return False

        # Check cbgpPeer2AddrFamilyPrefixTable - explicitly check for OID ordering errors
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeer2AddrFamilyPrefixTable"], "cbgpPeer2AddrFamilyPrefixTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeer2AddrFamilyPrefixTable"])
        if not _check_oids(output, cbgpPeer2AddrFamilyPrefixTableOIDs): return False

        return True

    log_headline("1.3", "Walking cbgpPeer2 tables (combined)")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table, True, count=3, wait=5)
    assert result, "SNMP checks for cbgpPeer2Table failed"

    def _snmp_check_cbgpPeer2Table_ipv4_only():
        if not _snmp_walk_by_af(OIDS["cbgpPeer2Table"], cbgpPeer2TableOIDs_v4, ipv4_af_type, "cbgpPeer2Table IPv4-only"):
            return False
        if not _snmp_walk_by_af(OIDS["cbgpPeer2AddrFamilyTable"], cbgpPeer2AddrFamilyTableOIDs_v4, ipv4_af_type, "cbgpPeer2AddrFamilyTable IPv4-only"):
            return False
        if not _snmp_walk_by_af(OIDS["cbgpPeer2AddrFamilyPrefixTable"], cbgpPeer2AddrFamilyPrefixTableOIDs_v4, ipv4_af_type, "cbgpPeer2AddrFamilyPrefixTable IPv4-only"):
            return False
        return True

    log_headline("1.4", "Walking cbgpPeer2 tables (IPv4-only)")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table_ipv4_only, True, count=3, wait=5)
    assert result, "SNMP IPv4-only walk checks for cbgpPeer2Table failed"

    def _snmp_check_cbgpPeer2Table_ipv6_only():
        if not _snmp_walk_by_af(OIDS["cbgpPeer2Table"], cbgpPeer2TableOIDs_v6, ipv6_af_type, "cbgpPeer2Table IPv6-only"):
            return False
        if not _snmp_walk_by_af(OIDS["cbgpPeer2AddrFamilyTable"], cbgpPeer2AddrFamilyTableOIDs_v6, ipv6_af_type, "cbgpPeer2AddrFamilyTable IPv6-only"):
            return False
        if not _snmp_walk_by_af(OIDS["cbgpPeer2AddrFamilyPrefixTable"], cbgpPeer2AddrFamilyPrefixTableOIDs_v6, ipv6_af_type, "cbgpPeer2AddrFamilyPrefixTable IPv6-only"):
            return False
        return True

    log_headline("1.5", "Walking cbgpPeer2 tables (IPv6-only)")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table_ipv6_only, True, count=3, wait=5)
    assert result, "SNMP IPv6-only walk checks for cbgpPeer2Table failed"

    # 6. Test VRF Peer Table
    def _snmp_check_vrf_peer():

        output, _ = snmp.walk(OIDS["cbgpPeer3Table"])

        if not _check_oids(output, cbgpPeer3TableOIDs): return False
        return True

    log_headline("1.6", "Walking cbgpPeer3 VRF table (combined)")
    _, result = topotest.run_and_expect(_snmp_check_vrf_peer, True, count=3, wait=5)
    assert result, "SNMP checks for VRF peer failed"

    def _collect_vrf_indices(checks):
        pattern = re.compile(rf"{re.escape(OIDS['cbgpPeer3Table'])}\.1\.\d+\.(\d+)\.")
        indices = set()
        for oid, _, _ in checks:
            match = pattern.match(oid)
            if match:
                indices.add(int(match.group(1)))
        return indices

    def _snmp_walk_peer3_by_af(checks, af_type, label):
        aggregated = {}
        columns = _collect_columns(checks, OIDS["cbgpPeer3Table"])
        vrf_indices = sorted(_collect_vrf_indices(checks))
        for column in columns:
            for vrf_index in vrf_indices:
                start_oid = f"{OIDS['cbgpPeer3Table']}.1.{column}.{vrf_index}.{af_type}"
                output, _ = snmp.walk(start_oid)
                aggregated.update(output)
        expected_keys = {oid for oid, _, _ in checks}
        filtered = {oid: value for oid, value in aggregated.items() if oid in expected_keys}
        if not _check_oids(filtered, checks):
            return False
        if not _ensure_exact_keys(filtered, checks, label):
            return False
        return True

    def _snmp_check_vrf_peer_ipv4_only():
        return _snmp_walk_peer3_by_af(
            cbgpPeer3TableOIDs_v4,
            ipv4_af_type,
            "cbgpPeer3Table IPv4-only",
        )

    log_headline("1.7", "Walking cbgpPeer3 table (IPv4-only)")
    _, result = topotest.run_and_expect(_snmp_check_vrf_peer_ipv4_only, True, count=3, wait=5)
    assert result, "SNMP IPv4-only walk checks for cbgpPeer3Table failed"

    def _snmp_check_vrf_peer_ipv6_only():
        return _snmp_walk_peer3_by_af(
            cbgpPeer3TableOIDs_v6,
            ipv6_af_type,
            "cbgpPeer3Table IPv6-only",
        )

    if cbgpPeer3TableOIDs_v6:
        log_headline("1.8", "Walking cbgpPeer3 table (IPv6-only)")
        _, result = topotest.run_and_expect(_snmp_check_vrf_peer_ipv6_only, True, count=3, wait=5)
        assert result, "SNMP IPv6-only walk checks for cbgpPeer3Table failed"

def test_cisco_bgp4_mib_get():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    log_headline("2.", "CISCO-BGP4-MIB GET suite")
    test_func = functools.partial(bgp_converge_summary, r1)
    log_headline("2.1", "Waiting for all BGP sessions to establish")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"
    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    # Helper function to check individual OIDs using snmp.get
    def _check_oids_get(checks):
        """
        Iterates through a list of checks, performs an snmp.get for each OID,
        and compares the result with the expected value.

        Args:
            checks (list): A list of tuples, where each tuple is
                        (OID, expected_value, description).

        Returns:
            bool: True if all checks pass, False otherwise.
        """
        for oid, expected_value, description in checks:
            # Assume snmp.get returns a tuple: (value, error_message)
            # value is None if the OID is not found or an error occurs.
            value = snmp.get(oid)

            # --- Case 1: The OID should NOT exist ---
            if expected_value is None:
                if value is not None:
                    # Failure: The OID was found when it should have been absent.
                    log_message = f"SNMP GET FAIL: {description} - OID {oid} {value}should be absent but was found."
                    logger.error(log_message)
                    return False
                else:
                    # Success: The OID is correctly absent.
                    log_message = f"SNMP GET PASS: {description}, {oid}"
                    logger.info(log_message)

            # --- Case 2: The OID SHOULD exist with a specific value ---
            else:
                if value is None:
                    # Failure: The OID was not found at all.
                    log_message = f"SNMP GET FAIL: {description} - OID {oid} was not found"
                    logger.error(log_message)
                    return False

                # Failure: The OID was found, but its value is incorrect.
                if str(value) != str(expected_value):
                    log_message = (
                        f"SNMP GET FAIL: {description} - Pattern not found for OID {oid}: "
                        f"Expected '{expected_value}', but got '{value}'"
                    )
                    logger.error(log_message)
                    return False

                # Success: The OID was found with the correct value.
                log_message = f"SNMP GET PASS: {description}, {oid}, {expected_value}"
                logger.info(log_message)

        return True


    # 1. Test cbgpPeerTable using snmp.get
    def _snmp_check_cbgpPeerTable_get():
        # Check SNMP gets for cbgpPeerTable
        if not _check_oids_get(cbgpPeerTableOIDs): return False

        # Check SNMP gets for cbgpPeerAddrFamilyTable
        if not _check_oids_get(cbgpPeerAddrFamilyTableOIDs): return False

        # Checks  SNMP gets for cbgpPeerAddrFamilyPrefixTable
        if not _check_oids_get(cbgpPeerAddrFamilyPrefixTableOIDs): return False

        return True

    log_headline("2.2", "SNMP get checks for cbgpPeer tables")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeerTable_get, True, count=3, wait=5)
    assert result, "SNMP GET checks for cbgpPeerTable failed"


    # 2. Test IPv6 Peer Tables using snmp.get
    def _snmp_check_cbgpPeer2Table_get():

        # Check SNMP gets for cbgpPeer2Table
        if not _check_oids_get(cbgpPeer2TableOIDs): return False

        # Checks SNMP gets for cbgpPeer2AddrFamilyTable
        if not _check_oids_get(cbgpPeer2AddrFamilyTableOIDs): return False

        # Checks NMP gets for cbgpPeer2AddrFamilyPrefixTable
        if not _check_oids_get(cbgpPeer2AddrFamilyPrefixTableOIDs): return False

        return True

    log_headline("2.3", "SNMP get checks for cbgpPeer2 tables")
    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table_get, True, count=3, wait=5)
    assert result, "SNMP GET checks for cbgpPeer2Table failed"


    # 3. Test VRF Peer Table using snmp.get
    def _snmp_check_vrf_peer_get():
        if not _check_oids_get(cbgpPeer3TableOIDs): return False
        return True

    log_headline("2.4", "SNMP get checks for cbgpPeer3 VRF table")
    _, result = topotest.run_and_expect(_snmp_check_vrf_peer_get, True, count=3, wait=5)
    assert result, "SNMP GET checks for VRF peer failed"


def test_bgp_snmp_no_peers():
    """Test BGP SNMP behavior when no peers are configured - run after main tests."""
    tgen = get_topogen()

    # Use r1 for this test
    r1 = tgen.gears["r1"]

    log_headline("3.", "SNMP behavior with no configured peers")

    # Remove all BGP neighbors from default VRF
    log_headline("3.1", "Removing default-VRF BGP neighbors")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        no neighbor 10.10.0.2
        no neighbor 10.10.1.2
        no neighbor 10.10.2.2
        no neighbor fd00::2
        no neighbor fd00:1::2
        no neighbor fd00:2::2
        """
    )

    # Also remove VRF peers if any
    log_headline("3.2", "Removing VRF-specific BGP neighbors")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001 vrf vrf1
        no neighbor 10.10.5.2
        no neighbor fd00:5::2
        """
    )

    # Wait for configuration to apply
    sleep(3)

    print("Testing SNMP walk")

    # Verify no peers exist
    def _verify_no_peers():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        for afi in ["ipv4Unicast", "ipv6Unicast"]:
            if afi in output and "peers" in output[afi]:
                if len(output[afi]["peers"]) > 0:
                    return False
        return True

    test_func = functools.partial(_verify_no_peers)
    log_headline("3.3", "Verifying all BGP peers removed")
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert result, "Failed to remove all BGP peers"

    # Test SNMP queries when no peers are configured
    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    def _snmpwalk_no_peers_remote_addr():
        # First verify BGP is alive before the test
        try:
            pre_test_check = json.loads(r1.vtysh_cmd("show bgp summary json"))
        except:
            return False  # BGP already dead

        try:

            output, _ = snmp.walk(OIDS["cbgpPeer2Table"])

            # If we get here without exception, check if BGP is still alive
            try:
                post_test_check = json.loads(r1.vtysh_cmd("show bgp summary json"))
                # BGP survived - either fix is applied or crash didn't occur
                return True  # This is unexpected if fix not applied
            except:
                # BGP died after SNMP operation - crash occurred!
                return False  # This indicates the crash happened

        except Exception as e:
            error_str = str(e).lower()
            # Check if BGP crashed (timeout/no response) or just returned error
            if "timeout" in error_str or "no response" in error_str:
                # Likely BGP crashed - verify by checking if it's still responsive
                try:
                    json.loads(r1.vtysh_cmd("show bgp summary json"))
                    return True  # BGP still alive, just SNMP timeout
                except:
                    return False  # BGP crashed!
            else:
                # Got SNMP error but need to verify BGP is still alive
                try:
                    json.loads(r1.vtysh_cmd("show bgp summary json"))
                    return True  # BGP alive, got expected SNMP error
                except:
                    return False  # BGP crashed during SNMP operation


    log_headline("3.4", "SNMP walk of cbgpPeer2Table with no peers")
    _, result = topotest.run_and_expect(_snmpwalk_no_peers_remote_addr, True, count=10, wait=2)


    if result:
        print("BGP survived SNMP walk")
    else:
        print("BGP crashed during SNMP walk")
        assert False, "BGP daemon crashed"

    def _snmpwalk_no_peers_state():
        """bgp4V2PeerState should also trigger crash if fix not applied."""
        # Verify BGP is still alive before this test
        try:
            pre_test_check = json.loads(r1.vtysh_cmd("show bgp summary json"))
        except:
            return False  # BGP already dead from previous test

        try:
            # This Cisco BGP MIB OID may also trigger the same crash condition
            output, _ = snmp.walk(OIDS["cbgpPeerTable"])

            # Check if BGP survived
            try:
                post_test_check = json.loads(r1.vtysh_cmd("show bgp summary json"))
                return True  # BGP survived
            except:
                return False  # BGP crashed

        except Exception as e:
            # Check for crash indicators
            error_str = str(e).lower()
            if "timeout" in error_str or "no response" in error_str:
                try:
                    json.loads(r1.vtysh_cmd("show bgp summary json"))
                    return True  # BGP alive despite timeout
                except:
                    return False  # BGP crashed
            else:
                try:
                    json.loads(r1.vtysh_cmd("show bgp summary json"))
                    return True  # BGP alive, got SNMP error
                except:
                    return False  # BGP crashed

    log_headline("3.5", "SNMP walk of cbgpPeerTable with no peers")
    _, result = topotest.run_and_expect(_snmpwalk_no_peers_state, True, count=10, wait=2)

    if result:
        print("BGP survived second SNMP walk")
    else:
        print("BGP crashed during second SNMP walk")
        assert False, "BGP daemon crashed"

    # Verify BGP daemon is still running after SNMP operations
    def _verify_bgp_still_alive():
        """Final check that BGP daemon survived the SNMP operations."""
        try:
            # If BGP crashed, this command will fail
            output = json.loads(r1.vtysh_cmd("show bgp summary json"))
            return True
        except:
            return False

    log_headline("3.6", "Verifying bgpd is still alive after SNMP walks")
    _, result = topotest.run_and_expect(_verify_bgp_still_alive, True, count=10, wait=2)
    assert result, "BGP daemon crashed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    log_headline("4.", "Reporting memory leaks")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))