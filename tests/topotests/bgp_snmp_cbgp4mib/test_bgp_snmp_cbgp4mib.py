#!/usr/bin/env python
#
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
MIB_OBJECTS = "1.3.6.1.4.1.9.9.187.1"
OIDS = {
    "cbgpRouteTable": "1.3.6.1.4.1.9.9.187.1.1.1",
    "cbgpPeerTable": f"{MIB_BASE}.1",
    "cbgpPeerCapsTable": f"{MIB_BASE}.2",
    "cbgpPeerAddrFamilyTable": f"{MIB_BASE}.3",
    "cbgpPeerAddrFamilyPrefixTable": f"{MIB_BASE}.4",
    "cbgpPeer2Table": f"{MIB_BASE}.5",
    "cbgpPeer2CapsTable": f"{MIB_BASE}.6",
    "cbgpPeer2AddrFamilyTable": f"{MIB_BASE}.7",
    "cbgpPeer2AddrFamilyPrefixTable": f"{MIB_BASE}.8",
    "cbgpPeer3Table": f"{MIB_BASE}.9",
    "cbgpGlobal": f"{MIB_OBJECTS}.3",
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


cbgpGlobalOIDs = [
    (rf'{OIDS["cbgpGlobal"]}.1.0', 'E0', "cbgpNotifsEnable (all enabled)"),
    (rf'{OIDS["cbgpGlobal"]}.2.0', '65001', "cbgpLocalAs"),
]

cbgpPeerTableOIDs = []
cbgpPeerCapsTableOIDs = []
cbgpPeer2TableOIDs = []
cbgpPeer2TableOIDs_v4 = []
cbgpPeer2CapsTableOIDs = []
cbgpPeerAddrFamilyTableOIDs = []
cbgpPeerAddrFamilyPrefixTableOIDs = []
cbgpPeer2AddrFamilyTableOIDs = []
cbgpPeer2AddrFamilyTableOIDs_v4 = []
cbgpPeer2AddrFamilyPrefixTableOIDs = []
cbgpPeer3TableOIDs = []
cbgpPeer3TableOIDs_v4 = []

for peer_ipv4, peer_ipv6, peer_ipv4_lcl, peer_ipv6_lcl, peer_ipv4_rmt, peer_ipv6_rmt in zip(peers_ipv4, peers_ipv6, peers_ipv4_lcl, peers_ipv6_lcl, peers_ipv4_rmt, peers_ipv6_rmt):
    # Peer 10.10.0.2 has filtering applied, others don't
    accepted_prefixes = '3' if peer_ipv4 == '10.10.0.2' else '5'
    denied_prefixes = '2' if peer_ipv4 == '10.10.0.2' else '0'
    advertised_prefixes = '7'
    
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
    ])

    cbgpPeerAddrFamilyPrefixTableOIDs.extend([
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.1.{peer_ipv4}.{ipv4_unicast_af_idx}', accepted_prefixes, "cbgpPeerAcceptedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.2.{peer_ipv4}.{ipv4_unicast_af_idx}', denied_prefixes, "cbgpPeerDeniedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.3.{peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeerPrefixAdminLimit"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.4.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeerPrefixThreshold"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.5.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeerPrefixClearThreshold"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.6.{peer_ipv4}.{ipv4_unicast_af_idx}', advertised_prefixes, "cbgpPeerAdvertisedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.7.{peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeerSuppressedPrefixes"),
        (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.8.{peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeerWithdrawnPrefixes"),
    ])

    cbgpPeer2TableOIDs.extend([
        #IPv4 Peer
        (rf'{OIDS["cbgpPeer2Table"]}.1.1.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer2Type"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.2.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_rmt, "cbgpPeer2RemoteAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.3.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer2State"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.4.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer2AdminStatus"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.5.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer2NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.6.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_lcl, "cbgpPeer2LocalAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.8.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer2LocalAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.9.{ipv4_af_type}.{peer_ipv4}', '1.1.1.1', "cbgpPeer2LocalIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.11.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer2RemoteAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.12.{ipv4_af_type}.{peer_ipv4}', '2.2.2.2', "cbgpPeer2RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.17.{ipv4_af_type}.{peer_ipv4}', '00 00', "cbgpPeer2LastError"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.18.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer2FsmEstablishedTransitions"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.20.{ipv4_af_type}.{peer_ipv4}', '30', "cbgpPeer2ConnectRetryInterval"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.21.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer2HoldTime"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.22.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer2KeepAlive"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.23.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer2HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.24.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer2KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.26.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer2MinRouteAdvertisementInterval"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.28.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer2LastErrorTxt"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.29.{ipv4_af_type}.{peer_ipv4}', '5', "cbgpPeer2PrevState (idle)"),
        #IPv6 Peer
        (rf'{OIDS["cbgpPeer2Table"]}.1.1.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer2Type"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.2.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_rmt, "cbgpPeer2RemoteAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.3.{ipv6_af_type}.{peer_ipv6}', '6', "cbgpPeer2State"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.4.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer2AdminStatus"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.5.{ipv6_af_type}.{peer_ipv6}', '4', "cbgpPeer2NegotiatedVersion"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.6.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_lcl, "cbgpPeer2LocalAddr"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.8.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer2LocalAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.9.{ipv6_af_type}.{peer_ipv6}', '1.1.1.1', "cbgpPeer2LocalIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.11.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer2RemoteAs"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.12.{ipv6_af_type}.{peer_ipv6}', '2.2.2.2', "cbgpPeer2RemoteIdentifier"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.17.{ipv6_af_type}.{peer_ipv6}', '00 00', "cbgpPeer2LastError"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.18.{ipv6_af_type}.{peer_ipv6}', '1', "cbgpPeer2FsmEstablishedTransitions"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.20.{ipv6_af_type}.{peer_ipv6}', '30', "cbgpPeer2ConnectRetryInterval"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.21.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer2HoldTime"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.22.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer2KeepAlive"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.23.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer2HoldTimeConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.24.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer2KeepAliveConfigured"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.26.{ipv6_af_type}.{peer_ipv6}', '0', "cbgpPeer2MinRouteAdvertisementInterval"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.28.{ipv6_af_type}.{peer_ipv6}', '00', "cbgpPeer2LastErrorTxt"),
        (rf'{OIDS["cbgpPeer2Table"]}.1.29.{ipv6_af_type}.{peer_ipv6}', '5', "cbgpPeer2PrevState (idle)"),
    ])
        
    cbgpPeer2AddrFamilyTableOIDs.extend([
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '2', "cbgpPeer2AddrFamilyAfi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
        (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', 'IPv6 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName"),
    ])

    cbgpPeer2AddrFamilyPrefixTableOIDs.extend([
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', accepted_prefixes, "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '5', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2AcceptedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', denied_prefixes, "cbgpPeer2DeniedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2DeniedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '0', "cbgpPeer2DeniedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '75', "cbgpPeer2PrefixThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.5.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixClearThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.5.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixClearThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.5.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '75', "cbgpPeer2PrefixClearThreshold"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', advertised_prefixes, "cbgpPeer2AdvertisedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', advertised_prefixes, "cbgpPeer2AdvertisedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '1', "cbgpPeer2AdvertisedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.7.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2SuppressedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.7.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2SuppressedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.7.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '0', "cbgpPeer2SuppressedPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.8.{ipv4_af_type}.{peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2WithdrawnPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.8.{ipv6_af_type}.{peer_ipv6}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2WithdrawnPrefixes"),
        (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.8.{ipv6_af_type}.{peer_ipv6}.{ipv6_unicast_af_idx}', '0', "cbgpPeer2WithdrawnPrefixes"),
    ])

    cbgpPeer3TableOIDs.extend([
            # --- IPv4 Peer (2.2.2.2) Checks ---
            (rf'{OIDS["cbgpPeer3Table"]}.1.2.0.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3Type"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.3.0.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_rmt, "cbgpPeer3RemoteAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.4.0.{ipv4_af_type}.{peer_ipv4}', 'VRF default'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"), # "VRF default"
            (rf'{OIDS["cbgpPeer3Table"]}.1.5.0.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer3State"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.6.0.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer3AdminStatus"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.7.0.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3NegotiatedVersion"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.8.0.{ipv4_af_type}.{peer_ipv4}', peer_ipv4_lcl, "cbgpPeer3LocalAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.10.0.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3LocalAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.11.0.{ipv4_af_type}.{peer_ipv4}', '1.1.1.1', "cbgpPeer3LocalIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.13.0.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3RemoteAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.14.0.{ipv4_af_type}.{peer_ipv4}', '2.2.2.2', "cbgpPeer3RemoteIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.19.0.{ipv4_af_type}.{peer_ipv4}', '00 00', "cbgpPeer3LastError"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.20.0.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3FsmEstablishedTransitions"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.22.0.{ipv4_af_type}.{peer_ipv4}', '30', "cbgpPeer3ConnectRetryInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.23.0.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTime"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.24.0.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAlive"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.25.0.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTimeConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.26.0.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAliveConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.28.0.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.30.0.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer3LastErrorTxt"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.31.0.{ipv4_af_type}.{peer_ipv4}', '5', "cbgpPeer3PrevState"),

            # --- IPv6 Peer (fd00::1:0:0:2) Checks ---
            (rf'{OIDS["cbgpPeer3Table"]}.1.2.0.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer3Type"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.3.0.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_rmt, "cbgpPeer3RemoteAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.4.0.{ipv6_af_type}.{peer_ipv6}', 'VRF default'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"), # "VRF default"
            (rf'{OIDS["cbgpPeer3Table"]}.1.5.0.{ipv6_af_type}.{peer_ipv6}', '6', "cbgpPeer3State"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.6.0.{ipv6_af_type}.{peer_ipv6}', '2', "cbgpPeer3AdminStatus"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.7.0.{ipv6_af_type}.{peer_ipv6}', '4', "cbgpPeer3NegotiatedVersion"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.8.0.{ipv6_af_type}.{peer_ipv6}', peer_ipv6_lcl, "cbgpPeer3LocalAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.10.0.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer3LocalAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.11.0.{ipv6_af_type}.{peer_ipv6}', '1.1.1.1', "cbgpPeer3LocalIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.13.0.{ipv6_af_type}.{peer_ipv6}', '65001', "cbgpPeer3RemoteAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.14.0.{ipv6_af_type}.{peer_ipv6}', '2.2.2.2', "cbgpPeer3RemoteIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.19.0.{ipv6_af_type}.{peer_ipv6}', '00 00', "cbgpPeer3LastError"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.20.0.{ipv6_af_type}.{peer_ipv6}', '1', "cbgpPeer3FsmEstablishedTransitions"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.22.0.{ipv6_af_type}.{peer_ipv6}', '30', "cbgpPeer3ConnectRetryInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.23.0.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer3HoldTime"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.24.0.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer3KeepAlive"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.25.0.{ipv6_af_type}.{peer_ipv6}', '180', "cbgpPeer3HoldTimeConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.26.0.{ipv6_af_type}.{peer_ipv6}', '60', "cbgpPeer3KeepAliveConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.28.0.{ipv6_af_type}.{peer_ipv6}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.30.0.{ipv6_af_type}.{peer_ipv6}', '00', "cbgpPeer3LastErrorTxt"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.31.0.{ipv6_af_type}.{peer_ipv6}', '5', "cbgpPeer3PrevState"),
        ])

# =============================================================================
# cbgpRouteTable Test Data
# =============================================================================
# cbgpRouteTable OID: .1.3.6.1.4.1.9.9.187.1.1.1
#
# INDEX: { cbgpRouteAfi, cbgpRouteSafi, cbgpRoutePeerType, cbgpRoutePeer,
#          cbgpRouteAddrPrefix, cbgpRouteAddrPrefixLen }
#
# OID structure:
# <base>.1.<column>.<afi>.<safi>.<peerType>.<peerLen>.<peer[0-n]>.<prefixLen>.<prefix[0-n]>.<prefixBitLen>
#
# Columns:
#  1 - cbgpRouteAfi (INTEGER)
#  2 - cbgpRouteSafi (INTEGER)
#  3 - cbgpRoutePeerType (INTEGER: 1=ipv4, 2=ipv6)
#  4 - cbgpRoutePeer (OCTET STRING)
#  5 - cbgpRouteAddrPrefix (OCTET STRING)
#  6 - cbgpRouteAddrPrefixLen (Unsigned32)
#  7 - cbgpRouteOrigin (INTEGER: 1=igp, 2=egp, 3=incomplete)
#  8 - cbgpRouteASPathSegment (OCTET STRING)
#  9 - cbgpRouteNextHop (InetAddress)
# 10 - cbgpRouteMedPresent (TruthValue: 1=true, 2=false)
# 11 - cbgpRouteMultiExitDisc (Unsigned32)
# 12 - cbgpRouteLocalPrefPresent (TruthValue: 1=true, 2=false)
# 13 - cbgpRouteLocalPref (Unsigned32)
# 14 - cbgpRouteAtomicAggregate (INTEGER: 1=less-specific-not-selected, 2=less-specific-selected)
# 15 - cbgpRouteAggregatorAS (Unsigned32)
# 16 - cbgpRouteAggregatorAddrType (INTEGER)
# 17 - cbgpRouteAggregatorAddr (InetAddress)
# 18 - cbgpRouteBest (TruthValue)
# 19 - cbgpRouteUnknownAttr (OCTET STRING)

cbgpRouteTableOIDs = []

# IPv4 Unicast routes from peer 10.10.0.2 (first peer in peers_ipv4 list)
# r2 advertises: 172.16.1.0/24, 172.16.2.0/24, 172.16.3.0/24, 172.16.4.0/24, 172.16.5.0/24
# r1 filters out 172.16.2.0/24 and 172.16.4.0/24 via FILTER_IN route-map
# So r1 should have: 172.16.1.0/24, 172.16.3.0/24, 172.16.5.0/24 from 10.10.0.2

# Peer 10.10.0.2 = OID encoding: peerType=1, peerLen=4, peer=10.10.0.2
# IPv4 prefix 172.16.1.0/24 = prefixLen=4, prefix=172.16.1.0, prefixBitLen=24

ipv4_peer_oid = "1.4.10.10.0.2"  # peerType.peerLen.peer[0].peer[1].peer[2].peer[3]

# Route 172.16.1.0/24 from peer 10.10.0.2
route_172_16_1_0 = f"{ipv4_peer_oid}.4.172.16.1.0.24"  # prefixLen.prefix[0-3].prefixBitLen
cbgpRouteTableOIDs.extend([
    # AFI=1 (IPv4), SAFI=1 (Unicast) - Test all 19 columns for this route
    # Column 1: cbgpRouteAfi
    (rf'{OIDS["cbgpRouteTable"]}.1.1.1.1.{route_172_16_1_0}', '1', "cbgpRouteAfi 172.16.1.0/24"),
    # Column 2: cbgpRouteSafi
    (rf'{OIDS["cbgpRouteTable"]}.1.2.1.1.{route_172_16_1_0}', '1', "cbgpRouteSafi 172.16.1.0/24"),
    # Column 3: cbgpRoutePeerType
    (rf'{OIDS["cbgpRouteTable"]}.1.3.1.1.{route_172_16_1_0}', '1', "cbgpRoutePeerType 172.16.1.0/24"),
    # Column 4: cbgpRoutePeer
    (rf'{OIDS["cbgpRouteTable"]}.1.4.1.1.{route_172_16_1_0}', '0A 0A 00 02', "cbgpRoutePeer 172.16.1.0/24"),
    # Column 5: cbgpRouteAddrPrefix
    (rf'{OIDS["cbgpRouteTable"]}.1.5.1.1.{route_172_16_1_0}', 'AC 10 01 00', "cbgpRouteAddrPrefix 172.16.1.0/24"),
    # Column 6: cbgpRouteAddrPrefixLen
    (rf'{OIDS["cbgpRouteTable"]}.1.6.1.1.{route_172_16_1_0}', '24', "cbgpRouteAddrPrefixLen 172.16.1.0/24"),
    # Column 7: cbgpRouteOrigin (1=IGP, 2=EGP, 3=incomplete)
    (rf'{OIDS["cbgpRouteTable"]}.1.7.1.1.{route_172_16_1_0}', '1', "cbgpRouteOrigin 172.16.1.0/24 (IGP)"),
    # Column 8: cbgpRouteASPathSegment (empty for iBGP, no AS path segments)
    (rf'{OIDS["cbgpRouteTable"]}.1.8.1.1.{route_172_16_1_0}', r'""', "cbgpRouteASPathSegment 172.16.1.0/24 (empty)"),
    # Column 9: cbgpRouteNextHop (10.10.0.2 = 0A 0A 00 02)
    (rf'{OIDS["cbgpRouteTable"]}.1.9.1.1.{route_172_16_1_0}', '0A 0A 00 02', "cbgpRouteNextHop 172.16.1.0/24"),
    # Column 10: cbgpRouteMedPresent (1=true for iBGP routes with default MED)
    (rf'{OIDS["cbgpRouteTable"]}.1.10.1.1.{route_172_16_1_0}', '1', "cbgpRouteMedPresent 172.16.1.0/24 (true)"),
    # Column 11: cbgpRouteMultiExitDisc (0 = default MED)
    (rf'{OIDS["cbgpRouteTable"]}.1.11.1.1.{route_172_16_1_0}', '0', "cbgpRouteMultiExitDisc 172.16.1.0/24"),
    # Column 12: cbgpRouteLocalPrefPresent (1=true)
    (rf'{OIDS["cbgpRouteTable"]}.1.12.1.1.{route_172_16_1_0}', '1', "cbgpRouteLocalPrefPresent 172.16.1.0/24 (true)"),
    # Column 13: cbgpRouteLocalPref (100 = default)
    (rf'{OIDS["cbgpRouteTable"]}.1.13.1.1.{route_172_16_1_0}', '100', "cbgpRouteLocalPref 172.16.1.0/24"),
    # Column 14: cbgpRouteAtomicAggregate (1=less-specific-not-selected, 2=less-specific-selected)
    (rf'{OIDS["cbgpRouteTable"]}.1.14.1.1.{route_172_16_1_0}', '2', "cbgpRouteAtomicAggregate 172.16.1.0/24 (less-specific-selected)"),
    # Column 15: cbgpRouteAggregatorAS (0 = no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.15.1.1.{route_172_16_1_0}', '0', "cbgpRouteAggregatorAS 172.16.1.0/24"),
    # Column 16: cbgpRouteAggregatorAddrType (0=unknown when no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.16.1.1.{route_172_16_1_0}', '0', "cbgpRouteAggregatorAddrType 172.16.1.0/24"),
    # Column 17: cbgpRouteAggregatorAddr (0.0.0.0 when no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.17.1.1.{route_172_16_1_0}', '00 00 00 00', "cbgpRouteAggregatorAddr 172.16.1.0/24 (0.0.0.0)"),
    # Column 18: cbgpRouteBest (1=true, 2=false)
    (rf'{OIDS["cbgpRouteTable"]}.1.18.1.1.{route_172_16_1_0}', '1', "cbgpRouteBest 172.16.1.0/24 (true)"),
])

# Route 172.16.3.0/24 from peer 10.10.0.2
route_172_16_3_0 = f"{ipv4_peer_oid}.4.172.16.3.0.24"
cbgpRouteTableOIDs.extend([
    (rf'{OIDS["cbgpRouteTable"]}.1.1.1.1.{route_172_16_3_0}', '1', "cbgpRouteAfi 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.2.1.1.{route_172_16_3_0}', '1', "cbgpRouteSafi 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.3.1.1.{route_172_16_3_0}', '1', "cbgpRoutePeerType 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.4.1.1.{route_172_16_3_0}', '0A 0A 00 02', "cbgpRoutePeer 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.5.1.1.{route_172_16_3_0}', 'AC 10 03 00', "cbgpRouteAddrPrefix 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.6.1.1.{route_172_16_3_0}', '24', "cbgpRouteAddrPrefixLen 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.7.1.1.{route_172_16_3_0}', '1', "cbgpRouteOrigin 172.16.3.0/24 (IGP)"),
    (rf'{OIDS["cbgpRouteTable"]}.1.12.1.1.{route_172_16_3_0}', '1', "cbgpRouteLocalPrefPresent 172.16.3.0/24 (true)"),
    (rf'{OIDS["cbgpRouteTable"]}.1.13.1.1.{route_172_16_3_0}', '100', "cbgpRouteLocalPref 172.16.3.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.18.1.1.{route_172_16_3_0}', '1', "cbgpRouteBest 172.16.3.0/24 (true)"),
])

# Route 172.16.5.0/24 from peer 10.10.0.2
route_172_16_5_0 = f"{ipv4_peer_oid}.4.172.16.5.0.24"
cbgpRouteTableOIDs.extend([
    (rf'{OIDS["cbgpRouteTable"]}.1.1.1.1.{route_172_16_5_0}', '1', "cbgpRouteAfi 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.2.1.1.{route_172_16_5_0}', '1', "cbgpRouteSafi 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.3.1.1.{route_172_16_5_0}', '1', "cbgpRoutePeerType 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.4.1.1.{route_172_16_5_0}', '0A 0A 00 02', "cbgpRoutePeer 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.5.1.1.{route_172_16_5_0}', 'AC 10 05 00', "cbgpRouteAddrPrefix 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.6.1.1.{route_172_16_5_0}', '24', "cbgpRouteAddrPrefixLen 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.7.1.1.{route_172_16_5_0}', '1', "cbgpRouteOrigin 172.16.5.0/24 (IGP)"),
    (rf'{OIDS["cbgpRouteTable"]}.1.12.1.1.{route_172_16_5_0}', '1', "cbgpRouteLocalPrefPresent 172.16.5.0/24 (true)"),
    (rf'{OIDS["cbgpRouteTable"]}.1.13.1.1.{route_172_16_5_0}', '100', "cbgpRouteLocalPref 172.16.5.0/24"),
    (rf'{OIDS["cbgpRouteTable"]}.1.18.1.1.{route_172_16_5_0}', '1', "cbgpRouteBest 172.16.5.0/24 (true)"),
])

# IPv6 Unicast route from peer fd00::2
# r2 advertises: fd01:2::1/128
# Peer fd00::2 in OID encoding: peerType=2, peerLen=16, peer=fd00:0000:0000:0000:0000:0000:0000:0002
ipv6_peer_oid = "2.16.253.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2"  # peerType.peerLen.peer[0-15]

# Route fd01:2::1/128 from peer fd00::2
# fd01:0002:0000:0000:0000:0000:0000:0001 = 253.1.0.2.0.0.0.0.0.0.0.0.0.0.0.1
route_fd01_2_1 = f"{ipv6_peer_oid}.16.253.1.0.2.0.0.0.0.0.0.0.0.0.0.0.1.128"
cbgpRouteTableOIDs.extend([
    # AFI=2 (IPv6), SAFI=1 (Unicast)
    # Column 1: cbgpRouteAfi
    (rf'{OIDS["cbgpRouteTable"]}.1.1.2.1.{route_fd01_2_1}', '2', "cbgpRouteAfi fd01:2::1/128"),
    # Column 2: cbgpRouteSafi
    (rf'{OIDS["cbgpRouteTable"]}.1.2.2.1.{route_fd01_2_1}', '1', "cbgpRouteSafi fd01:2::1/128"),
    # Column 3: cbgpRoutePeerType
    (rf'{OIDS["cbgpRouteTable"]}.1.3.2.1.{route_fd01_2_1}', '2', "cbgpRoutePeerType fd01:2::1/128"),
    # Column 4: cbgpRoutePeer (fd00::2 = FD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02)
    (rf'{OIDS["cbgpRouteTable"]}.1.4.2.1.{route_fd01_2_1}', 'FD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02', "cbgpRoutePeer fd01:2::1/128"),
    # Column 5: cbgpRouteAddrPrefix (fd01:2::1 = FD 01 00 02 00 00 00 00 00 00 00 00 00 00 00 01)
    (rf'{OIDS["cbgpRouteTable"]}.1.5.2.1.{route_fd01_2_1}', 'FD 01 00 02 00 00 00 00 00 00 00 00 00 00 00 01', "cbgpRouteAddrPrefix fd01:2::1/128"),
    # Column 6: cbgpRouteAddrPrefixLen
    (rf'{OIDS["cbgpRouteTable"]}.1.6.2.1.{route_fd01_2_1}', '128', "cbgpRouteAddrPrefixLen fd01:2::1/128"),
    # Column 7: cbgpRouteOrigin (1=IGP)
    (rf'{OIDS["cbgpRouteTable"]}.1.7.2.1.{route_fd01_2_1}', '1', "cbgpRouteOrigin fd01:2::1/128 (IGP)"),
    # Column 8: cbgpRouteASPathSegment (empty for iBGP)
    (rf'{OIDS["cbgpRouteTable"]}.1.8.2.1.{route_fd01_2_1}', r'""', "cbgpRouteASPathSegment fd01:2::1/128 (empty)"),
    # Column 9: cbgpRouteNextHop - skipped as IPv6 may use link-local address
    # Column 10: cbgpRouteMedPresent (1=true)
    (rf'{OIDS["cbgpRouteTable"]}.1.10.2.1.{route_fd01_2_1}', '1', "cbgpRouteMedPresent fd01:2::1/128 (true)"),
    # Column 11: cbgpRouteMultiExitDisc (0 = default MED)
    (rf'{OIDS["cbgpRouteTable"]}.1.11.2.1.{route_fd01_2_1}', '0', "cbgpRouteMultiExitDisc fd01:2::1/128"),
    # Column 12: cbgpRouteLocalPrefPresent (1=true)
    (rf'{OIDS["cbgpRouteTable"]}.1.12.2.1.{route_fd01_2_1}', '1', "cbgpRouteLocalPrefPresent fd01:2::1/128 (true)"),
    # Column 13: cbgpRouteLocalPref (100 = default)
    (rf'{OIDS["cbgpRouteTable"]}.1.13.2.1.{route_fd01_2_1}', '100', "cbgpRouteLocalPref fd01:2::1/128"),
    # Column 14: cbgpRouteAtomicAggregate (2=less-specific-selected)
    (rf'{OIDS["cbgpRouteTable"]}.1.14.2.1.{route_fd01_2_1}', '2', "cbgpRouteAtomicAggregate fd01:2::1/128 (less-specific-selected)"),
    # Column 15: cbgpRouteAggregatorAS (0 = no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.15.2.1.{route_fd01_2_1}', '0', "cbgpRouteAggregatorAS fd01:2::1/128"),
    # Column 16: cbgpRouteAggregatorAddrType (0=unknown when no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.16.2.1.{route_fd01_2_1}', '0', "cbgpRouteAggregatorAddrType fd01:2::1/128"),
    # Column 17: cbgpRouteAggregatorAddr (0.0.0.0 when no aggregator)
    (rf'{OIDS["cbgpRouteTable"]}.1.17.2.1.{route_fd01_2_1}', '00 00 00 00', "cbgpRouteAggregatorAddr fd01:2::1/128 (0.0.0.0)"),
    # Column 18: cbgpRouteBest (1=true)
    (rf'{OIDS["cbgpRouteTable"]}.1.18.2.1.{route_fd01_2_1}', '1', "cbgpRouteBest fd01:2::1/128 (true)"),
])

# --- EBGP peer (r3, AS 65002) for AS-path loop filtering test ---
# r3 sends 4 routes: 2 normal, 2 with AS 65001 prepended (causing AS-loop).
# r1 has route-map FILTER_EBGP_IN that denies 192.168.2.0/24.
# Expected on r1: accepted=1, denied=3 (1 route-map + 2 AS-loop)
ebgp_peer_ipv4 = "10.10.6.2"
ebgp_peer_ipv4_lcl = "0A 0A 06 01"
ebgp_peer_ipv4_rmt = "0A 0A 06 02"
ebgp_accepted = '1'
ebgp_denied = '3'

cbgpPeerTableOIDs.extend([
    (rf'{OIDS["cbgpPeerTable"]}.1.7.{ebgp_peer_ipv4}', '00', "cbgpPeerLastErrorTxt (EBGP)"),
    (rf'{OIDS["cbgpPeerTable"]}.1.8.{ebgp_peer_ipv4}', '5', "cbgpPeerPrevState (EBGP)"),
])

cbgpPeerAddrFamilyTableOIDs.extend([
    (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.1.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeerAddrFamilyAfi (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.2.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeerAddrFamilySafi (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyTable"]}.1.3.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeerAddrFamilyName (EBGP)"),
])

cbgpPeerAddrFamilyPrefixTableOIDs.extend([
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.1.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', ebgp_accepted, "cbgpPeerAcceptedPrefixes (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.2.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', ebgp_denied, "cbgpPeerDeniedPrefixes (EBGP) - includes AS-loop"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.3.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeerPrefixAdminLimit (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.4.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeerPrefixThreshold (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.5.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeerPrefixClearThreshold (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.7.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeerSuppressedPrefixes (EBGP)"),
    (rf'{OIDS["cbgpPeerAddrFamilyPrefixTable"]}.1.8.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeerWithdrawnPrefixes (EBGP)"),
])

ebgp_peer2_entries = [
    (rf'{OIDS["cbgpPeer2Table"]}.1.1.{ipv4_af_type}.{ebgp_peer_ipv4}', '1', "cbgpPeer2Type (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.2.{ipv4_af_type}.{ebgp_peer_ipv4}', ebgp_peer_ipv4_rmt, "cbgpPeer2RemoteAddr (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.3.{ipv4_af_type}.{ebgp_peer_ipv4}', '6', "cbgpPeer2State (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.4.{ipv4_af_type}.{ebgp_peer_ipv4}', '2', "cbgpPeer2AdminStatus (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.5.{ipv4_af_type}.{ebgp_peer_ipv4}', '4', "cbgpPeer2NegotiatedVersion (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.6.{ipv4_af_type}.{ebgp_peer_ipv4}', ebgp_peer_ipv4_lcl, "cbgpPeer2LocalAddr (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.8.{ipv4_af_type}.{ebgp_peer_ipv4}', '65001', "cbgpPeer2LocalAs (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.9.{ipv4_af_type}.{ebgp_peer_ipv4}', '1.1.1.1', "cbgpPeer2LocalIdentifier (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.11.{ipv4_af_type}.{ebgp_peer_ipv4}', '65002', "cbgpPeer2RemoteAs (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.12.{ipv4_af_type}.{ebgp_peer_ipv4}', '3.3.3.3', "cbgpPeer2RemoteIdentifier (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.17.{ipv4_af_type}.{ebgp_peer_ipv4}', '00 00', "cbgpPeer2LastError (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.18.{ipv4_af_type}.{ebgp_peer_ipv4}', '1', "cbgpPeer2FsmEstablishedTransitions (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.20.{ipv4_af_type}.{ebgp_peer_ipv4}', '30', "cbgpPeer2ConnectRetryInterval (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.21.{ipv4_af_type}.{ebgp_peer_ipv4}', '180', "cbgpPeer2HoldTime (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.22.{ipv4_af_type}.{ebgp_peer_ipv4}', '60', "cbgpPeer2KeepAlive (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.23.{ipv4_af_type}.{ebgp_peer_ipv4}', '180', "cbgpPeer2HoldTimeConfigured (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.24.{ipv4_af_type}.{ebgp_peer_ipv4}', '60', "cbgpPeer2KeepAliveConfigured (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.26.{ipv4_af_type}.{ebgp_peer_ipv4}', '0', "cbgpPeer2MinRouteAdvertisementInterval (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.28.{ipv4_af_type}.{ebgp_peer_ipv4}', '00', "cbgpPeer2LastErrorTxt (EBGP)"),
    (rf'{OIDS["cbgpPeer2Table"]}.1.29.{ipv4_af_type}.{ebgp_peer_ipv4}', '5', "cbgpPeer2PrevState (EBGP)"),
]
cbgpPeer2TableOIDs.extend(ebgp_peer2_entries)
cbgpPeer2TableOIDs_v4.extend(ebgp_peer2_entries)

ebgp_peer2_af_entries = [
    (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.1.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilyAfi (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.2.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '1', "cbgpPeer2AddrFamilySafi (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyTable"]}.1.3.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', 'IPv4 Unicast'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer2AddrFamilyName (EBGP)"),
]
cbgpPeer2AddrFamilyTableOIDs.extend(ebgp_peer2_af_entries)
cbgpPeer2AddrFamilyTableOIDs_v4.extend(ebgp_peer2_af_entries)

cbgpPeer2AddrFamilyPrefixTableOIDs.extend([
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', ebgp_accepted, "cbgpPeer2AcceptedPrefixes (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', ebgp_denied, "cbgpPeer2DeniedPrefixes (EBGP) - includes AS-loop"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.3.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '10', "cbgpPeer2PrefixAdminLimit (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.4.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixThreshold (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.5.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '75', "cbgpPeer2PrefixClearThreshold (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.7.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2SuppressedPrefixes (EBGP)"),
    (rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.8.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}', '0', "cbgpPeer2WithdrawnPrefixes (EBGP)"),
])

ebgp_peer3_entries = [
    (rf'{OIDS["cbgpPeer3Table"]}.1.2.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '1', "cbgpPeer3Type (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.3.0.{ipv4_af_type}.{ebgp_peer_ipv4}', ebgp_peer_ipv4_rmt, "cbgpPeer3RemoteAddr (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.4.0.{ipv4_af_type}.{ebgp_peer_ipv4}', 'VRF default'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.5.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '6', "cbgpPeer3State (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.6.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '2', "cbgpPeer3AdminStatus (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.7.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '4', "cbgpPeer3NegotiatedVersion (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.8.0.{ipv4_af_type}.{ebgp_peer_ipv4}', ebgp_peer_ipv4_lcl, "cbgpPeer3LocalAddr (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.10.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '65001', "cbgpPeer3LocalAs (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.11.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '1.1.1.1', "cbgpPeer3LocalIdentifier (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.13.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '65002', "cbgpPeer3RemoteAs (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.14.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '3.3.3.3', "cbgpPeer3RemoteIdentifier (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.19.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '00 00', "cbgpPeer3LastError (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.20.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '1', "cbgpPeer3FsmEstablishedTransitions (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.22.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '30', "cbgpPeer3ConnectRetryInterval (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.23.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '180', "cbgpPeer3HoldTime (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.24.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '60', "cbgpPeer3KeepAlive (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.25.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '180', "cbgpPeer3HoldTimeConfigured (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.26.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '60', "cbgpPeer3KeepAliveConfigured (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.28.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '0', "cbgpPeer3MinRouteAdvertisementInterval (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.30.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '00', "cbgpPeer3LastErrorTxt (EBGP)"),
    (rf'{OIDS["cbgpPeer3Table"]}.1.31.0.{ipv4_af_type}.{ebgp_peer_ipv4}', '5', "cbgpPeer3PrevState (EBGP)"),
]
cbgpPeer3TableOIDs.extend(ebgp_peer3_entries)
cbgpPeer3TableOIDs_v4.extend(ebgp_peer3_entries)

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

def log_headline(section, message):
    logger.info(f"=== [{section}] {message} ===")

def build_topo(tgen):
    "Builds the topology."
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    # r1-r2 links: eth0-eth2 for default VRF, eth3-eth5 for RED VRF
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth0
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth1
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth2
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth3 (RED VRF)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth4 (RED VRF)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])  # eth5 (RED VRF)
    # r1-r3 link: EBGP peer for AS-path loop filtering test
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"])  # r1-eth6, r3-eth0

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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M snmp",
        )
        snmpd_conf = os.path.join(CWD, "{}/snmpd.conf".format(rname))
        if os.path.exists(snmpd_conf):
            router.load_config(
                TopoRouter.RD_SNMP,
                snmpd_conf,
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

    test_func = functools.partial(bgp_converge_summary, r1)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"

    vrf_peers_ipv4 = ["10.10.3.2", "10.10.4.2", "10.10.5.2"]
    vrf_peers_ipv4_lcl = ["0A 0A 03 01", "0A 0A 04 01", "0A 0A 05 01"]
    vrf_peers_ipv4_rmt = ["0A 0A 03 02", "0A 0A 04 02", "0A 0A 05 02"]

    vrf_id = get_vrf_id(r1, "RED")

    for peer_ipv4, peer_ipv4_lcl, peer_ipv4_rmt in zip(vrf_peers_ipv4, vrf_peers_ipv4_lcl, vrf_peers_ipv4_rmt):
    
        cbgpPeer3TableOIDs.extend([
            # --- IPv4 Peer (10.10.10.2) Checks ---
            (rf'{OIDS["cbgpPeer3Table"]}.1.2.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '1', "cbgpPeer3Type"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.3.{vrf_id}.{ipv4_af_type}.{peer_ipv4}',  peer_ipv4_rmt, "cbgpPeer3RemoteAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.4.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', 'VRF RED'.encode('utf-8').hex(' ').upper() + ' 00', "cbgpPeer3VrfName"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.5.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '6', "cbgpPeer3State"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.6.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '2', "cbgpPeer3AdminStatus"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.7.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3NegotiatedVersion"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.8.{vrf_id}.{ipv4_af_type}.{peer_ipv4}',  peer_ipv4_lcl, "cbgpPeer3LocalAddr"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.10.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3LocalAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.11.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '10.10.3.1', "cbgpPeer3LocalIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.13.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '65001', "cbgpPeer3RemoteAs"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.14.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '10.10.3.2', "cbgpPeer3RemoteIdentifier"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.15.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3InUpdates"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.16.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '4', "cbgpPeer3OutUpdates"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.19.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '00 00', "cbgpPeer3LastError"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.22.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '30', "cbgpPeer3ConnectRetryInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.23.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTime"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.24.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAlive"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.25.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '180', "cbgpPeer3HoldTimeConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.26.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '60', "cbgpPeer3KeepAliveConfigured"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.28.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '0', "cbgpPeer3MinRouteAdvertisementInterval"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.30.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '00', "cbgpPeer3LastErrorTxt"),
            (rf'{OIDS["cbgpPeer3Table"]}.1.31.{vrf_id}.{ipv4_af_type}.{peer_ipv4}', '5', "cbgpPeer3PrevState"),
        ])

    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    def _check_snmp_walk_no_errors(table_oid, table_name):
        """Check that snmpwalk completes without OID ordering errors."""
        cmd = f"snmpwalk -v2c -c public -Ln -On localhost {table_oid}"
        result = r1.cmd(cmd)
        
        if "OID not increasing" in result or "Error:" in result:
            logger.error(f"SNMP walk error for {table_name}:")
            logger.error(result)
            return False
        
        return True

    def _check_snmp_get_oids(snmp_inst, checks):
        """Check OIDs via snmpget for scalar and non-walkable OIDs."""
        for oid, expected_value, description in checks:
            value = snmp_inst.get(oid)
            if expected_value is None:
                if value is not None:
                    logger.error(f"SNMP GET FAIL: {description} - OID {oid} should be absent but was found: {value}")
                    return False
                logger.info(f"SNMP GET PASS: {description}, {oid} (absent)")
            else:
                if value is None:
                    logger.error(f"SNMP GET FAIL: {description} - OID {oid} not found")
                    return False
                if str(value) != str(expected_value):
                    logger.error(f"SNMP GET FAIL: {description} - OID {oid}: expected '{expected_value}', got '{value}'")
                    return False
                logger.info(f"SNMP GET PASS: {description}, {oid}, {expected_value}")
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

    # 1. Test cbgpGlobal scalars
    def _snmp_check_cbgpGlobal():
        if not _check_snmp_get_oids(snmp, cbgpGlobalOIDs):
            return False
        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpGlobal, True, count=2, wait=5)
    assert result, "SNMP checks for cbgpGlobal scalars failed"

    # 2. Test cbgpPeerCapsTable
    def _snmp_check_cbgpPeerCapsTable():
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeerCapsTable"], "cbgpPeerCapsTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeerCapsTable"])
        if not output:
            logger.error("cbgpPeerCapsTable: No entries found in SNMP walk")
            return False
        logger.info(f"cbgpPeerCapsTable: Found {len(output)} OIDs in walk")
        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeerCapsTable, True, count=2, wait=5)
    assert result, "SNMP checks for cbgpPeerCapsTable failed"

    # 3. Test cbgpPeer2CapsTable
    def _snmp_check_cbgpPeer2CapsTable():
        if not _check_snmp_walk_no_errors(OIDS["cbgpPeer2CapsTable"], "cbgpPeer2CapsTable"):
            return False
        output, _ = snmp.walk(OIDS["cbgpPeer2CapsTable"])
        if not output:
            logger.error("cbgpPeer2CapsTable: No entries found in SNMP walk")
            return False
        logger.info(f"cbgpPeer2CapsTable: Found {len(output)} OIDs in walk")
        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2CapsTable, True, count=2, wait=5)
    assert result, "SNMP checks for cbgpPeer2CapsTable failed"

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

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeerTable, True, count=2, wait=5)
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

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table, True, count=2, wait=5)
    assert result, "SNMP checks for cbgpPeer2Table failed"

    # 6. Test VRF Peer Table
    def _snmp_check_vrf_peer():

        output, _ = snmp.walk(OIDS["cbgpPeer3Table"])

        if not _check_oids(output, cbgpPeer3TableOIDs): return False
        return True

    _, result = topotest.run_and_expect(_snmp_check_vrf_peer, True, count=2, wait=5)
    assert result, "SNMP checks for VRF peer failed"

    # 7. Test cbgpRouteTable - BGP Route Table
    def _snmp_check_cbgpRouteTable():
        """Test cbgpRouteTable for IPv4 and IPv6 unicast routes."""
        
        # Check for OID ordering errors first
        if not _check_snmp_walk_no_errors(OIDS["cbgpRouteTable"], "cbgpRouteTable"):
            return False
        
        # Walk the cbgpRouteTable
        output, _ = snmp.walk(OIDS["cbgpRouteTable"])
        
        if not output:
            logger.error("cbgpRouteTable: No routes found in SNMP walk")
            return False
        
        logger.info(f"cbgpRouteTable: Found {len(output)} OIDs in walk")
        
        # Check expected routes
        if not _check_oids(output, cbgpRouteTableOIDs):
            return False
        
        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpRouteTable, True, count=3, wait=5)
    assert result, "SNMP checks for cbgpRouteTable failed"

def test_cisco_mib_wrong_type():
    """Walk the entire CISCO-BGP4-MIB and fail if any OID has 'Wrong Type'.

    When the Cisco MIB is loaded, snmpwalk validates the ASN type returned by
    the agent against the SYNTAX declared in the MIB.  Any mismatch is flagged
    as 'Wrong Type (should be ...)'.  This test walks every table in the MIB
    and asserts that zero Wrong Type errors are present.

    The test fails if the Cisco MIB files are not installed.
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    mib_dir = "/usr/share/snmp/mibs/cisco"
    mib_name = "CISCO-BGP4-MIB"

    probe = r1.cmd(
        f"snmptranslate -M +{mib_dir} -m +{mib_name} "
        f"{mib_name}::cbgpPeer2LocalIdentifier 2>&1"
    ).strip()
    assert "cbgpPeer2LocalIdentifier" in probe, (
        f"{mib_name} is not installed at {mib_dir}. "
        f"Place CISCO-BGP4-MIB.my and CISCO-SMI.my in {mib_dir}."
    )
    logger.info(f"Cisco MIB precheck passed: {probe}")

    test_func = functools.partial(bgp_converge_summary, r1)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"

    # Walk the entire CISCO-BGP4-MIB enterprise subtree
    cisco_bgp4_oid = "1.3.6.1.4.1.9.9.187"
    cmd = (
        f"snmpwalk -v2c -c public -M +{mib_dir} -m +{mib_name} "
        f"localhost {cisco_bgp4_oid}"
    )
    out = r1.cmd(cmd)

    wrong_type_lines = [l for l in out.strip().splitlines() if "Wrong Type" in l]

    # Group by OID column name for readable output
    wrong_type_by_oid = {}
    for line in wrong_type_lines:
        oid_name = line.split("::")[1].split(".")[0] if "::" in line else line.split("=")[0].strip()
        wrong_type_by_oid.setdefault(oid_name, []).append(line)

    for oid_name, lines in wrong_type_by_oid.items():
        logger.error(f"FAIL: {oid_name} — {len(lines)} instance(s) with Wrong Type")
        for line in lines:
            logger.error(f"  {line.strip()}")

    total_oids = len(out.strip().splitlines())
    logger.info(
        f"Walked {total_oids} OIDs under {mib_name}, "
        f"found {len(wrong_type_lines)} Wrong Type error(s) "
        f"across {len(wrong_type_by_oid)} OID column(s)"
    )

    assert not wrong_type_lines, (
        f"SNMP agent returned Wrong Type for {len(wrong_type_lines)} OID(s) "
        f"across {len(wrong_type_by_oid)} column(s): "
        + ", ".join(f"{name} ({len(lines)})" for name, lines in wrong_type_by_oid.items())
    )

def test_cisco_bgp4_mib_get():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    test_func = functools.partial(bgp_converge_summary, r1)
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


    # 0. Test cbgpGlobal scalars using snmp.get
    def _snmp_check_cbgpGlobal_get():
        if not _check_oids_get(cbgpGlobalOIDs): return False
        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpGlobal_get, True, count=2, wait=5)
    assert result, "SNMP GET checks for cbgpGlobal scalars failed"

    # 1. Test cbgpPeerTable using snmp.get
    def _snmp_check_cbgpPeerTable_get():
        if not _check_oids_get(cbgpPeerTableOIDs): return False

        if not _check_oids_get(cbgpPeerAddrFamilyTableOIDs): return False

        if not _check_oids_get(cbgpPeerAddrFamilyPrefixTableOIDs): return False

        return True

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeerTable_get, True, count=2, wait=5)
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

    _, result = topotest.run_and_expect(_snmp_check_cbgpPeer2Table_get, True, count=2, wait=5)
    assert result, "SNMP GET checks for cbgpPeer2Table failed"


    # 3. Test VRF Peer Table using snmp.get
    def _snmp_check_vrf_peer_get():
        if not _check_oids_get(cbgpPeer3TableOIDs): return False
        return True

    _, result = topotest.run_and_expect(_snmp_check_vrf_peer_get, True, count=2, wait=5)
    assert result, "SNMP GET checks for VRF peer failed"


def test_snmp_cli_cross_validation():
    """
    Cross-validate SNMP counter values against CLI show command outputs.

    For each BGP peer, queries both SNMP (cbgpPeer2 tables) and CLI
    (show bgp neighbors json) and verifies the values match:
      - cbgpPeer2State vs bgpState
      - cbgpPeer2RemoteAs vs remoteAs
      - cbgpPeer2AcceptedPrefixes vs acceptedPrefixCounter
      - cbgpPeer2AdvertisedPrefixes vs sentPrefixCounter
      - cbgpPeer2AcceptedPrefixes + cbgpPeer2DeniedPrefixes vs totalPrefixCounter
        (for peers with soft-reconfiguration inbound, validating the pfiltered fix)
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    log_headline("4.", "SNMP vs CLI cross-validation suite")
    test_func = functools.partial(bgp_converge_summary, r1)
    log_headline("4.1", "Waiting for all BGP sessions to establish")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"

    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    # BGP state name to SNMP numeric mapping (RFC 4273 / CISCO-BGP4-MIB)
    bgp_state_map = {
        "Idle": "1",
        "Connect": "2",
        "Active": "3",
        "OpenSent": "4",
        "OpenConfirm": "5",
        "Established": "6",
    }

    # Define all default-VRF peers with their CLI address, SNMP indexing,
    # address families, and whether soft-reconfiguration is enabled.
    cross_check_peers = [
        {
            "cli_addr": "10.10.0.2",
            "snmp_af_type": ipv4_af_type,
            "snmp_peer_addr": "10.10.0.2",
            "afis": [("ipv4Unicast", ipv4_unicast_af_idx)],
            "soft_reconfig": True,
        },
        {
            "cli_addr": "10.10.1.2",
            "snmp_af_type": ipv4_af_type,
            "snmp_peer_addr": "10.10.1.2",
            "afis": [("ipv4Unicast", ipv4_unicast_af_idx)],
            "soft_reconfig": False,
        },
        {
            "cli_addr": "10.10.2.2",
            "snmp_af_type": ipv4_af_type,
            "snmp_peer_addr": "10.10.2.2",
            "afis": [("ipv4Unicast", ipv4_unicast_af_idx)],
            "soft_reconfig": False,
        },
        {
            "cli_addr": "fd00::2",
            "snmp_af_type": ipv6_af_type,
            "snmp_peer_addr": peers_ipv6[0],
            "afis": [
                ("ipv4Unicast", ipv4_unicast_af_idx),
                ("ipv6Unicast", ipv6_unicast_af_idx),
            ],
            "soft_reconfig": False,
        },
        {
            "cli_addr": "fd00:1::2",
            "snmp_af_type": ipv6_af_type,
            "snmp_peer_addr": peers_ipv6[1],
            "afis": [
                ("ipv4Unicast", ipv4_unicast_af_idx),
                ("ipv6Unicast", ipv6_unicast_af_idx),
            ],
            "soft_reconfig": False,
        },
        {
            "cli_addr": "fd00:2::2",
            "snmp_af_type": ipv6_af_type,
            "snmp_peer_addr": peers_ipv6[2],
            "afis": [
                ("ipv4Unicast", ipv4_unicast_af_idx),
                ("ipv6Unicast", ipv6_unicast_af_idx),
            ],
            "soft_reconfig": False,
        },
        {
            "cli_addr": "10.10.6.2",
            "snmp_af_type": ipv4_af_type,
            "snmp_peer_addr": ebgp_peer_ipv4,
            "afis": [("ipv4Unicast", ipv4_unicast_af_idx)],
            "soft_reconfig": True,
        },
    ]

    def _cross_validate_peer_state_and_as():
        """Cross-check BGP state and remote AS for all peers."""
        for peer in cross_check_peers:
            cli_addr = peer["cli_addr"]
            af_type = peer["snmp_af_type"]
            snmp_addr = peer["snmp_peer_addr"]

            try:
                cli_output = json.loads(
                    r1.vtysh_cmd(f"show bgp neighbors {cli_addr} json")
                )
                peer_data = cli_output.get(cli_addr, {})
            except Exception as e:
                logger.error(f"[{cli_addr}] Failed to get CLI data: {e}")
                return False

            # Cross-check 1: BGP State
            cli_state = peer_data.get("bgpState", "Unknown")
            expected_snmp_state = bgp_state_map.get(cli_state)
            snmp_state = snmp.get(
                f'{OIDS["cbgpPeer2Table"]}.1.3.{af_type}.{snmp_addr}'
            )
            if expected_snmp_state and str(snmp_state) != expected_snmp_state:
                logger.error(
                    f"[{cli_addr}] State mismatch: "
                    f"CLI={cli_state} (SNMP expected={expected_snmp_state}), "
                    f"SNMP actual={snmp_state}"
                )
                return False
            logger.info(
                f"[{cli_addr}] State cross-check PASS: "
                f"CLI={cli_state}, SNMP={snmp_state}"
            )

            # Cross-check 2: Remote AS
            cli_remote_as = str(peer_data.get("remoteAs", ""))
            snmp_remote_as = str(
                snmp.get(
                    f'{OIDS["cbgpPeer2Table"]}.1.11.{af_type}.{snmp_addr}'
                )
            )
            if cli_remote_as != snmp_remote_as:
                logger.error(
                    f"[{cli_addr}] Remote AS mismatch: "
                    f"CLI={cli_remote_as}, SNMP={snmp_remote_as}"
                )
                return False
            logger.info(
                f"[{cli_addr}] Remote AS cross-check PASS: "
                f"CLI={cli_remote_as}, SNMP={snmp_remote_as}"
            )

        return True

    log_headline("4.2", "Cross-checking BGP state and remote AS")
    _, result = topotest.run_and_expect(
        _cross_validate_peer_state_and_as, True, count=10, wait=2
    )
    assert result, "SNMP vs CLI cross-check failed for BGP state or remote AS"

    def _cross_validate_prefix_counters():
        """Cross-check accepted and advertised prefix counters for all peers."""
        for peer in cross_check_peers:
            cli_addr = peer["cli_addr"]
            af_type = peer["snmp_af_type"]
            snmp_addr = peer["snmp_peer_addr"]

            try:
                cli_output = json.loads(
                    r1.vtysh_cmd(f"show bgp neighbors {cli_addr} json")
                )
                peer_data = cli_output.get(cli_addr, {})
            except Exception as e:
                logger.error(f"[{cli_addr}] Failed to get CLI data: {e}")
                return False

            for afi_name, afi_safi_idx in peer["afis"]:
                af_info = (
                    peer_data
                    .get("addressFamilyInfo", {})
                    .get(afi_name, {})
                )
                label = f"{cli_addr}/{afi_name}"

                # Cross-check 3: AcceptedPrefixes
                # CLI: acceptedPrefixCounter = peer->pcount[afi][safi]
                # SNMP: cbgpPeer2AcceptedPrefixes = peer->pcount[afi][safi]
                cli_accepted = af_info.get("acceptedPrefixCounter")
                snmp_accepted = snmp.get(
                    f'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1'
                    f'.{af_type}.{snmp_addr}.{afi_safi_idx}'
                )
                if cli_accepted is not None and str(cli_accepted) != str(snmp_accepted):
                    logger.error(
                        f"[{label}] AcceptedPrefixes mismatch: "
                        f"CLI={cli_accepted}, SNMP={snmp_accepted}"
                    )
                    return False
                logger.info(
                    f"[{label}] AcceptedPrefixes cross-check PASS: "
                    f"CLI={cli_accepted}, SNMP={snmp_accepted}"
                )

                # Cross-check 4: AdvertisedPrefixes
                # CLI: sentPrefixCounter = PAF_SUBGRP(paf)->scount
                # SNMP: cbgpPeer2AdvertisedPrefixes = PAF_SUBGRP(paf)->scount
                cli_sent = af_info.get("sentPrefixCounter")
                snmp_advertised = snmp.get(
                    f'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.6'
                    f'.{af_type}.{snmp_addr}.{afi_safi_idx}'
                )
                if cli_sent is not None and str(cli_sent) != str(snmp_advertised):
                    logger.error(
                        f"[{label}] AdvertisedPrefixes mismatch: "
                        f"CLI={cli_sent}, SNMP={snmp_advertised}"
                    )
                    return False
                logger.info(
                    f"[{label}] AdvertisedPrefixes cross-check PASS: "
                    f"CLI={cli_sent}, SNMP={snmp_advertised}"
                )

        return True

    log_headline("4.3", "Cross-checking accepted and advertised prefix counters")
    _, result = topotest.run_and_expect(
        _cross_validate_prefix_counters, True, count=10, wait=2
    )
    assert result, "SNMP vs CLI cross-check failed for prefix counters"

    def _cross_validate_adj_rib_in_totals():
        """
        For peers with soft-reconfiguration inbound, verify that:
            SNMP(accepted + denied) == CLI(totalPrefixCounter)

        This validates the pfiltered fix: after centralizing pfiltered
        at the filtered: label, pcount + pfiltered should equal the
        total number of entries in adj-rib-in.

        CLI source: show bgp <afi> neighbors <peer> received-routes json
                    -> totalPrefixCounter (walks adj_in at display time)
        SNMP source: cbgpPeer2AcceptedPrefixes + cbgpPeer2DeniedPrefixes
                    = peer->pcount + peer->pfiltered (maintained incrementally)
        """
        soft_reconfig_peers = [
            p for p in cross_check_peers if p["soft_reconfig"]
        ]

        for peer in soft_reconfig_peers:
            cli_addr = peer["cli_addr"]
            af_type = peer["snmp_af_type"]
            snmp_addr = peer["snmp_peer_addr"]

            for afi_name, afi_safi_idx in peer["afis"]:
                label = f"{cli_addr}/{afi_name}"
                # Map CLI AFI name to the show command AFI keyword
                if afi_name == "ipv4Unicast":
                    afi_keyword = "ipv4 unicast"
                elif afi_name == "ipv6Unicast":
                    afi_keyword = "ipv6 unicast"
                else:
                    continue

                try:
                    cli_output = json.loads(
                        r1.vtysh_cmd(
                            f"show bgp {afi_keyword} neighbors "
                            f"{cli_addr} received-routes json"
                        )
                    )
                    cli_total = cli_output.get("totalPrefixCounter", -1)
                except Exception as e:
                    logger.error(
                        f"[{label}] Failed to get received-routes: {e}"
                    )
                    return False

                snmp_accepted_val = snmp.get(
                    f'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1'
                    f'.{af_type}.{snmp_addr}.{afi_safi_idx}'
                )
                snmp_denied_val = snmp.get(
                    f'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2'
                    f'.{af_type}.{snmp_addr}.{afi_safi_idx}'
                )

                try:
                    snmp_total = int(snmp_accepted_val) + int(snmp_denied_val)
                except (ValueError, TypeError):
                    logger.error(
                        f"[{label}] Could not parse SNMP values: "
                        f"accepted={snmp_accepted_val}, denied={snmp_denied_val}"
                    )
                    return False

                if cli_total != snmp_total:
                    logger.error(
                        f"[{label}] Adj-RIB-In total mismatch: "
                        f"CLI totalPrefixCounter={cli_total}, "
                        f"SNMP (accepted+denied)={snmp_total} "
                        f"(accepted={snmp_accepted_val}, denied={snmp_denied_val}). "
                        f"If SNMP < CLI, pfiltered is under-counting."
                    )
                    return False
                logger.info(
                    f"[{label}] Adj-RIB-In total cross-check PASS: "
                    f"CLI={cli_total}, SNMP={snmp_total} "
                    f"(accepted={snmp_accepted_val}+denied={snmp_denied_val})"
                )

        return True

    log_headline(
        "4.4",
        "Cross-checking SNMP(accepted+denied) vs CLI totalPrefixCounter "
        "(soft-reconfig peers)"
    )
    _, result = topotest.run_and_expect(
        _cross_validate_adj_rib_in_totals, True, count=10, wait=2
    )
    assert result, (
        "SNMP(accepted+denied) != CLI(totalPrefixCounter) for a "
        "soft-reconfiguration peer. This indicates pfiltered is "
        "under-counting denied prefixes."
    )

    log_headline("4.5", "SNMP vs CLI cross-validation PASSED")


def test_pfiltered_counts_all_deny_reasons():
    """
    Verify that cbgpPeer2DeniedPrefixes (pfiltered) counts ALL deny paths,
    not just route-map and input-filter denials.

    Topology:
      r3 (AS 65002) → r1 (AS 65001), EBGP

    r3 sends 4 IPv4 routes to r1:
      - 192.168.1.0/24: normal (AS path "65002") → accepted
      - 192.168.2.0/24: normal (AS path "65002") → denied by route-map FILTER_EBGP_IN
      - 192.168.3.0/24: AS-loop (AS path "65002 65001") → denied by AS-path loop check
      - 192.168.4.0/24: AS-loop (AS path "65002 65001") → denied by AS-path loop check

    Expected SNMP counters for peer 10.10.6.2:
      cbgpPeer2AcceptedPrefixes = 1
      cbgpPeer2DeniedPrefixes = 3  (1 route-map + 2 AS-loop)

    Before the pfiltered fix, denied would be 1 (only route-map counted).
    After the fix, denied is 3 (all deny paths counted).
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    log_headline("5.", "pfiltered counts all deny reasons (AS-loop + route-map)")

    # Wait for BGP convergence
    test_func = functools.partial(bgp_converge_summary, r1)
    log_headline("5.1", "Waiting for all BGP sessions to establish (including EBGP r3)")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see all BGP sessions established on r1"

    snmp = SnmpTester(r1, "localhost", "public", "2c", "-Ln -On")

    # Verify via CLI that r3 peer shows expected route counts.
    # Note: CLI filteredPrefixCounter only counts policy denials (route-map/filter),
    # NOT AS-path loop denials. The SNMP pfiltered counter (with our fix) counts all.
    def _verify_ebgp_cli_counters():
        """Cross-check adj-rib-in population via CLI received-routes."""
        try:
            output = json.loads(
                r1.vtysh_cmd("show bgp ipv4 unicast neighbors 10.10.6.2 received-routes json")
            )
            total = output.get("totalPrefixCounter", -1)
            filtered = output.get("filteredPrefixCounter", -1)
            logger.info(
                f"CLI received-routes for 10.10.6.2: total={total}, filtered={filtered}"
            )
            # totalPrefixCounter = 4 (all routes in adj-rib-in via soft-reconfig)
            if total != 4:
                logger.error(f"Expected totalPrefixCounter=4, got {total}")
                return False
            # filteredPrefixCounter = 1 (only route-map denial; CLI re-applies
            # bgp_input_filter + bgp_input_modifier but NOT AS-loop check)
            if filtered != 1:
                logger.error(f"Expected filteredPrefixCounter=1, got {filtered}")
                return False
            return True
        except Exception as e:
            logger.error(f"CLI check failed: {e}")
            return False

    log_headline("5.2", "Verifying CLI route counters for EBGP peer")
    _, result = topotest.run_and_expect(_verify_ebgp_cli_counters, True, count=15, wait=2)
    assert result, "CLI counters for EBGP peer did not match expected values"

    # Also verify accepted count via show bgp neighbors json
    def _verify_ebgp_accepted():
        """Check acceptedPrefixCounter matches expected value."""
        try:
            output = json.loads(r1.vtysh_cmd("show bgp neighbors 10.10.6.2 json"))
            peer_info = output.get("10.10.6.2", {})
            af_info = peer_info.get("addressFamilyInfo", {}).get("ipv4Unicast", {})
            accepted = af_info.get("acceptedPrefixCounter", -1)
            logger.info(f"CLI acceptedPrefixCounter for 10.10.6.2: {accepted}")
            if accepted != 1:
                logger.error(f"Expected acceptedPrefixCounter=1, got {accepted}")
                return False
            return True
        except Exception as e:
            logger.error(f"CLI accepted check failed: {e}")
            return False

    log_headline("5.2b", "Verifying CLI acceptedPrefixCounter for EBGP peer")
    _, result = topotest.run_and_expect(_verify_ebgp_accepted, True, count=15, wait=2)
    assert result, "CLI acceptedPrefixCounter for EBGP peer did not match"

    # Now check SNMP counters
    accepted_oid = rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.1.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}'
    denied_oid = rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.{ebgp_peer_ipv4}.{ipv4_unicast_af_idx}'

    def _verify_ebgp_snmp_pfiltered():
        """Check SNMP cbgpPeer2DeniedPrefixes includes AS-loop denials."""
        accepted = snmp.get(accepted_oid)
        denied = snmp.get(denied_oid)
        logger.info(
            f"SNMP counters for 10.10.6.2: accepted={accepted}, denied={denied}"
        )
        if str(accepted) != '1':
            logger.error(f"cbgpPeer2AcceptedPrefixes: expected 1, got {accepted}")
            return False
        if str(denied) != '3':
            logger.error(
                f"cbgpPeer2DeniedPrefixes: expected 3 (1 route-map + 2 AS-loop), got {denied}. "
                "If denied=1, the pfiltered fix is missing."
            )
            return False
        return True

    log_headline("5.3", "Verifying SNMP pfiltered counter includes AS-loop denials")
    _, result = topotest.run_and_expect(_verify_ebgp_snmp_pfiltered, True, count=10, wait=2)
    assert result, (
        "cbgpPeer2DeniedPrefixes did not count AS-path loop denials. "
        "Expected denied=3 (1 route-map + 2 AS-loop), check pfiltered fix in bgp_route.c"
    )

    # Also verify the existing IBGP peer with route-map-only filtering still works
    ibgp_denied_oid = rf'{OIDS["cbgpPeer2AddrFamilyPrefixTable"]}.1.2.{ipv4_af_type}.10.10.0.2.{ipv4_unicast_af_idx}'

    def _verify_ibgp_snmp_pfiltered():
        """Confirm IBGP peer (10.10.0.2) still shows correct route-map-only denial count."""
        denied = snmp.get(ibgp_denied_oid)
        logger.info(f"SNMP denied for IBGP peer 10.10.0.2: {denied}")
        if str(denied) != '2':
            logger.error(f"cbgpPeer2DeniedPrefixes for 10.10.0.2: expected 2, got {denied}")
            return False
        return True

    log_headline("5.4", "Verifying IBGP peer route-map-only denied count unchanged")
    _, result = topotest.run_and_expect(_verify_ibgp_snmp_pfiltered, True, count=5, wait=2)
    assert result, "IBGP peer denied count changed unexpectedly"

    log_headline("5.5", "pfiltered test PASSED - all deny paths correctly counted")


def test_cbgp4_traps():
    """
    Verify CISCO-BGP4-MIB trap notifications by cycling BGP peer sessions
    and capturing traps via snmptrapd.

    IPv4 peer (10.10.0.2) tests both legacy and Peer2 notifications:
      Backward: cbgpFsmStateChange(1), cbgpBackwardTransition(2),
                cbgpPeer2BackwardTransNotification(6),
                cbgpPeer2FsmStateChange(7), cbgpPeer2BackwardTransition(8)
      Established: cbgpPeer2EstablishedNotification(5)

    IPv6 peer (fd00::2) tests Peer2 notifications only (legacy is IPv4-only):
      Backward: cbgpPeer2BackwardTransNotification(6),
                cbgpPeer2FsmStateChange(7), cbgpPeer2BackwardTransition(8)
      Established: cbgpPeer2EstablishedNotification(5)
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    log_headline("TRAP", "CBGP4 MIB SNMP Trap Tests")

    if os.system("which snmptrapd") != 0:
        pytest.skip("snmptrapd not installed - skipping trap tests")

    test_func = functools.partial(bgp_converge_summary, r1)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "BGP not converged before trap test"

    trap_log = "/tmp/cbgp4_traps.log"

    def _has_trap(log_text, trap_num):
        """Check if a specific CBGP4 notification OID is in the trap log.

        Notification OIDs are .1.3.6.1.4.1.9.9.187.0.<trap_num>.
        Uses negative lookahead to prevent e.g. trap 1 matching trap 10.
        """
        pattern = r'\.1\.3\.6\.1\.4\.1\.9\.9\.187\.0\.{}(?!\d)'.format(trap_num)
        return bool(re.search(pattern, log_text))

    def _start_trapd():
        r1.run("rm -f {}".format(trap_log))
        r1.run(
            "snmptrapd -Lf {} -On "
            "--disableAuthorization=yes "
            "udp:162 &".format(trap_log)
        )
        sleep(2)

    def _stop_trapd():
        r1.run("pkill -f snmptrapd 2>/dev/null; true")
        sleep(1)

    def _read_trap_log():
        return r1.run("cat {} 2>/dev/null".format(trap_log))

    _start_trapd()

    try:
        # ================================================================
        # Phase 1: IPv4 backward transition
        # Shut down peer on r2 side to trigger traps on r1.
        # r2 sends CEASE/AdminShutdown NOTIFICATION; r1 transitions
        # from Established to Idle, firing backward transition hooks.
        # ================================================================
        log_headline("TRAP.1", "IPv4 backward transition - shutting 10.10.0.1 on r2")
        r2.vtysh_cmd(
            """
            configure terminal
            router bgp 65001
            neighbor 10.10.0.1 shutdown
            """
        )

        def _check_ipv4_backward():
            output = _read_trap_log()
            if not output.strip():
                return False
            traps = {
                "cbgpFsmStateChange(1)": _has_trap(output, 1),
                "cbgpBackwardTransition(2)": _has_trap(output, 2),
                "cbgpPeer2BackwardTransNotif(6)": _has_trap(output, 6),
                "cbgpPeer2FsmStateChange(7)": _has_trap(output, 7),
                "cbgpPeer2BackwardTransition(8)": _has_trap(output, 8),
            }
            for name, present in traps.items():
                logger.info(
                    "IPv4 backward: {} = {}".format(
                        name, "FOUND" if present else "missing"
                    )
                )
            return all(traps.values())

        _, result = topotest.run_and_expect(
            _check_ipv4_backward, True, count=20, wait=2
        )
        assert result, "Missing CBGP4 backward transition traps for IPv4 peer"

        trap_output = _read_trap_log()

        # Verify varbinds contain the IPv4 peer address OID component
        assert "10.10.0" in trap_output, \
            "Backward transition trap varbinds missing peer address 10.10.0.x"

        # Verify cbgpPeer2PrevState varbind contains 6 (Established)
        # OID: .1.3.6.1.4.1.9.9.187.1.2.5.1.29.1.10.10.0.2
        prev_state_oid = ".1.3.6.1.4.1.9.9.187.1.2.5.1.29.1.10.10.0.2"
        if prev_state_oid in trap_output:
            assert "INTEGER: 6" in trap_output, \
                "cbgpPeer2PrevState should be 6 (Established) for backward transition"
            logger.info("cbgpPeer2PrevState varbind verified: 6 (Established)")

        # ================================================================
        # Phase 2: IPv4 established notification
        # Bring peer back up; r1 transitions through Connect/OpenSent/
        # OpenConfirm to Established, firing the established hook.
        # ================================================================
        log_headline("TRAP.2", "IPv4 established - unsetting shutdown on r2")
        r2.vtysh_cmd(
            """
            configure terminal
            router bgp 65001
            no neighbor 10.10.0.1 shutdown
            """
        )

        def _check_ipv4_established():
            output = _read_trap_log()
            return _has_trap(output, 5)

        _, result = topotest.run_and_expect(
            _check_ipv4_established, True, count=30, wait=2
        )
        assert result, "Missing cbgpPeer2EstablishedNotification(5) for IPv4 peer"

        # Wait for full re-convergence before IPv6 test
        _, result = topotest.run_and_expect(
            functools.partial(bgp_converge_summary, r1), None, count=30, wait=2
        )
        assert result is None, "BGP did not re-converge after IPv4 trap test"

        # ================================================================
        # Phase 3: IPv6 backward transition
        # Restart snmptrapd with a fresh log to isolate IPv6 traps.
        # Legacy traps (1, 2) must NOT fire for IPv6 peers.
        # ================================================================
        log_headline("TRAP.3", "IPv6 backward transition - shutting fd00::1 on r2")
        _stop_trapd()
        _start_trapd()

        r2.vtysh_cmd(
            """
            configure terminal
            router bgp 65001
            neighbor fd00::1 shutdown
            """
        )

        def _check_ipv6_backward():
            output = _read_trap_log()
            if not output.strip():
                return False
            traps = {
                "cbgpPeer2BackwardTransNotif(6)": _has_trap(output, 6),
                "cbgpPeer2FsmStateChange(7)": _has_trap(output, 7),
                "cbgpPeer2BackwardTransition(8)": _has_trap(output, 8),
            }
            for name, present in traps.items():
                logger.info(
                    "IPv6 backward: {} = {}".format(
                        name, "FOUND" if present else "missing"
                    )
                )
            return all(traps.values())

        _, result = topotest.run_and_expect(
            _check_ipv6_backward, True, count=20, wait=2
        )
        assert result, "Missing CBGP4 backward transition traps for IPv6 peer"

        ipv6_output = _read_trap_log()
        assert not _has_trap(ipv6_output, 2), \
            "Legacy cbgpBackwardTransition(2) must not fire for IPv6 peers"
        logger.info("Confirmed: no legacy backward trap for IPv6 peer")

        # ================================================================
        # Phase 4: IPv6 established notification
        # ================================================================
        log_headline("TRAP.4", "IPv6 established - unsetting shutdown on r2")
        r2.vtysh_cmd(
            """
            configure terminal
            router bgp 65001
            no neighbor fd00::1 shutdown
            """
        )

        def _check_ipv6_established():
            output = _read_trap_log()
            return _has_trap(output, 5)

        _, result = topotest.run_and_expect(
            _check_ipv6_established, True, count=30, wait=2
        )
        assert result, "Missing cbgpPeer2EstablishedNotification(5) for IPv6 peer"

        assert not _has_trap(_read_trap_log(), 1), \
            "Legacy cbgpFsmStateChange(1) must not fire for IPv6 peers"
        logger.info("Confirmed: no legacy FSM state change trap for IPv6 peer")

        # Wait for full re-convergence
        _, result = topotest.run_and_expect(
            functools.partial(bgp_converge_summary, r1), None, count=30, wait=2
        )
        assert result is None, "BGP did not re-converge after IPv6 trap test"

    finally:
        _stop_trapd()

    log_headline("TRAP.5", "All CBGP4 trap tests PASSED")


def test_bgp_snmp_no_peers():
    """Test BGP SNMP behavior when no peers are configured - run after main tests."""
    tgen = get_topogen()
    
    # Use r1 for this test
    r1 = tgen.gears["r1"]
    
    # Remove all BGP neighbors from default VRF
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        no neighbor 10.10.0.2
        no neighbor 10.10.1.2
        no neighbor 10.10.2.2
        no neighbor 10.10.6.2
        no neighbor fd00::2
        no neighbor fd00:1::2
        no neighbor fd00:2::2
        """
    )
    
    # Also remove VRF peers if any
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
    
    _, result = topotest.run_and_expect(_verify_bgp_still_alive, True, count=10, wait=2)
    assert result, "BGP daemon crashed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    log_headline("6.", "Reporting memory leaks")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
