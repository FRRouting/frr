#!/usr/bin/env python3

"""
exa-send.py: Send EVPN Type-2 routes with extended community subtypes via ExaBGP API
"""

from sys import stdout
from time import sleep

# Wait for ExaBGP to be ready
sleep(5)

# EVPN Type-2 Routes (MAC/IP Advertisement)
# Route 9: E-Tree Extended Community - IPv4 EVPN Type-2
# Format: announce route [l2vpn evpn] [2]:[RD]:[ESI]:[Eth Tag]:[MAC]:[IP] label <label> next-hop <nh> origin igp extended-community <comm>
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:55]:[192.168.100.10] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x0605000000000000\n"
)
stdout.flush()

# Route 10: I-SID Extended Community - IPv4 EVPN Type-2
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:56]:[192.168.100.11] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x0607000123000000\n"
)
stdout.flush()

# Route 11: Load Balancing Extended Community (EVPN encoding) - IPv4 EVPN Type-2
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:57]:[192.168.100.12] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x060e000001000064\n"
)
stdout.flush()

# Route 12: E-Tree Extended Community - IPv6 EVPN Type-2
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:66]:[2001:db8:100::10] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x0605000000000000\n"
)
stdout.flush()

# Route 13: I-SID Extended Community - IPv6 EVPN Type-2
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:67]:[2001:db8:100::11] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x0607000123000000\n"
)
stdout.flush()

# Route 14: Load Balancing Extended Community (EVPN encoding) - IPv6 EVPN Type-2
stdout.write(
    "announce route [l2vpn evpn] [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:68]:[2001:db8:100::12] label 10000 next-hop 192.168.1.101 origin igp extended-community 0x060e000001000064\n"
)
stdout.flush()

# Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)

