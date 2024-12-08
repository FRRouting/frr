# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#

# IANA Address Family Identifier
AFI_IP = 1
AFI_IP6 = 2
AFI_L2VPN = 25

# IANA Subsequent Address Family Idenitifier
SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SAFI_MPLS_LABEL = 4
SAFI_EVPN = 70
SAFI_MPLS_VPN = 128
SAFI_IP_FLOWSPEC = 133
SAFI_VPN_FLOWSPEC = 134


<<<<<<< HEAD
#------------------------------------------------------------------------------
=======
# ------------------------------------------------------------------------------
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
class AddressFamily:
    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.afi, self.safi) == (other.afi, other.safi)

    def __str__(self):
<<<<<<< HEAD
        return f'afi: {self.afi}, safi: {self.safi}'
=======
        return f"afi: {self.afi}, safi: {self.safi}"
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)

    def __hash__(self):
        return hash((self.afi, self.safi))


<<<<<<< HEAD
#------------------------------------------------------------------------------
=======
# ------------------------------------------------------------------------------
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
class AF:
    IPv4_UNICAST = AddressFamily(AFI_IP, SAFI_UNICAST)
    IPv6_UNICAST = AddressFamily(AFI_IP6, SAFI_UNICAST)
    IPv4_VPN = AddressFamily(AFI_IP, SAFI_MPLS_VPN)
    IPv6_VPN = AddressFamily(AFI_IP6, SAFI_MPLS_VPN)
    IPv4_MPLS = AddressFamily(AFI_IP, SAFI_MPLS_LABEL)
    IPv6_MPLS = AddressFamily(AFI_IP6, SAFI_MPLS_LABEL)
    IPv4_FLOWSPEC = AddressFamily(AFI_IP, SAFI_IP_FLOWSPEC)
    IPv6_FLOWSPEC = AddressFamily(AFI_IP6, SAFI_IP_FLOWSPEC)
    VPNv4_FLOWSPEC = AddressFamily(AFI_IP, SAFI_VPN_FLOWSPEC)
    VPNv6_FLOWSPEC = AddressFamily(AFI_IP6, SAFI_VPN_FLOWSPEC)
    L2EVPN = AddressFamily(AFI_L2VPN, SAFI_EVPN)
    L2VPN_FLOWSPEC = AddressFamily(AFI_L2VPN, SAFI_VPN_FLOWSPEC)
