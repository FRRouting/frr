# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import ipaddress
import struct

from .af import AddressFamily, AF
from .rd import RouteDistinguisher


def decode_label(label):
    # from frr
    # frr encode just one label
    return (label[0] << 12) | (label[1] << 4) | (label[2] & 0xF0) >> 4


def padding(databin, len_):
    """
    Assumption:
        One nlri per update/withdraw message, so we can add
        a padding to the prefix without worrying about its length
    """
    if len(databin) >= len_:
        return databin
    return databin + b"\0" * (len_ - len(databin))


def dissect_nlri(nlri_data, afi, safi):
    """
    Exract nlri information based on the address family
    """
    addr_family = AddressFamily(afi, safi)
    if addr_family == AF.IPv6_VPN:
        return NlriIPv6Vpn.parse(nlri_data)
    elif addr_family == AF.IPv4_VPN:
        return NlriIPv4Vpn.parse(nlri_data)
    elif addr_family == AF.IPv6_UNICAST:
        return NlriIPv6Unicast.parse(nlri_data)

    return {"ip_prefix": "Unknown"}


# ------------------------------------------------------------------------------
class NlriIPv4Unicast:
    @staticmethod
    def parse(data):
        """parses prefixes from withdrawn_routes or nrli data"""

        if detect_add_path_prefix46(data, 32):
            (addpath_id, prefix_len) = struct.unpack_from("!IB", data)
            addpath_id = {"path_id": addpath_id}
            prefix = padding(data[5:], 4)
        else:
            (prefix_len,) = struct.unpack_from("!B", data)
            addpath_id = {}
            prefix = padding(data[1:], 4)

        return {
            "ip_prefix": f"{ipaddress.IPv4Address(prefix)}/{prefix_len}",
            **addpath_id,
        }


# ------------------------------------------------------------------------------

"""
From Scapy: https://github.com/secdev/scapy/blob/master/scapy/contrib/bgp.py
"""


def detect_add_path_prefix46(s, max_bit_length):
    """
    Detect IPv4/IPv6 prefixes conform to BGP Additional Path but NOT conform
    to standard BGP..

    This is an adapted version of wireshark's detect_add_path_prefix46
    https://github.com/wireshark/wireshark/blob/ed9e958a2ed506220fdab320738f1f96a3c2ffbb/epan/dissectors/packet-bgp.c#L2905
    Kudos to them !
    """

    def orb(x):
        # type: (Union[int, str, bytes]) -> int
        """Return ord(x) when not already an int."""
        if isinstance(x, int):
            return x
        return ord(x)

    # Must be compatible with BGP Additional Path
    i = 0
    while i + 4 < len(s):
        i += 4
        prefix_len = orb(s[i])
        if prefix_len > max_bit_length:
            return False
        addr_len = (prefix_len + 7) // 8
        i += 1 + addr_len
        if i > len(s):
            return False
        if prefix_len % 8:
            if orb(s[i - 1]) & (0xFF >> (prefix_len % 8)):
                return False
    # Must NOT be compatible with standard BGP
    i = 0
    while i + 4 < len(s):
        prefix_len = orb(s[i])
        if prefix_len == 0 and len(s) > 1:
            return True
        if prefix_len > max_bit_length:
            return True
        addr_len = (prefix_len + 7) // 8
        i += 1 + addr_len
        if i > len(s):
            return True
        if prefix_len % 8:
            if orb(s[i - 1]) & (0xFF >> (prefix_len % 8)):
                return True
    return False


class NlriIPv6Unicast:
    @staticmethod
    def parse(data):
        """parses prefixes from withdrawn_routes or nrli data"""

        # we have an add-path id
        if detect_add_path_prefix46(data, max_bit_length=128):
            (addpath_id, prefix_len) = struct.unpack_from("!IB", data)
            addpath_id = {"path_id": addpath_id}
            prefix = padding(data[5:], 16)
        else:
            (prefix_len,) = struct.unpack_from("!B", data)
            addpath_id = {}
            prefix = padding(data[1:], 16)

        return {
            "ip_prefix": f"{ipaddress.IPv6Address(prefix)}/{prefix_len}",
            **addpath_id,
        }


# ------------------------------------------------------------------------------
class NlriIPv4Vpn:
    UNPACK_STR = "!B3s8s"
    UNPACK_STR_ADDPATH = "!IB3s8s"

    @classmethod
    def parse(cls, data):
        # ipv4 prefix length 32 + label and rd length 88
        if detect_add_path_prefix46(data, max_bit_length=120):
            (addpath_id, bit_len, label, rd) = struct.unpack_from(
                cls.UNPACK_STR_ADDPATH, data
            )
            addpath_id = {"path_id": addpath_id}
            offset = struct.calcsize(cls.UNPACK_STR_ADDPATH)
        else:
            (bit_len, label, rd) = struct.unpack_from(cls.UNPACK_STR, data)
            offset = struct.calcsize(cls.UNPACK_STR)
            addpath_id = {}

        ipv4 = padding(data[offset:], 4)
        # prefix_len = total_bits_len - label_bits_len - rd_bits_len
        prefix_len = bit_len - 3 * 8 - 8 * 8
        return {
            "label": decode_label(label),
            "rd": str(RouteDistinguisher(rd)),
            "ip_prefix": f"{ipaddress.IPv4Address(ipv4)}/{prefix_len}",
            **addpath_id,
        }


# ------------------------------------------------------------------------------
class NlriIPv6Vpn:
    UNPACK_STR = "!B3s8s"
    UNPACK_STR_ADDPATH = "!IB3s8s"

    @classmethod
    def parse(cls, data):
        # rfc 3107, 8227
        # ipv6 prefix length 128 + label and rd length 88
        if detect_add_path_prefix46(data, max_bit_length=216):
            (addpath_id, bit_len, label, rd) = struct.unpack_from(
                cls.UNPACK_STR_ADDPATH, data
            )
            addpath_id = {"path_id": addpath_id}
            offset = struct.calcsize(cls.UNPACK_STR_ADDPATH)
        else:
            (bit_len, label, rd) = struct.unpack_from(cls.UNPACK_STR, data)
            offset = struct.calcsize(cls.UNPACK_STR)
            addpath_id = {}

        ipv6 = padding(data[offset:], 16)
        prefix_len = bit_len - 3 * 8 - 8 * 8
        return {
            "label": decode_label(label),
            "rd": str(RouteDistinguisher(rd)),
            "ip_prefix": f"{ipaddress.IPv6Address(ipv6)}/{prefix_len}",
            **addpath_id,
        }


# ------------------------------------------------------------------------------
class NlriIPv4Mpls:
    pass


# ------------------------------------------------------------------------------
class NlriIPv6Mpls:
    pass


# ------------------------------------------------------------------------------
class NlriIPv4FlowSpec:
    pass


# ------------------------------------------------------------------------------
class NlriIPv6FlowSpec:
    pass


# ------------------------------------------------------------------------------
class NlriVpn4FlowSpec:
    pass


# ------------------------------------------------------------------------------
class NlriVpn6FlowSpec:
    pass


# ------------------------------------------------------------------------------
class NlriL2EVPN:
    pass


# ------------------------------------------------------------------------------
class NlriL2VPNFlowSpec:
    pass
