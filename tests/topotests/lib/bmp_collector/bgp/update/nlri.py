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
        (prefix_len,) = struct.unpack_from("!B", data)
        prefix = padding(data[1:], 4)

        return {"ip_prefix": f"{ipaddress.IPv4Address(prefix)}/{prefix_len}"}


# ------------------------------------------------------------------------------
class NlriIPv6Unicast:
    @staticmethod
    def parse(data):
        """parses prefixes from withdrawn_routes or nrli data"""
        (prefix_len,) = struct.unpack_from("!B", data)
        prefix = padding(data[1:], 16)

        return {"ip_prefix": f"{ipaddress.IPv6Address(prefix)}/{prefix_len}"}


# ------------------------------------------------------------------------------
class NlriIPv4Vpn:
    UNPACK_STR = "!B3s8s"

    @classmethod
    def parse(cls, data):
        (bit_len, label, rd) = struct.unpack_from(cls.UNPACK_STR, data)
        offset = struct.calcsize(cls.UNPACK_STR)

        ipv4 = padding(data[offset:], 4)
        # prefix_len = total_bits_len - label_bits_len - rd_bits_len
        prefix_len = bit_len - 3 * 8 - 8 * 8
        return {
            "label": decode_label(label),
            "rd": str(RouteDistinguisher(rd)),
            "ip_prefix": f"{ipaddress.IPv4Address(ipv4)}/{prefix_len}",
        }


# ------------------------------------------------------------------------------
class NlriIPv6Vpn:
    UNPACK_STR = "!B3s8s"

    @classmethod
    def parse(cls, data):
        # rfc 3107, 8227
        (bit_len, label, rd) = struct.unpack_from(cls.UNPACK_STR, data)
        offset = struct.calcsize(cls.UNPACK_STR)

        ipv6 = padding(data[offset:], 16)
        prefix_len = bit_len - 3 * 8 - 8 * 8
        return {
            "label": decode_label(label),
            "rd": str(RouteDistinguisher(rd)),
            "ip_prefix": f"{ipaddress.IPv6Address(ipv6)}/{prefix_len}",
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
