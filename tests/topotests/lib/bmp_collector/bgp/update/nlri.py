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

        # we have an add-path id, this check is simpler than the unnecessary (i think?)
        # detect_addpath_prefix_ipv46(data, max_bit_length=32) procedure
        if len(data) > 5:
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
this is the addpath detection from wireshark, not perfect but works in our use cases

static int detect_add_path_prefix46(tvbuff_t *tvb, gint offset, gint end, gint max_bit_length)
in packet-bgp.c BGP dissector from Wireshark
"""


def detect_addpath_prefix_ipv46(data, max_bit_length):
    end = len(data)

    # proof by contradiction
    # assuming this a well-formatted add-path prefix
    # if we find an error it means there was no path-id, or a badly formatted one
    # prefix length would be right after path id
    # (i don't understand why they loop this check in range(4, end, 4) in Wireshark)
    offset = 4
    prefix_len = data[offset]

    # the prefix length is bigger than the maximum allowed size
    if prefix_len > max_bit_length:
        return False

    addr_len = (prefix_len + 7) // 8
    offset += 1 + addr_len

    # the prefix length announces a prefix bigger than what we have
    if offset > end:
        return False

    # the prefix length tells us that the last byte will have more some 0 padding bits
    # and those bits are not set to 0
    if prefix_len % 8 > 0 and data[offset - 1] & (0xFF >> (prefix_len % 8)) > 0:
        return False

    # proof by contradiction
    # assuming there is not an add-path prefix, and this is well formatted
    # if we find an error it may mean there was a path-id
    # assuming there is no add-path path-id
    offset = 0
    while offset < end:
        # prefix length would be first
        prefix_len = data[offset]

        # prefix length is zero and we have more than one byte of address so maybe this was a path-id
        if prefix_len == 0 and end - offset > 1:
            return True

        # invalid prefix length so maybe this was a path-id
        if prefix_len > max_bit_length:
            return True

        addr_len = (prefix_len + 7) // 8
        offset += 1 + addr_len

        # the prefix length announces a prefix bigger than what we have
        if offset > end:
            return True  # maybe this was a path-id

        # the prefix length tells us that the last byte will have more some 0 padding bits
        # and those bits are not set to 0
        if prefix_len % 8 > 0 and data[offset - 1] & (0xFF >> (prefix_len % 8)) > 0:
            return True  # maybe it was a path-id

    # we don't know if it's add-path so let's say no
    return False

class NlriIPv6Unicast:
    @staticmethod
    def parse(data):
        """parses prefixes from withdrawn_routes or nrli data"""

        # we have an add-path id
        if detect_addpath_prefix_ipv46(data, max_bit_length=128):
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
