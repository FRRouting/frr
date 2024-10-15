# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import struct
import ipaddress

from . import nlri as NLRI
from .af import AddressFamily, AF
from .rd import RouteDistinguisher


PATH_ATTR_FLAG_OPTIONAL = 1 << 7
PATH_ATTR_FLAG_TRANSITIVE = 1 << 6
PATH_ATTR_FLAG_PARTIAL = 1 << 5
PATH_ATTR_FLAG_EXTENDED_LENGTH = 1 << 4

PATH_ATTR_TYPE_ORIGIN = 1
PATH_ATTR_TYPE_AS_PATH = 2
PATH_ATTR_TYPE_NEXT_HOP = 3
PATH_ATTR_TYPE_MULTI_EXIT_DISC = 4
PATH_ATTR_TYPE_LOCAL_PREF = 5
PATH_ATTR_TYPE_ATOMIC_AGGREGATE = 6
PATH_ATTR_TYPE_AGGREGATOR = 7
PATH_ATTR_TYPE_COMMUNITIES = 8
PATH_ATTR_TYPE_ORIGINATOR_ID = 9
PATH_ATTR_TYPE_CLUSTER_LIST = 10
PATH_ATTR_TYPE_MP_REACH_NLRI = 14
PATH_ATTR_TYPE_MP_UNREACH_NLRI = 15
PATH_ATTR_TYPE_EXTENDED_COMMUNITIES = 16
PATH_ATTR_TYPE_AS4_PATH = 17
PATH_ATTR_TYPE_AS4_AGGREGATOR = 18
PATH_ATTR_TYEP_PMSI_TUNNEL_ATTRIBUTE = 22

ORIGIN_IGP = 0x00
ORIGIN_EGP = 0x01
ORIGIN_INCOMPLETE = 0x02


# ------------------------------------------------------------------------------
class PathAttribute:
    PATH_ATTRS = {}
    UNKNOWN_ATTR = None
    UNPACK_STR = "!BB"

    @classmethod
    def register_path_attr(cls, path_attr):
        def _register_path_attr(subcls):
            cls.PATH_ATTRS[path_attr] = subcls
            return subcls

        return _register_path_attr

    @classmethod
    def lookup_path_attr(cls, type_code):
        return cls.PATH_ATTRS.get(type_code, cls.UNKNOWN_ATTR)

    @classmethod
    def dissect(cls, data):
        flags, type_code = struct.unpack_from(cls.UNPACK_STR, data)
        offset = struct.calcsize(cls.UNPACK_STR)

        # get attribute length
        attr_len_str = "!H" if (flags & PATH_ATTR_FLAG_EXTENDED_LENGTH) else "!B"

        (attr_len,) = struct.unpack_from(attr_len_str, data[offset:])

        offset += struct.calcsize(attr_len_str)

        path_attr_cls = cls.lookup_path_attr(type_code)
        if path_attr_cls == cls.UNKNOWN_ATTR:
            return data[offset + attr_len :], None

        return data[offset + attr_len :], path_attr_cls.dissect(
            data[offset : offset + attr_len]
        )


# ------------------------------------------------------------------------------
@PathAttribute.register_path_attr(PATH_ATTR_TYPE_ORIGIN)
class PathAttrOrigin:
    ORIGIN_STR = {
        ORIGIN_IGP: "IGP",
        ORIGIN_EGP: "EGP",
        ORIGIN_INCOMPLETE: "INCOMPLETE",
    }

    @classmethod
    def dissect(cls, data):
        (origin,) = struct.unpack_from("!B", data)

        return {"origin": cls.ORIGIN_STR.get(origin, "UNKNOWN")}


# ------------------------------------------------------------------------------
@PathAttribute.register_path_attr(PATH_ATTR_TYPE_AS_PATH)
class PathAttrAsPath:
    AS_PATH_TYPE_SET = 0x01
    AS_PATH_TYPE_SEQUENCE = 0x02

    @staticmethod
    def get_asn_len(asns):
        """XXX: Add this nightmare to determine the ASN length"""
        pass

    @classmethod
    def dissect(cls, data):
        (_type, _len) = struct.unpack_from("!BB", data)
        data = data[2:]

        _type_str = "Ordred" if _type == cls.AS_PATH_TYPE_SEQUENCE else "Raw"
        segment = []
        while data:
            (asn,) = struct.unpack_from("!I", data)
            segment.append(asn)
            data = data[4:]

        return {"as_path": " ".join(str(a) for a in segment)}


# ------------------------------------------------------------------------------
@PathAttribute.register_path_attr(PATH_ATTR_TYPE_NEXT_HOP)
class PathAttrNextHop:
    @classmethod
    def dissect(cls, data):
        (nexthop,) = struct.unpack_from("!4s", data)
        return {"bgp_nexthop": str(ipaddress.IPv4Address(nexthop))}


# ------------------------------------------------------------------------------
class PathAttrMultiExitDisc:
    pass


# ------------------------------------------------------------------------------
@PathAttribute.register_path_attr(PATH_ATTR_TYPE_MP_REACH_NLRI)
class PathAttrMpReachNLRI:
    """
    +---------------------------------------------------------+
    | Address Family Identifier (2 octets)                    |
    +---------------------------------------------------------+
    | Subsequent Address Family Identifier (1 octet)          |
    +---------------------------------------------------------+
    | Length of Next Hop Network Address (1 octet)            |
    +---------------------------------------------------------+
    | Network Address of Next Hop (variable)                  |
    +---------------------------------------------------------+
    | Number of SNPAs (1 octet)                               |
    +---------------------------------------------------------+
    | Length of first SNPA(1 octet)                           |
    +---------------------------------------------------------+
    | First SNPA (variable)                                   |
    +---------------------------------------------------------+
    | Length of second SNPA (1 octet)                         |
    +---------------------------------------------------------+
    | Second SNPA (variable)                                  |
    +---------------------------------------------------------+
    | ...                                                     |
    +---------------------------------------------------------+
    | Length of Last SNPA (1 octet)                           |
    +---------------------------------------------------------+
    | Last SNPA (variable)                                    |
    +---------------------------------------------------------+
    | Network Layer Reachability Information (variable)       |
    +---------------------------------------------------------+
    """

    UNPACK_STR = "!HBB"
    NLRI_RESERVED_LEN = 1

    @staticmethod
    def dissect_nexthop(nexthop_data, nexthop_len):
        msg = {}
        if nexthop_len == 4:
            # IPv4
            (ipv4,) = struct.unpack_from("!4s", nexthop_data)
            msg["nxhp_ip"] = str(ipaddress.IPv4Address(ipv4))
        elif nexthop_len == 12:
            # RD + IPv4
            (rd, ipv4) = struct.unpack_from("!8s4s", nexthop_data)
            msg["nxhp_ip"] = str(ipaddress.IPv4Address(ipv4))
            msg["nxhp_rd"] = str(RouteDistinguisher(rd))
        elif nexthop_len == 16:
            # IPv6
            (ipv6,) = struct.unpack_from("!16s", nexthop_data)
            msg["nxhp_ip"] = str(ipaddress.IPv6Address(ipv6))
        elif nexthop_len == 24:
            # RD + IPv6
            (rd, ipv6) = struct.unpack_from("!8s16s", nexthop_data)
            msg["nxhp_ip"] = str(ipaddress.IPv6Address(ipv6))
            msg["nxhp_rd"] = str(RouteDistinguisher(rd))
        elif nexthop_len == 32:
            # IPv6 + IPv6 link-local
            (ipv6, link_local) = struct.unpack_from("!16s16s", nexthop_data)
            msg["nxhp_ip"] = str(ipaddress.IPv6Address(ipv6))
            msg["nxhp_link-local"] = str(ipaddress.IPv6Address(link_local))
        elif nexthop_len == 48:
            # RD + IPv6 +  RD + IPv6 link-local
            u_str = "!8s16s8s16s"
            (rd1, ipv6, rd2, link_local) = struct.unpack_from(u_str, nexthop_data)
            msg["nxhp_rd1"] = str(RouteDistinguisher(rd1))
            msg["nxhp_ip"] = str(ipaddress.IPv6Address(ipv6))
            msg["nxhp_rd2"] = str(RouteDistinguisher(rd2))
            msg["nxhp_link-local"] = str(ipaddress.IPv6Address(link_local))

        return msg

    @staticmethod
    def dissect_snpa(snpa_data):
        pass

    @classmethod
    def dissect(cls, data):
        (afi, safi, nexthop_len) = struct.unpack_from(cls.UNPACK_STR, data)
        offset = struct.calcsize(cls.UNPACK_STR)
        msg = {"afi": afi, "safi": safi}

        # dissect nexthop
        nexthop_data = data[offset : offset + nexthop_len]
        nexthop = cls.dissect_nexthop(nexthop_data, nexthop_len)
        msg.update(nexthop)

        offset += nexthop_len
        # dissect snpa or just reserved
        offset += 1
        # dissect nlri
        nlri = NLRI.dissect_nlri(data[offset:], afi, safi)
        msg.update(nlri)

        return msg


# ------------------------------------------------------------------------------
@PathAttribute.register_path_attr(PATH_ATTR_TYPE_MP_UNREACH_NLRI)
class PathAttrMpUnReachNLRI:
    """
    +---------------------------------------------------------+
    | Address Family Identifier (2 bytes)                     |
    +---------------------------------------------------------+
    | Subsequent Address Family Identifier (1 byte)           |
    +---------------------------------------------------------+
    | Withdrawn Routes (variable)                             |
    +---------------------------------------------------------+
    """

    UNPACK_STR = "!HB"

    @classmethod
    def dissect(cls, data):
        (afi, safi) = struct.unpack_from(cls.UNPACK_STR, data)
        offset = struct.calcsize(cls.UNPACK_STR)
        msg = {"bmp_log_type": "withdraw", "afi": afi, "safi": safi}

        if data[offset:]:
            # dissect withdrawn_routes
            msg.update(NLRI.dissect_nlri(data[offset:], afi, safi))

        return msg


# ------------------------------------------------------------------------------
class PathAttrLocalPref:
    pass


# ------------------------------------------------------------------------------
class PathAttrAtomicAgregate:
    pass


# ------------------------------------------------------------------------------
class PathAttrAggregator:
    pass


# ------------------------------------------------------------------------------
class PathAttrCommunities:
    pass


# ------------------------------------------------------------------------------
class PathAttrOriginatorID:
    pass


# ------------------------------------------------------------------------------
class PathAttrClusterList:
    pass


# ------------------------------------------------------------------------------
class PathAttrExtendedCommunities:
    pass


# ------------------------------------------------------------------------------
class PathAttrPMSITunnel:
    pass


# ------------------------------------------------------------------------------
class PathAttrLinkState:
    pass


# ------------------------------------------------------------------------------
class PathAttrLargeCommunities:
    pass
