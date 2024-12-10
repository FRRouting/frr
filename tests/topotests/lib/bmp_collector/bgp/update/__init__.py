# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import ipaddress
import struct

from .nlri import NlriIPv4Unicast
from .path_attributes import PathAttribute


<<<<<<< HEAD
#------------------------------------------------------------------------------
class BGPUpdate:
    UNPACK_STR = '!16sHBH'
=======
# ------------------------------------------------------------------------------
class BGPUpdate:
    UNPACK_STR = "!16sHBH"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    STATIC_SIZE = 23

    @classmethod
    def dissect(cls, data):
<<<<<<< HEAD
        msg = {'bmp_log_type': 'update'}
        common_size = struct.calcsize(cls.UNPACK_STR)
        (marker,
         length,
         update_type,
         withdrawn_routes_len) = struct.unpack_from(cls.UNPACK_STR, data)

        # get withdrawn routes
        withdrawn_routes = ''
        if withdrawn_routes_len:
            withdrawn_routes = NlriIPv4Unicast.parse(
                data[common_size:common_size + withdrawn_routes_len]
            )
            msg['bmp_log_type'] = 'withdraw'
=======
        msg = {"bmp_log_type": "update"}
        common_size = struct.calcsize(cls.UNPACK_STR)
        (marker, length, update_type, withdrawn_routes_len) = struct.unpack_from(
            cls.UNPACK_STR, data
        )

        # get withdrawn routes
        withdrawn_routes = ""
        if withdrawn_routes_len:
            withdrawn_routes = NlriIPv4Unicast.parse(
                data[common_size : common_size + withdrawn_routes_len]
            )
            msg["bmp_log_type"] = "withdraw"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
            msg.update(withdrawn_routes)

        # get path attributes
        (total_path_attrs_len,) = struct.unpack_from(
<<<<<<< HEAD
                '!H', data[common_size+withdrawn_routes_len:])

        if total_path_attrs_len:
            offset = cls.STATIC_SIZE + withdrawn_routes_len
            path_attrs_data = data[offset:offset + total_path_attrs_len]
=======
            "!H", data[common_size + withdrawn_routes_len :]
        )

        if total_path_attrs_len:
            offset = cls.STATIC_SIZE + withdrawn_routes_len
            path_attrs_data = data[offset : offset + total_path_attrs_len]
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
            while path_attrs_data:
                path_attrs_data, pattr = PathAttribute.dissect(path_attrs_data)
                if pattr:
                    msg = {**msg, **pattr}

        # get nlri
<<<<<<< HEAD
        nlri_len = length - cls.STATIC_SIZE - withdrawn_routes_len - total_path_attrs_len
        if nlri_len > 0:
            nlri = NlriIPv4Unicast.parse(data[length - nlri_len:length])
=======
        nlri_len = (
            length - cls.STATIC_SIZE - withdrawn_routes_len - total_path_attrs_len
        )
        if nlri_len > 0:
            nlri = NlriIPv4Unicast.parse(data[length - nlri_len : length])
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
            msg.update(nlri)

        return data[length:], msg
