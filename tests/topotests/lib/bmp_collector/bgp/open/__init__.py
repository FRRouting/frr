# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import ipaddress
import struct


class BGPOpen:
<<<<<<< HEAD
    UNPACK_STR = '!16sHBBHH4sB'

    @classmethod
    def dissect(cls, data):
        (marker,
         length,
         open_type,
         version,
         my_as,
         hold_time,
         bgp_id,
         optional_params_len) = struct.unpack_from(cls.UNPACK_STR, data)

        data = data[struct.calcsize(cls.UNPACK_STR) + optional_params_len:]
=======
    UNPACK_STR = "!16sHBBHH4sB"

    @classmethod
    def dissect(cls, data):
        (
            marker,
            length,
            open_type,
            version,
            my_as,
            hold_time,
            bgp_id,
            optional_params_len,
        ) = struct.unpack_from(cls.UNPACK_STR, data)

        data = data[struct.calcsize(cls.UNPACK_STR) + optional_params_len :]
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)

        # XXX: parse optional parameters

        return data, {
<<<<<<< HEAD
            'version': version,
            'my_as': my_as,
            'hold_time': hold_time,
            'bgp_id': ipaddress.ip_address(bgp_id),
            'optional_params_len': optional_params_len,
=======
            "version": version,
            "my_as": my_as,
            "hold_time": hold_time,
            "bgp_id": ipaddress.ip_address(bgp_id),
            "optional_params_len": optional_params_len,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        }
