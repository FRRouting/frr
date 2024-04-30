# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import ipaddress
import struct


#------------------------------------------------------------------------------
class RouteDistinguisher:
    """
    type 0:
    +---------------------------------------------------------------------+
    + type=0 (2 bytes)| Administrator subfield | Assigned number subfiled |
    +                 | AS number (2 bytes)    | Service Provider 4 bytes)|
    +---------------------------------------------------------------------+

    type 1:
    +---------------------------------------------------------------------+
    + type=1 (2 bytes)| Administrator subfield | Assigned number subfiled |
    +                 | IPv4 (4 bytes)         | Service Provider 2 bytes)|
    +---------------------------------------------------------------------+

    type 2:
    +-------------------------------------------------------------------------+
    + type=2 (2 bytes)| Administrator subfield     | Assigned number subfiled |
    +                 | 4-bytes AS number (4 bytes)| Service Provider 2 bytes)|
    +-------------------------------------------------------------------------+
    """
    def __init__(self, rd):
        self.rd = rd
        self.as_number = None
        self.admin_ipv4 = None
        self.four_bytes_as = None
        self.assigned_sp = None
        self.repr_str = ''
        self.dissect()

    def dissect(self):
        (rd_type,) = struct.unpack_from('!H', self.rd)
        if rd_type == 0:
            (self.as_number,
                    self.assigned_sp) = struct.unpack_from('!HI', self.rd[2:])
            self.repr_str = f'{self.as_number}:{self.assigned_sp}'

        elif rd_type == 1:
            (self.admin_ipv4,
             self.assigned_sp) = struct.unpack_from('!IH', self.rd[2:])
            ipv4 = str(ipaddress.IPv4Address(self.admin_ipv4))
            self.repr_str = f'{self.as_number}:{self.assigned_sp}'

        elif rd_type == 2:
            (self.four_bytes_as,
             self.assigned_sp) = struct.unpack_from('!IH', self.rd[2:])
            self.repr_str = f'{self.four_bytes_as}:{self.assigned_sp}'

    def __str__(self):
        return self.repr_str
