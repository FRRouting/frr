# SPDX-License-Identifier: GPL-2.0-or-later
# xref unique ID hash calculation
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

import struct
from hashlib import sha256


def bititer(data, bits, startbit=True):
    """
    just iterate the individual bits out from a bytes object

    if startbit is True, an '1' bit is inserted at the very beginning
    goes <bits> at a time, starts at LSB.
    """
    bitavail, v = 0, 0
    if startbit and len(data) > 0:
        v = data.pop(0)
        yield (v & ((1 << bits) - 1)) | (1 << (bits - 1))
        bitavail = 9 - bits
        v >>= bits - 1

    while len(data) > 0:
        while bitavail < bits:
            v |= data.pop(0) << bitavail
            bitavail += 8
        yield v & ((1 << bits) - 1)
        bitavail -= bits
        v >>= bits


def base32c(data):
    """
    Crockford base32 with extra dashes
    """
    chs = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    o = ""
    if type(data) == str:
        data = [ord(v) for v in data]
    else:
        data = list(data)
    for i, bits in enumerate(bititer(data, 5)):
        if i == 5:
            o = o + "-"
        elif i == 10:
            break
        o = o + chs[bits]
    return o


def uidhash(filename, hashstr, hashu32a, hashu32b):
    """
    xref Unique ID hash used in FRRouting
    """
    filename = "/".join(filename.rsplit("/")[-2:])

    hdata = filename.encode("UTF-8") + hashstr.encode("UTF-8")
    hdata += struct.pack(">II", hashu32a, hashu32b)
    i = sha256(hdata).digest()
    return base32c(i)
