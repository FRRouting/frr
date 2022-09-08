#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
basic tests for topotato.pcapng
"""

import io
import hashlib

from topotato.pcapng import (
    Sink,
    SectionHeader,
    IfDesc,
    EnhancedPacket,
    JournalExport,
)


def test_reproducible():
    """
    Throw a bunch of random data into a pcap-ng file, and check the result.

    Everything in this should be deterministic, i.e. the pcap-ng file should
    always be identical byte for byte.  Therefore, it's hashed and checked
    against the hash at the end.
    """
    ofd = io.BytesIO()
    sink = Sink(ofd, "<")

    h = SectionHeader(uname="test")
    sink.write(h)

    ts = 1658519119.7561605

    ifd = IfDesc()
    ifd.options.append(ifd.OptName("eth0"))
    ifd.options.append(ifd.OptDescription("description"))
    ifd.options.append(ifd.OptOS("topotato container"))
    ifd.options.append(ifd.OptTSResol(9))
    sink.write(ifd)

    pkt = EnhancedPacket(
        0,
        int(ts * 1e9),
        6 * b"\xff" + 6 * b"\x02" + b"\x08" + b"\x05",
    )
    pkt.options.append(pkt.OptPacketID(1234))
    pkt.add_hash()
    sink.write(pkt)

    ts += 0.123456789

    pkt = EnhancedPacket(
        0,
        int(ts * 1e9),
        6 * b"\xff" + 6 * b"\x06" + b"\x08" + b"\x05",
    )
    pkt.options.append(pkt.OptPacketID(1235))
    pkt.add_hash()
    sink.write(pkt)

    ts += 0.23456789

    sde = JournalExport(
        {
            "__REALTIME_TIMESTAMP": int(ts * 1e6),
            "foo": "bar",
            "bla": "a\nb",
            "asdf": b"\x00",
        }
    )
    sink.write(sde)

    ### if something changed / failure, save and check output with wireshark
    # with open(filename, "wb") as wfd:
    #     wfd.write(ofd.getvalue())

    assert (
        hashlib.sha1(ofd.getvalue()).hexdigest()
        == "5c4e18b93021696dd93f8997cb658d311c826255"
    )
