#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
Capture an IS-IS PDU off a link and send it again, as an attacker replaying
it would, or as an insider holding the key would after changing it.

    pdu_replay.py capture <interface> <source MAC> <PDU type> <timeout> [<hex>]
        print the first matching frame received on interface, in hex; with
        <hex>, only a frame that contains these bytes
    pdu_replay.py send <interface> <hex frame>
        send the frame on interface
    pdu_replay.py forge <interface> <hex frame> <key> <hex TLV>
        put the TLV into the padding of a P2P IIH, sign it again with
        HMAC-SHA-256 (RFC 5310) and send it
    pdu_replay.py rewrite-esn <interface> <hex frame> <session> <packet>
        set the Extended Sequence Number of an IIH or SNP, without signing
        it again, and send it
"""

import binascii
import hashlib
import hmac
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PDU = 14 + 3  # the IS-IS PDU follows the 802.3 header and the LLC
APAD = bytes.fromhex("878fe1f3")


def capture(ifname, src_mac, pdu_type, timeout, marker=b""):
    src = binascii.unhexlify(src_mac.replace(":", ""))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((ifname, 0))
    end = time.time() + timeout
    while time.time() < end:
        if not select.select([sock], [], [], 0.5)[0]:
            continue
        frame = sock.recv(65535)
        if frame[6:12] == src and frame[14:17] == b"\xfe\xfe\x03":
            if frame[PDU + 4] & 0x1F == pdu_type and marker in frame:
                print(binascii.hexlify(frame).decode())
                return 0
    return 1


def send(ifname, frame):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((ifname, 0))
    sock.send(frame)
    return 0


def pdu_length(frame):
    # In IIHs the PDU length follows the circuit type, source ID and holding
    # time; in SNPs it follows the fixed header
    if frame[PDU + 4] & 0x1F in (15, 16, 17):
        return struct.unpack_from("!H", frame, PDU + 8 + 1 + 6 + 2)[0]
    return struct.unpack_from("!H", frame, PDU + 8)[0]


def tlvs(frame):
    """(offset, type, length) of each TLV of the PDU in frame"""
    pos, end = PDU + frame[PDU + 1], PDU + pdu_length(frame)
    while pos < end:
        yield pos, frame[pos], frame[pos + 1]
        pos += 2 + frame[pos + 1]


def forge(ifname, frame, key, tlv):
    frame = bytearray(frame)
    pdu_len, digest, padding = pdu_length(frame), None, None
    for pos, tlv_type, tlv_len in tlvs(frame):
        if tlv_type == 10 and frame[pos + 2] == 3:
            digest = (pos + 5, tlv_len - 3)
        elif tlv_type == 8 and padding is None and tlv_len >= len(tlv):
            padding = (pos, tlv_len)

    # the TLV, then what is left of the padding TLV it went into
    pos, pad_len = padding
    frame[pos : pos + len(tlv)] = tlv
    frame[pos + len(tlv)] = 8
    frame[pos + len(tlv) + 1] = pad_len - len(tlv)

    offset, length = digest
    frame[offset : offset + length] = (APAD * 16)[:length]
    frame[offset : offset + length] = hmac.new(
        key.encode(), bytes(frame[PDU : PDU + pdu_len]), hashlib.sha256
    ).digest()
    return send(ifname, frame)


def rewrite_esn(ifname, frame, session, packet):
    frame = bytearray(frame)
    pos = next(pos for pos, tlv_type, _ in tlvs(frame) if tlv_type == 11)
    struct.pack_into("!QI", frame, pos + 2, session, packet)
    return send(ifname, frame)


if __name__ == "__main__":
    if sys.argv[1] == "capture":
        sys.exit(
            capture(
                sys.argv[2],
                sys.argv[3],
                int(sys.argv[4]),
                float(sys.argv[5]),
                binascii.unhexlify(sys.argv[6]) if len(sys.argv) > 6 else b"",
            )
        )
    if sys.argv[1] == "forge":
        sys.exit(
            forge(
                sys.argv[2],
                binascii.unhexlify(sys.argv[3]),
                sys.argv[4],
                binascii.unhexlify(sys.argv[5]),
            )
        )
    if sys.argv[1] == "rewrite-esn":
        sys.exit(
            rewrite_esn(
                sys.argv[2],
                binascii.unhexlify(sys.argv[3]),
                int(sys.argv[4]),
                int(sys.argv[5]),
            )
        )
    sys.exit(send(sys.argv[2], binascii.unhexlify(sys.argv[3])))
