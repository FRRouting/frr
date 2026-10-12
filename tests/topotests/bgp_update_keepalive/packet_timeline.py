# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""Passive native TCP/BGP timeline decoder; no transmitted packets."""

import collections
import ipaddress
import socket
import struct
import hashlib


def native_messages(path):
    data = path.read_bytes()
    if len(data) < 24:
        return []
    endian, scale = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6)}[
        data[:4]
    ]
    streams = collections.defaultdict(list)
    pos = 24
    while pos < len(data):
        if pos + 16 > len(data):
            break
        sec, part, size, total = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        frame = data[pos : pos + size]
        pos += size
        if len(frame) != size:
            break
        assert size == total and frame[12:14] == b"\x08\x00"
        ip = frame[14:]
        ihl = (ip[0] & 15) * 4
        length = struct.unpack_from("!H", ip, 2)[0]
        assert ip[9] == 6
        tcp = ip[ihl:length]
        header = (tcp[12] >> 4) * 4
        sport, dport, sequence = struct.unpack_from("!HHI", tcp)
        flow = (socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport)
        streams[flow].append((sec + part / scale, sequence, tcp[13], tcp[header:]))
    result = []
    for flow, chunks in streams.items():
        if not any(c[3] for c in chunks):
            continue
        syns = {c[1] for c in chunks if c[2] & 2}
        assert len(syns) == 1
        base = (next(iter(syns)) + 1) & 0xFFFFFFFF
        seen = {}
        times = {}
        for at, seq, flags, payload in chunks:
            offset = (seq - base) & 0xFFFFFFFF
            if not payload:
                continue
            assert offset + len(payload) < 1000000
            for i, value in enumerate(payload, offset):
                assert i not in seen or seen[i] == value
                if i not in seen:
                    seen[i] = value
                    times[i] = at
        assert set(seen) == set(range(max(seen) + 1))
        stream = bytes(seen[i] for i in range(len(seen)))
        i = 0
        while i < len(stream):
            if len(stream) - i < 19:
                break
            assert stream[i : i + 16] == b"\xff" * 16
            n = struct.unpack_from("!H", stream, i + 16)[0]
            assert 19 <= n <= 4096
            if i + n > len(stream):
                break
            msg = stream[i : i + n]
            row = {
                "at": times[i],
                "flow": list(flow),
                "type": msg[18],
                "message_sha256": hashlib.sha256(msg).hexdigest(),
            }
            if msg[18] == 2:
                withdrawn = struct.unpack_from("!H", msg, 19)[0]
                at = 21 + withdrawn
                attributes = struct.unpack_from("!H", msg, at)[0]
                nlri = msg[at + 2 + attributes :]
                prefixes = []
                j = 0
                while j < len(nlri):
                    bits = nlri[j]
                    j += 1
                    count = (bits + 7) // 8
                    assert bits <= 32 and j + count <= len(nlri)
                    prefixes.append(
                        str(
                            ipaddress.IPv4Address(
                                nlri[j : j + count] + b"\0" * (4 - count)
                            )
                        )
                        + "/"
                        + str(bits)
                    )
                    j += count
                row["nlri"] = prefixes
                vector = msg[21 : 21 + withdrawn]
                prefixes = []
                j = 0
                while j < len(vector):
                    bits = vector[j]
                    j += 1
                    count = (bits + 7) // 8
                    assert bits <= 32 and j + count <= len(vector)
                    prefixes.append(
                        str(
                            ipaddress.IPv4Address(
                                vector[j : j + count] + b"\0" * (4 - count)
                            )
                        )
                        + "/"
                        + str(bits)
                    )
                    j += count
                row["withdrawn"] = prefixes
            result.append(row)
            i += n
    return sorted(result, key=lambda m: m["at"])
