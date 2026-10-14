# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""A fixed local BGP peer advertising two valid, distinct AFI/SAFI prefixes."""

import ipaddress
import select
import socket
import struct
import sys
import time


def message(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def attribute(flags, kind, body):
    return bytes([flags, kind, len(body)]) + body


def nlri(network):
    prefix = ipaddress.ip_network(network)
    return (
        bytes([prefix.prefixlen])
        + prefix.network_address.packed[: (prefix.prefixlen + 7) // 8]
    )


def read_message(connection):
    def read(size):
        result = b""
        while len(result) < size:
            value = connection.recv(size - len(result))
            if not value:
                raise EOFError("FRR closed the configured peer")
            result += value
        return result

    header = read(19)
    assert header[:16] == b"\xff" * 16
    length, kind = struct.unpack("!HB", header[16:])
    assert 19 <= length <= 4096
    return kind, read(length - 19)


def announce():
    mp = (
        struct.pack("!HBB", 2, 1, 16)
        + socket.inet_pton(socket.AF_INET6, "2001:db8:1::13")
        + b"\0"
        + nlri("2001:db8:2361::/64")
    )
    attrs = (
        attribute(64, 1, b"\0")
        + attribute(64, 2, struct.pack("!BBH", 2, 1, 65020))
        + attribute(64, 3, socket.inet_aton("192.0.2.13"))
        + attribute(128, 14, mp)
    )
    return message(
        2, struct.pack("!HH", 0, len(attrs)) + attrs + nlri("198.51.100.61/32")
    )


def withdraw():
    classic = nlri("198.51.100.61/32")
    attrs = attribute(128, 15, struct.pack("!HB", 2, 1) + nlri("2001:db8:2361::/64"))
    return message(
        2,
        struct.pack("!H", len(classic))
        + classic
        + struct.pack("!H", len(attrs))
        + attrs,
    )


with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("192.0.2.13", 179))
    listener.listen(1)
    print("LISTENING", flush=True)
    connection, address = listener.accept()
    assert address[0] == "192.0.2.1"
    with connection:
        connection.settimeout(5)
        caps = b"".join(
            bytes([1, 4]) + struct.pack("!HBB", afi, 0, 1) for afi in [1, 2]
        )
        options = bytes([2, len(caps)]) + caps
        connection.sendall(
            message(
                1,
                struct.pack(
                    "!BHH4sB",
                    4,
                    65020,
                    30,
                    socket.inet_aton("192.0.2.13"),
                    len(options),
                )
                + options,
            )
        )
        kind, _ = read_message(connection)
        assert kind == 1
        connection.sendall(message(4))
        while True:
            kind, _ = read_message(connection)
            assert kind != 3
            if kind == 4:
                break
        print("ESTABLISHED", flush=True)
        last = time.monotonic()
        while True:
            ready, _, _ = select.select([connection, sys.stdin], [], [], 0.2)
            if connection in ready:
                kind, _ = read_message(connection)
                assert kind != 3
            if sys.stdin in ready:
                command = sys.stdin.readline().strip()
                if command in ["", "stop"]:
                    break
                assert command in ["announce", "withdraw"]
                connection.sendall(announce() if command == "announce" else withdraw())
                print(command.upper(), flush=True)
            if time.monotonic() - last > 5:
                connection.sendall(message(4))
                last = time.monotonic()
