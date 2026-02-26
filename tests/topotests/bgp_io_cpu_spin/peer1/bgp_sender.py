#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
bgp_sender.py: Minimal raw BGP speaker that sends many individual UPDATE
messages as fast as possible.

This replaces ExaBGP for the I/O spin test because ExaBGP's Python-based
route sending is too slow to create sufficient TCP buffer pressure.

Uses non-blocking I/O with select() to send UPDATE messages while also
handling keepalive exchanges, preventing session drops when the receiver
processes slowly (e.g., with input-queue-limit 1).

Usage: bgp_sender.py <peer_ip> <local_as> <peer_as> <route_count>
"""

import select
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_KEEPALIVE = 4
BGP_VERSION = 4
HOLD_TIME = 10


def build_open(local_as, router_id):
    """Build a BGP OPEN message."""
    rid = socket.inet_aton(router_id)
    opt_params = b""
    payload = (
        struct.pack("!BHH4sB", BGP_VERSION, local_as, HOLD_TIME, rid, len(opt_params))
        + opt_params
    )
    length = 19 + len(payload)
    return MARKER + struct.pack("!HB", length, BGP_OPEN) + payload


def build_keepalive():
    """Build a BGP KEEPALIVE message."""
    return MARKER + struct.pack("!HB", 19, BGP_KEEPALIVE)


def build_update(prefix_ip, prefix_len, next_hop):
    """Build a BGP UPDATE message announcing a single prefix."""
    # Withdrawn routes length = 0
    withdrawn = struct.pack("!H", 0)

    # Path attributes
    attrs = b""

    # ORIGIN: IGP (flags=0x40 transitive, type=1, len=1, value=0)
    attrs += struct.pack("!BBB", 0x40, 1, 1) + struct.pack("!B", 0)

    # AS_PATH: AS_SEQUENCE with 15 ASNs (required for eBGP)
    # flags=0x40 transitive, type=2
    # Use 2-byte AS numbers (no 4-byte AS capability negotiated)
    # A longer AS path makes the per-route as-path regex evaluation in the
    # SLOW_IMPORT route-map more expensive, allowing fewer access-list
    # entries to achieve the same main-thread slowdown.
    as_numbers = [65001] + list(range(64001, 64015))  # 15 ASNs
    as_path_segment = struct.pack("!BB", 2, len(as_numbers))
    for asn in as_numbers:
        as_path_segment += struct.pack("!H", asn)
    attrs += struct.pack("!BBB", 0x40, 2, len(as_path_segment)) + as_path_segment

    # NEXT_HOP: (flags=0x40 transitive, type=3, len=4)
    attrs += struct.pack("!BBB", 0x40, 3, 4) + socket.inet_aton(next_hop)

    path_attr_len = struct.pack("!H", len(attrs))

    # NLRI: prefix_len(1) + prefix bytes (ceil(prefix_len/8))
    prefix_bytes = (prefix_len + 7) // 8
    ip_bytes = socket.inet_aton(prefix_ip)[:prefix_bytes]
    nlri = struct.pack("!B", prefix_len) + ip_bytes

    payload = withdrawn + path_attr_len + attrs + nlri
    length = 19 + len(payload)
    return MARKER + struct.pack("!HB", length, BGP_UPDATE) + payload


def recv_msg(sock):
    """Receive a single BGP message, return (type, payload)."""
    header = b""
    while len(header) < 19:
        data = sock.recv(19 - len(header))
        if not data:
            raise ConnectionError("Connection closed")
        header += data

    length = struct.unpack("!H", header[16:18])[0]
    msg_type = header[18]

    remaining = length - 19
    payload = b""
    while len(payload) < remaining:
        data = sock.recv(remaining - len(payload))
        if not data:
            raise ConnectionError("Connection closed")
        payload += data

    return msg_type, payload


def process_incoming(recv_buf):
    """Process incoming BGP messages from recv_buf, count keepalives.

    Returns (updated recv_buf, number of keepalives received).
    """
    ka_count = 0
    while len(recv_buf) >= 19:
        if recv_buf[:16] != MARKER:
            recv_buf = recv_buf[1:]
            continue
        msg_len = struct.unpack("!H", recv_buf[16:18])[0]
        if len(recv_buf) < msg_len:
            break
        msg_type = recv_buf[18]
        recv_buf = recv_buf[msg_len:]
        if msg_type == BGP_KEEPALIVE:
            ka_count += 1
    return recv_buf, ka_count


def send_blob_with_keepalive(sock, blob):
    """Send blob using non-blocking I/O while handling keepalives.

    The receiver may process slowly (input-queue-limit), causing TCP
    back-pressure. We must still respond to keepalives to prevent
    the session from dropping. Keepalive responses are prioritized
    over blob data so they are sent as soon as the socket becomes
    writable.
    """
    sock.setblocking(False)
    sent = 0
    recv_buf = b""
    pending_ka = 0
    ka = build_keepalive()

    while sent < len(blob):
        readable, writable, _ = select.select([sock], [sock], [], 10.0)

        if not readable and not writable:
            raise TimeoutError("No progress in 10 seconds")

        # Handle incoming keepalives
        if readable:
            try:
                data = sock.recv(65536)
                if not data:
                    raise ConnectionError("Connection closed during send")
                recv_buf += data
            except BlockingIOError:
                pass
            recv_buf, ka_count = process_incoming(recv_buf)
            pending_ka += ka_count

        if writable:
            # Send pending keepalive responses first
            while pending_ka > 0:
                try:
                    sock.send(ka)
                    pending_ka -= 1
                except BlockingIOError:
                    break

            # Then send update data
            try:
                n = sock.send(blob[sent:])
                if n > 0:
                    sent += n
            except BlockingIOError:
                pass

    sock.setblocking(True)
    return sent


def main():
    if len(sys.argv) != 5:
        print("Usage: bgp_sender.py <peer_ip> <local_as> <peer_as> <route_count>")
        sys.exit(1)

    peer_ip = sys.argv[1]
    local_as = int(sys.argv[2])
    peer_as = int(sys.argv[3])
    route_count = int(sys.argv[4])

    # Connect and complete BGP OPEN handshake, retrying on failure.
    # Under heavy CI load the initial OPEN can be dropped, so we retry
    # the entire connect + handshake sequence.
    router_id = "192.168.1.1"
    sock = None
    for attempt in range(30):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((peer_ip, 179))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.sendall(build_open(local_as, router_id))
            msg_type, _ = recv_msg(sock)
            if msg_type != BGP_OPEN:
                raise ConnectionError("Expected OPEN, got type {}".format(msg_type))
            sock.sendall(build_keepalive())
            msg_type, _ = recv_msg(sock)
            if msg_type != BGP_KEEPALIVE:
                raise ConnectionError("Expected KEEPALIVE, got type {}".format(msg_type))
            break
        except (ConnectionError, ConnectionRefusedError, OSError, socket.timeout):
            if sock:
                sock.close()
                sock = None
            time.sleep(2)
    else:
        print("ERROR: Could not establish BGP session with {}".format(peer_ip))
        sys.exit(1)

    print("BGP session established with {}".format(peer_ip))

    # Pre-build all UPDATE messages for maximum send speed
    updates = []
    for i in range(route_count):
        b = (i >> 8) & 0xFF
        c = i & 0xFF
        updates.append(build_update("10.0.{}.{}".format(b, c), 32, router_id))

    # Send all UPDATE messages as fast as possible while handling keepalives.
    # join into one blob so TCP can batch them for maximum throughput.
    blob = b"".join(updates)
    print("Sending {} UPDATE messages ({} bytes)...".format(route_count, len(blob)))
    send_blob_with_keepalive(sock, blob)

    print("Sent {} UPDATE messages".format(route_count))

    # Keep session alive with frequent keepalives.
    # Sending keepalives every 1 second also ensures that FRR's ibuf_work
    # ring buffer gets flushed: when all UPDATE data has been read from
    # the socket into ibuf_work, bgp_process_reads skips ibuf_work
    # parsing on EAGAIN. The keepalives provide fresh socket data that
    # triggers read_ibuf_work to process the buffered UPDATEs.
    sock.settimeout(1)
    while True:
        try:
            msg_type, _ = recv_msg(sock)
            if msg_type == BGP_KEEPALIVE:
                sock.sendall(build_keepalive())
        except socket.timeout:
            sock.sendall(build_keepalive())
        except (ConnectionError, BrokenPipeError):
            break


if __name__ == "__main__":
    main()
