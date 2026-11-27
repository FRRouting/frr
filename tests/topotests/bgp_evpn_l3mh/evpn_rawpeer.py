#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Minimal EVPN BGP speaker that re-announces one RT-2 with chosen labels.

ExaBGP cannot announce EVPN MAC/IP routes from its configuration. This speaker
sends the same (RD, ESI, ETAG, MAC, IP) RT-2 with identical attributes and only
the MPLS labels changed, which a real peer emits as a single UPDATE.

Usage: evpn_rawpeer.py LOCAL_IP LOCAL_AS PEER_IP ESI ETAG MAC IP RT_ADMIN
Commands on stdin, one per line: "announce LABEL1 LABEL2", "announce-nort
LABEL1 LABEL2" (no extended communities) or "withdraw". Each takes optional
"rd=N" (RD local index, default 5), "mac=MAC", "etag=ETAG" and "ip=IP"
overrides.
"""

import socket
import struct
import sys
import threading
import time

MARKER = b"\xff" * 16
HEADER_LEN = 19
OPEN, UPDATE, NOTIFICATION, KEEPALIVE = 1, 2, 3, 4
AFI_L2VPN, SAFI_EVPN = 25, 70


def log(fmt, *args):
    sys.stderr.write("%s evpn_rawpeer: %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
    sys.stderr.flush()


def message(kind, body):
    return MARKER + struct.pack("!HB", HEADER_LEN + len(body), kind) + body


def attribute(flags, code, value):
    # Extended length keeps every attribute encodable regardless of size.
    return struct.pack("!BBH", flags | 0x10, code, len(value)) + value


def recv_message(sock):
    def exactly(count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise EOFError("peer closed the connection")
            data += chunk
        return data

    header = exactly(HEADER_LEN)
    length, kind = struct.unpack("!HB", header[16:HEADER_LEN])
    return kind, exactly(length - HEADER_LEN)


class Speaker:
    def __init__(self, local_ip, local_as, peer_ip, esi, etag, mac, ip, rt_admin):
        self.local_ip = local_ip
        self.local_as = int(local_as)
        self.peer_ip = peer_ip
        self.esi = bytes.fromhex(esi.replace(":", ""))
        self.etag = int(etag)
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.ip = socket.inet_aton(ip)
        self.rt_admin = int(rt_admin)
        self.sock = None
        self.lock = threading.Lock()

    def send(self, data):
        with self.lock:
            self.sock.sendall(data)

    def open_message(self):
        caps = struct.pack("!BBHBB", 1, 4, AFI_L2VPN, 0, SAFI_EVPN)
        caps += struct.pack("!BBI", 65, 4, self.local_as)
        opt = struct.pack("!BB", 2, len(caps)) + caps
        body = struct.pack("!BHH", 4, self.local_as, 10)
        body += socket.inet_aton("10.0.0.99")
        body += struct.pack("!B", len(opt)) + opt
        return message(OPEN, body)

    def rt2(self, labels, rd=5, mac=None, etag=None, ip=None):
        rd = (
            struct.pack("!H", 1)
            + socket.inet_aton(self.local_ip)
            + struct.pack("!H", rd)
        )
        etag = self.etag if etag is None else etag
        mac = self.mac if mac is None else mac
        ip = self.ip if ip is None else ip
        value = rd + self.esi + struct.pack("!I", etag)
        value += struct.pack("!B", 48) + mac + struct.pack("!B", 32) + ip
        for label in labels:
            value += struct.pack("!I", label)[1:]
        return struct.pack("!BB", 2, len(value)) + value

    def announce(self, labels, with_rt=True, **key):
        nh = socket.inet_aton(self.local_ip)
        mp_reach = struct.pack("!HBB", AFI_L2VPN, SAFI_EVPN, len(nh)) + nh + b"\x00"
        mp_reach += self.rt2(labels, **key)
        # RT type 0 (2-octet AS), sub-type 2; the VRF import matches on the
        # local-admin (L3VNI) only.
        rt = struct.pack("!BBHI", 0x00, 0x02, self.local_as, self.rt_admin)
        attrs = attribute(0x40, 1, struct.pack("!B", 0))
        attrs += attribute(0x40, 2, struct.pack("!BBI", 2, 1, self.local_as))
        if with_rt:
            attrs += attribute(0xC0, 16, rt)
        attrs += attribute(0x80, 14, mp_reach)
        self.send(message(UPDATE, struct.pack("!HH", 0, len(attrs)) + attrs))

    def withdraw(self, **key):
        mp_unreach = struct.pack("!HB", AFI_L2VPN, SAFI_EVPN) + self.rt2([0], **key)
        attrs = attribute(0x80, 15, mp_unreach)
        self.send(message(UPDATE, struct.pack("!HH", 0, len(attrs)) + attrs))

    def establish(self):
        self.sock = socket.create_connection(
            (self.peer_ip, 179), timeout=60, source_address=(self.local_ip, 0)
        )
        self.send(self.open_message())
        while True:
            kind, body = recv_message(self.sock)
            if kind == OPEN:
                self.send(message(KEEPALIVE, b""))
            elif kind == KEEPALIVE:
                self.sock.settimeout(None)
                log("session established")
                return
            elif kind == NOTIFICATION:
                raise RuntimeError("NOTIFICATION %s" % body[:2].hex())

    def keepalive_loop(self):
        while True:
            time.sleep(3)
            try:
                self.send(message(KEEPALIVE, b""))
            except OSError as err:
                log("keepalive failed: %s", err)
                return

    def reader_loop(self):
        while True:
            try:
                kind, body = recv_message(self.sock)
            except (OSError, EOFError) as err:
                log("read failed: %s", err)
                return
            if kind == NOTIFICATION:
                log("received NOTIFICATION %s", body[:2].hex())
                return


def parse_key(words):
    key = {}
    for word in words:
        name, _, value = word.partition("=")
        if name in ("rd", "etag"):
            key[name] = int(value)
        elif name == "mac":
            key[name] = bytes.fromhex(value.replace(":", ""))
        elif name == "ip":
            key[name] = socket.inet_aton(value)
    return key


def main():
    speaker = Speaker(*sys.argv[1:9])
    deadline = time.time() + 120
    while True:
        try:
            speaker.establish()
            break
        except (OSError, EOFError, RuntimeError) as err:
            if speaker.sock is not None:
                speaker.sock.close()
            if time.time() >= deadline:
                raise
            log("handshake failed (%s), retrying", err)
            time.sleep(1)

    threading.Thread(target=speaker.keepalive_loop, daemon=True).start()
    threading.Thread(target=speaker.reader_loop, daemon=True).start()

    for line in sys.stdin:
        words = line.split()
        labels = [int(w) for w in words[1:] if "=" not in w]
        key = parse_key(words[1:])
        if words[:1] == ["announce"]:
            log("announce %s", words[1:])
            speaker.announce(labels, **key)
        elif words[:1] == ["announce-nort"]:
            log("announce %s without extended communities", words[1:])
            speaker.announce(labels, with_rt=False, **key)
        elif words[:1] == ["withdraw"]:
            log("withdraw %s", words[1:])
            speaker.withdraw(**key)


if __name__ == "__main__":
    main()
