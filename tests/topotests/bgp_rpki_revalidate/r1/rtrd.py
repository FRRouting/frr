#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Minimal RPKI-to-Router (RFC 6810, version 0) cache for topotests.
#
# Unlike the static cache in bgp_rpki_topo1, the VRP set can change while the
# session is up: the CSV file given on the command line is re-read on every
# Serial Query, and the router receives the difference to the serial it
# already has (announcements and withdrawals), as a real cache would send it.

import csv
import ipaddress
import socket
import socketserver
import struct
import sys
import threading

LISTEN_HOST, LISTEN_PORT = "0.0.0.0", 15432
SESSION_ID = 2345

PROTO_VERSION = 0
SERIAL_QUERY_TYPE = 1
RESET_QUERY_TYPE = 2
CACHE_RESPONSE_TYPE = 3
IPV4_PREFIX_TYPE = 4
IPV6_PREFIX_TYPE = 6
END_OF_DATA_TYPE = 7
CACHE_RESET_TYPE = 8
ERROR_REPORT_TYPE = 10

HEADER_LEN = 8
FLAGS_ANNOUNCE = 1
FLAGS_WITHDRAW = 0


def dbg(m):
    print(m)
    sys.stdout.flush()


def load_vrps(path):
    vrps = set()
    with open(path, "r") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0] == "ASN":
                continue
            rasn, rnet, rmaxlen = row[0], row[1], row[2]
            net = ipaddress.ip_network(rnet)
            vrps.add((int(rasn[2:]), str(net), int(rmaxlen)))
    return frozenset(vrps)


class RTRDatabase:
    def __init__(self, vrps_file):
        self.vrps_file = vrps_file
        self.lock = threading.Lock()
        self.serial = 1
        self.history = {self.serial: load_vrps(vrps_file)}

    def refresh(self):
        """Re-read the VRP file, bump the serial if it changed."""
        vrps = load_vrps(self.vrps_file)
        with self.lock:
            if vrps != self.history[self.serial]:
                self.serial += 1
                self.history[self.serial] = vrps
                dbg(f"VRP set changed, serial is now {self.serial}")
            return self.serial

    def current(self):
        with self.lock:
            return self.serial, self.history[self.serial]

    def delta(self, serial):
        """(announce, withdraw, new serial) from serial, or None if unknown."""
        with self.lock:
            if serial not in self.history:
                return None
            old, new = self.history[serial], self.history[self.serial]
            return new - old, old - new, self.serial


class RTRConnHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.pending = []

    def send(self, data):
        # Queued, and sent with flush() in one go, as a real cache would
        self.pending.append(data)

    def flush(self):
        self.request.sendall(b"".join(self.pending))
        self.pending = []

    def send_cache_response(self):
        self.send(
            struct.pack("!BBHI", PROTO_VERSION, CACHE_RESPONSE_TYPE, SESSION_ID, 8)
        )

    def send_prefix(self, vrp, flags):
        asn, prefix, maxlen = vrp
        net = ipaddress.ip_network(prefix)
        dbg(f"<prefix {prefix} maxlen {maxlen} AS{asn} flags {flags}")
        if net.version == 4:
            fmt, ptype, plen = "!BBHIBBBB4sI", IPV4_PREFIX_TYPE, 20
        else:
            fmt, ptype, plen = "!BBHIBBBB16sI", IPV6_PREFIX_TYPE, 32
        self.send(
            struct.pack(
                fmt,
                PROTO_VERSION,
                ptype,
                0,
                plen,
                flags,
                net.prefixlen,
                maxlen,
                0,
                net.network_address.packed,
                asn,
            )
        )

    def send_end_of_data(self, serial):
        dbg(f"<End of Data serial {serial}")
        self.send(
            struct.pack(
                "!BBHII", PROTO_VERSION, END_OF_DATA_TYPE, SESSION_ID, 12, serial
            )
        )

    def send_cache_reset(self):
        dbg("<Cache Reset")
        self.send(struct.pack("!BBHI", PROTO_VERSION, CACHE_RESET_TYPE, 0, 8))

    def handle_reset_query(self):
        self.server.db.refresh()
        serial, vrps = self.server.db.current()
        dbg(f">Reset Query, sending {len(vrps)} VRPs, serial {serial}")
        self.send_cache_response()
        for vrp in sorted(vrps):
            self.send_prefix(vrp, FLAGS_ANNOUNCE)
        self.send_end_of_data(serial)
        self.flush()

    def handle_serial_query(self, serial):
        self.server.db.refresh()
        delta = self.server.db.delta(serial)
        if delta is None:
            dbg(f">Serial Query {serial}: unknown serial")
            self.send_cache_reset()
            self.flush()
            return
        announce, withdraw, new_serial = delta
        dbg(
            f">Serial Query {serial}: +{len(announce)} -{len(withdraw)}, serial {new_serial}"
        )
        self.send_cache_response()
        for vrp in sorted(withdraw):
            self.send_prefix(vrp, FLAGS_WITHDRAW)
        for vrp in sorted(announce):
            self.send_prefix(vrp, FLAGS_ANNOUNCE)
        self.send_end_of_data(new_serial)
        self.flush()

    def handle(self):
        dbg(f"New connection from {self.client_address}")
        while True:
            hdr = self.request.recv(HEADER_LEN, socket.MSG_WAITALL)
            if len(hdr) < HEADER_LEN:
                break
            _, pdu_type, _, length = struct.unpack("!BBHI", hdr)
            body = b""
            if length > HEADER_LEN:
                body = self.request.recv(length - HEADER_LEN, socket.MSG_WAITALL)

            if pdu_type == SERIAL_QUERY_TYPE:
                self.handle_serial_query(struct.unpack("!I", body[:4])[0])
            elif pdu_type == RESET_QUERY_TYPE:
                self.handle_reset_query()
            elif pdu_type == ERROR_REPORT_TYPE:
                dbg(f">Error Report: {body!r}")
                break


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, bind, handler, db):
        super().__init__(bind, handler)
        self.db = db


def main():
    db = RTRDatabase(sys.argv[2])
    server = ThreadedTCPServer((LISTEN_HOST, LISTEN_PORT), RTRConnHandler, db)
    dbg(f"Server listening on {LISTEN_HOST} port {LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    f = open(sys.argv[1], "w")
    sys.stdout = f
    sys.stderr = f
    main()
