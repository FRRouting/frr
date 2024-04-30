#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (C) 2023 Tomas Hlavacek (tmshlvck@gmail.com)

from typing import List, Tuple, Callable, Type
import socket
import threading
import socketserver
import struct
import ipaddress
import csv
import os
import sys

LISTEN_HOST, LISTEN_PORT = "0.0.0.0", 15432
VRPS_FILE = os.path.join(sys.path[0], "vrps.csv")


def dbg(m: str):
    print(m)
    sys.stdout.flush()


class RTRDatabase(object):
    def __init__(self, vrps_file: str) -> None:
        self.last_serial = 0
        self.ann4 = []
        self.ann6 = []
        self.withdraw4 = []
        self.withdraw6 = []

        with open(vrps_file, "r") as fh:
            for rasn, rnet, rmaxlen, _ in csv.reader(fh):
                try:
                    net = ipaddress.ip_network(rnet)
                    asn = int(rasn[2:])
                    maxlen = int(rmaxlen)
                    if net.version == 6:
                        self.ann6.append((asn, str(net), maxlen))
                    elif net.version == 4:
                        self.ann4.append((asn, str(net), maxlen))
                    else:
                        raise ValueError(f"Unknown AFI: {net.version}")
                except Exception as e:
                    dbg(
                        f"VRPS load: ignoring {str((rasn, rnet,rmaxlen))} because {str(e)}"
                    )

    def get_serial(self) -> int:
        return self.last_serial

    def set_serial(self, serial: int) -> None:
        self.last_serial = serial

    def get_announcements4(self, serial: int = 0) -> List[Tuple[int, str, int]]:
        if serial > self.last_serial:
            return self.ann4
        else:
            return []

    def get_withdrawals4(self, serial: int = 0) -> List[Tuple[int, str, int]]:
        if serial > self.last_serial:
            return self.withdraw4
        else:
            return []

    def get_announcements6(self, serial: int = 0) -> List[Tuple[int, str, int]]:
        if serial > self.last_serial:
            return self.ann6
        else:
            return []

    def get_withdrawals6(self, serial: int = 0) -> List[Tuple[int, str, int]]:
        if serial > self.last_serial:
            return self.withdraw6
        else:
            return []


class RTRConnHandler(socketserver.BaseRequestHandler):
    PROTO_VERSION = 0

    def setup(self) -> None:
        self.session_id = 2345
        self.serial = 1024

        dbg(f"New connection from: {str(self.client_address)} ")
        # TODO: register for notifies

    def finish(self) -> None:
        pass
        # TODO: de-register

    HEADER_LEN = 8

    def decode_header(self, buf: bytes) -> Tuple[int, int, int, int]:
        # common header in all received packets
        return struct.unpack("!BBHI", buf)
        # reutnrs (proto_ver, pdu_type, sess_id, length)

    SERNOTIFY_TYPE = 0
    SERNOTIFY_LEN = 12

    def send_sernotify(self, serial: int) -> None:
        # serial notify PDU
        dbg(f"<Serial Notify session_id={self.session_id} serial={serial}")
        self.request.send(
            struct.pack(
                "!BBHII",
                self.PROTO_VERSION,
                self.SERNOTIFY_TYPE,
                self.session_id,
                self.SERNOTIFY_LEN,
                serial,
            )
        )

    CACHERESPONSE_TYPE = 3
    CACHERESPONSE_LEN = 8

    def send_cacheresponse(self) -> None:
        # cache response PDU
        dbg(f"<Cache response session_id={self.session_id}")
        self.request.send(
            struct.pack(
                "!BBHI",
                self.PROTO_VERSION,
                self.CACHERESPONSE_TYPE,
                self.session_id,
                self.CACHERESPONSE_LEN,
            )
        )

    FLAGS_ANNOUNCE = 1
    FLAGS_WITHDRAW = 0

    IPV4_TYPE = 4
    IPV4_LEN = 20

    def send_ipv4(self, ipnet: str, asn: int, maxlen: int, flags: int):
        # IPv4 PDU
        dbg(f"<IPv4 net={ipnet} asn={asn} maxlen={maxlen} flags={flags}")
        ip = ipaddress.IPv4Network(ipnet)
        self.request.send(
            struct.pack(
                "!BBHIBBBB4sI",
                self.PROTO_VERSION,
                self.IPV4_TYPE,
                0,
                self.IPV4_LEN,
                flags,
                ip.prefixlen,
                maxlen,
                0,
                ip.network_address.packed,
                asn,
            )
        )

    def announce_ipv4(self, ipnet, asn, maxlen):
        self.send_ipv4(ipnet, asn, maxlen, self.FLAGS_ANNOUNCE)

    def withdraw_ipv4(self, ipnet, asn, maxlen):
        self.send_ipv4(ipnet, asn, maxlen, self.FLAGS_WITHDRAW)

    IPV6_TYPE = 6
    IPV6_LEN = 32

    def send_ipv6(self, ipnet: str, asn: int, maxlen: int, flags: int):
        # IPv6 PDU
        dbg(f"<IPv6 net={ipnet} asn={asn} maxlen={maxlen} flags={flags}")
        ip = ipaddress.IPv6Network(ipnet)
        self.request.send(
            struct.pack(
                "!BBHIBBBB16sI",
                self.PROTO_VERSION,
                self.IPV6_TYPE,
                0,
                self.IPV6_LEN,
                flags,
                ip.prefixlen,
                maxlen,
                0,
                ip.network_address.packed,
                asn,
            )
        )

    def announce_ipv6(self, ipnet: str, asn: int, maxlen: int):
        self.send_ipv6(ipnet, asn, maxlen, self.FLAGS_ANNOUNCE)

    def withdraw_ipv6(self, ipnet: str, asn: int, maxlen: int):
        self.send_ipv6(ipnet, asn, maxlen, self.FLAGS_WITHDRAW)

    EOD_TYPE = 7
    EOD_LEN = 12

    def send_endofdata(self, serial: int):
        # end of data PDU
        dbg(f"<End of Data session_id={self.session_id} serial={serial}")
        self.server.db.set_serial(serial)
        self.request.send(
            struct.pack(
                "!BBHII",
                self.PROTO_VERSION,
                self.EOD_TYPE,
                self.session_id,
                self.EOD_LEN,
                serial,
            )
        )

    CACHERESET_TYPE = 8
    CACHERESET_LEN = 8

    def send_cachereset(self):
        # cache reset PDU
        dbg("<Cache Reset")
        self.request.send(
            struct.pack(
                "!BBHI",
                self.PROTO_VERSION,
                self.CACHERESET_TYPE,
                0,
                self.CACHERESET_LEN,
            )
        )

    SERIAL_QUERY_TYPE = 1
    SERIAL_QUERY_LEN = 12

    def handle_serial_query(self, buf: bytes, sess_id: int):
        serial = struct.unpack("!I", buf)[0]
        dbg(f">Serial query: {serial}")
        if sess_id:
            self.server.db.set_serial(serial)
        else:
            self.server.db.set_serial(0)
        self.send_cacheresponse()

        for asn, ipnet, maxlen in self.server.db.get_announcements4(serial):
            self.announce_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_withdrawals4(serial):
            self.withdraw_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_announcements6(serial):
            self.announce_ipv6(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_withdrawals6(serial):
            self.withdraw_ipv6(ipnet, asn, maxlen)

        self.send_endofdata(self.serial)

    RESET_TYPE = 2

    def handle_reset(self):
        dbg(">Reset")
        self.session_id += 1
        self.server.db.set_serial(0)
        self.send_cacheresponse()

        for asn, ipnet, maxlen in self.server.db.get_announcements4(self.serial):
            self.announce_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_announcements6(self.serial):
            self.announce_ipv6(ipnet, asn, maxlen)

        self.send_endofdata(self.serial)

    ERROR_TYPE = 10

    def handle_error(self, buf: bytes):
        dbg(f">Error: {str(buf)}")
        self.server.shutdown()
        self.server.stopped = True
        raise ConnectionError("Received an RPKI error packet from FRR. Exiting")

    def handle(self):
        while True:
            b = self.request.recv(self.HEADER_LEN, socket.MSG_WAITALL)
            if len(b) == 0:
                break
            proto_ver, pdu_type, sess_id, length = self.decode_header(b)
            dbg(
                f">Header proto_ver={proto_ver} pdu_type={pdu_type} sess_id={sess_id} length={length}"
            )

            if sess_id:
                self.session_id = sess_id

            if pdu_type == self.SERIAL_QUERY_TYPE:
                b = self.request.recv(
                    self.SERIAL_QUERY_LEN - self.HEADER_LEN, socket.MSG_WAITALL
                )
                self.handle_serial_query(b, sess_id)

            elif pdu_type == self.RESET_TYPE:
                self.handle_reset()

            elif pdu_type == self.ERROR_TYPE:
                b = self.request.recv(length - self.HEADER_LEN, socket.MSG_WAITALL)
                self.handle_error(b)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(
        self, bind: Tuple[str, int], handler: Type[RTRConnHandler], db: RTRDatabase
    ) -> None:
        super().__init__(bind, handler)
        self.db = db


def main():
    db = RTRDatabase(VRPS_FILE)
    server = ThreadedTCPServer((LISTEN_HOST, LISTEN_PORT), RTRConnHandler, db)
    dbg(f"Server listening on {LISTEN_HOST} port {LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        f = open(sys.argv[1], "w")
        sys.__stdout__ = f
        sys.stdout = f
        sys.__stderr__ = f
        sys.stderr = f

    main()
