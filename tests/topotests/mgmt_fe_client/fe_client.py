#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# November 27 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
# noqa: E501
#
import argparse
import errno
import logging
import os
import socket
import sys
import time
from pathlib import Path

import mgmt_pb2

MGMT_MSG_MARKER_PROTOBUF = b"\000###"
MGMT_MSG_MARKER_NATIVE = b"\001###"


def __parse_args():
    MPATH = "/var/run/frr/mgmtd_fe.sock"
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help="Be verbose")
    parser.add_argument("--server", default=MPATH, help="path to server socket")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")

    return args


def __server_connect(spath):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    logging.debug("Connecting to server on %s", spath)
    while ec := sock.connect_ex(str(spath)):
        logging.warn("retry server connection in .5s (%s)", os.strerror(ec))
        time.sleep(0.5)
    logging.info("Connected to server on %s", spath)
    return sock


def mgmt_pb_recv_msg(sock, msg):
    """Receive a mgmtd protobuf message from a stream socket."""
    marker = sock.recv(4)
    assert marker in (MGMT_MSG_MARKER_PROTOBUF, MGMT_MSG_MARKER_NATIVE)

    msize = int.from_bytes(sock.recv(4), byteorder="big")
    mdata = sock.recv(msize)

    msg.ParseFromString(mdata)
    return msg


def mgmt_pb_send_msg(sock, msg):
    """Send a mgmtd protobuf message from a stream socket."""
    marker = MGMT_MSG_MARKER_PROTOBUF
    mdata = msg.SerializeToString()
    msize = int.to_bytes(len(mdata), byteorder="big", length=4)
    sock.send(marker)
    sock.send(msize)
    sock.send(mdata)


def create_session(sock):
    req = mgmt_pb2.FeRegisterReq()
    req.client_name = "test-client"
    mgmt_pb_send_msg(sock, req)
    logging.debug("Sent FeRegisterReq: %s", req)

    req = mgmt_pb2.FeSessionReq()
    req.create = 1
    req.client_conn_id = 1
    mgmt_pb_send_msg(sock, req)
    logging.debug("Sent FeSessionReq: %s", req)

    reply = mgmt_pb_recv_msg(sock, mgmt_pb2.FeSessionReply())
    logging.debug("Received FeSessionReply: %s", reply)


def __main():
    args = __parse_args()
    sock = __server_connect(Path(args.server))
    create_session(sock)


def main():
    try:
        __main()
    except KeyboardInterrupt:
        logging.info("Exiting")
    except Exception as error:
        logging.error("Unexpected error exiting: %s", error, exc_info=True)


if __name__ == "__main__":
    main()
