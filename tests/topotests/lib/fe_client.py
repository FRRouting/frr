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
import json
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

CWD = os.path.dirname(os.path.realpath(__file__))

# This is painful but works if you have installed protobuf would be better if we
# actually built and installed these but ... python packaging.
try:
    sys.path.append(os.path.dirname(CWD))
    from munet.base import commander

    commander.cmd_raises(f"protoc --python_out={CWD} -I {CWD}/../../../lib mgmt.proto")
except Exception as error:
    logging.error("can't create protobuf definition modules %s", error)
    raise

try:
    sys.path[0:0] = "."
    import mgmt_pb2
except Exception as error:
    logging.error("can't import proto definition modules %s", error)
    raise

CANDIDATE_DS = mgmt_pb2.DatastoreId.CANDIDATE_DS
OPERATIONAL_DS = mgmt_pb2.DatastoreId.OPERATIONAL_DS
RUNNING_DS = mgmt_pb2.DatastoreId.RUNNING_DS
STARTUP_DS = mgmt_pb2.DatastoreId.STARTUP_DS

# =====================
# Native message values
# =====================

MGMT_MSG_MARKER_PROTOBUF = b"\000###"
MGMT_MSG_MARKER_NATIVE = b"\001###"

#
# Native message formats
#
MSG_HDR_FMT = "=H2xIQQ"
HDR_FIELD_CODE = 0
HDR_FIELD_VSPLIT = 1
HDR_FIELD_SESS_ID = 2
HDR_FIELD_REQ_ID = 3

MSG_ERROR_FMT = "=h6x"
ERROR_FIELD_ERROR = 0

# MSG_GET_TREE_FMT = "=B7x"
# GET_TREE_FIELD_RESULT_TYPE = 0

MSG_TREE_DATA_FMT = "=bBB5x"
TREE_DATA_FIELD_PARTIAL_ERROR = 0
TREE_DATA_FIELD_RESULT_TYPE = 1
TREE_DATA_FIELD_MORE = 2

MSG_GET_DATA_FMT = "=BB6x"
GET_DATA_FIELD_RESULT_TYPE = 0
GET_DATA_FIELD_FLAGS = 1
GET_DATA_FLAG_STATE = 0x1
GET_DATA_FLAG_CONFIG = 0x2
GET_DATA_FLAG_EXACT = 0x4

MSG_NOTIFY_FMT = "=B7x"
NOTIFY_FIELD_RESULT_TYPE = 0

#
# Native message codes
#
MSG_CODE_ERROR = 0
# MSG_CODE_GET_TREE = 1
MSG_CODE_TREE_DATA = 2
MSG_CODE_GET_DATA = 3
MSG_CODE_NOTIFY = 4

msg_native_formats = {
    MSG_CODE_ERROR: MSG_ERROR_FMT,
    # MSG_CODE_GET_TREE: MSG_GET_TREE_FMT,
    MSG_CODE_TREE_DATA: MSG_TREE_DATA_FMT,
    MSG_CODE_GET_DATA: MSG_GET_DATA_FMT,
    MSG_CODE_NOTIFY: MSG_NOTIFY_FMT,
}


# Result formats
MSG_FORMAT_XML = 1
MSG_FORMAT_JSON = 2
MSG_FORMAT_LYB = 3


def cstr(mdata):
    assert mdata[-1] == 0
    return mdata[:-1]


class FEClientError(Exception):
    pass


class PBMessageError(FEClientError):
    def __init__(self, msg, errstr):
        self.msg = msg
        # self.sess_id = mhdr[HDR_FIELD_SESS_ID]
        # self.req_id = mhdr[HDR_FIELD_REQ_ID]
        self.error = -1
        self.errstr = errstr
        super().__init__(f"PBMessageError: {self.errstr}: {msg}")


class NativeMessageError(FEClientError):
    def __init__(self, mhdr, mfixed, mdata):
        self.mhdr = mhdr
        self.sess_id = mhdr[HDR_FIELD_SESS_ID]
        self.req_id = mhdr[HDR_FIELD_REQ_ID]
        self.error = mfixed[0]
        self.errstr = cstr(mdata)
        super().__init__(
            "NativeMessageError: "
            f"session {self.sess_id} reqid {self.req_id} "
            f"error {self.error}: {self.errstr}"
        )


#
# Low-level socket functions
#


def recv_wait(sock, size):
    """Receive a fixed number of bytes from a stream socket."""
    data = b""
    while len(data) < size:
        newdata = sock.recv(size - len(data))
        if not newdata:
            raise Exception("Socket closed")
        data += newdata
    return data


def recv_msg(sock):
    marker = recv_wait(sock, 4)
    assert marker in (MGMT_MSG_MARKER_PROTOBUF, MGMT_MSG_MARKER_NATIVE)

    msize = int.from_bytes(recv_wait(sock, 4), byteorder=sys.byteorder)
    assert msize >= 8
    mdata = recv_wait(sock, msize - 8) if msize > 8 else b""

    return mdata, marker == MGMT_MSG_MARKER_NATIVE


def send_msg(sock, marker, mdata):
    """Send a mgmtd native message to a stream socket."""
    msize = int.to_bytes(len(mdata) + 8, byteorder=sys.byteorder, length=4)
    sock.send(marker)
    sock.send(msize)
    sock.send(mdata)


class Session:
    """A session to the mgmtd server."""

    client_id = 1

    def __init__(self, sock):
        self.sock = sock
        self.next_req_id = 1

        req = mgmt_pb2.FeMessage()
        req.register_req.client_name = "test-client"
        self.send_pb_msg(req)
        logging.debug("Sent FeRegisterReq: %s", req)

        req = mgmt_pb2.FeMessage()
        req.session_req.create = 1
        req.session_req.client_conn_id = Session.client_id
        Session.client_id += 1
        self.send_pb_msg(req)
        logging.debug("Sent FeSessionReq: %s", req)

        reply = self.recv_pb_msg(mgmt_pb2.FeMessage())
        logging.debug("Received FeSessionReply: %s", repr(reply))

        assert reply.session_reply.success
        self.sess_id = reply.session_reply.session_id

    def close(self, clean=True):
        if clean:
            req = mgmt_pb2.FeMessage()
            req.session_req.create = 0
            req.session_req.sess_id = self.sess_id
            self.send_pb_msg(req)
        self.sock.close()
        self.sock = None

    def get_next_req_id(self):
        req_id = self.next_req_id
        self.next_req_id += 1
        return req_id

    # --------------------------
    # Protobuf message functions
    # --------------------------

    def recv_pb_msg(self, msg):
        """Receive a protobuf message."""
        mdata, native = recv_msg(self.sock)
        assert not native

        msg.ParseFromString(mdata)

        req = getattr(msg, msg.WhichOneof("message"))
        if req.HasField("success"):
            if not req.success:
                raise PBMessageError(msg, req.error_if_any)

        return msg

    def send_pb_msg(self, msg):
        """Send a protobuf message."""
        mdata = msg.SerializeToString()
        return send_msg(self.sock, MGMT_MSG_MARKER_PROTOBUF, mdata)

    # ------------------------
    # Native message functions
    # ------------------------

    def recv_native_msg(self):
        """Send a native message."""
        mdata, native = recv_msg(self.sock)
        assert native

        hlen = struct.calcsize(MSG_HDR_FMT)
        hdata = mdata[:hlen]
        mhdr = struct.unpack(MSG_HDR_FMT, hdata)
        code = mhdr[0]

        if code not in msg_native_formats:
            raise Exception(f"Unknown native msg code {code} rcvd")

        mfmt = msg_native_formats[code]
        flen = struct.calcsize(mfmt)
        fdata = mdata[hlen : hlen + flen]
        mfixed = struct.unpack(mfmt, fdata)
        mdata = mdata[hlen + flen :]

        if code == MSG_ERROR_FMT:
            raise NativeMessageError(mhdr, mfixed, mdata)

        return mhdr, mfixed, mdata

    def send_native_msg(self, mdata):
        """Send a native message."""
        return send_msg(self.sock, MGMT_MSG_MARKER_NATIVE, mdata)

    def get_native_msg_header(self, msg_code):
        req_id = self.get_next_req_id()
        hdata = struct.pack(MSG_HDR_FMT, msg_code, 0, self.sess_id, req_id)
        return hdata, req_id

    # -----------------------
    # Front-end API Fountains
    # -----------------------

    def lock(self, lock=True, ds_id=mgmt_pb2.CANDIDATE_DS):
        req = mgmt_pb2.FeMessage()
        req.lockds_req.session_id = self.sess_id
        req.lockds_req.req_id = self.get_next_req_id()
        req.lockds_req.ds_id = ds_id
        req.lockds_req.lock = lock
        self.send_pb_msg(req)
        logging.debug("Sent LockDsReq: %s", req)

        reply = self.recv_pb_msg(mgmt_pb2.FeMessage())
        logging.debug("Received Reply: %s", repr(reply))
        assert reply.lockds_reply.success

    def get_data(self, query, data=True, config=False):
        # Create the message
        mdata, req_id = self.get_native_msg_header(MSG_CODE_GET_DATA)
        flags = GET_DATA_FLAG_STATE if data else 0
        flags |= GET_DATA_FLAG_CONFIG if config else 0
        mdata += struct.pack(MSG_GET_DATA_FMT, MSG_FORMAT_JSON, flags)
        mdata += query.encode("utf-8") + b"\x00"

        self.send_native_msg(mdata)
        logging.debug("Sent GET-TREE")

        mhdr, mfixed, mdata = self.recv_native_msg()
        assert mdata[-1] == 0
        result = mdata[:-1].decode("utf-8")

        logging.debug("Received GET: %s: %s", mfixed, mdata)
        return result

    # def subscribe(self, notif_xpath):
    #     # Create the message
    #     mdata, req_id = self.get_native_msg_header(MSG_CODE_SUBSCRIBE)
    #     mdata += struct.pack(MSG_SUBSCRIBE_FMT, MSG_FORMAT_JSON)
    #     mdata += notif_xpath.encode("utf-8") + b"\x00"

    #     self.send_native_msg(mdata)
    #     logging.debug("Sent SUBSCRIBE")

    def recv_notify(self, xpaths=None):
        while True:
            logging.debug("Waiting for Notify Message")
            mhdr, mfixed, mdata = self.recv_native_msg()
            if mhdr[HDR_FIELD_CODE] == MSG_CODE_NOTIFY:
                logging.debug("Received Notify Message: %s: %s", mfixed, mdata)
            else:
                raise Exception(f"Received NON-NOTIFY Message: {mfixed}: {mdata}")

            vsplit = mhdr[HDR_FIELD_VSPLIT]
            assert mdata[vsplit - 1] == 0
            xpath = mdata[: vsplit - 1].decode("utf-8")

            assert mdata[-1] == 0
            result = mdata[vsplit:-1].decode("utf-8")

            if not xpaths:
                return result
            js = json.loads(result)
            key = [x for x in js.keys()][0]
            for xpath in xpaths:
                if key.startswith(xpath):
                    return result
            logging.debug("'%s' didn't match xpath filters", key)


def __parse_args():
    MPATH = "/var/run/frr/mgmtd_fe.sock"
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l", "--listen", nargs="*", metavar="XPATH", help="xpath[s] to listen for"
    )
    parser.add_argument(
        "--notify-count",
        type=int,
        default=1,
        help="Number of notifications to listen for 0 for infinite",
    )
    parser.add_argument(
        "-b", "--both", action="store_true", help="return both config and data"
    )
    parser.add_argument(
        "-c", "--config-only", action="store_true", help="return config only"
    )
    parser.add_argument(
        "-q", "--query", nargs="+", metavar="XPATH", help="xpath[s] to query"
    )
    parser.add_argument("-s", "--server", default=MPATH, help="path to server socket")
    parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose")
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


def __main():
    args = __parse_args()
    sock = __server_connect(Path(args.server))
    sess = Session(sock)

    if args.query:
        # Performa an xpath query
        # query = "/frr-interface:lib/interface/state/mtu"
        for query in args.query:
            logging.info("Sending query: %s", query)
            result = sess.get_data(
                query, data=not args.config_only, config=(args.both or args.config_only)
            )
            print(result)

    if args.listen is not None:
        i = args.notify_count
        while i > 0 or args.notify_count == 0:
            notif = sess.recv_notify(args.listen)
            print(notif)
            i -= 1


def main():
    try:
        __main()
    except KeyboardInterrupt:
        logging.info("Exiting")
    except Exception as error:
        logging.error("Unexpected error exiting: %s", error, exc_info=True)


if __name__ == "__main__":
    main()
