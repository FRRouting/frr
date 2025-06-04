#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# November 27 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
# noqa: E501
#
"""A MGMTD front-end client."""
import argparse
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(CWD))

from munet.base import Timeout

RUNNING_DS = 1
CANDIDATE_DS = 2
OPERATIONAL_DS = 3

datastore_name = {
    RUNNING_DS: "running",
    CANDIDATE_DS: "candidate",
    OPERATIONAL_DS: "operational",
}

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

MSG_NOTIFY_FMT = "=BB6x"
NOTIFY_FIELD_RESULT_TYPE = 0
NOTIFY_FIELD_OP = 1
NOTIFY_OP_NOTIFICATION = 0
NOTIFY_OP_REPLACE = 1
NOTIFY_OP_DELETE = 2
NOTIFY_OP_PATCH = 3
NOTIFY_OP_GET_SYNC = 4

MSG_NOTIFY_SELECT_FMT = "=B7x"

MSG_SESSION_REQ_FMT = "=B7x"

MSG_SESSION_REPLY_FMT = "=B7x"
SESSION_REPLY_FIELD_CREATED = 0

MSG_LOCK_FMT = "=BB6x"
LOCK_FIELD_DATASTORE = 0
LOCK_FIELD_LOCK = 1

MSG_LOCK_REPLY_FMT = "=BB6x"
LOCK_REPLY_FIELD_DATASTORE = 0
LOCK_REPLY_FIELD_LOCK = 1

MSG_COMMIT_FMT = "=BBBB4x"
COMMIT_FIELD_SOURCE = 0
COMMIT_FIELD_TARGET = 1
COMMIT_FIELD_ACTION = 2
COMMIT_ACTION_APPLY = 0
COMMIT_ACTION_ABORT = 1
COMMIT_ACTION_VALIDATE = 2
COMMIT_FIELD_UNLOCK = 3

MSG_COMMIT_REPLY_FMT = "=BBBB4x"
COMMIT_REPLY_FIELD_SOURCE = 0
COMMIT_REPLY_FIELD_TARGET = 1
COMMIT_REPLY_FIELD_ACTION = 2
COMMIT_REPLY_ACTION_APPLY = COMMIT_ACTION_APPLY
COMMIT_REPLY_ACTION_ABORT = COMMIT_ACTION_ABORT
COMMIT_REPLY_ACTION_VALIDATE = COMMIT_ACTION_VALIDATE
COMMIT_REPLY_FIELD_UNLOCK = 3

#
# Native message codes
#
MSG_CODE_ERROR = 0
# MSG_CODE_GET_TREE = 1
MSG_CODE_TREE_DATA = 2
MSG_CODE_GET_DATA = 3
MSG_CODE_NOTIFY = 4
MSG_CODE_NOTIFY_SELECT = 9
MSG_CODE_SESSION_REQ = 10
MSG_CODE_SESSION_REPLY = 11
MSG_CODE_LOCK = 19
MSG_CODE_LOCK_REPLY = 20
MSG_CODE_COMMIT = 21
MSG_CODE_COMMIT_REPLY = 22

msg_native_formats = {
    MSG_CODE_ERROR: MSG_ERROR_FMT,
    # MSG_CODE_GET_TREE: MSG_GET_TREE_FMT,
    MSG_CODE_TREE_DATA: MSG_TREE_DATA_FMT,
    MSG_CODE_GET_DATA: MSG_GET_DATA_FMT,
    MSG_CODE_NOTIFY: MSG_NOTIFY_FMT,
    MSG_CODE_NOTIFY_SELECT: MSG_NOTIFY_SELECT_FMT,
    MSG_CODE_SESSION_REQ: MSG_SESSION_REQ_FMT,
    MSG_CODE_SESSION_REPLY: MSG_SESSION_REPLY_FMT,
    MSG_CODE_LOCK: MSG_LOCK_FMT,
    MSG_CODE_LOCK_REPLY: MSG_LOCK_REPLY_FMT,
    MSG_CODE_COMMIT: MSG_COMMIT_FMT,
    MSG_CODE_COMMIT_REPLY: MSG_COMMIT_REPLY_FMT,
}


# Result formats
MSG_FORMAT_XML = 1
MSG_FORMAT_JSON = 2
MSG_FORMAT_LYB = 3


def cstr(mdata):
    """Convert a null-term byte array into a string, excluding the null terminator."""
    assert mdata[-1] == 0
    return mdata[:-1]


class FEClientError(Exception):
    """Base class for frontend client errors."""

    pass


class PBMessageError(FEClientError):
    """Exception for errors related to protobuf messages."""

    def __init__(self, msg, errstr):
        """Initialize PBMessageError with message and error string."""
        self.msg = msg
        # self.sess_id = mhdr[HDR_FIELD_SESS_ID]
        # self.req_id = mhdr[HDR_FIELD_REQ_ID]
        self.error = -1
        self.errstr = errstr
        super().__init__(f"PBMessageError: {self.errstr}: {msg}")


class NativeMessageError(FEClientError):
    """Exception for errors related to native messages."""

    def __init__(self, mhdr, mfixed, mdata):
        """Initialize NativeMessageError with message header, fixed fields, and data."""
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
    """Receive a message from the socket, ensuring it has a valid marker."""
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
        """Initialize a session with the mgmtd server."""
        self.sock = sock
        self.next_req_id = 1

        # Establish a native session
        self.sess_id = 0
        mdata, _ = self.get_native_msg_header(MSG_CODE_SESSION_REQ)
        mdata += struct.pack(MSG_SESSION_REQ_FMT, MSG_FORMAT_JSON)
        mdata += "test-client".encode("utf-8") + b"\x00"
        self.send_native_msg(mdata)
        logging.debug("Sent native SESSION-REQ")

        mhdr, mfixed, mdata = self.recv_native_msg()
        if mhdr[HDR_FIELD_CODE] == MSG_CODE_SESSION_REPLY:
            logging.debug(
                "Recv native SESSION-REPLY Message: sess-id %u: fixed: %s: %s",
                mhdr[HDR_FIELD_SESS_ID],
                mfixed,
                mdata,
            )
        else:
            raise Exception(f"Recv NON-SESSION-REPLY Message: {mfixed}: {mdata}")
        assert mfixed[0]
        self.sess_id = mhdr[HDR_FIELD_SESS_ID]

    def close(self, clean=True):
        """Close the session."""
        if clean:
            # sending session_req with a non-zero session ID destroys the session.
            mdata, _ = self.get_native_msg_header(MSG_CODE_SESSION_REQ)
            mdata += struct.pack(MSG_SESSION_REQ_FMT, MSG_FORMAT_JSON)
            self.send_native_msg(mdata)
            logging.debug("Sent native SESSION-REQ (destroy)")
        self.sock.close()
        self.sock = None

    def get_next_req_id(self):
        """Generate the next request ID for a new session."""
        req_id = self.next_req_id
        self.next_req_id += 1
        return req_id

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
        """Send a native message to the mgmtd server."""
        return send_msg(self.sock, MGMT_MSG_MARKER_NATIVE, mdata)

    def get_native_msg_header(self, msg_code):
        """Generate a native message header for a given message code."""
        req_id = self.get_next_req_id()
        hdata = struct.pack(MSG_HDR_FMT, msg_code, 0, self.sess_id, req_id)
        return hdata, req_id

    # -----------------------
    # Front-end API Fountains
    # -----------------------

    def lock(self, lock=True, ds_id=CANDIDATE_DS):
        """Lock or unlock a datastore.

        Args:
            lock (bool, optional): Whether to lock (True) or unlock (False) the
                                   datastore. Defaults to True.
            ds_id (int, optional): The datastore ID. Defaults to CANDIDATE_DS.

        Returns:
            None

        Raises:
            AssertionError: If the lock request fails.
        """
        mdata, _ = self.get_native_msg_header(MSG_CODE_LOCK)
        mdata += struct.pack(MSG_LOCK_FMT, ds_id, lock)
        self.send_native_msg(mdata)
        if lock:
            logging.debug("Sent LOCK %s message", datastore_name[ds_id])
        else:
            logging.debug("Sent UNLOCK %s message", datastore_name[ds_id])

        mhdr, mfixed, _ = self.recv_native_msg()
        assert mhdr[HDR_FIELD_REQ_ID] == mdata[HDR_FIELD_REQ_ID]
        assert mhdr[HDR_FIELD_CODE] == MSG_CODE_LOCK_REPLY
        assert mfixed[LOCK_FIELD_DATASTORE] == ds_id
        assert mfixed[LOCK_FIELD_LOCK] == lock
        logging.debug(
            "Received LOCK reply, %s is %s",
            datastore_name[ds_id],
            "locked" if lock else "unlocked",
        )

    def get_data(self, query, data=True, config=False):
        """Retrieve data from the mgmtd server based on an XPath query.

        Args:
            query (str): The XPath query string.
            data (bool, optional): Whether to retrieve state data. Defaults to True.
            config (bool, optional): Whether to retrieve configuration data.
                                     Defaults to False.

        Returns:
            str: The retrieved data in JSON format.

        Raises:
            AssertionError: If the response data is not properly formatted.
        """
        mdata, _ = self.get_native_msg_header(MSG_CODE_GET_DATA)
        flags = GET_DATA_FLAG_STATE if data else 0
        flags |= GET_DATA_FLAG_CONFIG if config else 0
        mdata += struct.pack(MSG_GET_DATA_FMT, MSG_FORMAT_JSON, flags)
        mdata += query.encode("utf-8") + b"\x00"

        self.send_native_msg(mdata)
        logging.debug("Sent GET-TREE")

        _, mfixed, mdata = self.recv_native_msg()
        assert mdata[-1] == 0
        result = mdata[:-1].decode("utf-8")

        logging.debug("Received GET: %s: %s", mfixed, mdata)
        return result

    def add_notify_select(self, replace, notif_xpaths):
        """Send a request to add notification subscriptions to the given XPaths.

        Args:
            replace (bool): Whether to replace existing notification subscriptions.
            notif_xpaths (list of str): List of XPaths to subscribe to notifications on.
        """
        mdata, _ = self.get_native_msg_header(MSG_CODE_NOTIFY_SELECT)
        mdata += struct.pack(MSG_NOTIFY_SELECT_FMT, replace)

        for xpath in notif_xpaths:
            mdata += xpath.encode("utf-8") + b"\x00"

        self.send_native_msg(mdata)
        logging.debug("Sent NOTIFY_SELECT")

    def recv_notify(self, xpaths=None):
        """Receive a notification message, optionally setting up XPath filters first.

        Args:
            xpaths (list of str, optional): List of XPaths to filter notifications.

        Returns:
            tuple: (result_type, operation, xpath, message data)

        Raises:
            TimeoutError: If no notification is received within the timeout period.
            Exception: If a non-notification message is received.
        """
        if xpaths:
            self.add_notify_select(True, xpaths)

        for _ in Timeout(60):
            logging.debug("Waiting for Notify Message")
            mhdr, mfixed, mdata = self.recv_native_msg()
            if mhdr[HDR_FIELD_CODE] == MSG_CODE_NOTIFY:
                logging.debug("Received Notify Message: %s: %s", mfixed, mdata)
            else:
                raise Exception(f"Received NON-NOTIFY Message: {mfixed}: {mdata}")

            vsplit = mhdr[HDR_FIELD_VSPLIT]
            result_type = mfixed[0]
            op = mfixed[1]
            assert mdata[vsplit - 1] == 0
            assert mdata[-1] == 0
            xpath = mdata[: vsplit - 1].decode("utf-8")
            return result_type, op, xpath, mdata[vsplit:-1].decode("utf-8")
        else:
            raise TimeoutError("Timeout waiting for notifications")


def __parse_args():
    """Parse command-line arguments for the mgmtd client."""
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
        "--datastore", action="store_true", help="listen for datastore notifications"
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
    """Establish a connection to the mgmtd server over a Unix socket.

    Args:
        spath (str): Path to the Unix domain socket.

    Returns:
        socket: A connected Unix socket.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    logging.debug("Connecting to server on %s", spath)
    while ec := sock.connect_ex(str(spath)):
        logging.warn("retry server connection in .5s (%s)", os.strerror(ec))
        time.sleep(0.5)
    logging.info("Connected to server on %s", spath)
    # Set a timeout of 5 minutes for socket operations.
    sock.settimeout(60 * 5)
    return sock


def __main():
    """Process client commands and handle queries or notifications."""
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
        if args.listen:
            sess.add_notify_select(True, args.listen)
        while i > 0 or args.notify_count == 0:
            result_type, op, xpath, notif = sess.recv_notify()
            if op == NOTIFY_OP_NOTIFICATION:
                if args.datastore:
                    logging.warning("ignoring non-datastore notification: %s", notif)
                else:
                    print(notif)
            elif not args.datastore:
                logging.warning(
                    "ignoring datastore notification op: %s xpath: %s data: %s",
                    op,
                    xpath,
                    notif,
                )
            elif op == NOTIFY_OP_PATCH:
                print(f"#OP=PATCH: {xpath}")
                print(notif)
            elif op == NOTIFY_OP_REPLACE:
                print(f"#OP=REPLACE: {xpath}")
                print(notif)
            elif op == NOTIFY_OP_DELETE:
                print(f"#OP=DELETE: {xpath}")
                assert len(notif) == 0
            elif op == NOTIFY_OP_GET_SYNC:
                print(f"#OP=SYNC: {xpath}")
                print(notif)
            else:
                logging.error("Unknown notification OP: %s", op)
                sys.exit(1)
            i -= 1


def main():
    """Entry point for the mgmtd client application."""
    try:
        __main()
    except KeyboardInterrupt:
        logging.info("Exiting")
    except TimeoutError as error:
        logging.error("Timeout: %s", error)
        sys.exit(2)
    except Exception as error:
        logging.error("Unexpected error exiting: %s", error, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
