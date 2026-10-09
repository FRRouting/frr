#!/usr/bin/python3
# SPDX-License-Identifier: ISC
#
# pce_sim.py: minimal PCEP PCE simulator used by the pathd_pcep_topo1
# topotest.  It listens for incoming TCP connections on port 4189 (or
# whichever port is passed via -p) and implements just enough of
# RFC 5440 / RFC 8231 for a FRR pathd PCC (or the standalone pcep_pcc
# binary in pceplib/) to reach the operational state.
#
# What this simulator does:
#   - accepts TCP/4189 connections from one or more PCCs
#   - on each connection:
#       * reads the PCC's PCEP Open message
#       * sends an Open back (with Stateful PCE Capability + SR PCE
#         Capability TLVs, so pathd considers the PCE stateful and
#         capable of SR)
#       * sends a Keepalive (acknowledging the PCC's Open)
#       * runs a loop forwarding incoming messages to the log file and
#         emitting a Keepalive every "keep-alive" seconds
#       * tolerates and silently drains any other PCEP message types
#         (PCRpt / PCErr / Close / ...) the PCC may send
#
# It is intentionally tiny -- the goal is to drive pceplib and
# pathd_pcep code paths in FRR, not to be a fully-conformant PCE.
#
# The simulator writes a structured log to the path given as the first
# positional argument so the topotest can verify that PCEs actually
# saw an incoming session.

import argparse
import os
import socket
import struct
import sys
import threading
import time

# PCEP common header constants (RFC 5440 section 6.1)
PCEP_VERSION = 1
PCEP_MSG_OPEN = 1
PCEP_MSG_KEEPALIVE = 2
PCEP_MSG_PCREQ = 3
PCEP_MSG_PCREP = 4
PCEP_MSG_NOTIFY = 5
PCEP_MSG_ERROR = 6
PCEP_MSG_CLOSE = 7
PCEP_MSG_PCRPT = 10
PCEP_MSG_PCUPD = 11
PCEP_MSG_INITIATE = 12

PCEP_MSG_NAME = {
    1: "Open",
    2: "Keepalive",
    3: "PCReq",
    4: "PCRep",
    5: "Notify",
    6: "Error",
    7: "Close",
    10: "PCRpt",
    11: "PCUpd",
    12: "PCInitiate",
}

# PCEP object class / type for OPEN
PCEP_OBJ_CLASS_OPEN = 1
PCEP_OBJ_TYPE_OPEN = 1

# TLV types we send in our OPEN
TLV_STATEFUL_PCE_CAP = 16  # RFC 8231
TLV_SR_PCE_CAP = 26  # RFC 8664

DEFAULT_KEEPALIVE = 5
DEFAULT_DEAD_TIMER = 20

LOG_FH = None
LOG_LOCK = threading.Lock()


def log(msg):
    """Write a timestamped line to the log file (and also stderr)."""
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    with LOG_LOCK:
        if LOG_FH is not None:
            LOG_FH.write(line + "\n")
            LOG_FH.flush()
        sys.stderr.write(line + "\n")
        sys.stderr.flush()


def build_common_header(msg_type, body_len):
    """Build the 4 byte PCEP common header. body_len is the size of the
    payload that follows the header (so the on-wire length field is
    body_len + 4)."""
    ver_flags = (PCEP_VERSION & 0x07) << 5
    return struct.pack("!BBH", ver_flags, msg_type, body_len + 4)


def build_tlv(tlv_type, value_bytes):
    """Build a PCEP TLV (Type/Length/Value with 4 byte aligned padding)."""
    length = len(value_bytes)
    pad = (4 - (length % 4)) % 4
    return struct.pack("!HH", tlv_type, length) + value_bytes + (b"\x00" * pad)


def build_open_message(
    keepalive=DEFAULT_KEEPALIVE, dead_timer=DEFAULT_DEAD_TIMER, sid=1
):
    """Build a PCEP Open message advertising stateful + SR capability."""
    # Stateful PCE capability TLV: U=1 (update), I=1 (initiate)
    stateful_flags = struct.pack("!I", (1 << 0) | (1 << 2))
    stateful_tlv = build_tlv(TLV_STATEFUL_PCE_CAP, stateful_flags)

    # SR PCE Capability TLV body: 2 reserved + flags + MSD
    sr_body = struct.pack("!BBBB", 0, 0, 0, 10)
    sr_tlv = build_tlv(TLV_SR_PCE_CAP, sr_body)

    tlvs = stateful_tlv + sr_tlv

    # Open object body: ver(3)+flags(5) | keepalive | deadtimer | sid
    ver_flags = (PCEP_VERSION & 0x07) << 5
    obj_body = struct.pack("!BBBB", ver_flags, keepalive, dead_timer, sid)
    obj_payload = obj_body + tlvs

    # Object common header (4 bytes): class | type/flags | length
    obj_class = PCEP_OBJ_CLASS_OPEN
    obj_type_flags = (PCEP_OBJ_TYPE_OPEN & 0x0F) << 4  # P=0, I=0
    obj_len = 4 + len(obj_payload)
    obj_hdr = struct.pack("!BBH", obj_class, obj_type_flags, obj_len)

    body = obj_hdr + obj_payload
    return build_common_header(PCEP_MSG_OPEN, len(body)) + body


def build_keepalive_message():
    return build_common_header(PCEP_MSG_KEEPALIVE, 0)


def recvn(sock, n):
    """Read exactly n bytes from sock, or return b'' on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def recv_pcep_message(sock):
    """Receive one PCEP message; return (msg_type, payload) or None on EOF."""
    hdr = recvn(sock, 4)
    if len(hdr) < 4:
        return None
    ver_flags, msg_type, total_len = struct.unpack("!BBH", hdr)
    if total_len < 4:
        log("invalid total length %d in header" % total_len)
        return None
    payload = recvn(sock, total_len - 4)
    if len(payload) < total_len - 4:
        return None
    return msg_type, payload


class PCESession(threading.Thread):
    """Handle one PCC connection."""

    def __init__(self, conn, peer, keepalive):
        super().__init__(daemon=True)
        self.conn = conn
        self.peer = peer
        self.keepalive = keepalive
        self.last_send = 0
        self.stopping = False

    def send(self, data, what):
        try:
            self.conn.sendall(data)
            self.last_send = time.time()
            log("%s: tx %s (%d bytes)" % (self.peer, what, len(data)))
        except OSError as e:
            log("%s: send %s failed: %s" % (self.peer, what, e))
            self.stopping = True

    def run(self):
        log("%s: session started" % (self.peer,))
        # Use a 1s recv timeout so we can drive periodic keepalives.
        self.conn.settimeout(1.0)

        # Send our Open immediately on connect (the PCC will likely have
        # done the same; PCEP Opens cross on the wire).
        self.send(build_open_message(keepalive=self.keepalive), "Open")

        got_open_from_pcc = False
        opened = False
        while not self.stopping:
            try:
                msg = recv_pcep_message(self.conn)
            except socket.timeout:
                msg = None
            except OSError as e:
                log("%s: recv failed: %s" % (self.peer, e))
                break

            if msg is None:
                # No message this iteration -- check timers.
                pass
            else:
                msg_type, _payload = msg
                name = PCEP_MSG_NAME.get(msg_type, "Unknown(%d)" % msg_type)
                log("%s: rx %s" % (self.peer, name))

                if msg_type == PCEP_MSG_OPEN and not got_open_from_pcc:
                    got_open_from_pcc = True
                    # Acknowledge the PCC's Open with a Keepalive.
                    self.send(build_keepalive_message(), "Keepalive (ack PCC Open)")
                    opened = True
                elif msg_type == PCEP_MSG_CLOSE:
                    log("%s: peer sent Close, exiting" % (self.peer,))
                    break

            # Periodic keepalive
            if opened and (time.time() - self.last_send) >= self.keepalive:
                self.send(build_keepalive_message(), "Keepalive (periodic)")

            # Detect socket EOF without read by quick poll
            if msg is None:
                # Peek to see if we're still connected; recv with timeout
                # already returned None on timeout, so just continue.
                pass

        try:
            self.conn.close()
        except OSError:
            pass
        log("%s: session ended" % (self.peer,))


def serve(host, port, keepalive):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(8)
    log("PCE simulator listening on %s:%d (keepalive=%ds)" % (host, port, keepalive))

    while True:
        try:
            conn, addr = sock.accept()
        except KeyboardInterrupt:
            log("PCE simulator: interrupted, exiting")
            break
        except OSError as e:
            log("PCE simulator: accept failed: %s" % (e,))
            break
        peer = "%s:%d" % addr
        log("accept from %s" % (peer,))
        PCESession(conn, peer, keepalive).start()

    try:
        sock.close()
    except OSError:
        pass


def main():
    global LOG_FH
    parser = argparse.ArgumentParser(description="Minimal PCEP PCE simulator")
    parser.add_argument("logfile", help="path to log file")
    parser.add_argument(
        "-H", "--host", default="0.0.0.0", help="address to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=4189,
        help="TCP port to listen on (default: 4189)",
    )
    parser.add_argument(
        "-k",
        "--keepalive",
        type=int,
        default=DEFAULT_KEEPALIVE,
        help="keepalive interval in seconds (default: 5)",
    )
    args = parser.parse_args()

    LOG_FH = open(args.logfile, "a", buffering=1)
    log("pce_sim starting pid=%d argv=%s" % (os.getpid(), sys.argv))

    try:
        serve(args.host, args.port, args.keepalive)
    finally:
        if LOG_FH is not None:
            LOG_FH.close()


if __name__ == "__main__":
    main()
