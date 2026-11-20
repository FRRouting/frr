#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# capture_isis.py
#
# Copyright (c) 2026
#
"""Sniff IS-IS PDUs on a node until SIGINT/SIGTERM.

Two uses for test_isis_equal_lsp_churn.py:

* Wire evidence: store the capture and write it to --pcap on stop.
* Template tracking: with --template-out, every genuine flood of the
  LSP selected by --lsp-id from --accept-mac is written (as PDU hex)
  to --template-out, so the test always replays the peer's current LSP
  byte-for-byte.  Frames from any other source MAC (the test injector)
  never update the template.

PDUs are parsed byte-wise; acceptance does not depend on scapy contrib
dissection.
"""

import argparse
import os
import signal
import struct
import sys
import time

from scapy.all import AsyncSniffer, conf, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def parse_isis(raw):
    if len(raw) < 20:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if len(pdu) < 8 or pdu[0] != 0x83:
        return None
    info = {"pdutype": pdu[4], "src_mac": ":".join("%02x" % b for b in raw[6:12])}
    if pdu[4] in (18, 20) and len(pdu) >= 27:
        info["lifetime"] = struct.unpack("!H", pdu[10:12])[0]
        info["lspid"] = pdu[12:20].hex()
        info["seqno"] = struct.unpack("!I", pdu[20:24])[0]
    return info


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--pcap", default="")
    parser.add_argument("--filter", default="isis")
    parser.add_argument("--template-out", default="")
    parser.add_argument("--accept-mac", default="")
    parser.add_argument("--lsp-id", default="")
    parser.add_argument("--ready-file", default="")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    def process(pkt):
        if not args.template_out:
            return
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            return
        if info is None or info.get("pdutype") != 20:
            return
        if info.get("lspid") != args.lsp_id:
            return
        if info.get("src_mac") != args.accept_mac:
            return
        raw = bytes(pkt)[17:]
        tmp = args.template_out + ".tmp"
        with open(tmp, "w") as fp:
            fp.write(raw.hex())
        os.replace(tmp, args.template_out)

    sniffer = AsyncSniffer(
        iface=args.iface,
        filter=args.filter,
        store=bool(args.pcap),
        prn=process if args.template_out else None,
    )
    try:
        sniffer.start()
    except Exception as exc:
        sys.stderr.write("scapy sniff failed on %s: %s\n" % (args.iface, exc))
        sys.exit(1)

    if args.ready_file:
        with open(args.ready_file, "w") as fp:
            fp.write("ready\n")

    while not _stop:
        time.sleep(0.1)

    try:
        sniffer.stop()
    except Exception:
        pass

    if args.pcap:
        pkts = list(sniffer.results or [])
        wrpcap(args.pcap, pkts)
        # Make the file visible on shared rundir mounts before we exit.
        try:
            os.fsync(os.open(args.pcap, os.O_RDONLY))
        except OSError:
            pass


if __name__ == "__main__":
    main()
