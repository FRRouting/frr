#!/usr/bin/env python3
#
# SPDX-License-Identifier: ISC
#
# isis_inject.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
Raw LAN-IIH injector for the IS-IS DIS churn topotest.

Runs on host h1, which is attached to LAN1 but speaks no IS-IS itself.
It sniffs genuine L2 LAN hellos to capture one PDU template per
router, then replays a template with chosen header edits at a bounded
rate.  All PDU handling is byte-wise on the ISO 10589 layout: the
fixed LAN-hello header is 27 bytes, with the priority at offset 19,
the LAN ID (designated IS) at offsets 20..26, and TLVs from offset
27.  FRR pads hellos with TLV 8 up to the MTU, so the padding is
stripped before a replay would overflow the MTU.

Subcommands:
  template IFACE OUTFILE TIMEOUT
      Sniff until a hello template for every expected sysid has been
      captured, write {"<sysid>": {"pdu": <hex>, "src_mac": <mac>}}
      to OUTFILE, then print "TEMPLATE_DONE".
  send IFACE TEMPLATE_FILE SRC_SYSID DST_SYSID COUNT SPACING
       [priority P] [dis HEX]
      Replay SRC_SYSID's template COUNT times, SPACING seconds apart,
      from SRC_SYSID's MAC to DST_SYSID's MAC, with the given edits,
      then print "SENT=COUNT".
"""

import json
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, LLC, Raw, conf, sendp

conf.verb = 0

EXPECTED_SYSIDS = ["000000000001", "000000000002"]


def parse_lan_iih(raw):
    "Return {sysid, pdu} for an L2 LAN hello frame, else None."
    if len(raw) < 17 + 27:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if pdu[0] != 0x83 or (pdu[4] & 0x1F) != 16:
        return None
    return {"sysid": pdu[9:15].hex(), "pdu": pdu}


def strip_padding(pdu):
    "Drop TLV 8 padding and fix up the hello's PDU length field."
    pdu = bytearray(pdu)
    off = 27
    while off + 2 <= len(pdu):
        tlv_type, tlv_len = pdu[off], pdu[off + 1]
        if tlv_type == 8:
            pdu = pdu[:off]
            pdu[17:19] = struct.pack("!H", off)
            break
        off += 2 + tlv_len
    return bytes(pdu)


def build_variant(pdu, priority=None, dis=None):
    pdu = bytearray(pdu)
    if priority is not None:
        pdu[19] = priority
    if dis is not None:
        pdu[20:27] = bytes.fromhex(dis)
    return strip_padding(bytes(pdu))


def cmd_template(iface, outfile, timeout):
    templates = {}

    def process(pkt):
        info = parse_lan_iih(bytes(pkt))
        if info and info["sysid"] in EXPECTED_SYSIDS and info["sysid"] not in templates:
            templates[info["sysid"]] = {
                "pdu": info["pdu"].hex(),
                "src_mac": ":".join("%02x" % b for b in bytes(pkt)[6:12]),
            }

    sniffer = AsyncSniffer(iface=iface, store=False, prn=process)
    sniffer.start()
    deadline = time.time() + timeout
    while time.time() < deadline and len(templates) < len(EXPECTED_SYSIDS):
        time.sleep(0.3)
    sniffer.stop()
    if len(templates) < len(EXPECTED_SYSIDS):
        print("TEMPLATE_FAILED " + json.dumps(sorted(templates)))
        return 1
    with open(outfile, "w") as fp:
        json.dump(templates, fp)
    print("TEMPLATE_DONE")
    return 0


def cmd_send(iface, template_file, src, dst, count, spacing, priority, dis):
    with open(template_file) as fp:
        templates = json.load(fp)
    pdu = build_variant(bytes.fromhex(templates[src]["pdu"]), priority, dis)
    frame = (
        Ether(dst=templates[dst]["src_mac"], src=templates[src]["src_mac"])
        / LLC(dsap=0xFE, ssap=0xFE, ctrl=0x03)
        / Raw(load=pdu)
    )
    for _ in range(count):
        sendp(frame, iface=iface, verbose=0)
        time.sleep(spacing)
    print("SENT={}".format(count))
    return 0


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    if args[0] == "template":
        return cmd_template(args[1], args[2], float(args[3]))
    if args[0] == "send":
        priority = dis = None
        rest = args[7:]
        while rest:
            if rest[0] == "priority":
                priority = int(rest[1])
            elif rest[0] == "dis":
                dis = rest[1]
            rest = rest[2:]
        return cmd_send(
            args[1], args[2], args[3], args[4], int(args[5]), float(args[6]),
            priority, dis,
        )
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
