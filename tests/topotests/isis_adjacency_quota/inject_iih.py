#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_iih.py - build and send IS-IS LAN IIHs for
# test_isis_adjacency_quota.py.  PDUs are built byte-wise so that
# acceptance does not depend on scapy contrib dissection.

import argparse
import json
import struct
import time

from scapy.all import Ether, Raw, conf, get_if_hwaddr, sendp

conf.verb = 0

AREA_DEFAULT = bytes.fromhex("490001")


def tlv(t, value):
    return bytes([t, len(value)]) + value


def build_iih(sysid, holdtime, level=2, snpa_tlv=None, area=AREA_DEFAULT,
              protocols=b"\x01\xcc", ipv4=bytes([10, 213, 12, 99]),
              auth=None, priority=0, dis=b"\x00" * 7):
    pdu_type = 15 if level == 1 else 16
    circ_type = 1 if level == 1 else 2
    tlvs = b""
    if area is not None:
        tlvs += tlv(1, bytes([len(area)]) + area)
    if protocols is not None:
        tlvs += tlv(129, protocols)
    if ipv4 is not None:
        tlvs += tlv(132, ipv4)
    if snpa_tlv is not None:
        tlvs += tlv(6, snpa_tlv)
    if auth is not None:
        tlvs += tlv(10, auth)
    hdr = (bytes([0x83, 27, 1, 6, pdu_type, 1, 0, 0, circ_type])
           + sysid + struct.pack("!H", holdtime)
           + struct.pack("!H", 27 + len(tlvs))
           + bytes([priority]) + dis)
    return hdr + tlvs


def send_frame(iface, pdu):
    src = get_if_hwaddr(iface)
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst="01:80:c2:00:00:15", src=src, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--frames", required=True, help="JSON list of specs")
    parser.add_argument("--spacing", type=float, default=0.2)
    args = parser.parse_args()

    frames = json.loads(args.frames)
    sent = []
    for index, spec in enumerate(frames):
        pdu = build_iih(
            bytes.fromhex(spec["sysid"]), spec["holdtime"],
            level=spec.get("level", 2),
            snpa_tlv=(bytes.fromhex(spec["snpa_tlv"])
                      if spec.get("snpa_tlv") else None),
            area=(bytes.fromhex(spec["area"]) if spec.get("area") else None),
            protocols=(bytes.fromhex(spec["protocols"])
                       if spec.get("protocols") else None),
            ipv4=bytes(spec["ipv4"]) if spec.get("ipv4") else None,
            auth=(bytes.fromhex(spec["auth"]) if spec.get("auth") else None),
        )
        if index:
            time.sleep(args.spacing)
        send_frame(args.iface, pdu)
        sent.append(spec["sysid"])
    print("SENT_JSON=" + json.dumps({"count": len(sent)}))


if __name__ == "__main__":
    main()
