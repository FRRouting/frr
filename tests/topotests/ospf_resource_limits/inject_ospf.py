#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_ospf.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Send raw OSPF frames for test_ospf_resource_limits.py.

Each frame is described by a JSON object in the --frames list and is
built byte-by-byte (the same wire format as the runtime-confirmation
script for this bug class, so rogue Hellos, DD, LSU and LSAck carry
the same key fields).  Frames are sent on a schedule (monotonic
seconds, "at") with scapy; the result line SENT_JSON reports what was
actually handed to the interface.

Frame kinds:
  hello:  src_ip, router_id, include_target (bool), multicast (bool),
          corrupt (bool)
  dd:     src_ip, router_id, seq, flags, headers (list of hex LSA
          headers), multicast (bool)
  lsu:    src_ip, router_id, lsas (list of hex full LSAs), multicast
  ack:    src_ip, router_id, lsa_header (hex), multicast
"""

import json
import socket
import struct
import sys
import time

from scapy.all import Ether, IP, Raw, conf, sendp

conf.verb = 0

HELLO_INTERVAL = 2
DEAD_INTERVAL = 8
TARGET_IP = "10.222.20.1"
TARGET_RID = "10.255.20.1"
ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_MAC = "01:00:5e:00:00:05"


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def fletcher_checksum(lsa):
    data = bytearray(lsa[2:])
    data[14:16] = b"\x00\x00"
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - 15) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return (x << 8) | y


def ospf_packet(router_id, packet_type, body, corrupt=False):
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2, packet_type, 24 + len(body), socket.inet_aton(router_id),
            socket.inet_aton("0.0.0.0"), 0, 0, b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if corrupt:
        packet[12] ^= 0x01
    valid = internet_checksum(bytes(packet)) == 0
    if valid == corrupt:
        raise ValueError("generated OSPF checksum state is wrong")
    return bytes(packet)


def make_hello(router_id, include_target=True, corrupt=False):
    body = struct.pack(
        "!4sHBBI4s4s",
        socket.inet_aton("255.255.255.0"), HELLO_INTERVAL, 0x02, 0,
        DEAD_INTERVAL, socket.inet_aton(TARGET_IP), socket.inet_aton("0.0.0.0"),
    )
    if include_target:
        body += socket.inet_aton(TARGET_RID)
    return ospf_packet(router_id, 1, body, corrupt)


def make_external_lsa(lsa_id, adv_router, age=1, sequence=0x80000001):
    body = (
        socket.inet_aton("255.255.255.0")
        + b"\x80\x00\x00\x14"
        + socket.inet_aton("0.0.0.0")
        + struct.pack("!I", 0)
    )
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            age, 0x02, 5, socket.inet_aton(lsa_id), socket.inet_aton(adv_router),
            sequence, 0, 36,
        )
        + body
    )
    struct.pack_into("!H", lsa, 16, fletcher_checksum(lsa))
    return bytes(lsa)


def make_lsu(router_id, lsas):
    return ospf_packet(router_id, 4, struct.pack("!I", len(lsas)) + b"".join(lsas))


def make_dd(router_id, sequence, flags, headers=()):
    body = struct.pack("!HBBI", 1500, 0x02, flags, sequence) + b"".join(headers)
    return ospf_packet(router_id, 2, body)


def make_ack(router_id, lsa):
    return ospf_packet(router_id, 5, lsa[:20])


def build_frame(spec, target_mac):
    kind = spec["kind"]
    if kind == "hello":
        payload = make_hello(spec["router_id"], spec.get("include_target", True),
                             spec.get("corrupt", False))
    elif kind == "dd":
        headers = [bytes.fromhex(h) for h in spec.get("headers", [])]
        payload = make_dd(spec["router_id"], spec["seq"], spec["flags"], headers)
    elif kind == "lsu":
        lsas = []
        for lsa in spec["lsas"]:
            if isinstance(lsa, dict):
                lsas.append(make_external_lsa(lsa["id"], lsa["adv_router"],
                                              age=lsa.get("age", 1)))
            else:
                lsas.append(bytes.fromhex(lsa))
        payload = make_lsu(spec["router_id"], lsas)
    elif kind == "ack":
        if "lsa_header" in spec:
            header = bytes.fromhex(spec["lsa_header"])
        else:
            header = make_external_lsa(spec["lsa"]["id"], spec["lsa"]["adv_router"],
                                       age=spec["lsa"].get("age", 3600),
                                       sequence=spec["lsa"].get("sequence", 0x80000001))
        payload = make_ack(spec["router_id"], header)
    else:
        raise ValueError("unknown frame kind %r" % kind)

    multicast = spec.get("multicast", kind == "hello")
    return Ether(src=spec["src_mac"],
                 dst=ALL_SPF_MAC if multicast else target_mac) / \
        IP(src=spec["src_ip"],
           dst=ALL_SPF_ROUTERS if multicast else TARGET_IP,
           ttl=1, proto=89) / Raw(payload)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--frames", required=True,
                        help="JSON list of frame objects")
    args = parser.parse_args()

    specs = json.loads(args.frames)
    ordered = sorted(specs, key=lambda item: item["at"])
    target_mac = None
    for spec in ordered:
        if not spec.get("multicast", spec["kind"] == "hello"):
            target_mac = spec["target_mac"]
            break

    started = time.monotonic()
    sent = []
    for spec in ordered:
        delay = started + spec["at"] - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        frame = build_frame(spec, target_mac)
        sendp(frame, iface=args.iface, count=1, verbose=False)
        sent.append({
            "label": spec.get("label", spec["kind"]),
            "at": round(time.monotonic() - started, 6),
            "src_ip": spec["src_ip"],
            "kind": spec["kind"],
        })
    print("SENT_JSON=" + json.dumps({"count": len(sent), "sent": sent}))


if __name__ == "__main__":
    main()
