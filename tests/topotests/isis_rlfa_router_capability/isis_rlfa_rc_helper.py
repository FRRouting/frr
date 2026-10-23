#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# isis_rlfa_rc_helper.py
# Part of NetDEF Topology Tests
#
# Byte-wise IS-IS PDU builder/parser used by
# test_isis_rlfa_router_capability.py.  Keeping the craft and the
# dissection independent of scapy contrib dissectors makes the test
# robust against scapy version differences.  The ISO 8473 Fletcher
# checksum replicates lib/checksum.c fletcher_checksum() (MODX 4102,
# C-style signed modulo).

import json
import os
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, Raw, conf, get_if_hwaddr, sendp, wrpcap

conf.verb = 0

TLV_ROUTER_CAP = 242


def c_mod(a, b):
    return a % b if a >= 0 else -((-a) % b)


def fletcher(data, offset):
    buf = bytearray(data)
    buf[offset] = 0
    buf[offset + 1] = 0
    c0 = c1 = 0
    left = len(buf)
    pos = 0
    while left:
        n = min(left, 4102)
        for j in range(pos, pos + n):
            c0 += buf[j]
            c1 += c0
        c0 %= 255
        c1 %= 255
        pos += n
        left -= n
    x = c_mod((len(buf) - offset - 1) * c0 - c1, 255)
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return (x << 8) | (y & 0xFF)


def strip_tlv(pdu, tlv_type):
    "Remove one TLV from the LSP PDU and fix the PDU length."
    body = bytearray(pdu)
    off = 27  # end of the LSP header
    while off + 2 <= len(body):
        t, l = body[off], body[off + 1]
        if off + 2 + l > len(body):
            raise ValueError("TLV %d overruns PDU" % t)
        if t == tlv_type:
            del body[off:off + 2 + l]
            body[8:10] = struct.pack("!H", len(body))
            return bytes(body)
        off += 2 + l
    raise ValueError("TLV %d not found" % tlv_type)


def build_from_template(template, seqno, lifetime, strip_router_cap):
    pdu = bytearray(template)
    if strip_router_cap:
        pdu = bytearray(strip_tlv(bytes(pdu), TLV_ROUTER_CAP))
    pdu[10:12] = struct.pack("!H", lifetime)
    pdu[20:24] = struct.pack("!I", seqno)
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    return bytes(pdu)


def build_psnp(source_sysid, entries):
    body = b""
    for lifetime, lsp_id, seqno, cksum in entries:
        body += struct.pack("!H", lifetime) + lsp_id + struct.pack("!IH", seqno, cksum)
    tlvs = bytes([9, len(body)]) + body
    common = bytes([0x83, 17, 1, 0, 27, 1, 0, 0])  # L2 PSNP
    pdu_len = len(common) + 2 + len(source_sysid) + 1 + len(tlvs)
    return common + struct.pack("!H", pdu_len) + source_sysid + b"\x00" + tlvs


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


def send_frame(iface, pdu):
    src = get_if_hwaddr(iface)
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst="01:80:c2:00:00:15", src=src, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def run_template(cfg):
    "Elicit one router's LSP with PSNPs and capture it as a forging template."
    lsp_id = bytes.fromhex(cfg["lsp_id"])
    source_sysid = bytes.fromhex(cfg["source_sysid"])
    template = {"hex": None}

    def has_router_cap(pdu):
        off = 27
        while off + 2 <= len(pdu):
            t, l = pdu[off], pdu[off + 1]
            if off + 2 + l > len(pdu):
                return False
            if t == TLV_ROUTER_CAP:
                return True
            off += 2 + l
        return False

    def process(pkt):
        if template["hex"] is not None:
            return
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            return
        if info is None or info.get("pdutype") != 20:
            return
        if info.get("lspid") != cfg["lsp_id"]:
            return
        pdu = bytes(pkt)[17:]
        # Only accept a post-convergence LSP: the Router Capability TLV is
        # present once zebra has assigned the router-id.
        if cfg.get("require_router_cap") and not has_router_cap(pdu):
            return
        template["hex"] = pdu.hex()

    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=True, prn=process)
    sniffer.start()
    time.sleep(0.4)
    deadline = time.monotonic() + cfg["timeout"]
    while template["hex"] is None and time.monotonic() < deadline:
        send_frame(cfg["iface"], build_psnp(source_sysid, [(600, lsp_id, 0, 0)]))
        time.sleep(1)
    packets = list(sniffer.stop() or [])
    wrpcap(cfg["pcap_path"], packets)
    print(
        "TEMPLATE_JSON="
        + json.dumps({"template_hex": template["hex"], "pcap_path": cfg["pcap_path"]})
    )


def run_inject(cfg):
    "Send the forged frames of one bounded scenario and capture the link."
    template = bytes.fromhex(cfg["template_hex"])
    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    frames = []
    for seqno, strip in cfg["frames"]:
        frames.append(build_from_template(template, seqno, cfg["lifetime"], strip))
        sent.append({"seq": seqno, "strip_router_cap": strip})
    for index, frame in enumerate(frames):
        if index:
            time.sleep(1)
        send_frame(cfg["iface"], frame)
    time.sleep(cfg["tail"])
    packets = list(sniffer.stop() or [])
    events = []
    for pkt in packets:
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            continue
        if info is None:
            continue
        info["time"] = round(float(pkt.time) - epoch, 6)
        info["abs_time"] = float(pkt.time)
        events.append(info)
    wrpcap(cfg["pcap_path"], packets)
    print(
        "ISIS_CAPTURE_JSON="
        + json.dumps({"sent": sent, "events": events, "pcap_path": cfg["pcap_path"]}, sort_keys=True)
    )


def run_observer(cfg):
    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=True)
    sniffer.start()
    epoch = time.time()
    print("OBS_EPOCH=%f" % epoch, flush=True)
    while not os.path.exists(cfg["stop_file"]):
        time.sleep(0.3)
    packets = list(sniffer.stop() or [])
    events = []
    for pkt in packets:
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            continue
        if info is None:
            continue
        info["time"] = round(float(pkt.time) - epoch, 6)
        info["abs_time"] = float(pkt.time)
        events.append(info)
    wrpcap(cfg["pcap_path"], packets)
    with open(cfg["out_json"], "w") as fp:
        json.dump({"events": events, "pcap_path": cfg["pcap_path"]}, fp, sort_keys=True)
    print("OBS_DONE", flush=True)


if __name__ == "__main__":
    _cfg = json.load(open(sys.argv[1]))
    if _cfg["role"] == "template":
        run_template(_cfg)
    elif _cfg["role"] == "inject":
        run_inject(_cfg)
    else:
        run_observer(_cfg)
