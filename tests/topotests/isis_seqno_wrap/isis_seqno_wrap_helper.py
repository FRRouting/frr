#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# isis_seqno_wrap_helper.py
# Part of NetDEF Topology Tests
#
# Byte-wise IS-IS PDU builder/parser used by test_isis_seqno_wrap.py.
# Keeping the craft and the dissection independent of scapy contrib
# dissectors makes the test robust against scapy version differences.
# The ISO 8473 Fletcher checksum replicates lib/checksum.c
# fletcher_checksum() (MODX 4102, C-style signed modulo).

import json
import os
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, Raw, conf, get_if_hwaddr, sendp, wrpcap

conf.verb = 0


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


def build_from_template(template, seqno, lifetime, corrupt):
    pdu = bytearray(template)
    pdu[10:12] = struct.pack("!H", lifetime)
    pdu[20:24] = struct.pack("!I", seqno)
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    if corrupt:
        pdu[27] ^= 0x5A
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
    elif pdu[4] in (26, 27) and len(pdu) >= 17:
        entries = []
        off = 17
        while off + 2 <= len(pdu):
            t, l = pdu[off], pdu[off + 1]
            if off + 2 + l > len(pdu):
                break
            if t == 9:
                for i in range(0, l - 15, 16):
                    e = pdu[off + 2 + i:off + 2 + i + 16]
                    entries.append(
                        {
                            "lifetime": struct.unpack("!H", e[0:2])[0],
                            "lspid": e[2:10].hex(),
                            "seqno": struct.unpack("!I", e[10:14])[0],
                        }
                    )
            off += 2 + l
        info["entries"] = entries
    return info


def events_of(packets, epoch):
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
    return events


def send_frame(iface, pdu):
    src = get_if_hwaddr(iface)
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst="01:80:c2:00:00:15", src=src, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def run_template(cfg):
    "Capture the victim's own LSP as a forging template."
    lsp_id = bytes.fromhex(cfg["lsp_id"])
    source_sysid = bytes.fromhex(cfg["source_sysid"])
    template = {"hex": None}

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
        template["hex"] = bytes(pkt)[17:].hex()

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
    lsp_id = bytes.fromhex(cfg["lsp_id"])
    source_sysid = bytes.fromhex(cfg["source_sysid"])
    max_seq = 0xFFFFFFFF
    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    frames = []
    if cfg["mode"] == "invalid":
        frames.append(build_from_template(template, max_seq, cfg["lifetime"], True))
        sent.append({"time": round(time.time() - epoch, 6), "seq": max_seq, "lifetime": cfg["lifetime"], "corrupt": True})
    elif cfg["mode"] in ("single", "purge"):
        seq = cfg["base_seq"] + 2
        lifetime = 0 if cfg["mode"] == "purge" else cfg["lifetime"]
        frames.append(build_from_template(template, seq, lifetime, False))
        sent.append({"time": round(time.time() - epoch, 6), "seq": seq, "lifetime": lifetime, "corrupt": False})
    elif cfg["mode"] == "psnp_max":
        frames.append(build_psnp(source_sysid, [(cfg["lifetime"], lsp_id, max_seq, 0)]))
        sent.append({"time": round(time.time() - epoch, 6), "seq": max_seq, "entry_lifetime": cfg["lifetime"]})
    elif cfg["mode"] in ("maxseq_single", "maxseq_burst"):
        count = 1 if cfg["mode"] == "maxseq_single" else cfg["count"]
        for _ in range(count):
            frames.append(build_from_template(template, max_seq, cfg["lifetime"], False))
            sent.append({"time": round(time.time() - epoch, 6), "seq": max_seq, "lifetime": cfg["lifetime"], "corrupt": False})
    for index, frame in enumerate(frames):
        if index:
            time.sleep(cfg["spacing"])
        send_frame(cfg["iface"], frame)
    time.sleep(cfg["tail"])
    packets = list(sniffer.stop() or [])
    events = events_of(packets, epoch)
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
    events = events_of(packets, epoch)
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
