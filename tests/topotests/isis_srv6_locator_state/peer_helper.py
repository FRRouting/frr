#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# peer_helper.py - fake IS-IS point-to-point peer + LSP injector used by
# test_isis_srv6_locator_state.py.  Runs inside the r2 host namespace.
#
# The helper impersonates router 0000.0000.0002 towards r1: it mirrors
# r1's IIH to form a real point-to-point adjacency (3-way state INIT/UP
# with r1 as neighbor), then injects crafted L1 LSPs from a spool
# directory.  PDUs are built and parsed byte-wise so that acceptance
# does not depend on scapy contrib dissection.  The ISO 8473 Fletcher
# checksum replicates lib/checksum.c:fletcher_checksum() (MODX 4102,
# C-style signed modulo).

import ipaddress
import json
import os
import struct
import sys
import time
from scapy.all import AsyncSniffer, Ether, Raw, conf, sendp

conf.verb = 0

INJECTOR_MAC = "02:00:00:00:00:02"
ALL_L1_IS_MAC = "01:80:c2:00:00:14"
IIH_INTERVAL = 1.0
AREA_TLV = bytes([0x01, 0x04, 0x03, 0x49, 0x00, 0x01])
PROTOCOLS_TLV = bytes([129, 2, 0xCC, 0x8E])
FAKE_IPV4 = "10.213.12.2"
FAKE_LL6 = "fe80::2"
FAKE_GUA6 = "2001:db8:12::2"


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
    elif pdu[4] == 17 and len(pdu) >= 20:
        info["sysid"] = pdu[9:15].hex()
        off = 20
        while off + 2 <= len(pdu):
            t, l = pdu[off], pdu[off + 1]
            if off + 2 + l > len(pdu):
                break
            if t == 240 and l >= 5:
                info["iih_state"] = pdu[off + 2]
                info["iih_ext_cid"] = struct.unpack("!I", pdu[off + 3:off + 7])[0]
            off += 2 + l
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


def send_frame(iface, pdu, src_mac):
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst=ALL_L1_IS_MAC, src=src_mac, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def build_iih(template, my_sysid, circ_id, state, nbr_id, nbr_circ_id,
              holdtime=30):
    hdr = bytearray(template[:20])
    hdr[9:15] = my_sysid
    hdr[15:17] = struct.pack("!H", holdtime)
    hdr[19] = circ_id
    tlvs = bytearray()
    tlvs += AREA_TLV
    tlvs += PROTOCOLS_TLV
    tlvs += bytes([132, 4]) + bytes(int(x) for x in FAKE_IPV4.split("."))
    tlvs += bytes([232, 16]) + ipaddress.IPv6Address(FAKE_LL6).packed
    tlvs += bytes([233, 16]) + ipaddress.IPv6Address(FAKE_GUA6).packed
    tw = (bytes([state]) + struct.pack("!I", 1) + nbr_id
          + struct.pack("!I", nbr_circ_id))
    tlvs += bytes([240, len(tw)]) + tw
    pdu = bytearray(bytes(hdr) + bytes(tlvs))
    pdu[17:19] = struct.pack("!H", len(pdu))
    return bytes(pdu)


def tlv236(prefix, metric=10):
    p = ipaddress.IPv6Network(prefix)
    body = struct.pack("!I", metric) + bytes([0, p.prefixlen])
    body += p.network_address.packed[: (p.prefixlen + 7) // 8]
    return bytes([236, len(body)]) + body


def tlv27(locators, metric=10):
    body = struct.pack("!H", 0)  # MTID 0
    for prefix in locators:
        p = ipaddress.IPv6Network(prefix)
        body += struct.pack("!I", metric) + bytes([0, 0, p.prefixlen])
        body += p.network_address.packed[: (p.prefixlen + 7) // 8] + bytes([0])
    return bytes([27, len(body)]) + body


def build_lsp(sysid, frag, seqno, lifetime, base_tlvs, extra_tlvs):
    hdr = bytearray(27)
    hdr[0] = 0x83
    hdr[1] = 27
    hdr[2] = 1
    hdr[4] = 0x12  # L1 LSP
    hdr[5] = 1
    hdr[12:20] = sysid + bytes([0, frag])
    hdr[20:24] = struct.pack("!I", seqno)
    hdr[10:12] = struct.pack("!H", lifetime)
    hdr[26] = 0x01  # IS-type level-1, no OL/ATT/P
    pdu = bytearray(bytes(hdr) + bytes(base_tlvs) + bytes(extra_tlvs))
    pdu[8:10] = struct.pack("!H", len(pdu))
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    return bytes(pdu)


def run_peer(cfg):
    stop_file = cfg["stop_file"]
    spool = cfg["spool_dir"]
    events_path = cfg["events_path"]
    events_fp = open(events_path, "a", buffering=1)
    fake_sysid = bytes.fromhex(cfg["fake_sysid"])
    target_sysid = bytes.fromhex(cfg["target_sysid"])

    # 1. Learn r1t's IIH as a template (header layout, ext circuit id).
    template = None
    ext_cid = 1

    def learn(pkt):
        nonlocal template, ext_cid
        if template is not None:
            return
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            return
        if info is None or info.get("pdutype") != 17:
            return
        if info.get("sysid") != cfg["target_sysid"]:
            return
        raw = bytes(pkt)[17:]
        if len(raw) < 20:
            return
        template = raw
        ext_cid = info.get("iih_ext_cid", 1)
        with open(cfg["template_path"], "w") as fp:
            fp.write(raw.hex())
        print("IIH_TEMPLATE ext_cid=%d" % ext_cid, flush=True)

    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=False,
                           prn=learn)
    sniffer.start()
    deadline = time.monotonic() + 60
    while template is None and time.monotonic() < deadline:
        if os.path.exists(stop_file):
            break
        time.sleep(0.2)
    sniffer.stop()
    if template is None:
        print("IIH_TEMPLATE_FAILED", flush=True)
        return 1

    # 2. Continuous event log + IIH keepalive + injection jobs.
    epoch = time.time()

    def log_events(pkt):
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            return
        if info is None:
            return
        info["time"] = round(float(pkt.time) - epoch, 6)
        info["abs_time"] = float(pkt.time)
        events_fp.write(json.dumps(info, sort_keys=True) + "\n")

    sniffer = AsyncSniffer(iface=cfg["iface"], filter="isis", store=False,
                           prn=log_events)
    sniffer.start()

    base_tlvs = AREA_TLV + PROTOCOLS_TLV
    base_tlvs += bytes([22, 11]) + target_sysid + bytes([0])
    base_tlvs += bytes([0, 0, 10]) + bytes([0])

    sent_jobs = set()
    iih_count = 0
    print("PEER_RUNNING", flush=True)
    while not os.path.exists(stop_file):
        # IIH keepalive: INIT for the first two, then UP with neighbor.
        state = 1 if iih_count < 2 else 0
        iih = build_iih(template, fake_sysid, 1, state,
                        target_sysid, ext_cid)
        send_frame(cfg["iface"], iih, INJECTOR_MAC)
        iih_count += 1
        # Injection jobs.
        for name in sorted(os.listdir(spool)):
            if not name.startswith("job_") or not name.endswith(".json"):
                continue
            if name in sent_jobs:
                continue
            job_path = os.path.join(spool, name)
            try:
                with open(job_path) as fp:
                    job = json.load(fp)
            except Exception:
                time.sleep(0.1)
                continue
            sent_jobs.add(name)
            done = {"name": job["name"], "sent": []}
            for index, spec in enumerate(job["frames"]):
                extra = b""
                for prefix in spec.get("reach", []):
                    extra += tlv236(prefix)
                if spec.get("locators"):
                    extra += tlv27(spec["locators"])
                pdu = build_lsp(fake_sysid, spec.get("frag", 0),
                                spec["seqno"], spec.get("lifetime", 600),
                                base_tlvs, extra)
                if index:
                    time.sleep(job.get("spacing", 0.4))
                send_frame(cfg["iface"], pdu, INJECTOR_MAC)
                done["sent"].append({"frag": spec.get("frag", 0),
                                     "seqno": spec["seqno"],
                                     "reach": spec.get("reach", []),
                                     "locators": spec.get("locators", []),
                                     "len": len(pdu)})
            with open(os.path.join(spool, name.replace(".json", ".done")),
                      "w") as fp:
                json.dump(done, fp, sort_keys=True)
            os.remove(job_path)
        time.sleep(IIH_INTERVAL)
    sniffer.stop()
    events_fp.close()
    print("PEER_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(run_peer(json.load(open(sys.argv[1]))))
