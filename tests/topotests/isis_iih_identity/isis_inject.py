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
Raw LAN-IIH/LSP injector for the IS-IS IIH identity topotest.

Runs on host h1, which is attached to LAN1 but speaks no IS-IS itself.
It sniffs genuine L2 LAN hellos and r2's L2 LSP to capture PDU
templates, then replays a template with chosen header edits at a
bounded rate.  All PDU handling is byte-wise on the ISO 10589 layout:
the fixed LAN-hello header is 27 bytes, with the system-id at offsets
9..14, the priority at offset 19, the LAN ID (designated IS) at offsets
20..26, the PDU length field at offsets 17..18, and TLVs from offset
27.  FRR pads hellos with TLV 8 up to the MTU, so the padding is
stripped before a replay.  LSP layout: remaining lifetime at 10..11,
LSP ID at 12..19, sequence number at 20..23, checksum at 24..25; the
ISO 8473 checksum is recomputed with the seqno bump.

Subcommands:
  template IFACE OUTFILE TIMEOUT
      Sniff until a hello template for every expected sysid and r2's
      LSP have been captured, write
      {"iih": {"<sysid>": {"pdu": <hex>, "src_mac": <mac>}},
       "lsp": {"<lspid>": {"pdu": <hex>, "seqno": <int>}}}
      to OUTFILE, then print "TEMPLATE_DONE".
  send IFACE TEMPLATE_FILE SRC_MAC DST_MAC COUNT SPACING EDITS_JSON
      Replay one variant COUNT times, SPACING seconds apart, from
      SRC_MAC to DST_MAC.  EDITS_JSON selects the template and the
      edits:
        {"template": "<sysid>"}                  LAN IIH template
        {"template": "lsp:<lspid>", "seqno_set": N}
                                                 LSP template, seqno=N
        optional IIH edits: "sysid" (hex), "pdu_type" (int),
        "bad_pdu_len" (int), "drop_tlvs" ([int]),
        "tlv6_replace" ([old_hex, new_hex]), "tlv6_append" (hex)
      Then print "SENT=COUNT".
"""

import json
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, LLC, Raw, conf, sendp

conf.verb = 0

EXPECTED_SYSIDS = ["000000000001", "000000000002"]
R2_LSPID_PREFIX = "0000000000020000"


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


def parse_l2_lsp(raw):
    "Return {lspid, seqno, pdu} for an L2 LSP frame, else None."
    if len(raw) < 17 + 27:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if pdu[0] != 0x83 or (pdu[4] & 0x1F) != 20:
        return None
    return {
        "lspid": pdu[12:20].hex(),
        "seqno": struct.unpack("!I", pdu[20:24])[0],
        "pdu": pdu,
    }


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


def fletcher_lsp(pdu):
    "Recompute the ISO 8473 checksum of an LSP PDU over pdu[12:]."
    buf = bytearray(pdu[12:])
    buf[12:14] = b"\x00\x00"
    c0 = c1 = 0
    p = 0
    left = len(buf)
    while left:
        partial = min(left, 4102)
        for _ in range(partial):
            c0 += buf[p]
            c1 += c0
            p += 1
        c0 %= 255
        c1 %= 255
        left -= partial
    x = ((len(buf) - 12 - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    out = bytearray(pdu)
    out[24] = x
    out[25] = y
    return bytes(out)


def edit_tlvs(pdu, drop_types=(), replace_mac=None, append_mac=None):
    "Drop whole TLVs, rewrite TLV 6 MACs, or append one TLV 6 entry."
    pdu = bytearray(pdu)
    off = 27
    out = bytearray(pdu[:27])
    while off + 2 <= len(pdu):
        t, l = pdu[off], pdu[off + 1]
        body = pdu[off + 2:off + 2 + l]
        if t not in drop_types:
            if t == 6 and replace_mac is not None:
                old, new = replace_mac
                body = body.replace(old, new)
            out += bytes([t, len(body)]) + body
        off += 2 + l
    if append_mac is not None:
        out += bytes([6, 6]) + append_mac
    out[17:19] = struct.pack("!H", len(out))
    return bytes(out)


def build_variant(templates, edits):
    if edits["template"].startswith("lsp:"):
        lspid = edits["template"][4:]
        pdu = bytearray(bytes.fromhex(templates["lsp"][lspid]["pdu"]))
        if "seqno_set" in edits or "seqno_bump" in edits or "lifetime_set" in edits:
            if "seqno_set" in edits:
                pdu[20:24] = struct.pack("!I", edits["seqno_set"])
            elif "seqno_bump" in edits:
                seq = struct.unpack("!I", pdu[20:24])[0] + edits["seqno_bump"]
                pdu[20:24] = struct.pack("!I", seq)
            if "lifetime_set" in edits:
                # the remaining-lifetime field is outside the checksum
                pdu[10:12] = struct.pack("!H", edits["lifetime_set"])
            pdu = fletcher_lsp(bytes(pdu))
        return bytes(pdu)
    pdu = bytearray(bytes.fromhex(templates["iih"][edits["template"]]["pdu"]))
    if "sysid" in edits:
        pdu[9:15] = bytes.fromhex(edits["sysid"])
    if "pdu_type" in edits:
        pdu[4] = edits["pdu_type"]
    if "drop_tlvs" in edits or "tlv6_replace" in edits or "tlv6_append" in edits:
        replace = None
        if "tlv6_replace" in edits:
            old, new = edits["tlv6_replace"]
            replace = (bytes.fromhex(old), bytes.fromhex(new))
        append = bytes.fromhex(edits["tlv6_append"]) if "tlv6_append" in edits else None
        pdu = edit_tlvs(bytes(pdu), tuple(edits.get("drop_tlvs", ())),
                        replace, append)
    pdu = strip_padding(bytes(pdu))
    if "bad_pdu_len" in edits:
        pdu = bytearray(pdu)
        pdu[17:19] = struct.pack("!H", edits["bad_pdu_len"])
        pdu = bytes(pdu)
    return pdu


def cmd_template(iface, outfile, timeout):
    iih = {}
    lsp = {}

    def process(pkt):
        raw = bytes(pkt)
        info = parse_lan_iih(raw)
        if info and info["sysid"] in EXPECTED_SYSIDS and info["sysid"] not in iih:
            iih[info["sysid"]] = {
                "pdu": info["pdu"].hex(),
                "src_mac": ":".join("%02x" % b for b in raw[6:12]),
            }
            return
        info = parse_l2_lsp(raw)
        if info and info["lspid"].startswith(R2_LSPID_PREFIX) and info["lspid"] not in lsp:
            lsp[info["lspid"]] = {"pdu": info["pdu"].hex(), "seqno": info["seqno"]}

    sniffer = AsyncSniffer(iface=iface, store=False, prn=process)
    sniffer.start()
    deadline = time.time() + timeout
    while time.time() < deadline and (len(iih) < len(EXPECTED_SYSIDS) or not lsp):
        time.sleep(0.3)
    sniffer.stop()
    if len(iih) < len(EXPECTED_SYSIDS) or not lsp:
        print("TEMPLATE_FAILED " + json.dumps({"iih": sorted(iih), "lsp": sorted(lsp)}))
        return 1
    with open(outfile, "w") as fp:
        json.dump({"iih": iih, "lsp": lsp}, fp)
    print("TEMPLATE_DONE")
    return 0


def cmd_send(iface, template_file, src_mac, dst_mac, count, spacing, edits_json):
    with open(template_file) as fp:
        templates = json.load(fp)
    pdu = build_variant(templates, json.loads(edits_json))
    frame = (
        Ether(dst=dst_mac, src=src_mac)
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
        return cmd_send(args[1], args[2], args[3], args[4], int(args[5]),
                        float(args[6]), args[7])
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
