#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

import argparse
import ipaddress
import select
import signal
import socket
import struct
import subprocess
import sys
import time


ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
IPPROTO_ICMPV6 = 58
ICMPV6_NS = 135
ICMPV6_NA = 136

keep_running = True


def _stop(_signum, _frame):
    global keep_running
    keep_running = False


def _mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def _mac_text(raw):
    return ":".join("{:02x}".format(byte) for byte in raw)


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _icmpv6_checksum(src, dst, payload):
    pseudo = src + dst + struct.pack("!I3xB", len(payload), IPPROTO_ICMPV6)
    return _checksum(pseudo + payload)


def _ether(dst, src, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


def _arp_payload(op, src_mac, src_ip, dst_mac, dst_ip):
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        op,
        src_mac,
        src_ip,
        dst_mac,
        dst_ip,
    )


def _send_garp(sock, mac, ip4):
    bmac = _mac_bytes(mac)
    bip = socket.inet_aton(ip4)
    payload = _arp_payload(1, bmac, bip, b"\xff" * 6, bip)
    sock.send(_ether(b"\xff" * 6, bmac, ETH_P_ARP, payload))
    print("sent garp {} {}".format(ip4, mac), flush=True)


def _ipv6_packet(src_ip, dst_ip, payload):
    src = ipaddress.IPv6Address(src_ip).packed
    dst = ipaddress.IPv6Address(dst_ip).packed
    header = struct.pack("!IHBB16s16s", 0x60000000, len(payload), IPPROTO_ICMPV6, 255, src, dst)
    return header + payload


def _na_payload(src_ip, dst_ip, target_ip, mac, solicited):
    flags = 0x20000000
    if solicited:
        flags |= 0x40000000

    target = ipaddress.IPv6Address(target_ip).packed
    option = struct.pack("!BB6s", 2, 1, _mac_bytes(mac))
    payload = struct.pack("!BBH", ICMPV6_NA, 0, 0) + struct.pack("!I", flags) + target + option
    checksum = _icmpv6_checksum(
        ipaddress.IPv6Address(src_ip).packed,
        ipaddress.IPv6Address(dst_ip).packed,
        payload,
    )
    return payload[:2] + struct.pack("!H", checksum) + payload[4:]


def _send_unsolicited_na(sock, mac, ip6):
    dst_ip = "ff02::1"
    dst_mac = _mac_bytes("33:33:00:00:00:01")
    payload = _na_payload(ip6, dst_ip, ip6, mac, False)
    sock.send(_ether(dst_mac, _mac_bytes(mac), ETH_P_IPV6, _ipv6_packet(ip6, dst_ip, payload)))
    print("sent unsolicited-na {} {}".format(ip6, mac), flush=True)


def _send_arp_reply(sock, mac, ip4, frame, arp):
    src_mac = _mac_bytes(mac)
    src_ip = socket.inet_aton(ip4)
    requester_mac = arp[8:14]
    requester_ip = arp[14:18]
    payload = _arp_payload(2, src_mac, src_ip, requester_mac, requester_ip)
    sock.send(_ether(frame[6:12], src_mac, ETH_P_ARP, payload))
    print("replied arp {} {} to {}".format(ip4, mac, _mac_text(frame[6:12])), flush=True)


def _send_na_reply(sock, mac, ip6, frame, ipv6, icmp):
    src_ip = ipaddress.IPv6Address(ipv6[8:24])
    if src_ip == ipaddress.IPv6Address("::"):
        dst_ip = "ff02::1"
        dst_mac = _mac_bytes("33:33:00:00:00:01")
        solicited = False
    else:
        dst_ip = str(src_ip)
        dst_mac = frame[6:12]
        solicited = True

    payload = _na_payload(ip6, dst_ip, ip6, mac, solicited)
    sock.send(_ether(dst_mac, _mac_bytes(mac), ETH_P_IPV6, _ipv6_packet(ip6, dst_ip, payload)))
    print("replied na {} {} to {}".format(ip6, mac, _mac_text(dst_mac)), flush=True)


def _parse_eth_payload(frame):
    if len(frame) < 14:
        return None, b""

    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == ETH_P_8021Q and len(frame) >= 18:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18

    return ethertype, frame[offset:]


def _handle_frame(sock, mac, ip4, ip6, frame):
    ethertype, payload = _parse_eth_payload(frame)
    if ethertype == ETH_P_ARP:
        if len(payload) < 28:
            return
        _, proto, hlen, plen, op = struct.unpack("!HHBBH", payload[:8])
        if proto != 0x0800 or hlen != 6 or plen != 4 or op != 1:
            return
        if payload[24:28] == socket.inet_aton(ip4):
            _send_arp_reply(sock, mac, ip4, frame, payload)
    elif ethertype == ETH_P_IPV6 and ip6:
        if len(payload) < 64:
            return
        next_header = payload[6]
        hop_limit = payload[7]
        icmp = payload[40:]
        if next_header != IPPROTO_ICMPV6 or hop_limit != 255 or icmp[0] != ICMPV6_NS:
            return
        target = ipaddress.IPv6Address(icmp[8:24])
        if target == ipaddress.IPv6Address(ip6):
            _send_na_reply(sock, mac, ip6, frame, payload, icmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--ip4", required=True)
    parser.add_argument("--ip6")
    parser.add_argument("--no-unsolicited-na", action="store_true")
    args = parser.parse_args()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)

    subprocess.call(["ip", "link", "set", "dev", args.interface, "promisc", "on"])

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.interface, 0))
    sock.setblocking(False)

    print(
        "dad_snooper start iface={} mac={} ip4={} ip6={}".format(
            args.interface, args.mac, args.ip4, args.ip6 or "none"
        ),
        flush=True,
    )

    for _ in range(3):
        _send_garp(sock, args.mac, args.ip4)
        if args.ip6 and not args.no_unsolicited_na:
            _send_unsolicited_na(sock, args.mac, args.ip6)
        time.sleep(0.25)

    try:
        while keep_running:
            readable, _, _ = select.select([sock], [], [], 1)
            if not readable:
                continue
            frame = sock.recv(65535)
            if frame[6:12] == _mac_bytes(args.mac):
                continue
            _handle_frame(sock, args.mac, args.ip4, args.ip6, frame)
    finally:
        subprocess.call(["ip", "link", "set", "dev", args.interface, "promisc", "off"])
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
