#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Capture Babel packets without requiring tcpdump in the test image."""

import argparse
import signal

from scapy.all import PcapWriter, UDP, conf


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # Open the capture socket before announcing readiness. Filtering in
    # Python also avoids Scapy's dependency on an external BPF compiler.
    capture = conf.L2listen(iface=args.iface)
    try:
        with PcapWriter(args.pcap, linktype=1, sync=True) as writer:
            writer.write_header(None)
            print("ready", flush=True)
            while not stopping:
                if not capture.select([capture], 0.1):
                    continue
                packet = capture.recv()
                if packet is not None and UDP in packet:
                    udp = packet[UDP]
                    if udp.sport == 6696 or udp.dport == 6696:
                        writer.write(packet)
    finally:
        capture.close()


if __name__ == "__main__":
    main()
