#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# tshark.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2016 by
# Adriano Marto Reis <adrianomarto@gmail.com>
#

import json
import subprocess
import time
from multiprocessing import Pipe, Process
from lib.topogen import get_topogen


class Tshark:

    def __init__(self, router_name, interface_name, display_filter="", duration=1.0):
        """
        Creates and starts a tshark instance capturing packets on a given
        interface of a router, using a given display filter, running for
        a given duration [seconds]
        """
        self.router = get_topogen().routers()[router_name]
        self.interface_name = interface_name
        command = [
            "tshark",
            "--interface",
            interface_name,
            "--autostop",
            f"duration:{duration}",
            "-Y",
            display_filter,
            "-T",
            "json",
            "-l",
        ]
        self.parent_conn, child_conn = Pipe()
        self.process = Process(target=self._exec, args=(child_conn, command))
        self.process.start()

        # Wait until the packet capture starts
        start_time = time.time()
        while (
            not self._has_packet_capture_started()
            and time.time() - start_time < duration
        ):
            time.sleep(1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Ensures the tshark process is terminated.
        """
        self.process.terminate()
        self.process.join()

    def get_packets(self):
        """
        Gets the captured packets as a dictionary. This will wait for the
        tshark command to finish in busy-wait. Returns an exception instead
        if any error occurs.
        """
        self.process.join()
        packets = self.parent_conn.recv()
        if isinstance(packets, Exception):
            raise packets
        return packets

    def _exec(self, conn, command):
        """
        Executes tshark on the topogen router and stores the captured packets
        as a dictionary.
        """
        try:
            output = self.router.cmd_raises(command, stderr=subprocess.DEVNULL)
            raw_packets = json.loads(output)

            # Extract the fields from each layer
            packets = []
            for raw_packet in raw_packets:
                packet = {}
                Tshark._build_packet(packet, raw_packet["_source"]["layers"])
                packets.append(packet)
            conn.send(packets)
        except Exception as error:
            conn.send(error)

    def _has_packet_capture_started(self):
        """
        Checks if the packet capture has started.
        """
        try:
            output = self.router.cmd_raises(
                ["ip", "--detail", "--json", "link", "show", self.interface_name]
            )
            status = json.loads(output)
            return status[0]["promiscuity"] == 1
        except Exception:
            return False

    @staticmethod
    def _build_packet(packets, layer):
        """
        Recursively extracts the fields from a layer to build a field:value
        dictionary.
        """
        for field_name, field_value in layer.items():
            if isinstance(field_value, dict):
                Tshark._build_packet(packets, field_value)
            else:
                packets[field_name] = field_value
