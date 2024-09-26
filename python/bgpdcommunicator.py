# SPDX-License-Identifier: GPL-2.0-or-later
# FRR bgpd socket communicator
#
# Copyright (C) 2024 Ofer Chen

import socket
import os
import argparse


class BGPDCommunicator:
    BUFFER_SIZE = 65536  # 64KB buffer size
    SOCKET_PATH = "/var/run/frr/bgpd.vty"
    TIMEOUT = 5
    TERMINATOR = b"\0\0\0"

    # error code mapping from https://github.com/FRRouting/frr/blob/master/bgpd/bgp_errors.c
    ERROR_CODES = {
        0: "Success",
        1: "BGP AS-path conversion failed",
        2: "BGP reserved SNPA length field received",
        3: "BGP missing update attribute",
        4: "BGP attribute too small",
        5: "BGP extended attribute too small",
        6: "BGP repeated update attribute",
        7: "BGP attribute too large",
        8: "BGP attribute parse error",
        9: "BGP optional attribute parse error (caused withdraw)",
        10: "BGP attribute fetch error",
        11: "BGP attribute length mismatch",
        12: "BGP MRT dump subsystem issue",
        13: "BGP update packet too small",
        14: "BGP update packet too large",
        15: "Unknown BGP capability received",
        16: "Unable to set TCP MD5 option on socket",
        17: "BGP received EVPN NLRI with PMSI included",
        18: "BGP received local MACIP but cannot handle it",
        19: "BGP received ESI for deletion but cannot process",
        20: "BGP received invalid label stack",
        21: "BGP failed to send data to zebra",
        22: "BGP capability invalid length",
        23: "BGP capability invalid data",
        24: "Vendor-specific capability received",
        25: "BGP unrecognized capability",
        26: "Invalid BGP next-hop length",
        27: "BGP send queue stuck warning",
        28: "BGP attribute flag is incorrect",
        29: "BGP attribute length is incorrect",
        30: "BGP attribute origin value invalid",
        31: "BGP as path is invalid",
        32: "BGP as path first AS invalid",
        33: "BGP PMSI tunnel attribute type is invalid",
        34: "BGP PMSI tunnel attribute length is invalid",
        35: "BGP AIGP attribute is incorrect",
        36: "BGP peer group operation error",
        37: "BGP peer deletion failed",
        38: "BGP table chunk memory allocation error",
        39: "BGP received MACIP with invalid IP address length",
        40: "BGP invalid label manager message",
        41: "BGP JSON memory allocation error",
        42: "BGP update group attributes too long",
        43: "BGP update group creation failed",
        44: "BGP error creating update packet",
        45: "BGP error receiving open packet",
        46: "BGP error sending to peer",
        47: "BGP invalid status received from peer",
        48: "BGP error receiving update packet",
        49: "BGP capability not enabled",
        50: "BGP error receiving notify message",
        51: "BGP error receiving keepalive packet",
        52: "BGP error receiving route refresh message",
        53: "BGP error processing received capability",
        54: "BGP nexthop update error",
        55: "BGP failed to apply label",
        56: "Invalid ECMP/Multipath value",
        57: "BGP packet processing error",
        58: "BGP VTEP invalid",
    }

    def __init__(self, socket_path=SOCKET_PATH, timeout=TIMEOUT):
        """Initialize connection to the bgpd socket."""
        self.socket_path = socket_path
        self.timeout = timeout
        self.sock = None

    def connect(self):
        """Connect to the BGP daemon's socket."""
        if not os.path.exists(self.socket_path):
            raise FileNotFoundError(f"Socket path {self.socket_path} does not exist.")

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.socket_path)
        except socket.error as e:
            raise ConnectionError(f"Failed to connect to bgpd socket: {str(e)}")

    def send_command(self, command):
        """Send a command to bgpd and receive the response."""
        if self.sock is None:
            raise ConnectionError("Not connected to bgpd socket.")

        if not isinstance(command, str) or not command.strip():
            raise ValueError("Command must be a non-empty string.")

        # NUL-terminated (\0) commands
        command_with_null = (command + "\0").encode("utf-8")

        try:
            self.sock.sendall(command_with_null)
            return self.receive_response()
        except socket.timeout as e:
            raise TimeoutError(
                f"Timeout occurred while sending command '{command}': {str(e)}"
            )
        except socket.error as e:
            raise IOError(f"Failed to send command '{command}': {str(e)}")

    def receive_response(self):
        """Receive the response from the bgpd socket."""
        response = b""
        try:
            while True:
                chunk = self.sock.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                response += chunk
                if BGPDCommunicator.TERMINATOR in response[-4:]:
                    break
        except socket.timeout as e:
            raise TimeoutError(f"Timeout occurred while receiving response: {str(e)}")
        except socket.error as e:
            raise IOError(f"Failed to receive response: {str(e)}")

        if not response:
            raise ValueError("Received an empty response from bgpd.")

        # 3 NUL markers and status code at the end
        if response[-4:-1] != BGPDCommunicator.TERMINATOR:
            raise ValueError("Invalid response format: missing NUL markers.")

        # Extract error status code
        status_code = response[-1]
        if status_code != 0:
            error_message = BGPDCommunicator.ERROR_CODES.get(
                status_code, f"Unknown error code: {status_code}"
            )
            raise RuntimeError(
                f"Command failed with status code {status_code}: {error_message}"
            )

        # response text is before the first NUL byte
        response_text = response.split(b"\0")[0]
        return response_text.decode("utf-8")

    def close(self):
        """Close the socket connection."""
        if self.sock:
            try:
                self.sock.close()
                self.sock = None
            except socket.error as e:
                raise IOError(f"Failed to close bgpd socket: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Send commands to the bgpd socket and receive responses."
    )
    parser.add_argument(
        "--socket",
        type=str,
        default=BGPDCommunicator.SOCKET_PATH,
        help="Path to the bgpd socket (default: %(default)s).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Socket timeout",
    )
    parser.add_argument(
        "command", type=str, help="BGP command to send to the bgpd daemon."
    )

    args = parser.parse_args()

    communicator = BGPDCommunicator(socket_path=args.socket, timeout=args.timeout)
    try:
        communicator.connect()
        response = communicator.send_command(args.command)
        print(response)
    finally:
        communicator.close()


if __name__ == "__main__":
    main()
