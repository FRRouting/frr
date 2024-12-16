#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import argparse

# XXX: something more reliable should be used "Twisted" a great choice.
import signal
import socket
import sys

from datetime import datetime

from bmp import BMPMsg

BGP_MAX_SIZE = 4096

# Global variable to track shutdown signal
shutdown = False


parser = argparse.ArgumentParser()
parser.add_argument("-a", "--address", type=str, default="0.0.0.0")
parser.add_argument("-p", "--port", type=int, default=1789)
parser.add_argument("-l", "--logfile", type=str, default="/var/log/bmp.log")


def handle_signal(signum, frame):
    global shutdown
    timestamp_print(f"Received signal {signum}, shutting down.")
    shutdown = True


def timestamp_print(message, file=sys.stderr):
    """Helper function to timestamp_print messages with timestamps."""

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}] {message}", file=file)


def main():
    global shutdown

    # Set up signal handling for SIGTERM and SIGINT
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    args = parser.parse_args()
    ADDRESS, PORT = args.address, args.port
    LOG_FILE = args.logfile

    timestamp_print(f"Starting bmpserver on {args.address}:{args.port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ADDRESS, PORT))
            s.listen()
            timestamp_print(f"Listening on TCP {args.address}:{args.port}")

            connection, client_address = s.accept()
            timestamp_print(f"TCP session opened from {client_address}")

            try:
                while not shutdown:  # Check for shutdown signal
                    data = connection.recv(BGP_MAX_SIZE)
                    if shutdown:
                        break

                    if not data:
                        # connection closed
                        break

                    timestamp_print(
                        f"Data received from {client_address}: length {len(data)}"
                    )

                    while len(data) > BMPMsg.MIN_LEN:
                        data = BMPMsg.dissect(data, log_file=LOG_FILE)

                    timestamp_print(f"Finished dissecting data from {client_address}")

            except Exception as e:
                timestamp_print(f"{e}")
                pass
            except KeyboardInterrupt:
                timestamp_print(f"Got Keyboard Interrupt.")
                pass
            finally:
                timestamp_print(f"TCP session closed with {client_address}")
                connection.close()
        except socket.error as sock_err:
            timestamp_print(f"Socket error: {e}")
        except Exception as e:
            timestamp_print(f"{e}")
        finally:
            timestamp_print(f"Server shutting down on {ADDRESS}:{PORT}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("BMP server was interrupted and is shutting down.")
        sys.exit(0)
