#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
import argparse
import errno
import logging

# XXX: something more reliable should be used "Twisted" a great choice.
import os
import signal
import socket
import sys

from datetime import datetime

from bmp import BMPMsg

# RFC8654 : max packet size is 65535 bytes
BGP_MAX_SIZE = 65535

# Global variable to track shutdown signal
shutdown = False

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--address", type=str, default="0.0.0.0")
parser.add_argument("-p", "--port", type=int, default=1789)
parser.add_argument("-l", "--logfile", type=str, default="/var/log/bmp.log")
parser.add_argument("-r", "--pidfile", type=str, default="/var/run/bmp.pid")


def handle_signal(signum, frame):
    global shutdown
    timestamp_print(f"Received signal {signum}, shutting down.")
    shutdown = True


def timestamp_print(message, file=sys.stderr):
    """Helper function to timestamp_print messages with timestamps."""

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}] {message}", file=file)


def check_pid(pid):
    if pid < 0:  # user input error
        return False
    if pid == 0:  # all processes
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.EPERM:  # a process we were denied access to
            return True
        if err.errno == errno.ESRCH:  # No such process
            return False
        # should never happen
        return False


def savepid():
    ownid = os.getpid()

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    mode = ((os.R_OK | os.W_OK) << 6) | (os.R_OK << 3) | os.R_OK

    try:
        fd = os.open(pid_file, flags, mode)
    except OSError:
        try:
            pid = open(pid_file, "r").readline().strip()
            if check_pid(int(pid)):
                timestamp_print(
                    f"PID file already exists and program still running {pid_file}\n"
                )
                return False
            else:
                # If pid is not running, reopen file without O_EXCL
                fd = os.open(pid_file, flags ^ os.O_EXCL, mode)
        except (OSError, IOError, ValueError):
            timestamp_print(
                f"issue accessing PID file {pid_file} (most likely permission or ownership)\n"
            )
            return False

    try:
        f = os.fdopen(fd, "w")
        line = "%d\n" % ownid
        f.write(line)
        f.close()
        saved_pid = True
    except IOError:
        timestamp_print(f"Can not create PID file {pid_file}\n")
        return False
    timestamp_print(f"Created PID file {pid_file} with value {ownid}\n")
    return True


def removepid():
    try:
        os.remove(pid_file)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            pass
        else:
            timestamp_print(f"Can not remove PID file {pid_file}\n")
            return
    timestamp_print(f"Removed PID file {pid_file}\n")


def main():
    global shutdown

    # Set up signal handling for SIGTERM and SIGINT
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    args = parser.parse_args()
    ADDRESS, PORT = args.address, args.port
    LOG_FILE = args.logfile

    global pid_file
    pid_file = args.pidfile

    timestamp_print(f"Starting bmpserver on {args.address}:{args.port}")

    savepid()

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
            timestamp_print(f"Socket error: {sock_err}")
        except Exception as e:
            timestamp_print(f"{e}")
        finally:
            timestamp_print(f"Server shutting down on {ADDRESS}:{PORT}")
            removepid()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("BMP server was interrupted and is shutting down.")
        removepid()
        sys.exit(0)
