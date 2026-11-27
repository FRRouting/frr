#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# scapy_capture.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#
# DEPRECATED: use lib/scapy_utils.py instead
"""Capture packets on a router interface to a pcap file with scapy.

Run as a script inside a router namespace, it sniffs until SIGINT/SIGTERM
and then writes the pcap.  start_capture() and stop_capture() run it from
a test.  tcpdump is not used: it is missing in some images and exits when
the interface goes down.
"""

import argparse
import os
import shlex
import signal
import sys
import threading
import time

from scapy.all import AsyncSniffer, conf, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def _wait_until(func, timeout_s=15, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _proc_alive(router, pid):
    out = router.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
    try:
        return int(out.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        return False


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _read_err(router, err_path):
    err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
    if os.path.exists(err_path):
        with open(err_path) as f:
            err = err or f.read()
    return err.strip()


def start_capture(router, iface, pcap_path, bpf=None):
    """Start capturing on router:iface into pcap_path; return the pid.

    pcap_path must be visible to both the router and the test, e.g. under
    tgen.logdir.  Returns once the capture socket is open, and fails the
    test if the capture does not start within 60 seconds.
    """
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    cmd = "nohup python3 %s --iface %s --pcap %s --ready-file %s" % (
        shlex.quote(os.path.realpath(__file__)),
        shlex.quote(iface),
        shlex.quote(pcap_path),
        shlex.quote(ready_path),
    )
    if bpf:
        cmd += " --filter %s" % shlex.quote(bpf)
    # nohup: router.cmd() closing the session would otherwise SIGHUP the sniffer.
    pid = router.cmd(
        "%s </dev/null >%s 2>&1 & echo $!" % (cmd, shlex.quote(err_path))
    ).strip()
    if pid:
        pid = pid.splitlines()[-1]
    assert pid.isdigit(), "scapy capture did not start on %s (pid %r)" % (
        router.name,
        pid,
    )
    _wait_until(
        lambda: _file_ready(ready_path) or not _proc_alive(router, pid),
        timeout_s=60,
    )
    if not _file_ready(ready_path):
        alive = _proc_alive(router, pid)
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        assert False, "scapy capture did not become ready on %s (pid %s, %s): %s" % (
            router.name,
            pid,
            "still running" if alive else "exited",
            _read_err(router, err_path) or "no capture stderr",
        )
    return pid


def stop_capture(router, pid, pcap_path):
    """Stop a capture from start_capture() and wait for its pcap file."""
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    if not _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ):
        assert False, "pcap %s missing after stopping capture: %s" % (
            pcap_path,
            _read_err(router, pcap_path + ".err") or "empty/missing file",
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--filter", default=None, help="BPF capture filter")
    parser.add_argument("--ready-file", default="")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    started = threading.Event()
    sniffer = AsyncSniffer(
        iface=args.iface,
        filter=args.filter,
        store=True,
        started_callback=started.set,
    )
    try:
        sniffer.start()
    except Exception as exc:
        sys.stderr.write("scapy sniff failed on %s: %s\n" % (args.iface, exc))
        sys.exit(1)

    # AsyncSniffer opens its socket in a thread and keeps any error there.
    while not started.wait(0.1):
        if not sniffer.thread.is_alive():
            sys.stderr.write(
                "scapy sniff failed on %s: %s\n" % (args.iface, sniffer.exception)
            )
            sys.exit(1)

    if args.ready_file:
        with open(args.ready_file, "w") as f:
            f.write("ready\n")

    while not _stop:
        time.sleep(0.1)

    try:
        sniffer.stop()
    except Exception:
        pass

    pkts = list(sniffer.results or [])
    wrpcap(args.pcap, pkts)
    # Make the file visible on shared rundir mounts before we exit.
    try:
        os.fsync(os.open(args.pcap, os.O_RDONLY))
    except OSError:
        pass


if __name__ == "__main__":
    main()
