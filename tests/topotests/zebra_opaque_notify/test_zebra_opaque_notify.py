#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Carmine Scarpitta
#

"""Test Zebra opaque message and registration notification delivery."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.sharpd]


def build_topo(tgen):
    """Build a single-router topology running Zebra and Sharp."""
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd"])

    tgen.start_router()

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure terminal
        log file sharpd.log debug
        end
        """,
        daemon="sharpd",
    )
    r1.vtysh_cmd("sharp create session 10", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque reg sharp session 10 type 250", daemon="sharpd")


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _read_sharp_log(log_path):
    try:
        with open(log_path, encoding="utf-8") as log_file:
            return log_file.read()
    except FileNotFoundError:
        return ""


def _wait_for_log_entry(log_path, start, entry, error):
    def test_func():
        return entry in _read_sharp_log(log_path)[start:]

    _, result = topotest.run_and_expect(test_func, True, count=20, wait=0.5)
    assert result is True, error


def _ensure_session_ready(r1, sharp_log):
    marker = "sharp_opaque_handler: [10] received opaque type 250"
    start = len(_read_sharp_log(sharp_log))

    def send_marker_until_received():
        r1.vtysh_cmd("sharp send opaque type 250 1", daemon="sharpd")
        return marker in _read_sharp_log(sharp_log)[start:]

    _, result = topotest.run_and_expect(
        send_marker_until_received, True, count=20, wait=0.5
    )
    assert result is True, "Sharp test session 10 did not receive the marker"


def test_no_receiver_registration_receives_no_opaque_message():
    """Leave subtype 101 unregistered; verify sharpd does not receive it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_log = os.path.join(tgen.logdir, "r1", "sharpd.log")

    _ensure_session_ready(r1, sharp_log)
    before = _read_sharp_log(sharp_log)

    # No Sharp client is registered to receive subtype 101.
    r1.vtysh_cmd("sharp send opaque type 101 1", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque type 250 1", daemon="sharpd")

    marker = "sharp_opaque_handler: [10] received opaque type 250"
    _wait_for_log_entry(
        sharp_log,
        len(before),
        marker,
        "Sharp test session 10 did not receive the marker message",
    )

    new_log = _read_sharp_log(sharp_log)[len(before) :]
    assert (
        "received opaque type 101" not in new_log
    ), "Sharp received an opaque message without a receiver registration"


def test_receiver_registration_receives_payload_without_notification():
    """Register for subtype 102; verify sharpd gets only the opaque payload."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_log = os.path.join(tgen.logdir, "r1", "sharpd.log")
    _ensure_session_ready(r1, sharp_log)
    before = len(_read_sharp_log(sharp_log))

    r1.vtysh_cmd("sharp send opaque reg sharp type 102", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque type 102 1", daemon="sharpd")

    payload = "sharp_opaque_handler: [0] received opaque type 102"
    try:
        _wait_for_log_entry(
            sharp_log,
            before,
            payload,
            "Sharp did not receive the opaque payload",
        )
        new_log = _read_sharp_log(sharp_log)[before:]
        assert "opaque notification REG, type 102" not in new_log, (
            "Sharp received a registration notification without subscribing "
            "to notifications"
        )
    finally:
        r1.vtysh_cmd("sharp send opaque unreg sharp type 102", daemon="sharpd")


def test_notification_only_client_gets_registration_not_payload():
    """Register session 0 for notifications and session 10 to receive subtype 103.

    Verify session 0 gets the registration notification but not the payload.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_log = os.path.join(tgen.logdir, "r1", "sharpd.log")
    _ensure_session_ready(r1, sharp_log)
    before = len(_read_sharp_log(sharp_log))

    # Session 0 subscribes only to notifications. Session 10 registers as
    # the receiver to trigger a registration event.
    r1.vtysh_cmd("sharp send opaque notify reg type 103", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque reg sharp session 10 type 103", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque reg sharp type 251", daemon="sharpd")

    notification = (
        "sharp_opq_notify_handler: received opaque notification REG, type 103 =>"
    )
    receiver_payload = "sharp_opaque_handler: [10] received opaque type 103"
    try:
        _wait_for_log_entry(
            sharp_log,
            before,
            notification,
            "Sharp did not receive the registration notification",
        )

        r1.vtysh_cmd("sharp send opaque type 103 1", daemon="sharpd")
        _wait_for_log_entry(
            sharp_log,
            before,
            receiver_payload,
            "The registered Sharp receiver did not receive the opaque payload",
        )

        # Wait for a session 0 marker sent after the payload, so its queue has
        # processed any earlier message before checking the log.
        r1.vtysh_cmd("sharp send opaque type 251 1", daemon="sharpd")
        session0_marker = "sharp_opaque_handler: [0] received opaque type 251"
        _wait_for_log_entry(
            sharp_log,
            before,
            session0_marker,
            "Sharp test session 0 did not receive the marker",
        )

        new_log = _read_sharp_log(sharp_log)[before:]
        assert "sharp_opaque_handler: [0] received opaque type 103" not in new_log, (
            "Zebra delivered the opaque payload to the notification-only Sharp "
            "client"
        )
    finally:
        r1.vtysh_cmd(
            "sharp send opaque unreg sharp session 10 type 103", daemon="sharpd"
        )
        r1.vtysh_cmd("sharp send opaque unreg sharp type 251", daemon="sharpd")
        r1.vtysh_cmd("sharp send opaque notify unreg type 103", daemon="sharpd")


def test_receiver_and_notification_registrations_get_both():
    """Register for subtype 104 and notifications; verify sharpd gets both."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_log = os.path.join(tgen.logdir, "r1", "sharpd.log")
    _ensure_session_ready(r1, sharp_log)
    before = len(_read_sharp_log(sharp_log))

    r1.vtysh_cmd("sharp send opaque notify reg type 104", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque reg sharp type 104", daemon="sharpd")
    r1.vtysh_cmd("sharp send opaque type 104 1", daemon="sharpd")

    notification = (
        "sharp_opq_notify_handler: received opaque notification REG, type 104 =>"
    )
    payload = "sharp_opaque_handler: [0] received opaque type 104"
    try:
        _wait_for_log_entry(
            sharp_log,
            before,
            notification,
            "Sharp did not receive the opaque registration notification",
        )
        _wait_for_log_entry(
            sharp_log,
            before,
            payload,
            "Sharp did not receive the opaque payload",
        )
    finally:
        r1.vtysh_cmd("sharp send opaque unreg sharp type 104", daemon="sharpd")
        r1.vtysh_cmd("sharp send opaque notify unreg type 104", daemon="sharpd")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
