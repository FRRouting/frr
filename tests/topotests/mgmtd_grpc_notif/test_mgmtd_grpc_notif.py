# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# Copyright (C) 2026  Eric Parsonage
#
"""
Test mgmtd gRPC Subscribe streaming of YANG notifications.

Two routers run RIP with matching authentication strings.  At runtime r1's
authentication string is changed so the next RIP packet from r2 fires a
frr-ripd authentication notification inside ripd.  mgmtd receives the backend
notification, selects the gRPC subscriber through the frontend selector tree,
and streams the encoded notification payload to the connected client.
"""

import glob
import json
import os
import threading
import time

import pytest
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter

CWD = os.path.dirname(os.path.realpath(__file__))
GRPCP_MGMTD = 50058
GRPC_SUBSCRIBE_TEST_PENDING_LIMIT = 4
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]


def _frr_grpc_module_available():
    """True when the FRR northbound gRPC module (grpc.so) is installed."""
    patterns = (
        "/usr/lib/*/frr/modules/grpc.so",
        "/usr/lib/frr/modules/grpc.so",
        "/usr/lib64/*/frr/modules/grpc.so",
        "/usr/lib64/frr/modules/grpc.so",
        "/usr/local/lib/*/frr/modules/grpc.so",
        "/usr/local/lib/frr/modules/grpc.so",
    )
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                return True

    frr_root = os.path.realpath(os.path.join(CWD, "../../.."))
    for base in (frr_root, os.environ.get("FRR_BUILD_DIR")):
        if not base:
            continue
        for rel in ("lib/.libs/grpc.so", "lib/grpc.so"):
            if os.path.isfile(os.path.join(base, rel)):
                return True
    return False


try:
    import grpc  # noqa: F401
    import grpc_tools  # noqa: F401
except ImportError:
    pytest.skip("skipping; gRPC modules not installed", allow_module_level=True)

if not _frr_grpc_module_available():
    pytest.skip(
        "skipping; FRR gRPC northbound module not installed "
        "(install frr-grpc or build with --enable-grpc)",
        allow_module_level=True,
    )

try:
    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config("frr.conf")
        if rname == "r1":
            router.load_config(
                TopoRouter.RD_MGMTD,
                "",
                f"-M grpc:{GRPCP_MGMTD},{GRPC_SUBSCRIBE_TEST_PENDING_LIMIT}",
            )

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _set_auth(router, key):
    "Set rip authentication string on router's first interface."
    conf = (
        "conf t\n"
        f"interface {router.name}-eth0\n"
        f"ip rip authentication string {key}\n"
    )
    router.net.cmd_raises("vtysh", stdin=conf)


def _commit_auth(router, key):
    "Set rip authentication string through mgmtd gRPC."
    path = (
        "/frr-interface:lib"
        f"/interface[name='{router.name}-eth0']"
        "/frr-ripd:rip/authentication-password"
    )
    cmd = f"COMMIT-SET,{path}={key}\n"
    return router.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_listen(r, xpath, timeout=15):
    cmd = f"SUBSCRIBE-LISTEN,{xpath},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_listen_with_path(r, xpath, timeout=15):
    cmd = f"SUBSCRIBE-LISTEN-WITH-PATH,{xpath},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_until_sync(r, xpath, timeout=15):
    cmd = f"SUBSCRIBE-UNTIL-SYNC,{xpath},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_until_heartbeat(r, xpath, heartbeat_ms=200, timeout=5):
    cmd = f"SUBSCRIBE-UNTIL-HEARTBEAT,{xpath},{heartbeat_ms},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_cancel(r, xpath, delay=0.5, timeout=5):
    cmd = f"SUBSCRIBE-CANCEL,{xpath},{delay},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_expect_shutdown(r, xpath, timeout=15):
    cmd = f"SUBSCRIBE-EXPECT-SHUTDOWN,{xpath},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_sample_count(r, xpath, interval_ms=200, count=3, timeout=5):
    cmd = f"SUBSCRIBE-SAMPLE-COUNT,{xpath},{interval_ms},{count},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_expect_error(r, mode, xpath, expected, timeout=5):
    cmd = f"SUBSCRIBE-EXPECT-ERROR,{mode},{xpath},{expected},{timeout}\n"
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_sample_expect_error(r, xpath, interval_ms, expected, timeout=5):
    cmd = (
        "SUBSCRIBE-SAMPLE-EXPECT-ERROR,"
        f"{xpath},{interval_ms},{expected},{timeout}\n"
    )
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_stream_repeat_expect_error(r, xpath, repeat, expected, timeout=5):
    cmd = (
        "SUBSCRIBE-STREAM-REPEAT-EXPECT-ERROR,"
        f"{xpath},{repeat},{expected},{timeout}\n"
    )
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def _run_invalid_encoding_expect_error(r, mode, xpath, expected, timeout=5):
    cmd = (
        "SUBSCRIBE-INVALID-ENCODING-EXPECT-ERROR,"
        f"{mode},{xpath},99,{expected},{timeout}\n"
    )
    return r.net.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=cmd)


def test_subscribe_receives_rip_auth_notification(tgen):
    r1 = tgen.gears["r1"]
    received = {}

    def listener():
        received["raw"] = _run_listen(r1, "/frr-ripd", timeout=30)

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(2)

    _set_auth(r1, "bar")

    t.join(timeout=35)
    assert not t.is_alive(), "Subscribe listener did not return in time"

    raw = received.get("raw", "").strip()
    assert raw, "Subscribe stream returned no notification"

    data = json.loads(raw.splitlines()[-1])
    assert set(data) & {
        "frr-ripd:authentication-failure",
        "frr-ripd:authentication-type-failure",
    }, f"unexpected notification payload: {data}"

    _set_auth(r1, "foo")


def test_subscribe_update_includes_notification_path(tgen):
    r1 = tgen.gears["r1"]
    received = {}

    def listener():
        received["raw"] = _run_listen_with_path(r1, "/frr-ripd", timeout=30)

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(2)

    _set_auth(r1, "bar")

    t.join(timeout=35)
    assert not t.is_alive(), "Subscribe listener did not return in time"

    raw = received.get("raw", "").strip()
    assert raw, "Subscribe stream returned no notification"

    update = json.loads(raw.splitlines()[-1])
    assert update["path"] in {
        "/frr-ripd:authentication-failure",
        "/frr-ripd:authentication-type-failure",
    }, f"unexpected notification path: {update}"
    data = json.loads(update["data"])
    assert set(data) & {
        "frr-ripd:authentication-failure",
        "frr-ripd:authentication-type-failure",
    }, f"unexpected notification payload: {data}"

    _set_auth(r1, "foo")


def test_commit_config_then_subscribe_receives_notification(tgen):
    r1 = tgen.gears["r1"]
    received = {}

    def listener():
        received["raw"] = _run_listen_with_path(r1, "/frr-ripd", timeout=30)

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(2)

    _commit_auth(r1, "bar")

    t.join(timeout=35)
    assert not t.is_alive(), "Subscribe listener did not return in time"

    raw = received.get("raw", "").strip()
    assert raw, "Subscribe stream returned no notification"

    update = json.loads(raw.splitlines()[-1])
    assert update["path"] in {
        "/frr-ripd:authentication-failure",
        "/frr-ripd:authentication-type-failure",
    }, f"unexpected notification path: {update}"
    data = json.loads(update["data"])
    assert set(data) & {
        "frr-ripd:authentication-failure",
        "frr-ripd:authentication-type-failure",
    }, f"unexpected notification payload: {data}"

    _commit_auth(r1, "foo")


def test_stream_sends_initial_state_and_sync(tgen):
    r1 = tgen.gears["r1"]
    # STREAM snapshots use mgmtd-local operational state in this test.
    raw = _run_until_sync(
        r1,
        "/frr-backend:clients",
        timeout=15,
    ).strip()

    responses = json.loads(raw.splitlines()[-1])
    assert responses, "STREAM Subscribe returned no responses"
    assert responses[-1] == {"sync_response": True}
    updates = [item for item in responses if "update" in item]
    assert updates, "STREAM Subscribe returned no initial state update"
    assert all(update["path"] == "/frr-backend:clients" for update in updates)
    assert any("frr-backend:clients" in update["update"] for update in updates)


def test_subscribe_rejects_empty_path_list(tgen):
    r1 = tgen.gears["r1"]

    assert "INVALID_ARGUMENT" in _run_expect_error(
        r1, "ON_CHANGE", "", "INVALID_ARGUMENT"
    )


def test_subscribe_rejects_unknown_selector(tgen):
    r1 = tgen.gears["r1"]

    assert "INVALID_ARGUMENT" in _run_expect_error(
        r1,
        "ON_CHANGE",
        "/frr-does-not-exist:notification",
        "INVALID_ARGUMENT",
    )


def test_sample_rejects_subminimum_interval(tgen):
    r1 = tgen.gears["r1"]

    assert "INVALID_ARGUMENT" in _run_sample_expect_error(
        r1, "/frr-ripd", 99, "INVALID_ARGUMENT"
    )


def test_sample_sends_periodic_state(tgen):
    r1 = tgen.gears["r1"]

    # SAMPLE reads the same mgmtd-local operational state path repeatedly.
    raw = _run_sample_count(
        r1,
        "/frr-backend:clients",
        interval_ms=200,
        count=3,
        timeout=5,
    ).strip()

    responses = json.loads(raw.splitlines()[-1])
    assert len(responses) >= 3
    assert all(response["path"] == "/frr-backend:clients" for response in responses)
    assert all("frr-backend:clients" in response["data"] for response in responses)


def test_stream_closes_when_pending_queue_limit_is_hit(tgen):
    r1 = tgen.gears["r1"]

    assert "OUT_OF_RANGE" in _run_stream_repeat_expect_error(
        r1,
        "/frr-backend:clients",
        GRPC_SUBSCRIBE_TEST_PENDING_LIMIT + 2,
        "OUT_OF_RANGE",
    )


def test_subscribe_heartbeat_on_quiet_stream(tgen):
    r1 = tgen.gears["r1"]

    assert "heartbeat" in _run_until_heartbeat(
        r1, "/frr-ripd", heartbeat_ms=200, timeout=5
    )


def test_subscribe_client_cancel_cleans_up_stream(tgen):
    r1 = tgen.gears["r1"]

    assert "CANCELLED" in _run_cancel(r1, "/frr-ripd")
    assert "heartbeat" in _run_until_heartbeat(
        r1, "/frr-ripd", heartbeat_ms=200, timeout=5
    )


@pytest.mark.parametrize("mode", ["POLL"])
def test_subscribe_rejects_unsupported_modes(tgen, mode):
    r1 = tgen.gears["r1"]

    assert "UNIMPLEMENTED" in _run_expect_error(
        r1, mode, "/frr-ripd", "UNIMPLEMENTED"
    )


def test_subscribe_rejects_unknown_encoding(tgen):
    r1 = tgen.gears["r1"]

    assert "INVALID_ARGUMENT" in _run_invalid_encoding_expect_error(
        r1, "ON_CHANGE", "/frr-ripd", "INVALID_ARGUMENT"
    )


def test_subscribe_selector_does_not_overmatch(tgen):
    r1 = tgen.gears["r1"]
    received = {}

    def listener():
        received["raw"] = _run_expect_error(
            r1, "ON_CHANGE", "/frr-backend:clients", "DEADLINE_EXCEEDED"
        )

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(1)
    _set_auth(r1, "baz")

    t.join(timeout=10)
    assert not t.is_alive(), "non-matching Subscribe listener did not time out"
    assert "DEADLINE_EXCEEDED" in received.get("raw", "")
    _set_auth(r1, "foo")


def test_subscribe_closes_cleanly_when_mgmtd_stops(tgen):
    r1 = tgen.gears["r1"]
    received = {}

    def listener():
        received["raw"] = _run_expect_shutdown(r1, "/frr-ripd", timeout=30)

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(1)

    r1.cmd_raises("kill -TERM $(cat /var/run/frr/mgmtd.pid)")

    t.join(timeout=35)
    assert not t.is_alive(), "Subscribe listener did not close after mgmtd stop"
    assert received.get("raw", "").strip() in {"CANCELLED", "UNAVAILABLE"}

    with open(os.path.join(tgen.logdir, "r1", "mgmtd.log"), encoding="utf-8") as log:
        contents = log.read()
        assert "Terminating on signal" in contents
        assert "Received signal 11" not in contents
