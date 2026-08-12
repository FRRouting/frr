#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# frr_reload_lib.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""
Helpers to drive tools/frr-reload.py "--reload" against a topotest router and
verify what it did.

These helpers deliberately exercise the *real* apply path ("frr-reload.py
--reload <file>"), not the "--test + vtysh -f delta" harness used by
lib/common_config.reset_config_on_routers(). Only the "--reload" path contains
the per-VRF batch-delete logic we want to cover, so the test must call it
directly.

Log signatures we key off (from tools/frr-reload.py, verified):
  * INFO  "<rundir>/reload-batch-del-XXXXXX.txt content ..."  -> the VRF-delete
          batch file path was taken.
  * WARN  "batch delete failed, falling back to per-line delete: ..." ->
          the batch failed and per-line fallback ran (we assert this is ABSENT
          on the happy path).
  * ERROR "FRR configuration reload failed"                 -> reload_ok=False;
          frr-reload exits non-zero.

With "--reload --stdout [--debug]" all of the above are emitted to the process
output, so we can capture and assert on them directly.
"""

import os
import re
import stat
import time

from lib.topolog import logger

FRR_RELOAD = "/usr/lib/frr/frr-reload.py"

# Regexes over the captured frr-reload output.
_RE_BATCH_FILE = re.compile(r"reload-batch-del-\w+\.txt content")
_RE_BATCH_FALLBACK = re.compile(
    r"batch delete failed|falling back to per-line"
)
_RE_RELOAD_FAILED = re.compile(r"FRR configuration reload failed")


class ReloadResult:
    """Outcome of one frr-reload.py --reload invocation."""

    def __init__(self, rc, output, elapsed):
        self.rc = rc
        self.output = output
        self.elapsed = elapsed

    @property
    def ok(self):
        return self.rc == 0 and not _RE_RELOAD_FAILED.search(self.output)

    @property
    def vrf_batch_attempted(self):
        return bool(_RE_BATCH_FILE.search(self.output))

    @property
    def vrf_batch_fell_back(self):
        return bool(_RE_BATCH_FALLBACK.search(self.output))


def write_conf(path, lines):
    """Write a list of config lines to a host path (visible inside the ns)."""
    with open(path, "w", encoding="ascii") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def frr_reload(router, conf_path, debug=True, extra_args=None):
    """Run "frr-reload.py --reload" on `router` against `conf_path`.

    `extra_args` is appended to the command line (used to point --bindir at the
    shim built by make_failing_batch_vtysh).

    Returns a ReloadResult with rc, combined stdout+stderr and wall-clock time.
    Timing is captured so scale tests can assert the batch design keeps the
    reload well under the systemd reload timeout.
    """
    dbg = " --debug" if debug else ""
    extra = (" " + " ".join(extra_args)) if extra_args else ""
    cmd = "{} --reload --stdout{}{} {}".format(FRR_RELOAD, dbg, extra, conf_path)
    logger.info("%s: running: %s", router.name, cmd)

    t0 = time.time()
    rc, out, err = router.net.cmd_status(cmd, warn=False)
    elapsed = time.time() - t0

    combined = (out or "") + (err or "")
    logger.info(
        "%s: frr-reload rc=%s elapsed=%.2fs", router.name, rc, elapsed
    )
    if rc != 0:
        logger.warning("%s: frr-reload output:\n%s", router.name, combined)
    return ReloadResult(rc, combined, elapsed)


def apply_and_verify(
    router,
    conf_path,
    lines,
    expect_vrf_batch=None,
    max_seconds=None,
    extra_args=None,
):
    """Write `lines` to `conf_path`, reload, and assert the common invariants.

    * reload succeeds (rc 0, no "reload failed")
    * if expect_vrf_batch is True       -> batch path used AND did not fall back
    * if expect_vrf_batch is False      -> no VRF-delete batch attempted
    * if expect_vrf_batch is "fallback" -> batch attempted AND fell back to the
                                           per-line path (negative-path test)
    * if max_seconds is set             -> reload completed within that budget
    """
    write_conf(conf_path, lines)
    res = frr_reload(router, conf_path, extra_args=extra_args)

    assert res.ok, "frr-reload failed on {} (rc={}):\n{}".format(
        router.name, res.rc, res.output
    )

    if expect_vrf_batch is True:
        assert res.vrf_batch_attempted, (
            "expected VRF-delete batch path to run on {}, but no "
            "'reload-batch-del-*.txt' marker was logged:\n{}".format(
                router.name, res.output
            )
        )
        assert not res.vrf_batch_fell_back, (
            "VRF-delete batch fell back to per-line delete on {} - the batch "
            "'vtysh -f' failed:\n{}".format(router.name, res.output)
        )
    elif expect_vrf_batch == "fallback":
        assert res.vrf_batch_attempted, (
            "expected the VRF-delete batch to be attempted on {} before "
            "falling back, but no 'reload-batch-del-*.txt' marker was "
            "logged:\n{}".format(router.name, res.output)
        )
        assert res.vrf_batch_fell_back, (
            "expected the VRF-delete batch to fail and fall back to per-line "
            "deletes on {}, but no fallback warning was logged:\n{}".format(
                router.name, res.output
            )
        )
    elif expect_vrf_batch is False:
        assert not res.vrf_batch_attempted, (
            "did not expect a VRF-delete batch on {} but one ran:\n{}".format(
                router.name, res.output
            )
        )

    if max_seconds is not None:
        assert res.elapsed <= max_seconds, (
            "frr-reload on {} took {:.2f}s (> {:.2f}s budget); the VRF batch "
            "design should keep this well under the systemd reload "
            "timeout".format(router.name, res.elapsed, max_seconds)
        )

    return res


def make_failing_batch_vtysh(router, dirpath):
    """Build a fake "vtysh" that fails only the VRF batch-delete invocation.

    frr-reload takes the vtysh it drives from "--bindir", so pointing it at the
    returned directory makes "vtysh -f <rundir>/reload-batch-del-*.txt" exit 13
    (CMD_WARNING_CONFIG_FAILED, what vtysh itself returns when a line in the
    file is rejected) while every other call - "vtysh -c", "vtysh -m -f", and
    the separate add batch "reload-<RANDOM>.txt" - reaches the real binary
    untouched.

    This is how the negative path gets exercised at all: the batch file is
    generated from the running-config delta, so every line in it came out of
    FRR and is valid by construction. There is no config we can write that
    makes the real vtysh reject it.

    Returns `dirpath`, ready to pass as --bindir.
    """
    real = router.net.cmd_nostatus("command -v vtysh").strip()
    assert real.startswith("/"), "could not locate the real vtysh on {}: {!r}".format(
        router.name, real
    )

    os.makedirs(dirpath, exist_ok=True)
    shim = os.path.join(dirpath, "vtysh")
    with open(shim, "w", encoding="ascii") as fh:
        fh.write(
            "#!/bin/sh\n"
            '# test shim - see make_failing_batch_vtysh() in frr_reload_lib.py\n'
            'for arg in "$@"; do\n'
            '    case "$arg" in\n'
            "    *reload-batch-del-*.txt)\n"
            '        echo "vtysh shim: refusing $arg" >&2\n'
            "        exit 13\n"
            "        ;;\n"
            "    esac\n"
            "done\n"
            'exec {} "$@"\n'.format(real)
        )
    os.chmod(
        shim,
        os.stat(shim).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
    )
    logger.info("%s: batch-failing vtysh shim at %s (real: %s)", router.name, shim, real)
    return dirpath


def running_config(router):
    """Return 'show running-config' text for `router` (default VRF view)."""
    return router.net.cmd_nostatus("vtysh -c 'show running-config no-header'")


def assert_lines_present(router, expected_lines):
    """Assert each line in `expected_lines` appears in running-config."""
    cfg = running_config(router)
    cfg_lines = {ln.strip() for ln in cfg.splitlines()}
    missing = [ln for ln in expected_lines if ln.strip() not in cfg_lines]
    assert not missing, "missing from {} running-config: {}\n---\n{}".format(
        router.name, missing, cfg
    )


def assert_lines_absent(router, unexpected_lines):
    """Assert none of `unexpected_lines` appears in running-config."""
    cfg = running_config(router)
    cfg_lines = {ln.strip() for ln in cfg.splitlines()}
    present = [ln for ln in unexpected_lines if ln.strip() in cfg_lines]
    assert not present, "still present in {} running-config: {}\n---\n{}".format(
        router.name, present, cfg
    )
