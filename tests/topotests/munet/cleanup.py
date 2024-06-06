# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# September 30 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""Provides functionality to cleanup processes on posix systems."""
import glob
import logging
import os
import signal


def get_pids_with_env(has_var, has_val=None):
    result = {}
    for pidenv in glob.iglob("/proc/*/environ"):
        pid = pidenv.split("/")[2]
        try:
            with open(pidenv, "rb") as rfb:
                envlist = [
                    x.decode("utf-8").split("=", 1) for x in rfb.read().split(b"\0")
                ]
                envlist = [[x[0], ""] if len(x) == 1 else x for x in envlist]
                envdict = dict(envlist)
                if has_var not in envdict:
                    continue
                if has_val is None:
                    result[pid] = envdict
                elif envdict[has_var] == str(has_val):
                    result[pid] = envdict
        except Exception:
            # E.g., process exited and files are gone
            pass
    return result


def _kill_piddict(pids_by_upid, sig):
    ourpid = str(os.getpid())
    for upid, pids in pids_by_upid:
        logging.info("Sending %s to (%s) of munet pid %s", sig, ", ".join(pids), upid)
        for pid in pids:
            try:
                if pid != ourpid:
                    cmdline = open(f"/proc/{pid}/cmdline", "r", encoding="ascii").read()
                    cmdline = cmdline.replace("\x00", " ")
                    logging.info("killing proc %s (%s)", pid, cmdline)
                    os.kill(int(pid), sig)
            except Exception:
                pass


def _get_our_pids():
    ourpid = str(os.getpid())
    piddict = get_pids_with_env("MUNET_PID", ourpid)
    pids = [x for x in piddict if x != ourpid]
    if pids:
        return {ourpid: pids}
    return {}


def _get_other_pids(rundir):
    if rundir:
        # get only munet pids using the given rundir
        piddict = get_pids_with_env("MUNET_RUNDIR", str(rundir))
    else:
        # Get all munet pids
        piddict = get_pids_with_env("MUNET_PID")
    unet_pids = {d["MUNET_PID"] for d in piddict.values() if "MUNET_PID" in d}
    pids_by_upid = {p: set() for p in unet_pids}
    for pid, envdict in piddict.items():
        if "MUNET_PID" not in envdict:
            continue
        unet_pid = envdict["MUNET_PID"]
        pids_by_upid[unet_pid].add(pid)
    # Filter out any child pid sets whos munet pid is still running
    return {x: y for x, y in pids_by_upid.items() if x not in y}


def _get_pids_by_upid(ours, rundir):
    if ours:
        assert rundir is None
        return _get_our_pids()
    return _get_other_pids(rundir)


def _cleanup_pids(ours, rundir):
    pids_by_upid = _get_pids_by_upid(ours, rundir).items()
    if not pids_by_upid:
        return

    t = "current" if ours else "previous"
    logging.info("Reaping %s munet processes", t)

    # _kill_piddict(pids_by_upid, signal.SIGTERM)

    # # Give them 5 second to exit cleanly
    # logging.info("Waiting up to 5s to allow for clean exit of abandon'd pids")
    # for _ in range(0, 5):
    #     pids_by_upid = _get_pids_by_upid(ours).items()
    #     if not pids_by_upid:
    #         return
    #     time.sleep(1)

    pids_by_upid = _get_pids_by_upid(ours, rundir).items()
    _kill_piddict(pids_by_upid, signal.SIGKILL)


def cleanup_current():
    """Attempt to cleanup preview runs.

    Currently this only scans for old processes.
    """
    _cleanup_pids(True, None)


def cleanup_previous(rundir=None):
    """Attempt to cleanup preview runs.

    Currently this only scans for old processes.
    """
    _cleanup_pids(False, rundir)


def is_running_in_rundir(rundir):
    return bool(get_pids_with_env("MUNET_RUNDIR", str(rundir)))
