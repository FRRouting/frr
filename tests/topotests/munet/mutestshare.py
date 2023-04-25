# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# January 28 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""A tiny init for namespaces in python inspired by the C program tini."""
import argparse
import errno
import logging
import os
import shlex
import signal
import subprocess
import sys
import threading
import time

from signal import Signals as S

from . import linux
from .base import commander


child_pid = -1
very_verbose = False
restore_signals = set()


def vdebug(*args, **kwargs):
    if very_verbose:
        logging.debug(*args, **kwargs)


def exit_with_status(pid, status):
    try:
        ec = status >> 8 if bool(status & 0xFF00) else status | 0x80
        logging.debug("reaped our child, exiting %s", ec)
        sys.exit(ec)
    except ValueError:
        vdebug("pid %s didn't actually exit", pid)


def waitpid(tag):
    logging.debug("%s: waitid for exiting processes", tag)
    idobj = os.waitid(os.P_ALL, 0, os.WEXITED)
    pid = idobj.si_pid
    status = idobj.si_status
    if pid == child_pid:
        exit_with_status(pid, status)
    else:
        logging.debug("%s: reaped zombie pid %s with status %s", tag, pid, status)


def new_process_group():
    pid = os.getpid()
    try:
        pgid = os.getpgrp()
        if pgid == pid:
            logging.debug("already process group leader %s", pgid)
        else:
            logging.debug("creating new process group %s", pid)
            os.setpgid(pid, 0)
    except Exception as error:
        logging.warning("unable to get new process group: %s", error)
        return

    # Block these in order to allow foregrounding, otherwise we'd get SIGTTOU blocked
    signal.signal(S.SIGTTIN, signal.SIG_IGN)
    signal.signal(S.SIGTTOU, signal.SIG_IGN)
    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        logging.debug("stdin not a tty no foregrounding required")
    else:
        try:
            # This will error if our session no longer associated with controlling tty.
            pgid = os.tcgetpgrp(fd)
            if pgid == pid:
                logging.debug("process group already in foreground %s", pgid)
            else:
                logging.debug("making us the foreground pgid backgrounding %s", pgid)
                os.tcsetpgrp(fd, pid)
        except OSError as error:
            if error.errno == errno.ENOTTY:
                logging.debug("session is no longer associated with controlling tty")
            else:
                logging.warning("unable to foreground pgid %s: %s", pid, error)
    signal.signal(S.SIGTTIN, signal.SIG_DFL)
    signal.signal(S.SIGTTOU, signal.SIG_DFL)


def exec_child(exec_args):
    # Restore signals to default handling:
    for snum in restore_signals:
        signal.signal(snum, signal.SIG_DFL)

    # Create new process group.
    new_process_group()

    estring = shlex.join(exec_args)
    try:
        # and exec the process
        logging.debug("child: executing '%s'", estring)
        os.execvp(exec_args[0], exec_args)
        # NOTREACHED
    except Exception as error:
        logging.warning("child: unable to execute '%s': %s", estring, error)
        raise


def is_creating_pid_namespace():
    p1name = subprocess.check_output(
        "readlink /proc/self/pid", stderr=subprocess.STDOUT, shell=True
    )
    p2name = subprocess.check_output(
        "readlink /proc/self/pid_for_children", stderr=subprocess.STDOUT, shell=True
    )
    return p1name != p2name


def restore_namespace(ppid_fd, uflags):
    fd = ppid_fd
    retry = 3
    for i in range(0, retry):
        try:
            linux.setns(fd, uflags)
        except OSError as error:
            logging.warning("could not reset to old namespace fd %s: %s", fd, error)
            if i == retry - 1:
                raise
            time.sleep(1)
    os.close(fd)


def create_thread_test():
    def runthread(name):
        logging.info("In thread: %s", name)

    logging.info("Create thread")
    thread = threading.Thread(target=runthread, args=(1,))
    logging.info("Run thread")
    thread.start()
    logging.info("Join thread")
    thread.join()


def run(args):
    del args
    # We look for this b/c the unshare pid will share with /sibn/init
    # nselm = "pid_for_children"
    # nsflags.append(f"--pid={pp / nselm}")
    # mutini now forks when created this way
    # cmd.append("--pid")
    # cmd.append("--fork")
    # cmd.append("--kill-child")
    # cmd.append("--mount-proc")

    uflags = linux.CLONE_NEWPID
    nslist = ["pid_for_children"]
    uflags |= linux.CLONE_NEWNS
    nslist.append("mnt")
    uflags |= linux.CLONE_NEWNET
    nslist.append("net")

    # Before values
    pid = os.getpid()
    nsdict = {x: os.readlink(f"/tmp/mu-global-proc/{pid}/ns/{x}") for x in nslist}

    #
    # UNSHARE
    #
    create_thread_test()

    ppid = os.getppid()
    ppid_fd = linux.pidfd_open(ppid)
    linux.unshare(uflags)

    # random syscall's fail until we fork a child to establish the new pid namespace.
    global child_pid  # pylint: disable=global-statement
    child_pid = os.fork()
    if not child_pid:
        logging.info("In child sleeping")
        time.sleep(1200)
        sys.exit(1)

    # verify after values differ
    nnsdict = {x: os.readlink(f"/tmp/mu-global-proc/{pid}/ns/{x}") for x in nslist}
    assert not {k for k in nsdict if nsdict[k] == nnsdict[k]}

    # Remount / and any future mounts below it as private
    commander.cmd_raises("mount --make-rprivate /")
    # Mount a new /proc in our new namespace
    commander.cmd_raises("mount -t proc proc /proc")

    #
    # In NEW NS
    #

    cid = os.fork()
    if not cid:
        logging.info("In second child sleeping")
        time.sleep(4)
        sys.exit(1)
    logging.info("Waiting for second child")
    os.waitpid(cid, 0)

    try:
        create_thread_test()
    except Exception as error:
        print(error)

    #
    # RESTORE
    #

    logging.info("In new namespace, restoring old")
    # Make sure we can go back, not sure since this is PID namespace, but maybe
    restore_namespace(ppid_fd, uflags)

    # verify after values the same
    nnsdict = {x: os.readlink(f"/proc/self/ns/{x}") for x in nslist}
    assert nsdict == nnsdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-v", dest="verbose", action="count", default=0, help="More -v's, more verbose"
    )
    ap.add_argument("rest", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    if args.verbose > 1:
        global very_verbose  # pylint: disable=global-statement
        very_verbose = True
    logging.basicConfig(
        level=level, format="%(asctime)s mutini: %(levelname)s: %(message)s"
    )

    status = 4
    try:
        run(args)
    except KeyboardInterrupt:
        logging.info("exiting (main), received KeyboardInterrupt in main")
    except Exception as error:
        logging.info("exiting (main), unexpected exception %s", error, exc_info=True)

    sys.exit(status)


if __name__ == "__main__":
    main()
