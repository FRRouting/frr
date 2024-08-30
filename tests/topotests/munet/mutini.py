#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# January 28 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""A tiny init for namespaces in python inspired by the C program tini."""


# pylint: disable=global-statement
import argparse
import errno
import logging
import os
import re
import select
import shlex
import signal
import subprocess
import sys

from signal import Signals as S


try:
    from munet import linux
except ModuleNotFoundError:
    # We cannot use relative imports and still run this module directly as a script, and
    # there are some use cases where we want to run this file as a script.
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))
    import linux


class g:
    """Global variables for our program."""

    child_pid = -1
    orig_pid = os.getpid()
    exit_signal = False
    pid_status_cache = {}
    restore_signals = set()
    very_verbose = False


unshare_flags = {
    "C": linux.CLONE_NEWCGROUP,
    "i": linux.CLONE_NEWIPC,
    "m": linux.CLONE_NEWNS,
    "n": linux.CLONE_NEWNET,
    "p": linux.CLONE_NEWPID,
    "u": linux.CLONE_NEWUTS,
    "T": linux.CLONE_NEWTIME,
}


ignored_signals = {
    S.SIGTTIN,
    S.SIGTTOU,
}
abort_signals = {
    S.SIGABRT,
    S.SIGBUS,
    S.SIGFPE,
    S.SIGILL,
    S.SIGKILL,
    S.SIGSEGV,
    S.SIGSTOP,
    S.SIGSYS,
    S.SIGTRAP,
}
no_prop_signals = abort_signals | ignored_signals | {S.SIGCHLD}


def vdebug(*args, **kwargs):
    if g.very_verbose:
        logging.debug(*args, **kwargs)


def get_pid_status_item(status, stat):
    m = re.search(rf"(?:^|\n){stat}:\t(.*)(?:\n|$)", status)
    return m.group(1).strip() if m else None


def pget_pid_status_item(pid, stat):
    if pid not in g.pid_status_cache:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            g.pid_status_cache[pid] = f.read().strip()
    return get_pid_status_item(g.pid_status_cache[pid], stat).strip()


def get_pid_name(pid):
    try:
        return get_pid_status_item(g.pid_status_cache[pid], "Name")
    except Exception:
        return str(pid)


# def init_get_child_pids():
#     """Return list of "children" pids.
#     We consider any process with a 0 parent pid to also be our child as it
#     nsentered our pid namespace from an external parent.
#     """
#     g.pid_status_cache.clear()
#     pids = (int(x) for x in os.listdir("/proc") if x.isdigit() and x != "1")
#     return (
#         x for x in pids if x == g.child_pid or pget_pid_status_item(x, "PPid") == "0"
#     )


def exit_with_status(status):
    if os.WIFEXITED(status):
        ec = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        ec = 0x80 | os.WTERMSIG(status)
    else:
        ec = 255
    logging.debug("exiting with code %s", ec)
    sys.exit(ec)


def __waitpid(tag, nohang=False):  # pylint: disable=inconsistent-return-statements
    if nohang:
        idobj = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        if idobj is None:
            return True
    else:
        idobj = os.waitid(os.P_ALL, 0, os.WEXITED)
        assert idobj is not None

    pid = idobj.si_pid
    status = idobj.si_status

    if pid != g.child_pid:
        pidname = get_pid_name(pid)
        logging.debug(
            "%s: reaped zombie %s (%s) w/ status %s", tag, pid, pidname, status
        )
        return False

    logging.debug("reaped child with status %s", status)
    exit_with_status(status)
    # NOTREACHED


def waitpid(tag):
    logging.debug("%s: waitid for exiting process", tag)
    __waitpid(tag, False)

    while True:
        logging.debug("%s: checking for another exiting process", tag)
        if __waitpid(tag, True):
            return


def sig_trasmit(signum, _):
    signame = signal.Signals(signum).name
    if g.child_pid == -1:
        # We've received a signal after setting up to be init proc
        # but prior to fork or fork returning with child pid
        logging.debug("received %s prior to child exec, exiting", signame)
        sys.exit(0x80 | signum)

    try:
        os.kill(g.child_pid, signum)
    except OSError as error:
        if error.errno != errno.ESRCH:
            logging.error(
                "error forwarding signal %s to child, exiting: %s", signum, error
            )
            sys.exit(0x80 | signum)
        logging.debug("child pid %s exited prior to signaling", g.child_pid)


def sig_sigchld(signum, _):
    assert signum == S.SIGCHLD


def setup_init_signals():
    valid = set(signal.valid_signals())
    named = set(x.value for x in signal.Signals)
    for snum in sorted(named):
        if snum not in valid:
            continue
        if S.SIGRTMIN <= snum <= S.SIGRTMAX:
            continue

        sname = signal.Signals(snum).name
        if snum == S.SIGCHLD:
            vdebug("installing local handler for %s", sname)
            signal.signal(snum, sig_sigchld)
            g.restore_signals.add(snum)
        elif snum in ignored_signals:
            vdebug("installing ignore handler for %s", sname)
            signal.signal(snum, signal.SIG_IGN)
            g.restore_signals.add(snum)
        elif snum in abort_signals:
            vdebug("leaving default handler for %s", sname)
            # signal.signal(snum, signal.SIG_DFL)
        else:
            vdebug("installing trasmit signal handler for %s", sname)
            try:
                signal.signal(snum, sig_trasmit)
                g.restore_signals.add(snum)
            except OSError as error:
                logging.warning(
                    "failed installing signal handler for %s: %s", sname, error
                )


def new_process_group():
    """Create and lead a new process group.

    This function will create a new process group if we are not yet leading one, and
    additionally foreground said process group in our session. This foregrounding
    action is copied from tini, and I believe serves a purpose when serving as init
    for a container (e.g., podman).
    """
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


def is_creating_pid_namespace():
    p1name = subprocess.check_output(
        "readlink /proc/self/pid", stderr=subprocess.STDOUT, shell=True
    )
    p2name = subprocess.check_output(
        "readlink /proc/self/pid_for_children", stderr=subprocess.STDOUT, shell=True
    )
    return p1name != p2name


def poll_for_pids(msg, tag):
    poller = select.poll()
    while True:
        logging.info("%s", msg)
        events = poller.poll(1000)
        logging.info("init: poll: checking for zombies and child exit: %s", events)
        try:
            waitpid(tag)
        except ChildProcessError as error:
            logging.warning("init: got SIGCHLD but no pid to wait on: %s", error)
    # NOTREACHED


def be_init(new_pg, exec_args):
    #
    # Arrange for us to be killed when our parent dies, this will subsequently also kill
    # all procs in any PID namespace we are init for.
    #
    logging.debug("set us to be SIGKILLed when parent exits")
    linux.set_parent_death_signal(signal.SIGKILL)

    # If we are createing a new PID namespace for children...
    if g.orig_pid != 1:
        logging.debug("started as pid %s", g.orig_pid)
        # assert is_creating_pid_namespace()

        # Fork to become pid 1
        logging.debug("forking to become pid 1")
        child_pid = os.fork()
        if child_pid:
            logging.debug("in parent waiting on child pid %s to exit", child_pid)
            status = os.wait()
            logging.debug("got child exit status %s", status)
            exit_with_status(status)
            # NOTREACHED

        # We must be pid 1 now.
        logging.debug("in child as pid %s", os.getpid())
        assert os.getpid() == 1

        # We need a new /proc now.
        logging.debug("mount new /proc")
        linux.mount("proc", "/proc", "proc")

        # If the parent exists kill us using SIGKILL
        logging.debug("set us to be SIGKILLed when parent exits")
        linux.set_parent_death_signal(signal.SIGKILL)

    if not exec_args:
        if not new_pg:
            logging.debug("no exec args, no new process group")
            # # if 0 == os.getpgid(0):
            # status = os.setpgid(0, 1)
            # logging.debug("os.setpgid(0, 1) == %s", status)
        else:
            logging.debug("no exec args, creating new process group")
            # No exec so we are the "child".
            new_process_group()

        # Reap children as init process
        vdebug("installing local handler for SIGCHLD")
        signal.signal(signal.SIGCHLD, sig_sigchld)
        poll_for_pids("init: waiting to reap zombies", "PAUSE-EXIT")
        # NOTREACHED

    # Set (parent) signal handlers before any fork to avoid race
    setup_init_signals()

    logging.debug("forking to execute child")
    g.child_pid = os.fork()
    if g.child_pid == 0:
        # In child, restore signals to default handling:
        for snum in g.restore_signals:
            signal.signal(snum, signal.SIG_DFL)

        # XXX is a new pg right?
        new_process_group()
        logging.debug("child: executing '%s'", shlex.join(exec_args))
        os.execvp(exec_args[0], exec_args)
        # NOTREACHED

    poll_for_pids(f"parent: waiting for child pid {g.child_pid} to exit", "PARENT")
    # NOTREACHED


def unshare(flags):
    """Unshare into new namespaces."""
    uflags = 0
    for flag in flags:
        if flag not in unshare_flags:
            raise ValueError(f"unknown unshare flag '{flag}'")
        uflags |= unshare_flags[flag]
    new_pid = bool(uflags & linux.CLONE_NEWPID)
    new_mnt = bool(uflags & linux.CLONE_NEWNS)

    logging.debug("unshareing with flags: %s", linux.clone_flag_string(uflags))
    linux.unshare(uflags)

    if new_pid and not new_mnt:
        try:
            # If we are not creating new mount namspace, remount /proc private
            # so that our mount of a new /proc doesn't affect parent namespace
            logging.debug("remount /proc recursive private")
            linux.mount("none", "/proc", None, linux.MS_REC | linux.MS_PRIVATE)
        except OSError as error:
            # EINVAL is OK b/c /proc not mounted may cause an error
            if error.errno != errno.EINVAL:
                raise
    if new_mnt:
        # Remount root as recursive private.
        logging.debug("remount / recursive private")
        linux.mount("none", "/", None, linux.MS_REC | linux.MS_PRIVATE)

    # if new_pid:
    #     logging.debug("mount new /proc")
    #     linux.mount("proc", "/proc", "proc")

    return new_pid


def main():
    #
    # Parse CLI args.
    #

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-P",
        "--no-proc-group",
        action="store_true",
        help="set to inherit the process group",
    )
    valid_flags = "".join(unshare_flags)
    ap.add_argument(
        "--unshare-flags",
        help=(
            f"string of unshare(1) flags. Supported values from '{valid_flags}'."
            " 'm' will remount `/` recursive private. 'p' will remount /proc"
            " and fork, and the child will be signaled to exit on exit of parent.."
        ),
    )
    ap.add_argument(
        "-v", dest="verbose", action="count", default=0, help="more -v's, more verbose"
    )
    ap.add_argument("rest", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    #
    # Setup logging.
    #

    level = logging.DEBUG if args.verbose else logging.INFO
    if args.verbose > 1:
        g.very_verbose = True
    logging.basicConfig(
        level=level, format="%(asctime)s mutini: %(levelname)s: %(message)s"
    )

    #
    # Run program
    #

    status = 5
    try:
        new_pid = False
        if args.unshare_flags:
            new_pid = unshare(args.unshare_flags)

        if g.orig_pid != 1 and not new_pid:
            # Simply hold the namespaces
            poll_for_pids("holding namespace waiting to be signaled to exit", "PARENT")
            # NOTREACHED

        be_init(not args.no_proc_group, args.rest)
        # NOTREACHED
        logging.critical("Exited from be_init!")
    except KeyboardInterrupt:
        logging.info("exiting (main), received KeyboardInterrupt in main")
        status = 0x80 | signal.SIGINT
    except Exception as error:
        logging.info("exiting (main), do to exception %s", error, exc_info=True)

    sys.exit(status)


if __name__ == "__main__":
    main()
