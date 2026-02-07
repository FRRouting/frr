# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# June 16 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""Common tests and utils for testing log output."""
import logging
import os
import re
import time

import pytest
from lib.common_config import step
from munet.testing.util import readline, retry
from munet.watchlog import WatchLog

our_pid = os.getpid()
daemons = ["mgmtd", "ospfd", "staticd"]
stdout_logs = {}
stderr_logs = {}
daemon_logs = {}
file_logs = {}


class WatchSyslog(WatchLog):
    """An object for watching the syslog (journalctl)."""

    def __init__(self, host, extra_args="", encoding="utf-8"):
        """Watch the syslog (journalctl)."""
        self.content = ""
        super().__init__("None", encoding)
        self.host = host
        self.p = host.popen(f"journalctl --follow --quiet --since=now {extra_args}")
        self.snapshot()

    def update_content(self):
        """Update our content with the output from journalctl."""
        self.host.cmd_raises("journalctl --sync --flush")
        newcontent = ""
        while True:
            s = readline(self.p.stdout, 1)
            if s is None:
                break
            newcontent += s
        self.content += newcontent
        return newcontent


def setup_test(munet):
    """Initialize watchlogs for the test."""
    r1 = munet.hosts["r1"]

    logging.debug("%s rundir is %s", r1.name, r1.rundir)
    for daemon in daemons:
        stdout_logs[daemon] = WatchLog(r1.rundir / f"{daemon}.out")
        stderr_logs[daemon] = WatchLog(r1.rundir / f"{daemon}.err")
        daemon_logs[daemon] = WatchLog(r1.rundir / f"{daemon}.log")


def _update_content(logs):
    for daemon in logs:
        logs[daemon].update_content()
    return {k: v.from_mark(v.last_snap_mark) for k, v in logs.items()}


def _update_snaps(logs):
    for log in logs.values():
        log.last_snap_mark = len(log.content)


@retry(retry_timeout=30, retry_sleep=0.1)
def scan_log(logs, regex):
    """Scan the WatchLog `log` for a regex match."""
    # Get latest content since last snapshot for all logs
    contents = _update_content(logs)

    # Check for regex match in each log
    if hasattr(contents, "items"):
        for daemon, content in contents.items():
            if re.search(regex, content):
                break
        else:
            return f"{regex} not found in daemon logs: {contents}"
    else:
        if not re.search(regex, contents):
            return f"{regex} not found in '{contents}'"


def scan_log_notfound(logs, regex):
    """Scan the WatchLogs `logs` for no regex match."""
    # Get latest content since last snapshot for all logs
    contents = _update_content(logs)

    # Check for regex match in each log
    for daemon in contents:
        if re.search(regex, contents[daemon]):
            logging.debug(
                "%s found in %s log content: '%s'", regex, daemon, contents[daemon]
            )
            return f"{regex} found in {daemon} log '{contents[daemon]}'"


def _do_test_log_notfound(r1, s, logs, level="", delay=2):
    cmd = f"send log level {level}" if level else "send log"
    regex = f"(?<!{cmd} )" + re.escape(s)

    # Check log first before sending command
    error = scan_log_notfound(logs, regex)
    assert not error

    # Log `s` and verify it still doesn't appear
    r1.cmd_raises(f"vtysh -c '{cmd} {s}'")

    # Wait delay seconds to give a chance for the looked for item to show up. Normally
    # non-retry delays are bad, but in the negative check case we need to wait.
    time.sleep(delay)

    error = scan_log_notfound(logs, regex)
    if not error:
        _update_snaps(logs)
    assert not error, "Found the match"


def _do_test_log(r1, s, logs, level=""):
    cmd = f"send log level {level}" if level else "send log"
    regex = f"(?<!{cmd} )" + re.escape(s)

    # Verify `s` not in the logs to-date.
    contents = _update_content(logs)
    for daemon in contents:
        assert not re.search(regex, contents[daemon])

    # Log `s` and verify it appears in each of the logs
    # Log `s` and verify it still doesn't appear
    r1.cmd_raises(f"vtysh -c '{cmd} {s}'")

    error = scan_log(logs, regex)
    if not error:
        _update_snaps(logs)
    assert not error, f"Error: {error}"


def do_test_log(unet, topotest_started=False):
    """Test logging functionality."""
    r1 = unet.hosts["r1"]

    if topotest_started:
        # Need this until topotest stops clearing cmdline targets and resetting per
        # daemon logfiles
        r1.cmd_raises('vtysh -c "conf\nlog file frr.log"')

    r1.cmd_raises('vtysh -c "conf\nno log stdout\nno log commands"')

    # Test logfiles
    step("Testing logging", reset=True)

    step("Testing common frr.log from startup config")
    common_log = {"common": WatchLog(r1.rundir / "frr.log")}
    s = f"LOGFILE-0-{our_pid}-MARK"
    _do_test_log(r1, s, common_log)

    if not topotest_started:
        # topotest launch will clear the log files, until fixed only munet launch works
        step("Testing daemon logfiles from cmdline")
        s = f"LOGFILE-1-{our_pid}-MARK"
        _do_test_log(r1, s, daemon_logs)

    # Clear cmdline targets which will have the --log=file:daemon.log setup
    # which we just tested
    step("Clearing cmdline log targets")
    r1.cmd_raises('vtysh -c "clear log cmdline-targets"')

    step("Testing daemon logfiles from cmdline no longer used")
    s = f"LOGFILE-2-{our_pid}-MARK"
    _do_test_log_notfound(r1, s, daemon_logs)

    # Test stdout
    step("Testing stdout")
    r1.cmd_raises('vtysh -c "conf" -c "log stdout"')

    s = f"STDOUT-0-{our_pid}-MARK"
    _do_test_log(r1, s, stdout_logs)

    # Test disable stdout
    step("Testing NO stdout")
    r1.cmd_raises('vtysh -c "conf" -c "no log stdout"')

    s = f"STDOUT-1-{our_pid}-MARK"
    _do_test_log_notfound(r1, s, stdout_logs)

    # Test new common logfile
    step("Testing new common logfile frr2.log")

    r1.cmd_raises('vtysh -c "conf\nlog file frr2.log"')
    common_log = {"common": WatchLog(r1.rundir / "frr2.log")}

    s = f"LOGFILE-4-{our_pid}-MARK"
    _do_test_log(r1, s, common_log)

    step("Testing new daemon logfile staticd2.log")

    r1.cmd_raises('vtysh -c "conf\nlog daemon staticd file staticd2.log"')
    staticd_log = {"staticd": WatchLog(r1.rundir / "staticd2.log")}
    s = f"LOGFILE-5-{our_pid}-MARK"
    _do_test_log(r1, s, staticd_log)


def do_test_filter_file(unet):
    """Test filtered logging functionality."""
    r1 = unet.hosts["r1"]

    # Test new filtered logfile
    step("Testing filtered logfile frr-filtered.log")
    r1.cmd_raises('vtysh -c "conf\nlog filtered-file frr-filtered.log"')
    r1.cmd_raises('vtysh -c "conf\nlog filter-text MARK-FOO"')
    filtered_log = {"filtered": WatchLog(r1.rundir / "frr-filtered.log")}

    s = f"LOGFILTER-0-{our_pid}-MARK-FOO"
    _do_test_log(r1, s, filtered_log)
    s = f"LOGFILTER-1-{our_pid}-MARK-BAR"
    _do_test_log_notfound(r1, s, filtered_log)


def do_test_syslog(unet):
    """Test syslo functionality."""
    r1 = unet.hosts["r1"]

    if not r1.get_exec_path_host("journalctl"):
        pytest.skip("Skipping syslog test as journalctl not found")
        return

    step("Testing logging with syslog", reset=True)

    #
    # Watch all sys
    #
    logs = {"syslog": WatchSyslog(r1)}

    # Test syslog
    step("Testing syslog")
    r1.cmd_raises('vtysh -c "conf" -c "log syslog"')

    s = f"SYSLOG-0-{our_pid}-MARK"
    _do_test_log(r1, s, logs)

    # Test disable syslog
    step("Testing NO syslog")
    r1.cmd_raises('vtysh -c "conf" -c "no log syslog"')

    s = f"SYSLOG-1-{our_pid}-MARK"
    _do_test_log_notfound(r1, s, logs)

    #
    # switch to watching only severity >= info
    #

    step("Testing syslog send and filter to 'info'")
    s = f"SYSLOG-2-{our_pid}-MARK"
    r1.cmd_raises('vtysh -c "conf" -c "log syslog info"')
    _do_test_log(r1, s, logs, "info")

    step("Testing syslog send 'debug' and filter to 'info'")
    s = f"SYSLOG-3-{our_pid}-MARK"
    _do_test_log_notfound(r1, s, logs, "debug")

    step("Testing set syslog filter level to 'debug'")
    s = f"SYSLOG-4-{our_pid}-MARK"
    r1.cmd_raises('vtysh -c "conf" -c "log syslog debug"')
    _do_test_log(r1, s, logs, "debug")

    step("Testing set syslog to default filter level")
    s = f"SYSLOG-5-{our_pid}-MARK"
    r1.cmd_raises('vtysh -c "conf" -c "log syslog"')
    _do_test_log(r1, s, logs)

    #
    # switch to watching only syslog facility user
    #
    logs = {"syslog": WatchSyslog(r1, extra_args="--facility=user")}

    step("Testing syslog facility 'user' (capturing facility 'user')")
    s = f"SYSLOG-6-{our_pid}-MARK"
    # r1.cmd_raises('vtysh -c "conf" -c "log facility user" -c "log syslog"')
    r1.cmd_raises('vtysh -c "conf" -c "log syslog"  -c "log facility user"')
    _do_test_log(r1, s, logs)

    step("Testing syslog facility 'daemon'")
    s = f"SYSLOG-7-{our_pid}-MARK"
    r1.cmd_raises('vtysh -c "conf" -c "no log facility"')
    _do_test_log_notfound(r1, s, logs)
