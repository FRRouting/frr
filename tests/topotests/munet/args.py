# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# April 14 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#
"""Common CLI execute argument."""


def add_launch_args(add_func):

    add_func("--gdb", metavar="NODE-LIST", help="comma-sep list of hosts to run gdb on")
    add_func(
        "--gdb-breakpoints",
        metavar="BREAKPOINT-LIST",
        help="comma-sep list of breakpoints to set",
    )
    add_func(
        "--gdb-use-emacs",
        action="store_true",
        help="Use emacsclient to run gdb instead of a shell",
    )

    add_func(
        "--host",
        action="store_true",
        help="no isolation for top namespace, bridges exposed to default namespace",
    )
    add_func(
        "--pcap",
        metavar="TARGET-LIST",
        help="comma-sep list of capture targets (NETWORK or NODE:IFNAME) or 'all'",
    )
    add_func(
        "--shell", metavar="NODE-LIST", help="comma-sep list of nodes to open shells on"
    )
    add_func(
        "--stderr",
        metavar="NODE-LIST",
        help="comma-sep list of nodes to open windows viewing stderr",
    )
    add_func(
        "--stdout",
        metavar="NODE-LIST",
        help="comma-sep list of nodes to open windows viewing stdout",
    )


def add_testing_args(add_func):
    add_func(
        "--cli-on-error",
        action="store_true",
        help="CLI on test failure",
    )

    add_func(
        "--coverage",
        action="store_true",
        help="Enable coverage gathering if supported",
    )

    add_func(
        "--cov-build-dir",
        help="Specify the build dir for locating coverage data files",
    )

    add_launch_args(add_func)

    add_func(
        "--pause",
        action="store_true",
        help="Pause after each test",
    )
    add_func(
        "--pause-at-end",
        action="store_true",
        help="Pause before taking munet down",
    )
    add_func(
        "--pause-on-error",
        action="store_true",
        help="Pause after (disables default when --shell or -vtysh given)",
    )
    add_func(
        "--no-pause-on-error",
        dest="pause_on_error",
        action="store_false",
        help="Do not pause after (disables default when --shell or -vtysh given)",
    )
