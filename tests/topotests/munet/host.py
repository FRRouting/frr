# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""Host process operations that differ by operating system.

Callers use this module. The Linux system calls stay in linux.py and the
FreeBSD system calls stay in freebsd.py.
"""

import importlib
import sys


def _backend():
    name = "freebsd" if sys.platform.startswith("freebsd") else "linux"
    if __package__:
        return importlib.import_module(f".{name}", __package__)
    return importlib.import_module(name)


def set_process_name(name):
    """Set the process name shown by ps."""
    _backend().set_process_name(name)


def set_parent_death_signal(signum):
    """Ask the kernel to signal this process when its parent exits."""
    _backend().set_parent_death_signal(signum)
