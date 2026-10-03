# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 by Nvidia Inc.
#                   Donald Sharp
"""Locate the config directory of the installed FRR.

``vtysh --help`` prints the ``./configure`` arguments of the vtysh on
``PATH``, so a packaged install and a source build both report the
directory that binary was built with.
"""

import re
import subprocess
from functools import lru_cache

from lib.topolog import logger

# Last --sysconfdir wins, same as ./configure.
_SYSCONFDIR_RE = re.compile(r"--sysconfdir=([^'\s]+)")

# Historical default used when vtysh cannot be queried.
_DEFAULT_FRR_SYSCONFDIR = "/etc/frr"


def _frr_sysconfdir_from_help(text):
    """Return the FRR config directory described by vtysh --help text."""
    found = _SYSCONFDIR_RE.findall(text or "")
    if not found:
        return None

    # configure.ac installs config files in ${sysconfdir}/frr.  A value
    # that already ends in /frr (Debian passes --sysconfdir=/etc/frr) is
    # stripped and then that suffix is appended again, so the result is
    # the same path.  FreeBSD's --sysconfdir=/usr/local/etc becomes
    # /usr/local/etc/frr.
    sysconfdir = found[-1].rstrip("/")
    if not sysconfdir.endswith("/frr"):
        sysconfdir = sysconfdir + "/frr"
    return sysconfdir


@lru_cache(maxsize=1)
def frr_sysconfdir():
    """Return the installed FRR config directory, querying vtysh once."""
    try:
        proc = subprocess.run(
            ["vtysh", "--help"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        logger.warning("Could not run vtysh --help: %s", error)
        return _DEFAULT_FRR_SYSCONFDIR

    text = (proc.stdout or "") + (proc.stderr or "")
    path = _frr_sysconfdir_from_help(text)
    if path:
        return path

    logger.warning(
        "vtysh --help did not report --sysconfdir; using %s",
        _DEFAULT_FRR_SYSCONFDIR,
    )
    return _DEFAULT_FRR_SYSCONFDIR
