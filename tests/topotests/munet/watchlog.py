# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# August 21 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""A module supporting an object for watching a logfile."""
import asyncio
import logging
import re

from pathlib import Path


class MatchFoundError(Exception):
    """An error raised when a match is not found."""

    def __init__(self, watchlog, match):
        self.watchlog = watchlog
        self.match = match
        super().__init__(watchlog, match)


class WatchLog:
    """An object for watching a logfile."""

    def __init__(self, path, encoding="utf-8"):
        """Watch a logfile.

        Args:
            path: that path of the logfile to watch
            encoding: the encoding of the logfile
        """
        # Immutable
        self.path = Path(path)
        self.encoding = encoding

        # Mutable
        self.content = ""
        self.last_snap_mark = 0
        self.last_user_mark = 0
        self.stat = None

        if self.path.exists():
            self.snapshot()

    def _stat_snapshot(self):
        ostat = self.stat

        if not self.path.exists():
            self.stat = None
            return ostat is not None

        stat = self.path.stat()
        self.stat = stat

        if ostat is None:
            return True

        return (
            stat.st_mtime_ns != ostat.st_mtime_ns
            or stat.st_ctime_ns != ostat.st_ctime_ns
            or stat.st_ino != ostat.st_ino
            or stat.st_size != ostat.st_size
        )

    def reset(self):
        self.content = ""
        self.last_user_mark = 0
        self.last_snap_mark = 0

    def update_content(self):
        ostat = self.stat
        osize = ostat.st_size if ostat else 0
        oino = ostat.st_ino if ostat else -1
        if not self._stat_snapshot():
            logging.debug("XXX logfile %s no stat change", self.path)
            return ""

        nino = self.stat.st_ino
        # If the inode changed and we had content previously warn
        if oino != -1 and oino != nino and self.content:
            logging.warning(
                "logfile %s replaced (new inode) resetting content", self.path
            )
            self.reset()
            osize = 0

        nsize = self.stat.st_size
        if osize > nsize:
            logging.warning("logfile %s shrunk resetting content", self.path)
            self.reset()
            osize = 0

        if osize == nsize:
            logging.debug(
                "XXX watchlog: %s no update, osize == nsize == %s", self.path, osize
            )
            return ""

        # Read non-blocking
        with open(self.path, "r", encoding=self.encoding) as f:
            if osize:
                f.seek(osize)
            logging.debug(
                "XXX watchlog: %s reading new content from %s to %s",
                self.path,
                osize,
                nsize,
            )
            newcontent = f.read(nsize - osize)

        self.content += newcontent
        return newcontent

    def raise_if_match_task(self, match):
        """Start an async task that searches for a match.

        This doesn't work well with pytest as the task must be awaited for the exception
        to propagate.
        """

        async def scan_for_match(wl, regex):
            while True:
                logging.debug("watchlog: %s scan for updating content", wl.path)
                wl.update_content()
                if m := regex.search(wl.content):
                    logging.error(
                        "XXX watchlog: %s regexp FOUND raising exception!", wl.path
                    )
                    raise MatchFoundError(wl, m)
                await asyncio.sleep(2)

        aw = scan_for_match(self, re.compile(match))
        return asyncio.create_task(aw)

    def from_mark(self, mark=None):
        """Return the file content starting from ``mark``.

        If ``mark`` is None then return content since last ``set_mark`` was called.

        If the file has been replaced (inode changes) then the marks will reset to 0.

        Args:
            mark: the mark in the content to return file content from.

        Return:
            returns the content between ``mark`` and the end of content.
        """
        if mark is None:
            mark = self.last_user_mark
        return self.content[mark:]

    def set_mark(self):
        """Set a mark for later use."""
        last_mark = self.last_user_mark
        self.last_user_mark = len(self.content)
        return last_mark

    def snapshot(self):
        """Update the file content and return new text.

        Returns any new text added since the last snapshot and updates the snapshot
        mark.

        Return:
            Newly added text.
        """
        # Update the content which may reset marks
        self.update_content()

        last_mark = self.last_snap_mark
        self.last_snap_mark = len(self.content)
        return self.content[last_mark:]

    def snapshot_refresh(self):
        """Update the file content and return the snapshot with this new content.

        If the file has been replaced (inode changes) then the marks will reset to 0.

        Return:
            returns the content from the last snapshot plus any new content
            added since ``snapshot()`` was called.
        """
        self.update_content()
        return self.from_mark(self.last_snap_mark)
