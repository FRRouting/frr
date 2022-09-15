#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
Random utility functions for use in topotato.
"""

# TODO: this needs another round of cleanup, and JSONCompare split off.

import sys
import os
import re
import logging
import traceback
import subprocess
import atexit
import shlex
import fcntl
import json
import difflib

from typing import List, Union

from .exceptions import TopotatoCLICompareFail

logger = logging.getLogger("topotato")
logger.setLevel(logging.DEBUG)

_wsp_re = re.compile(r"^[ \t]+")


def deindent(text: str, trim=False) -> str:
    """
    Determine and strip common indentation from a string.

    Intended for use with docstrings, which would generally be indented to
    match the surrounding code.  Common indentation is determined by finding
    the longest common prefix for all lines that contain any non-whitespace
    characters, i.e. whitespace-only lines are ignored.  (Those shouldn't have
    any indentation anyway.)
    """
    text = text.lstrip("\n")
    m = _wsp_re.match(text)
    do_trim = (lambda s: s.rstrip(" \t")) if trim else (lambda s: s)
    if m is not None:
        indent = m.group(0)
        out = []
        for line in text.splitlines():
            if line.strip() == "":
                out.append("")
            else:
                assert line.startswith(indent)
                out.append(do_trim(line[len(indent) :]))
        text = "\n".join(out)
    return text


def get_textdiff(text1: str, text2: str, title1="", title2="", **opts) -> str:
    """
    Diff formatting wrapper (just cleans up line endings)

    :param opts:  Remaining keywords passed to :py:func:`difflib.unified_diff`.
    :return:  Formatted diff, empty string if text1 == text2.
    """

    diff = "\n".join(
        difflib.unified_diff(text1, text2, fromfile=title1, tofile=title2, **opts)
    )
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff


class json_cmp_result:
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error):
        "Append error message to the result"
        for line in error.splitlines():
            self.errors.append(line)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0

    def __str__(self):
        return "\n".join(self.errors)


# used with an "isinstance"/"is" comparison
class JSONCompareDirective(dict):
    """
    Helper class/type base.

    Classes derived from this are used in JSON diff to pass additional
    options to :py:func:`json_cmp`.  The idea is that instances of these
    can be placed in the "expected" data as "in-band" signal for various flags,
    e.g.::

       expect = {
           "something": [
               JSONCompareIgnoreExtraListitems(),
               1,
               2,
           ],
       }
       json_cmp(data, expect)
    """


class JSONCompareIgnoreContent(JSONCompareDirective):
    """
    Ignore list/dict content in JSON compare.
    """


class JSONCompareIgnoreExtraListitems(JSONCompareDirective):
    """
    Ignore any additional list items for this list.
    """


class JSONCompareListKeyedDict(JSONCompareDirective):
    """
    Compare this list by looking for matching items regardless of order.

    This assumes the list contains dicts, and these dicts have some keys that
    should be used as "index".  Items are matched up between both lists by
    looking for the same values on these keys.

    :param keying: dict keys to look up/match up.
    """

    keying: List[Union[int, str]]

    def __init__(self, *keying):
        super().__init__()
        self.keying = keying


class JSONCompareDirectiveWrongSide(TypeError):
    """
    A JSONCompareDirective was seen on the "data" side of a compare.

    Directives need to go on the "expect" side.  Check argument order on
    :py:func:`json_cmp`.
    """


class JSONCompareUnexpectedDirective(TypeError):
    """
    Raised when hitting a JSONCompareDirective we weren't expecting.

    Some directives are only meaningful for dicts or lists, but not the other.
    """


def _json_diff(d1, d2):
    """
    Returns a string with the difference between JSON data.
    """
    json_format_opts = {
        "indent": 4,
        "sort_keys": True,
    }
    dstr1 = json.dumps(d1, **json_format_opts)
    dstr2 = json.dumps(d2, **json_format_opts)

    dstr1 = ("\n".join(dstr1.rstrip().splitlines()) + "\n").splitlines(1)
    dstr2 = ("\n".join(dstr2.rstrip().splitlines()) + "\n").splitlines(1)
    return get_textdiff(
        dstr2, dstr1, title1="Expected value", title2="Current value", n=0
    )


# pylint: disable=too-many-locals,too-many-branches
def _json_list_cmp(list1, list2, parent, result):
    "Handles list type entries."
    if isinstance(list1, JSONCompareIgnoreContent) or isinstance(
        list2, JSONCompareIgnoreContent
    ):
        return

    # Check second list2 type
    if not isinstance(list1, type([])) or not isinstance(list2, type([])):
        result.add_error(
            "{} has different type than expected ".format(parent)
            + "(have {}, expected {}):\n{}".format(
                type(list1), type(list2), _json_diff(list1, list2)
            )
        )
        return

    flags = [{}, {}]
    for i, l in [(0, list1), (1, list2)]:
        while l and isinstance(l[0], JSONCompareDirective):
            item = l.pop(0)
            flags[i][type(item)] = item

    # flags should only be in list2 for the time being
    assert not flags[0]

    # Check list size
    if len(list2) > len(list1):
        # and JSONCompareIgnoreExtraListitems not in flags[0]:
        result.add_error(
            "{} too few items ".format(parent)
            + "(have {}, expected {}:\n {})".format(
                len(list1), len(list2), _json_diff(list1, list2)
            )
        )
        return

    # List all unmatched items errors
    if JSONCompareListKeyedDict in flags[1]:
        keys = flags[1][JSONCompareListKeyedDict].keying
        for expected in list2:
            assert isinstance(expected, dict)

            keymatch = []
            for value in list1:
                if not isinstance(value, dict):
                    continue
                for key in keys:
                    if key not in expected:
                        continue
                    if (
                        json_cmp({"_": value.get(key)}, {"_": expected[key]})
                        is not None
                    ):
                        break
                else:
                    keymatch.append(value)

            keylabel = ",".join(["%s=%r" % (key, expected.get(key)) for key in keys])
            if not keymatch:
                result.add_error("no item found for %s" % (keylabel))
            elif len(keymatch) > 1:
                result.add_error("multiple items found for %s" % (keylabel))
            else:
                res = json_cmp(keymatch[0], expected)
                if res is not None:
                    result.add_error(
                        "{} value for key {} is different (\n  {})".format(
                            parent, keylabel, str(res).replace("\n", "\n  ")
                        )
                    )
    else:
        # unmatched = []
        for expected in list2:
            best_err = None
            for value in list1:
                res = json_cmp({"json": value}, {"json": expected})
                if res is None:
                    break
                if best_err is None or len(str(res)) < len(str(best_err)):
                    best_err = res
            else:
                result.add_error(
                    "{} list value is different (\n  {})".format(
                        parent, str(best_err).replace("\n", "\n  ")
                    )
                )

        # If there are unmatched items, error out.
        # if unmatched:
        #    result.add_error(
        #        '{} list value is different (\n{})'.format(
        #            parent, _json_diff(list1, list2)))


def json_cmp(d1, d2):
    """
    JSON compare function. Receives two parameters:
    * `d1`: json value
    * `d2`: json subset which we expect

    Returns `None` when all keys that `d1` has matches `d2`,
    otherwise a string containing what failed.

    Note: key absence can be tested by adding a key with value `None`.
    """
    squeue = [(d1, d2, "json")]
    result = json_cmp_result()

    while squeue:
        nd1, nd2, parent = squeue.pop(0)

        # Handle JSON beginning with lists.
        if isinstance(nd1, type([])) or isinstance(nd2, type([])):
            _json_list_cmp(nd1, nd2, parent, result)
            return result if result.has_errors() else None

        # Expect all required fields to exist.
        s1, s2 = set(nd1), set(nd2)
        s2_req = {key for key in nd2 if nd2[key] is not None}
        diff = s2_req - s1
        if diff != set({}):
            result.add_error(
                "expected key(s) {} in {} (have {}):\n{}".format(
                    str(list(diff)), parent, str(list(s1)), _json_diff(nd1, nd2)
                )
            )

        for key in s2.intersection(s1):
            # Test for non existence of key in d2
            if nd2[key] is None:
                result.add_error(
                    '"{}" should not exist in {} (have {}):\n{}'.format(
                        key, parent, str(s1), _json_diff(nd1[key], nd2[key])
                    )
                )
                continue

            if isinstance(nd1[key], JSONCompareDirective):
                raise JSONCompareDirectiveWrongSide(nd1[key])

            if isinstance(nd2[key], JSONCompareDirective):
                if isinstance(nd2[key], JSONCompareIgnoreContent):
                    continue

                raise JSONCompareUnexpectedDirective(nd2[key])

            # If nd1 key is a dict, we have to recurse in it later.
            if isinstance(nd2[key], type({})):
                if not isinstance(nd1[key], type({})):
                    result.add_error(
                        '{}["{}"] has different type than expected '.format(parent, key)
                        + "(have {}, expected {}):\n{}".format(
                            type(nd1[key]),
                            type(nd2[key]),
                            _json_diff(nd1[key], nd2[key]),
                        )
                    )
                    continue
                nparent = '{}["{}"]'.format(parent, key)
                squeue.append((nd1[key], nd2[key], nparent))
                continue

            # Check list items
            if isinstance(nd2[key], type([])):
                _json_list_cmp(nd1[key], nd2[key], parent, result)
                continue

            # Compare JSON values
            if nd1[key] != nd2[key]:
                result.add_error(
                    '{}["{}"] dict value is different (\n{})'.format(
                        parent, key, _json_diff(nd1[key], nd2[key])
                    )
                )
                continue

    if result.has_errors():
        return result

    return None


def text_rich_cmp(configs, rtr, out, expect, outtitle):
    lines = []
    for line in deindent(expect).split("\n"):
        items = line.split("$$")
        lre = []
        while len(items) > 0:
            lre.append(re.escape(items.pop(0)))
            if len(items) == 0:
                break
            expr = items.pop(0)
            if expr.startswith("="):
                expr = expr[1:]
                if expr.startswith(" "):
                    lre.append("\\s+")
                lre.append(re.escape(str(configs.eval(rtr, expr))))
                if expr.endswith(" "):
                    lre.append("\\s+")
            else:
                lre.append(expr)
        lines.append((line, "".join(lre)))

    x_got, x_exp = [], []
    fail = False

    for i, out_line in enumerate(out.split("\n")):
        if i >= len(lines):
            x_got.append(out_line)
            fail = True
            continue

        ref_line, ref_re = lines[i]
        if re.match("^" + ref_re + "$", out_line):
            x_got.append(out_line)
            x_exp.append(out_line)
        else:
            x_got.append(out_line)
            x_exp.append(ref_line)
            fail = True

    if not fail:
        return None

    return TopotatoCLICompareFail(
        "\n" + get_textdiff(x_got, x_exp, title1=outtitle, title2="expected")
    )


_env_path = os.environ["PATH"].split(":")


def exec_find(name, stacklevel=1):
    for p in _env_path:
        pname = os.path.join(p, name)
        if os.access(pname, os.X_OK):
            logger.debug(
                "executable %s found: %s",
                shlex.quote(name),
                shlex.quote(pname),
                stacklevel=stacklevel + 1,
            )
            return pname

    logger.warning("executable %s not found in PATH", shlex.quote(name))
    return None


class ClassHooks:
    _hooked_classes: List[type] = []

    class Result:
        def __init__(self):
            super().__init__()
            self.warnings = []
            self.errors = []

        def __bool__(self):
            return len(self.errors) == 0

        def warning(self, *args):
            self.warnings.append(args)

        def error(self, *args):
            self.errors.append(args)

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        ClassHooks._hooked_classes.append(cls)

    @classmethod
    def _check_env(cls, *, result, **kwargs):
        pass

    @classmethod
    def check_env_all(cls, **kwargs):
        result = cls.Result()
        for subcls in cls._hooked_classes:
            for parent in subcls.__mro__[1:]:
                # pylint: disable=protected-access
                if (
                    subcls._check_env.__code__
                    is getattr(parent, "_check_env", ClassHooks._check_env).__code__
                ):
                    break
            else:
                try:
                    subcls._check_env(result=result, **kwargs)
                except EnvironmentError as e:
                    result.errors.append(e)
        return result


_PathLike = Union[os.PathLike, str, bytes]


class TmpName:
    """
    Create filename for a temporary file in the same directory.

    The filename will be prefixed with ``.`` and suffixed with ``.tmp``.
    """

    filename: _PathLike

    def __init__(self, filename: _PathLike):
        self.filename = filename

    def __fspath__(self) -> str:
        filename = os.fsdecode(self.filename)
        dirname, basename = os.path.split(filename)
        return os.path.join(dirname, "." + basename + ".tmp")


class LockedFile:
    """
    Create a file and hold a POSIX advisory lock on it.

    The purpose of this is that the F_GETLK fcntl can retrieve the PID of the
    process holding the lock, and it automatically disappears when the process
    exits (even if it crashes and the file is still there).

    This should be used either as a context manager (``with LockedFile(...):``)
    or through the :py:func:`lock` method (which deletes the file at exit.)

    Has a "depth" counter to allow nested "lock"/"unlock" operations.
    """

    filename: _PathLike
    """
    Original file name passed when constructing.  Not used further.
    """
    _dir_fd: int
    """
    Directory file descriptor that this file will reside in.
    """
    _basename: _PathLike
    """
    File name relative to _dir_fd.
    """

    def __init__(self, filename: _PathLike, dir_fd=None):
        self.filename = filename
        self._depth = 0
        self._fd = None

        if dir_fd is None:
            dirname, basename = os.path.split(os.path.abspath(filename))
            self._basename = basename
            self._dir_fd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY)
        else:
            self._basename = filename
            self._dir_fd = os.dup(dir_fd)

    def __del__(self):
        os.close(self._dir_fd)

    def _open(self):
        self._depth += 1
        if self._fd is not None:
            return

        tmpname = TmpName(self._basename)
        try:

            def _opener(path, flags):
                return os.open(path, flags, mode=0o666, dir_fd=self._dir_fd)

            # pylint: disable=unspecified-encoding,consider-using-with
            self._fd = open(tmpname, "w", opener=_opener)
            fcntl.lockf(self._fd, fcntl.LOCK_EX)
            # lock file (and write data) first, then put it in place
            # => no intermediate race where the file could be seen by an
            #    external process, but without the lock held/data in it
            #
            # renameat2(RENAME_NOREPLACE) would be great here, but python
            # does not provide access to it
            os.rename(
                tmpname,
                self._basename,
                src_dir_fd=self._dir_fd,
                dst_dir_fd=self._dir_fd,
            )

        except:
            try:
                os.unlink(tmpname, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass
            try:
                os.unlink(self._basename, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass
            raise

    def _close(self):
        self._depth -= 1
        if self._depth:
            return

        os.unlink(self._basename, dir_fd=self._dir_fd)
        # delete file before implicit unlock in close()
        # => avoids the same kind of race as in _open
        self._fd.close()
        self._fd = None

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self._close()

    def lock(self):
        """
        Create and lock file.

        Registers with python atexit module to delete the file when the process
        exits.  Using lock() without any unlock() is normal use for situations
        where some file should be held for the entire duration of the process.
        """
        atexit.register(self._close)
        self._open()

        return self

    def unlock(self):
        """
        Unlock and delete file.
        """
        self._close()
        atexit.unregister(self._close)


# pylint: disable=too-many-instance-attributes
class AtomicPublishFile:
    """
    Write a file and move it in place (to "publish") with rename().

    The idea here is that when the file is seen, the contents have already
    been written into it.
    """

    filename: _PathLike
    """
    Original file name passed when constructing.  Not used further.
    """
    _dir_fd: int
    """
    Directory file descriptor that this file will reside in.
    """
    _basename: _PathLike
    """
    File name relative to _dir_fd.
    """
    _tmpname: TmpName
    """
    Temporary file name, also relative to _dir_fd.
    """

    def __init__(self, filename, *args, dir_fd=None, **kwargs):
        self.filename = filename
        self._args = args
        self._kwargs = kwargs

        self._fd = None
        if dir_fd is not None:
            self._basename = filename
            self._dir_fd = os.dup(dir_fd)
        else:
            dirname, basename = os.path.split(os.path.abspath(filename))
            self._basename = basename
            self._dir_fd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY)

        self._tmpname = TmpName(self._basename)

    def __del__(self):
        os.close(self._dir_fd)

    def __enter__(self):
        def _opener(path, flags):
            return os.open(path, flags, mode=0o666, dir_fd=self._dir_fd)

        # pylint: disable=unspecified-encoding
        self._fd = open(self._tmpname, *self._args, opener=_opener, **self._kwargs)
        return self._fd

    def __exit__(self, exc_type, exc_value, tb):
        self._fd.close()

        if exc_type is None:
            try:
                os.rename(
                    self._tmpname,
                    self.filename,
                    src_dir_fd=self._dir_fd,
                    dst_dir_fd=self._dir_fd,
                )
            except:
                try:
                    os.unlink(self._tmpname, dir_fd=self._dir_fd)
                except FileNotFoundError:
                    pass
                raise
        else:
            try:
                os.unlink(self._tmpname, dir_fd=self._dir_fd)
            except OSError:
                # already handling some exception, don't make things confusing
                pass


class Forked:
    """
    Context manager to execute some code in a forked child process.

    Use as::

       with Forked('text for exception') as is_child:
           if is_child:
               ...

    The parent process will wait for the child code to complete executing.
    If the exit code is nonzero, subprocess.CalledProcessError will be raised.
    Any exception in the child is printed and converted into exit code 1.

    Used in topotato to fork+exec some pieces in namespaces where nsenter is
    not a good fit.
    """

    def __init__(self, cmd):
        self.cmd = cmd
        self.childpid = None

    def __enter__(self):
        self.childpid = os.fork()
        return self.childpid == 0

    def __exit__(self, typ_, value, tb):
        if self.childpid:
            _, status = os.waitpid(self.childpid, 0)
            ec = os.waitstatus_to_exitcode(status)
            if ec != 0:
                raise subprocess.CalledProcessError(ec, self.cmd)
        elif typ_ is None:
            os._exit(0)
        else:
            sys.stderr.write("Exception in forked child:\n")
            traceback.print_exception(typ_, value, tb)
            os._exit(1)
