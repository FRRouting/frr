# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2017, 2022, LabN Consulting, L.L.C.
"""Mutest is a simple send/expect based testing framework.

This module implements the basic send/expect functionality for mutest.  The test
developer first creates a munet topology (:ref:`munet-config`) and then writes test
scripts ("test cases") which are composed of calls to the functions defined below
("steps").  In short these are:

Send/Expect functions:

    - :py:func:`step`

    - :py:func:`step_json`

    - :py:func:`match_step`

    - :py:func:`match_step_json`

    - :py:func:`wait_step`

    - :py:func:`wait_step_json`

Control/Utility functions:

    - :py:func:`script_dir`

    - :py:func:`include`

    - :py:func:`log`

    - :py:func:`test`

    - :py:func:`pause`

Test scripts are located by the :command:`mutest` command by their name.  The name of a
test script should take the form ``mutest_TESTNAME.py`` where ``TESTNAME`` is replaced
with a user chosen name for the test case.

Here's a simple example test script which first checks that a specific forwarding entry
is in the FIB for the IP destination ``10.0.1.1``.  Then it checks repeatedly for up to
10 seconds for a second forwarding entry in the FIB for the IP destination ``10.0.2.1``.

.. code-block:: python

    match_step("r1", 'vtysh -c "show ip fib 10.0.1.1"', "Routing entry for 10.0.1.0/24",
               "Check for FIB entry for 10.0.1.1")

    wait_step("r1",
              'vtysh -c "show ip fib 10.0.2.1"',
              "Routing entry for 10.0.2.0/24",
              desc="Check for FIB entry for 10.0.2.1",
              timeout=10)

Notice that the call arguments can be specified by their correct position in the list or
using keyword names, and they can also be specified over multiple lines if preferred.

All of the functions are documented and defined below.
"""

# pylint: disable=global-statement

import functools
import json
import logging
import pprint
import re
import subprocess
import sys
import time

from argparse import Namespace
from pathlib import Path
from typing import Any
from typing import Union

from deepdiff import DeepDiff as json_cmp

from munet.base import Commander


class ScriptError(Exception):
    """An unrecoverable script failure."""


class CLIOnErrorError(Exception):
    """Enter CLI after error."""

    def __init__(self, desc=""):
        self.desc = desc


def pause_test(desc=""):
    isatty = sys.stdout.isatty()
    if not isatty:
        desc = f" for {desc}" if desc else ""
        logging.info("NO PAUSE on non-tty terminal%s", desc)
        return

    while True:
        if desc:
            print(f"\n== PAUSING: {desc} ==")
        else:
            print("\n== PAUSING: *NO DESCRIPTION PROVIDED* ==")
        try:
            user = input(
                'PAUSED, type "cli" for CLI, "pdb" to debug, or press [Enter] to continue: '
            )
        except EOFError:
            print("^D...continuing")
            break
        user = user.strip()
        if user == "cli":
            raise CLIOnErrorError()
        if user == "pdb":
            breakpoint()  # pylint: disable=W1515
            break
        elif user == "Enter" or user == "enter":
            break
        elif user:
            print(f'Unrecognized input: "{user}"')
        else:
            break


def act_on_result(success, args, desc=""):
    if args.pause:
        pause_test(desc)
    elif success or len(desc) == 0:
        # No success on description-less steps are not considered errors.
        return
    if args.cli_on_error:
        raise CLIOnErrorError(desc)
    if args.pause_on_error:
        pause_test(desc)


class TestCaseInfo:
    """Object to hold nestable TestCase Results."""

    def __init__(self, tag: str, name: str, path: Path):
        self.path = path.absolute()
        self.tag = tag
        self.name = name
        self.steps = 0
        self.passed = 0
        self.failed = 0
        self.start_time = time.time()
        self.step_start_time = self.start_time
        self.run_time = None

    def __repr__(self):
        return (
            f"TestCaseInfo({self.tag} {self.name} steps {self.steps} "
            f"p {self.passed} f {self.failed} path {self.path})"
        )


class TestCase:
    """A mutest testcase.

    This is normally meant to be used internally by the mutest command to
    implement the user API. See README-mutest.org for usage details on the
    user API.

    Args:
        tag: identity of the test in a run. (x.x...)
        name: the name of the test case
        path: the test file that is being executed.
        targets: a dictionary of objects which implement ``cmd_nostatus(str)``
        output_logger: a logger for output and other messages from the test.
        result_logger: a logger to output the results of test steps to.
        full_summary: if True then print entire doctstring instead of
          only the first line in the results report

    Attributes:
        tag: identity of the test in a run
        name: the name of the test
        targets: dictionary of targets.

        steps: total steps executed so far.
        passed: number of passing steps.
        failed: number of failing steps.

        last: the last command output.
        last_m: the last result of re.search during a matching step on the output with
            newlines converted to spaces.

    :meta private:
    """

    # sum_hfmt = "{:5.5s} {:4.4s} {:>6.6s} {}"
    # sum_dfmt = "{:5s} {:4.4s} {:^6.6s} {}"
    sum_fmt = "%-10s %4.4s %{}s %6s  %s"

    def __init__(
        self,
        tag: int,
        name: str,
        path: Path,
        targets: dict,
        args: Namespace,
        output_logger: logging.Logger = None,
        result_logger: logging.Logger = None,
        full_summary: bool = False,
    ):
        self.info = TestCaseInfo(tag, name, path)
        self.__saved_info = []
        self.__short_doc_header = not full_summary

        self.__space_before_result = False

        # we are only ever in a section once, an include ends a section
        # so are never in section+include, and another section ends a
        # section, so we don't need __in_section to be save in the
        # TestCaseInfo struct.
        self.__in_section = False

        self.targets = targets
        self.args = args

        self.last = ""
        self.last_m = None

        self.rlog = result_logger
        self.olog = output_logger
        self.logf = functools.partial(self.olog.log, logging.INFO)

        oplog = logging.getLogger("mutest.oper")
        self.oplogf = oplog.debug
        self.oplogf("new TestCase: tag: %s name: %s path: %s", tag, name, path)

        # find the longerst target name and make target field that wide
        nmax = max(len(x) for x in targets)
        nmax = max(nmax, len("TARGET"))
        self.sum_fmt = TestCase.sum_fmt.format(nmax)

        # Let's keep this out of summary for now
        self.rlog.debug(self.sum_fmt, "NUMBER", "STAT", "TARGET", "TIME", "DESCRIPTION")
        self.rlog.debug("-" * 70)

    @property
    def tag(self):
        return self.info.tag

    @property
    def name(self):
        return self.info.name

    @property
    def steps(self):
        return self.info.steps

    @property
    def passed(self):
        return self.info.passed

    @property
    def failed(self):
        return self.info.failed

    def execute(self):
        """Execute the test case.

        :meta private:
        """
        assert TestCase.g_tc is None
        self.oplogf("execute")
        try:
            TestCase.g_tc = self
            e = self.__exec_script(self.info.path, True, False)
        except BaseException:
            self.__end_test()
            raise
        return *self.__end_test(), e

    def __del__(self):
        if TestCase.g_tc is self:
            logging.error("Internal error, TestCase.__end_test() was not called!")
            TestCase.g_tc = None

    def __push_execinfo(self, path: Path):
        self.oplogf(
            "__push_execinfo: path: %s current top is %s",
            path,
            pprint.pformat(self.info),
        )
        newname = self.name + path.stem
        self.info.steps += 1
        self.__saved_info.append(self.info)
        tag = f"{self.info.tag}.{self.info.steps}"
        self.info = TestCaseInfo(tag, newname, path)
        self.oplogf("__push_execinfo: now on top: %s", pprint.pformat(self.info))

    def __pop_execinfo(self):
        # do something with tag?
        finished_info = self.info
        self.info = self.__saved_info.pop()
        self.oplogf("  __pop_execinfo: poppped: %s", pprint.pformat(finished_info))
        self.oplogf("  __pop_execinfo: now on top: %s", pprint.pformat(self.info))
        return finished_info

    def __print_header(self, tag, header, add_newline=False):
        # self.olog.info(self.sum_fmt, tag, "", "", "", header)
        self.olog.info("== %s ==", f"TEST: {tag}. {header}")
        if add_newline:
            self.rlog.info("")
        self.rlog.info("%s. %s", tag, header)

    def __exec_script(self, path, print_header, add_newline):
        # Below was the original method to avoid the global TestCase
        # variable; however, we need global functions so we can import them
        # into test scripts. Without imports pylint will complain about undefined
        # functions and the resulting christmas tree of warnings is annoying.
        #
        # pylint: disable=possibly-unused-variable,exec-used,redefined-outer-name
        # include = self.include
        # log = self.logf
        # match_step = self.match_step
        # match_step_json = self.match_step_json
        # step = self.step
        # step_json = self.step_json
        # test = self.test
        # wait_step = self.wait_step
        # wait_step_json = self.wait_step_json

        name = f"{path.stem}{self.tag}"
        name = re.sub(r"\W|^(?=\d)", "_", name)

        _ok_result = "marker"
        try:
            self.oplogf("__exec_script: path %s", path)
            script = open(path, "r", encoding="utf-8").read()

            # Load the script into a function.
            script = script.strip()
            s2 = (
                # f"async def _{name}(ok_result):\n"
                f"def _{name}(ok_result):\n"
                + " "
                + script.replace("\n", "\n ")
                + "\n return ok_result\n"
                + "\n"
            )
            exec(s2)

            # Extract any docstring as a title.
            if print_header:
                title = locals()[f"_{name}"].__doc__
                if title is None:
                    title = ""
                title = title.lstrip()
                if self.__short_doc_header and (title := title.lstrip()):
                    if (idx := title.find("\n")) != -1:
                        title = title[:idx].strip()
                if not title:
                    title = f"Test from file: {self.info.path.name}"
                self.__print_header(self.info.tag, title, add_newline)
            self.__space_before_result = False

            # Execute the function.
            result = locals()[f"_{name}"](_ok_result)

            # Here's where we can do async in the future if we want.
            # result = await locals()[f"_{name}"](_ok_result)
        except ScriptError as error:
            return error
        except CLIOnErrorError:
            raise
        except Exception as error:
            logging.error(
                "Unexpected exception executing %s: %s", name, error, exc_info=True
            )
            return error
        else:
            if result is not _ok_result:
                logging.info("%s returned early, result: %s", name, result)
            else:
                self.oplogf("__exec_script: name %s completed normally", name)
        return None

    def __post_result(self, target, success, rstr, logstr=None):
        self.oplogf(
            "__post_result: target: %s success %s rstr %s", target, success, rstr
        )
        if success:
            self.info.passed += 1
            status = "PASS"
            outlf = self.logf
            reslf = self.rlog.info
        else:
            self.info.failed += 1
            status = "FAIL"
            outlf = self.olog.warning
            reslf = self.rlog.warning

        self.info.steps += 1
        if logstr is not None:
            outlf("R:%d %s: %s" % (self.steps, status, logstr))

        run_time = time.time() - self.info.step_start_time

        stepstr = f"{self.tag}.{self.steps}"
        rtimes = _delta_time_str(run_time)

        if self.__space_before_result:
            self.rlog.info("")
            self.__space_before_result = False

        reslf(self.sum_fmt, stepstr, status, target, rtimes, rstr)

        # start counting for next step now
        self.info.step_start_time = time.time()

    def __end_test(self) -> (int, int):
        """End the test log final results.

        Returns:
            number of steps, number passed, number failed, run time.
        """
        self.oplogf("__end_test: __in_section: %s", self.__in_section)
        if self.__in_section:
            self.__end_section()

        passed, failed = self.info.passed, self.info.failed

        # No close for loggers
        # self.olog.close()
        # self.rlog.close()
        self.olog = None
        self.rlog = None

        assert (
            TestCase.g_tc == self
        ), "TestCase global unexpectedly someon else in __end_test"
        TestCase.g_tc = None

        self.info.run_time = time.time() - self.info.start_time
        return passed, failed

    def _command(
        self,
        target: str,
        cmd: str,
    ) -> str:
        """Execute a ``cmd`` and return result.

        Args:
            target: the target to execute the command on.
            cmd: string to execut on the target.
        """
        out = self.targets[target].cmd_nostatus(
            cmd, stdin=subprocess.DEVNULL, warn=False
        )
        self.last = out = out.rstrip()
        report = out if out else "<no output>"
        self.logf("COMMAND OUTPUT:\n%s", report)
        return out

    def _command_json(
        self,
        target: str,
        cmd: str,
    ) -> Union[list, dict]:
        """Execute a json ``cmd`` and return json result.

        Args:
            target: the target to execute the command on.
            cmd: string to execute on the target.
        """
        out = self.targets[target].cmd_nostatus(
            cmd, stdin=subprocess.DEVNULL, warn=False
        )
        self.last = out = out.rstrip()
        try:
            js = json.loads(out)
        except Exception as error:
            js = None
            self.olog.warning(
                "JSON load failed. Check command output is in JSON format: %s",
                error,
            )
        self.logf("COMMAND OUTPUT:\n%s", out)
        return js

    def _match_command(
        self,
        target: str,
        cmd: str,
        match: str,
        expect_fail: bool,
        flags: int,
        exact_match: bool,
    ) -> (bool, Union[str, list]):
        """Execute a ``cmd`` and check result.

        Args:
            target: the target to execute the command on.
            cmd: string to execute on the target.
            match: regex to ``re.search()`` for in output.
            expect_fail: if True then succeed when the regexp doesn't match.
            flags: python regex flags to modify matching behavior
            exact_match: if True then ``match`` must be exactly matched somewhere
                in the output of ``cmd`` using ``str.find()``.

        Returns:
            (success, matches): if the match fails then "matches" will be None,
            otherwise if there were matching groups then groups() will be returned in
            ``matches`` otherwise group(0) (i.e., the matching text).
        """
        out = self._command(target, cmd)
        if exact_match:
            if match not in out:
                success = expect_fail
                ret = None
            else:
                success = not expect_fail
                ret = match
                level = logging.DEBUG if success else logging.WARNING
                self.olog.log(level, "exactly matched:%s:", ret)
            return success, ret

        search = re.search(match, out, flags)
        self.last_m = search
        if search is None:
            success = expect_fail
            ret = None
        else:
            success = not expect_fail
            ret = search.groups()
            if not ret:
                ret = search.group(0)

            level = logging.DEBUG if success else logging.WARNING
            self.olog.log(level, "matched:%s:", ret)
        return success, ret

    def _match_command_json(
        self,
        target: str,
        cmd: str,
        match: Union[str, list, dict],
        expect_fail: bool,
        exact_match: bool,
    ) -> (bool, Union[list, dict]):
        """Execute a json ``cmd`` and check result.

        Args:
            target: the target to execute the command on.
            cmd: string to execut on the target.
            match: A json ``str``, object (``dict``), or array (``list``) to
                compare against the json output from ``cmd``.
            expect_fail: if True then succeed when the json doesn't match.
            exact_match: if True then the json must exactly match.
        """
        js = self._command_json(target, cmd)
        if js is None:
            # Always fail on bad json, even if user expected failure
            # return expect_fail, {}
            return False, {}

        try:
            # Convert to string to validate the input is valid JSON
            if not isinstance(match, str):
                match = json.dumps(match)
            expect = json.loads(match)
        except Exception as error:
            expect = {}
            self.olog.warning(
                "JSON load failed. Check match value is in JSON format: %s", error
            )
            # Always fail on bad json, even if user expected failure
            # return expect_fail, {}
            return False, {}

        if exact_match:
            deep_diff = json_cmp(expect, js)
            # Convert DeepDiff completely into dicts or lists at all levels
            json_diff = json.loads(deep_diff.to_json())
        else:
            deep_diff = json_cmp(
                expect,
                js,
                ignore_order=True,
                cutoff_intersection_for_pairs=1,
                cutoff_distance_for_pairs=1,
            )
            # Convert DeepDiff completely into dicts or lists at all levels
            json_diff = json.loads(deep_diff.to_json())
            # Remove new fields in json object from diff
            if json_diff.get("dictionary_item_added") is not None:
                del json_diff["dictionary_item_added"]
            # Remove new json objects in json array from diff
            if (new_items := json_diff.get("iterable_item_added")) is not None:
                new_item_paths = list(new_items.keys())
                for path in new_item_paths:
                    del new_items[path]
                if len(new_items) == 0:
                    del json_diff["iterable_item_added"]

        if json_diff:
            success = expect_fail
            if not success:
                self.logf("JSON DIFF:%s:" % json_diff)
            return success, json_diff

        success = not expect_fail
        return success, js

    def _wait(
        self,
        target: str,
        cmd: str,
        match: Union[str, list, dict],
        is_json: bool,
        timeout: float,
        interval: float,
        expect_fail: bool,
        flags: int,
        exact_match: bool,
    ) -> Union[str, list, dict]:
        """Execute a command repeatedly waiting for result until timeout.

        ``match`` is a regular expression to search for in the output of ``cmd``
        when ``is_json`` is False.

        When ``is_json`` is True ``match`` must be a json object, a json array,
        or a ``str`` which parses into a json object. Likewise, the ``cmd`` output
        is parsed into a json object or array and then a comparison is done between
        the two json objects or arrays.
        """
        startt = time.time()
        endt = startt + timeout

        success = False
        ret = None
        while not success and time.time() < endt:
            if is_json:
                success, ret = self._match_command_json(
                    target, cmd, match, expect_fail, exact_match
                )
            else:
                success, ret = self._match_command(
                    target, cmd, match, expect_fail, flags, exact_match
                )
            if not success:
                time.sleep(interval)
        return success, ret

    # ---------------------
    # Public APIs for User
    # ---------------------

    def include(self, pathname: str, new_section: bool = False):
        """See :py:func:`~munet.mutest.userapi.include`.

        :meta private:
        """
        path = Path(pathname)
        path = self.info.path.parent.joinpath(path)
        do_cli = False

        self.oplogf(
            "include: new path: %s create section: %s currently __in_section: %s",
            path,
            new_section,
            self.__in_section,
        )

        if new_section:
            self.oplogf("include: starting new exec section")
            self.__start_exec_section(path)
            our_info = self.info
            # Note we do *not* mark __in_section True
        else:
            # swap the current path inside the top info
            old_path = self.info.path
            self.info.path = path
            self.oplogf("include: swapped info path: new %s old %s", path, old_path)

        try:
            e = self.__exec_script(
                path, print_header=new_section, add_newline=new_section
            )
        except CLIOnErrorError:
            do_cli = True

        if new_section:
            # Something within the section creating include has also created a section
            # end it, sections do not cross section creating file boundaries
            if self.__in_section:
                self.oplogf(
                    "include done: path: %s __in_section calling __end_section", path
                )
                self.__end_section()

            # We should now be back to the info we started with, b/c we don't actually
            # start a new section (__in_section) that then could have been ended inside
            # the included file.
            assert our_info == self.info

            self.oplogf(
                "include done: path: %s new_section calling __end_section", path
            )
            self.__end_section()
        else:
            # The current top path could be anything due to multiple inline includes as
            # well as section swap in and out. Forcibly return the top path to the file
            # we are returning to
            self.info.path = old_path
            self.oplogf("include: restored info path: %s", old_path)

        if do_cli:
            raise CLIOnErrorError()
        if e:
            raise ScriptError(e)

    def __end_section(self):
        self.oplogf("__end_section: __in_section: %s", self.__in_section)
        info = self.__pop_execinfo()
        passed, failed = info.passed, info.failed
        self.info.passed += passed
        self.info.failed += failed
        self.__space_before_result = True
        self.oplogf("__end_section setting __in_section to False")
        self.__in_section = False

    def __start_exec_section(self, path):
        self.oplogf("__start_exec_section: __in_section: %s", self.__in_section)
        if self.__in_section:
            self.__end_section()

        self.__push_execinfo(path)
        self.__space_before_result = False
        self.oplogf("NOT setting __in_section to True")
        assert not self.__in_section

    def section(self, desc: str):
        """See :py:func:`~munet.mutest.userapi.section`.

        :meta private:
        """
        self.oplogf("section: __in_section: %s", self.__in_section)
        # Grab path before we pop the current info off the top
        path = self.info.path
        old_steps = self.info.steps

        if self.__in_section:
            self.__end_section()

        self.__push_execinfo(path)
        add_nl = self.info.steps <= old_steps

        self.__space_before_result = False
        self.__in_section = True
        self.oplogf("   section setting __in_section to True")
        self.__print_header(self.info.tag, desc, add_nl)

    def pause(self):
        """See :py:func:`~munet.mutest.userapi.pause`.

        :meta private:
        """
        self.logf(
            "#%s.%s:%s:PAUSE",
            self.tag,
            self.steps + 1,
            self.info.path,
        )
        pause_test("mutest paused")

    def step(self, target: str, cmd: str) -> str:
        """See :py:func:`~munet.mutest.userapi.step`.

        :meta private:
        """
        self.logf(
            "#%s.%s:%s:STEP:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
        )
        return self._command(target, cmd)

    def step_json(self, target: str, cmd: str) -> Union[list, dict]:
        """See :py:func:`~munet.mutest.userapi.step_json`.

        :meta private:
        """
        self.logf(
            "#%s.%s:%s:STEP_JSON:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
        )
        return self._command_json(target, cmd)

    def match_step(
        self,
        target: str,
        cmd: str,
        match: str,
        desc: str = "",
        expect_fail: bool = False,
        flags: int = re.DOTALL,
        exact_match: bool = False,
    ) -> (bool, Union[str, list]):
        """See :py:func:`~munet.mutest.userapi.match_step`.

        :meta private:
        """
        self.logf(
            "#%s.%s:%s:MATCH_STEP:%s:%s:%s:%s:%s:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
            match,
            desc,
            expect_fail,
            flags,
            exact_match,
        )
        success, ret = self._match_command(
            target, cmd, match, expect_fail, flags, exact_match
        )
        if desc:
            self.__post_result(target, success, desc)
        act_on_result(success, self.args, desc)
        return success, ret

    def test_step(self, expr_or_value: Any, desc: str, target: str = "") -> bool:
        """See :py:func:`~munet.mutest.userapi.test`.

        :meta private:
        """
        success = bool(expr_or_value)
        self.__post_result(target, success, desc)
        act_on_result(success, self.args, desc)
        return success

    def match_step_json(
        self,
        target: str,
        cmd: str,
        match: Union[str, list, dict],
        desc: str = "",
        expect_fail: bool = False,
        exact_match: bool = False,
    ) -> (bool, Union[list, dict]):
        """See :py:func:`~munet.mutest.userapi.match_step_json`.

        :meta private:
        """
        self.logf(
            "#%s.%s:%s:MATCH_STEP_JSON:%s:%s:%s:%s:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
            match,
            desc,
            expect_fail,
            exact_match,
        )
        success, ret = self._match_command_json(
            target, cmd, match, expect_fail, exact_match
        )
        if desc:
            self.__post_result(target, success, desc)
        act_on_result(success, self.args, desc)
        return success, ret

    def wait_step(
        self,
        target: str,
        cmd: str,
        match: Union[str, dict],
        desc: str = "",
        timeout=10,
        interval=0.5,
        expect_fail: bool = False,
        flags: int = re.DOTALL,
        exact_match: bool = False,
    ) -> (bool, Union[str, list]):
        """See :py:func:`~munet.mutest.userapi.wait_step`.

        :meta private:
        """
        if interval is None:
            interval = min(timeout / 20, 0.25)
        self.logf(
            "#%s.%s:%s:WAIT_STEP:%s:%s:%s:%s:%s:%s:%s:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
            match,
            timeout,
            interval,
            desc,
            expect_fail,
            flags,
            exact_match,
        )
        success, ret = self._wait(
            target,
            cmd,
            match,
            False,
            timeout,
            interval,
            expect_fail,
            flags,
            exact_match,
        )
        if desc:
            self.__post_result(target, success, desc)
        act_on_result(success, self.args, desc)
        return success, ret

    def wait_step_json(
        self,
        target: str,
        cmd: str,
        match: Union[str, list, dict],
        desc: str = "",
        timeout=10,
        interval=None,
        expect_fail: bool = False,
        exact_match: bool = False,
    ) -> (bool, Union[list, dict]):
        """See :py:func:`~munet.mutest.userapi.wait_step_json`.

        :meta private:
        """
        if interval is None:
            interval = min(timeout / 20, 0.25)
        self.logf(
            "#%s.%s:%s:WAIT_STEP:%s:%s:%s:%s:%s:%s:%s:%s",
            self.tag,
            self.steps + 1,
            self.info.path,
            target,
            cmd,
            match,
            timeout,
            interval,
            desc,
            expect_fail,
            exact_match,
        )
        success, ret = self._wait(
            target, cmd, match, True, timeout, interval, expect_fail, 0, exact_match
        )
        if desc:
            self.__post_result(target, success, desc)
        act_on_result(success, self.args, desc)
        return success, ret


# A non-rentrant global to allow for simplified operations
TestCase.g_tc = None

# pylint: disable=protected-access


def _delta_time_str(run_time: float) -> str:
    if run_time < 0.0001:
        return "0.0"
    if run_time < 0.001:
        return f"{run_time:1.4f}"
    if run_time < 0.01:
        return f"{run_time:2.3f}"
    if run_time < 0.1:
        return f"{run_time:3.2f}"
    if run_time < 100:
        return f"{run_time:4.1f}"
    return f"{run_time:5f}s"


def section(desc: str):
    """Start a new section for steps, with a description.

    This starts a new section of tests. The result is basically
    the same as doing a non-inline include. The current test number
    is used to form a new sub-set of test steps. So if the current
    test number is 2.3, a section will now number subsequent steps
    2.3.1, 2.3.2, ...

    A subsequent :py:func:`section` or non-inline :py:func:`include`
    call ends the current section and advances the base test number.

    Args:
        desc: the description for the new section.
    """
    TestCase.g_tc.section(desc)


def log(fmt, *args, **kwargs):
    """Log a message in the testcase output log."""
    return TestCase.g_tc.logf(fmt, *args, **kwargs)


def include(pathname: str, new_section=False):
    """Include a file as part of testcase.

    Args:
        pathname: the file to include.
        new_section: if a new section should be created, otherwise
          commands are executed inline.
    """
    return TestCase.g_tc.include(pathname, new_section)


def script_dir() -> Path:
    """The pathname to the directory containing the current script file.

    When an include() is called the script_dir is updated to be current with the
    includeded file, and is reverted to the previous value when the include completes.
    """
    return TestCase.g_tc.info.path.parent


def get_target(name: str) -> Commander:
    """Get the target object with the given ``name``."""
    return TestCase.g_tc.targets[name]


def pause():
    """Pause the mutest and allow a user to either enter pdb or the cli."""
    return TestCase.g_tc.pause()


def step(target: str, cmd: str) -> str:
    """Execute a ``cmd`` on a ``target`` and return the output.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execute on the target.

    Returns:
        Returns the ``str`` output of the ``cmd``.
    """
    return TestCase.g_tc.step(target, cmd)


def step_json(target: str, cmd: str) -> Union[list, dict]:
    """Execute a json ``cmd`` on a ``target`` and return the json object or array.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execute on the target.

    Returns:
        Returns the json object or array after parsing the ``cmd`` output.

        If json parse fails, a warning is logged and an empty ``dict`` is used.
    """
    return TestCase.g_tc.step_json(target, cmd)


def test_step(expr_or_value: Any, desc: str, target: str = "") -> bool:
    """Evaluates ``expr_or_value`` and posts a result base on it bool(expr).

    If ``expr_or_value`` evaluates to a positive result (i.e., True, non-zero, non-None,
    non-empty string, non-empty list, etc..) then a PASS result is recorded, otherwise
    record a FAIL is recorded.

    Args:
        expr: an expression or value to evaluate
        desc: description of this test step.
        target: optional target to associate with this test in the result string.

    Returns:
        A bool indicating the test PASS or FAIL result.
    """
    return TestCase.g_tc.test_step(expr_or_value, desc, target)


def match_step(
    target: str,
    cmd: str,
    match: str,
    desc: str = "",
    expect_fail: bool = False,
    flags: int = re.DOTALL,
    exact_match: bool = False,
) -> (bool, Union[str, list]):
    """Execute a ``cmd`` on a ``target`` check result.

    Execute ``cmd`` on ``target`` and check if the regexp in ``match``
    matches or doesn't match (according to the ``expect_fail`` value) the
    ``cmd`` output.

    If the ``match`` regexp includes groups and if the match succeeds
    the group values will be returned in a list, otherwise the command
    output is returned.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execut on the ``target``.
        match: regex to match against output.
        desc: description of test, if no description then step failure is not
            considered an error and no result is logged.
        expect_fail: if True then succeed when the regexp doesn't match.
        flags: python regex flags to modify matching behavior
        exact_match: if True then ``match`` must be exactly matched somewhere
            in the output of ``cmd`` using ``str.find()``.

    Returns:
        Returns a 2-tuple. The first value is a bool indicating ``success``.
        The second value will be a list from ``re.Match.groups()`` if non-empty,
        otherwise ``re.Match.group(0)`` if there was a match otherwise None.
    """
    return TestCase.g_tc.match_step(
        target, cmd, match, desc, expect_fail, flags, exact_match
    )


def match_step_json(
    target: str,
    cmd: str,
    match: Union[str, list, dict],
    desc: str = "",
    expect_fail: bool = False,
    exact_match: bool = False,
) -> (bool, Union[list, dict]):
    """Execute a ``cmd`` on a ``target`` check result.

    Execute ``cmd`` on ``target`` and check if the json object or array in ``match``
    matches or doesn't match (according to the ``expect_fail`` value) the
    json output from ``cmd``.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execut on the ``target``.
        match: A json ``str``, object (``dict``), or array (``list``) to compare
            against the json output from ``cmd``.
        desc: description of test, if no description then step failure is not
            considered an error and no result is logged.
        expect_fail: if True then succeed if the a json doesn't match.
        exact_match: if True then the json must exactly match.

    Returns:
        Returns a 2-tuple. The first value is a bool indicating ``success``. The
        second value is a ``dict`` of the diff if there is a difference found in
        the json compare, otherwise the value is the json object (``dict``) or
        array (``list``) from the ``cmd``.

        If json parse fails, a warning is logged and an empty ``dict`` is used.
    """
    return TestCase.g_tc.match_step_json(
        target, cmd, match, desc, expect_fail, exact_match
    )


def wait_step(
    target: str,
    cmd: str,
    match: Union[str, dict],
    desc: str = "",
    timeout: float = 10.0,
    interval: float = 0.5,
    expect_fail: bool = False,
    flags: int = re.DOTALL,
    exact_match: bool = False,
) -> (bool, Union[str, list]):
    """Execute a ``cmd`` on a ``target`` repeatedly, looking for a result.

    Execute ``cmd`` on ``target``, every ``interval`` seconds for up to ``timeout``
    seconds until the output of ``cmd`` does or doesn't match (according to the
    ``expect_fail`` value) the ``match`` value.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execut on the ``target``.
        match: regexp to match against output.
        timeout: The number of seconds to repeat the ``cmd`` looking for a match
            (or non-match if ``expect_fail`` is True).
        interval: The number of seconds between running the ``cmd``. If not
            specified the value is calculated from the timeout value so that on
            average the cmd will execute 10 times. The minimum calculated interval
            is .25s, shorter values can be passed explicitly.
        desc: description of test, if no description then step failure is not
            considered an error and no result is logged.
        expect_fail: if True then succeed when the regexp *doesn't* match.
        flags: python regex flags to modify matching behavior
        exact_match: if True then ``match`` must be exactly matched somewhere
            in the output of ``cmd`` using ``str.find()``.

    Returns:
        Returns a 2-tuple. The first value is a bool indicating ``success``.
        The second value will be a list from ``re.Match.groups()`` if non-empty,
        otherwise ``re.Match.group(0)`` if there was a match otherwise None.
    """
    return TestCase.g_tc.wait_step(
        target, cmd, match, desc, timeout, interval, expect_fail, flags, exact_match
    )


def wait_step_json(
    target: str,
    cmd: str,
    match: Union[str, list, dict],
    desc: str = "",
    timeout=10,
    interval=None,
    expect_fail: bool = False,
    exact_match: bool = False,
) -> (bool, Union[list, dict]):
    """Execute a cmd repeatedly and wait for matching result.

    Execute ``cmd`` on ``target``, every ``interval`` seconds until
    the output of ``cmd`` matches or doesn't match (according to the
    ``expect_fail`` value) ``match``, for up to ``timeout`` seconds.

    Args:
        target: the target to execute the ``cmd`` on.
        cmd: string to execut on the ``target``.
        match: A json object, json array, or str representation of json to compare
            against json output from ``cmd``.
        desc: description of test, if no description then step failure is not
            considered an error and no result is logged.
        timeout: The number of seconds to repeat the ``cmd`` looking for a match
            (or non-match if ``expect_fail`` is True).
        interval: The number of seconds between running the ``cmd``. If not
            specified the value is calculated from the timeout value so that on
            average the cmd will execute 10 times. The minimum calculated interval
            is .25s, shorter values can be passed explicitly.
        expect_fail: if True then succeed if the a json doesn't match.
        exact_match: if True then the json must exactly match.

    Returns:
        Returns a 2-tuple. The first value is a bool indicating ``success``.
        The second value is a ``dict`` of the diff if there is a difference
        found in the json compare, otherwise the value is a json object (``dict``)
        or array (``list``) from the ``cmd`` output.

        If json parse fails, a warning is logged and an empty ``dict`` is used.
    """
    return TestCase.g_tc.wait_step_json(
        target, cmd, match, desc, timeout, interval, expect_fail, exact_match
    )


def luInclude(filename, CallOnFail=None):
    """Backward compatible API, do not use in new tests."""
    return include(filename)


def luLast(usenl=False):
    """Backward compatible API, do not use in new tests."""
    del usenl
    return TestCase.g_tc.last_m


def luCommand(
    target,
    cmd,
    regexp=".",
    op="none",
    result="",
    ltime=10,
    returnJson=False,
    wait_time=0.5,
):
    """Backward compatible API, do not use in new tests.

    Only non-json is verified to any degree of confidence by code inspection.

    For non-json should return match.group() if match else return bool(op == "fail").

    For json if no diff return the json else diff return bool(op == "jsoncmp_fail")
     bug if no json from output (fail parse) could maybe generate diff, which could
     then return
    """
    if op == "wait":
        if returnJson:
            return wait_step_json(target, cmd, regexp, result, ltime, wait_time)

        success, _ = wait_step(target, cmd, regexp, result, ltime, wait_time)
        match = luLast()
        if success and match is not None:
            return match.group()
        return success

    if op == "none":
        if returnJson:
            return step_json(target, cmd)
        return step(target, cmd)

    if returnJson and op in ("jsoncmp_fail", "jsoncmp_pass"):
        expect_fail = op == "jsoncmp_fail"
        return match_step_json(target, cmd, regexp, result, expect_fail)

    assert not returnJson
    assert op in ("fail", "pass")
    expect_fail = op == "fail"
    success, _ = match_step(target, cmd, regexp, result, expect_fail)
    match = luLast()
    if success and match is not None:
        return match.group()
    return success
