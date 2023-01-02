#!/usr/bin/env python

import subprocess
import sys
import os
import time

import pytest

fatal_error = ""


def setup_module(module):
    print("setup_module      module:%s" % module.__name__)


def teardown_module(module):
    print("teardown_module   module:%s" % module.__name__)


def setup_function(function):
    print("setup_function    function:%s" % function.__name__)


def teardown_function(function):
    print("teardown_function function:%s" % function.__name__)


def test_numbers_compare():
    a = 12
    print("Dummy Output")
    assert a == 12


def test_fail_example():
    assert True, "Some Text with explaination in case of failure"


@pytest.mark.xfail
def test_ls_exits_zero():
    "Tests for ls command on invalid file"

    global fatal_error

    proc = subprocess.Popen(
        ["ls", "/some/nonexistant/file"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        # Mark this as a fatal error which skips some other tests on failure
        fatal_error = "test_fail_example failed"
        assert proc.returncode == 0, "Return Code is non-Zero:\n%s" % stderr


def test_skipped_on_fatalerror():
    global fatal_error

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    assert True, "Some Text with explaination in case of failure"


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
