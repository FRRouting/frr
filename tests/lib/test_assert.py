import frrtest
import os
import re
import subprocess
import inspect

basedir = os.path.dirname(__file__)
program = os.path.join(basedir, "test_assert")


def check(number, rex=None):
    proc = subprocess.Popen(
        [frrtest.binpath(program), str(number)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate()
    exitcode = proc.wait()

    if rex is None:
        assert exitcode == 0
    else:
        assert exitcode != 0

        text = out.decode("US-ASCII") + err.decode("US-ASCII")
        rex = re.compile(rex, re.M | re.S)
        m = rex.search(text)
        assert m is not None, "non-matching output: %s" % text


def test_assert_0():
    check(0, r"test_assert\.c:\d+.*number > 0")


def test_assert_1():
    check(1, r"test_assert\.c:\d+.*number > 1.*\(B\) the number was 1")


def test_assert_2():
    check(2, r"test_assert\.c:\d+.*number > 2")


def test_assert_3():
    check(3, r"test_assert\.c:\d+.*number > 3.*\(A\) the number was 3")


def test_assert_4():
    check(4, r"test_assert\.c:\d+.*number > 4")


def test_assert_10():
    check(10, r"test_assert\.c:\d+.*number > 10.*\(D\) the number was 10")


def test_assert_11():
    check(11)
