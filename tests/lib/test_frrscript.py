import frrtest
import pytest

class TestFrrscript(frrtest.TestMultiOut):
    program = "./test_frrscript"

TestFrrscript.exit_cleanly()
