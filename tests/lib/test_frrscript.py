import frrtest
import pytest

if 'S["SCRIPTING_TRUE"]=""\n' not in open("../config.status").readlines():
    class TestFrrscript:
        @pytest.mark.skipif(True, reason="Test unsupported")
        def test_exit_cleanly(self):
            pass
else:

    class TestFrrscript(frrtest.TestMultiOut):
        program = "./test_frrscript"

    TestFrrscript.exit_cleanly()
