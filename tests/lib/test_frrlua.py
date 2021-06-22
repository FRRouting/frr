import frrtest
import pytest

if 'S["SCRIPTING_TRUE"]=""\n' not in open("../config.status").readlines():
    class TestFrrlua:
        @pytest.mark.skipif(True, reason="Test unsupported")
        def test_exit_cleanly(self):
            pass
else:

    class TestFrrlua(frrtest.TestMultiOut):
        program = "./test_frrlua"

    TestFrrlua.exit_cleanly()
