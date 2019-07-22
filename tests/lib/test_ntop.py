import frrtest
import pytest

class TestNtop(frrtest.TestMultiOut):
    program = './test_ntop'

    @pytest.mark.skipif('S["NTOP_NO_OVERRIDE_TRUE"]!=""\n' not in open('../config.status').readlines(),
                        reason='NTOP is not overridden')
    def test_exit_cleanly(self):
        return super(TestNtop, self).test_exit_cleanly()
