import frrtest

import pytest
import platform

if platform.uname()[0] == 'SunOS':
    class TestFuzzIsisTLV:
        @pytest.mark.skipif(True, reason='Test unsupported on SunOS')
        def test_exit_cleanly(self):
            pass
else:
    class TestFuzzIsisTLV(frrtest.TestMultiOut):
        program = './test_fuzz_isis_tlv'

    TestFuzzIsisTLV.exit_cleanly()
