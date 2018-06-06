import frrtest

import pytest
import platform
import socket


##
# on musl, ntop compresses a single :0: -> :: which is against RFC
##
def inet_ntop_broken():
    addr = '1:2:3:4:0:6:7:8'
    return socket.inet_ntop(socket.AF_INET6,
                            socket.inet_pton(socket.AF_INET6, addr)) != addr


if platform.uname()[0] == 'SunOS' or inet_ntop_broken():
    class TestFuzzIsisTLV:
        @pytest.mark.skipif(True, reason='Test unsupported')
        def test_exit_cleanly(self):
            pass
else:
    class TestFuzzIsisTLV(frrtest.TestMultiOut):
        program = './test_fuzz_isis_tlv'

    TestFuzzIsisTLV.exit_cleanly()
