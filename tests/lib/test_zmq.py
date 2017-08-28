import frrtest
import pytest
import os

class TestZMQ(frrtest.TestRefOut):
    program = './test_zmq'

    @pytest.mark.skipif('S["ZEROMQ_TRUE"]=""\n' not in open('../config.status').readlines(),
                        reason='ZEROMQ not enabled')
    def test_refout(self):
        return super(TestZMQ, self).test_refout()
