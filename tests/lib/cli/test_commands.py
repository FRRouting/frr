import frrtest
import pytest
import os

class TestCommands(frrtest.TestRefOut):
    program = './test_commands'

    @pytest.mark.skipif('QUAGGA_TEST_COMMANDS' not in os.environ,
                        reason='QUAGGA_TEST_COMMANDS not set')
    def test_refout(self):
        return super(TestCommands, self).test_refout()
