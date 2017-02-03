import frrtest
import pytest
import os

@pytest.mark.skipif('QUAGGA_TEST_COMMANDS' not in os.environ,
                    reason='QUAGGA_TEST_COMMANDS not set')
class TestCommands(frrtest.TestRefOut):
    program = './test_commands'
