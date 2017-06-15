"""
Topotest conftest.py file.
"""

from lib.topogen import get_topogen
import pytest

def pytest_addoption(parser):
    """
    Add topology-only option to the topology tester. This option makes pytest
    only run the setup_module() to setup the topology without running any tests.
    """
    parser.addoption('--topology-only', action='store_true',
                     help='Only set up this topology, don\'t run tests')

def pytest_runtest_call():
    """
    This function must be run after setup_module(), it does standarized post
    setup routines. It is only being used for the 'topology-only' option.
    """
    # pylint: disable=E1101
    # Trust me, 'config' exists.
    if pytest.config.getoption('--topology-only'):
        # Allow user to play with the setup.
        get_topogen().mininet_cli()
        pytest.exit('the topology executed successfully')
