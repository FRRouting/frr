"""
Topotest conftest.py file.
"""

from lib.topogen import get_topogen, diagnose_env
from lib.topotest import json_cmp_result
from lib.topolog import logger
import pytest

def pytest_addoption(parser):
    """
    Add topology-only option to the topology tester. This option makes pytest
    only run the setup_module() to setup the topology without running any tests.
    """
    parser.addoption('--topology-only', action='store_true',
                     help='Only set up this topology, don\'t run tests')

def pytest_assertrepr_compare(op, left, right):
    """
    Show proper assertion error message for json_cmp results.
    """
    json_result = left
    if not isinstance(json_result, json_cmp_result):
        json_result = right
        if not isinstance(json_result, json_cmp_result):
            return None

    return json_result.errors

def pytest_configure(config):
    "Assert that the environment is correctly configured."
    if not diagnose_env():
        pytest.exit('enviroment has errors, please read the logs')

def pytest_runtest_makereport(item, call):
    "Log all assert messages to default logger with error level"
    # Nothing happened
    if call.excinfo is None:
        return

    parent = item.parent
    modname = parent.module.__name__

    # Treat skips as non errors
    if call.excinfo.typename != 'AssertionError':
        logger.info('assert skipped at "{}/{}": {}'.format(
            modname, item.name, call.excinfo.value))
        return

    # Handle assert failures
    parent._previousfailed = item
    logger.error('assert failed at "{}/{}": {}'.format(
        modname, item.name, call.excinfo.value))
