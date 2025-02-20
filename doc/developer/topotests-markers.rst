.. _topotests-markers:

Markers
--------

To allow for automated selective testing on large scale continuous integration
systems, all tests must be marked with at least one of the following markers:

* babeld
* bfdd
* bgpd
* eigrpd
* isisd
* ldpd
* mgmtd
* nhrpd
* ospf6d
* ospfd
* pathd
* pbrd
* pimd
* ripd
* ripngd
* sharpd
* staticd
* vrrpd

The markers corespond to the daemon subdirectories in FRR's source code and have
to be added to tests on a module level depending on which daemons are used
during the test.

The goal is to have continuous integration systems scan code submissions, detect
changes to files in a daemons subdirectory and select only tests using that
daemon to run to shorten developers waiting times for test results and save test
infrastructure resources.

Newly written modules and code changes on tests, which do not contain any or
incorrect markers will be rejected by reviewers.


Registering markers
^^^^^^^^^^^^^^^^^^^
The Registration of new markers takes place in the file
``tests/topotests/pytest.ini``:

.. code:: python3

    # tests/topotests/pytest.ini
    [pytest]
    ...
    markers =
        babeld: Tests that run against BABELD
        bfdd: Tests that run against BFDD
        ...
        vrrpd: Tests that run against VRRPD


Adding markers to tests
^^^^^^^^^^^^^^^^^^^^^^^
Markers are added to a test by placing a global variable in the test module.

Adding a single marker:

.. code:: python3

    import pytest
    ...

    # add after imports, before defining classes or functions:
    pytestmark = pytest.mark.bfdd

    ...

    def test_using_bfdd():


Adding multiple markers:

.. code:: python3

    import pytest
    ...

    # add after imports, before defining classes or functions:
    pytestmark = [
        pytest.mark.bgpd,
        pytest.mark.ospfd,
        pytest.mark.ospf6d
    ]

    ...

    def test_using_bgpd_ospfd_ospf6d():


Selecting marked modules for testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Selecting by a single marker:

.. code:: bash

    pytest -v -m isisd

Selecting by multiple markers:

.. code:: bash

    pytest -v -m "isisd or ldpd or nhrpd"


Further Information
^^^^^^^^^^^^^^^^^^^
The `online pytest documentation <https://docs.pytest.org/en/stable/example/markers.html>`_
provides further information and usage examples for pytest markers.

