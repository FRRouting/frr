.. _topotests-snippets:

Snippets
--------

This document will describe common snippets of code that are frequently needed
to perform some test checks.

Checking for router / test failures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following check uses the topogen API to check for software failure (e.g.
zebra died) and/or for errors manually set by ``Topogen.set_error()``.

.. code:: py

   # Get the topology reference
   tgen = get_topogen()

   # Check for errors in the topology
   if tgen.routers_have_failure():
       # Skip the test with the topology errors as reason
       pytest.skip(tgen.errors)

Checking FRR routers version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This code snippet is usually run after the topology setup to make sure all
routers instantiated in the topology have the correct software version.

.. code:: py

   # Get the topology reference
   tgen = get_topogen()

   # Get the router list
   router_list = tgen.routers()

   # Run the check for all routers
   for router in router_list.values():
       if router.has_version('<', '3'):
           # Set topology error, so the next tests are skipped
           tgen.set_error('unsupported version')

A sample of this snippet in a test can be found `here
<ldp-vpls-topo1/test_ldp_vpls_topo1.py>`__.

Interacting with equipment
^^^^^^^^^^^^^^^^^^^^^^^^^^

You might want to interact with the topology equipment during the tests and
there are different ways to do so.

Notes:

1. When using the Topogen API, all the equipment code derives from ``Topogear``
   (`lib/topogen.py <lib/topogen.py>`__). If you feel brave you can look by
   yourself how the abstractions that will be mentioned here work.

2. When not using the ``Topogen`` API there is only one way to interact with
   the equipment, which is by calling the ``mininet`` API functions directly
   to spawn commands.

Interacting with the Linux sandbox
""""""""""""""""""""""""""""""""""

Without ``Topogen``:

.. code:: py

   global net
   output = net['r1'].cmd('echo "foobar"')
   print 'output is: {}'.format(output)

With ``Topogen``:

.. code:: py

   tgen = get_topogen()
   output = tgen.gears['r1'].run('echo "foobar"')
   print 'output is: {}'.format(output)

Interacting with VTYSH
""""""""""""""""""""""

Without ``Topogen``:

.. code:: py

   global net
   output = net['r1'].cmd('vtysh "show ip route" 2>/dev/null')
   print 'output is: {}'.format(output)

With ``Topogen``:

.. code:: py

   tgen = get_topogen()
   output = tgen.gears['r1'].vtysh_cmd("show ip route")
   print 'output is: {}'.format(output)

``Topogen`` also supports sending multiple lines of command:

.. code:: py

   tgen = get_topogen()
   output = tgen.gears['r1'].vtysh_cmd("""
   configure terminal
   router bgp 10
     bgp router-id 10.0.255.1
     neighbor 1.2.3.4 remote-as 10
     !
   router bgp 11
     bgp router-id 10.0.255.2
     !
   """)
   print 'output is: {}'.format(output)

You might also want to run multiple commands and get only the commands that
failed:

.. code:: py

   tgen = get_topogen()
   output = tgen.gears['r1'].vtysh_multicmd("""
   configure terminal
   router bgp 10
     bgp router-id 10.0.255.1
     neighbor 1.2.3.4 remote-as 10
     !
   router bgp 11
     bgp router-id 10.0.255.2
     !
   """, pretty_output=false)
   print 'output is: {}'.format(output)

Translating vtysh JSON output into Python structures:

.. code:: py

   tgen = get_topogen()
   json_output = tgen.gears['r1'].vtysh_cmd("show ip route json", isjson=True)
   output = json.dumps(json_output, indent=4)
   print 'output is: {}'.format(output)

   # You can also access the data structure as normal. For example:
   # protocol = json_output['1.1.1.1/32']['protocol']
   # assert protocol == "ospf", "wrong protocol"

.. note::

   ``vtysh_(multi)cmd`` is only available for router types of equipment.

Invoking mininet CLI
^^^^^^^^^^^^^^^^^^^^

Without ``Topogen``:

.. code:: py

   CLI(net)

With ``Topogen``:

.. code:: py

   tgen = get_topogen()
   tgen.mininet_cli()

Reading files
^^^^^^^^^^^^^

Loading a normal text file content in the current directory:

.. code:: py

   # If you are using Topogen
   # CURDIR = CWD
   #
   # Otherwise find the directory manually:
   CURDIR = os.path.dirname(os.path.realpath(__file__))

   file_name = '{}/r1/show_ip_route.txt'.format(CURDIR)
   file_content = open(file_name).read()

Loading JSON from a file:

.. code:: py

   import json

   file_name = '{}/r1/show_ip_route.json'.format(CURDIR)
   file_content = json.loads(open(file_name).read())

Comparing JSON output
^^^^^^^^^^^^^^^^^^^^^

After obtaining JSON output formatted with Python data structures, you may use
it to assert a minimalist schema:

.. code:: py

   tgen = get_topogen()
   json_output = tgen.gears['r1'].vtysh_cmd("show ip route json", isjson=True)

   expect = {
     '1.1.1.1/32': {
       'protocol': 'ospf'
     }
   }

   assertmsg = "route 1.1.1.1/32 was not learned through OSPF"
   assert json_cmp(json_output, expect) is None, assertmsg

``json_cmp`` function description (it might be outdated, you can find the
latest description in the source code at
:file:`tests/topotests/lib/topotest.py`

.. code:: text

   JSON compare function. Receives two parameters:
   * `d1`: json value
   * `d2`: json subset which we expect

   Returns `None` when all keys that `d1` has matches `d2`,
   otherwise a string containing what failed.

   Note: key absence can be tested by adding a key with value `None`.

Pausing execution
^^^^^^^^^^^^^^^^^

Preferably, choose the ``sleep`` function that ``topotest`` provides, as it
prints a notice during the test execution to help debug topology test execution
time.

.. code:: py

    # Using the topotest sleep
    from lib import topotest

    topotest.sleep(10, 'waiting 10 seconds for bla')
    # or just tell it the time:
    # topotest.sleep(10)
    # It will print 'Sleeping for 10 seconds'.

    # Or you can also use the Python sleep, but it won't show anything
    from time import sleep
    sleep(5)

iproute2 Linux commands as JSON
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``topotest`` has two helpers implemented that parses the output of ``ip route``
commands to JSON. It might simplify your comparison needs by only needing to
provide a Python dictionary.

.. code:: py

   from lib import topotest

   tgen = get_topogen()
   routes = topotest.ip4_route(tgen.gears['r1'])
   expected = {
     '10.0.1.0/24': {},
     '10.0.2.0/24': {
       'dev': 'r1-eth0'
     }
   }

   assertmsg = "failed to find 10.0.1.0/24 and/or 10.0.2.0/24"
   assert json_cmp(routes, expected) is None, assertmsg
