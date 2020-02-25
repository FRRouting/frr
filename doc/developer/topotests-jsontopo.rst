.. _topotests-json:

Topotests with JSON
===================

Overview
--------

On top of current topotests framework following enhancements are done:


* Creating the topology and assigning IPs to router' interfaces dynamically.
  It is achieved by using json file, in which user specify the number of
  routers, links to each router, interfaces for the routers and protocol
  configurations for all routers.

* Creating the configurations dynamically. It is achieved by using
  :file:`/usr/lib/frr/frr-reload.py` utility, which takes running configuration
  and the newly created configuration for any particular router and creates a
  delta file(diff file) and loads it to  router.


Logging of test case executions
-------------------------------

* The user can enable logging of testcases execution messages into log file by
  adding ``frrtest_log_dir = /tmp/topotests/`` in :file:`pytest.ini`.
* Router's current configuration can be displyed on console or sent to logs by
  adding ``show_router_config = True`` in :file:`pytest.ini`.

Log file name will be displayed when we start execution:

.. code-block:: console

   root@test:# python ./test_topo_json_single_link.py

   Logs will be sent to logfile:
   /tmp/topotests/test_topo_json_single_link_11:57:01.353797

Note: directory "/tmp/topotests/" is created by topotests by default, making
use of same directory to save execution logs.

Guidelines
----------

Writing New Tests
^^^^^^^^^^^^^^^^^

This section will guide you in all recommended steps to produce a standard
topology test.

This is the recommended test writing routine:

* Create a json file , which will have routers and protocol configurations
* Create topology from json
* Create configuration from json
* Write the tests
* Create a Pull Request


File Hierarchy
^^^^^^^^^^^^^^

Before starting to write any tests one must know the file hierarchy. The
repository hierarchy looks like this:

.. code-block:: console

   $ cd path/to/topotests
   $ find ./*
   ...
   ./example-topojson-test  # the basic example test topology-1
   ./example-topojson-test/test_example_topojson.json # input json file, having
   topology, interfaces, bgp and other configuration
   ./example-topojson-test/test_example_topojson.py # test script to write and
   execute testcases
   ...
   ./lib # shared test/topology functions
   ./lib/topojson.py # library to create topology and configurations dynamically
   from json file
   ./lib/common_config.py # library to create protocol's common configurations ex-
   static_routes, prefix_lists, route_maps etc.
   ./lib/bgp.py # library to create only bgp configurations

Defining the Topology and initial configuration in JSON file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first step to write a new test is to define the topology and initial
configuration. User has to define topology and initial configuration in JSON
file. Here is an example of JSON file::

   BGP neihghborship with single phy-link, sample JSON file:
   {
   "ipv4base": "192.168.0.0",
   "ipv4mask": 30,
   "ipv6base": "fd00::",
   "ipv6mask": 64,
   "link_ip_start": {"ipv4": "192.168.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 64},
   "lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 128},
   "routers": {
       "r1": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback"},
               "r2": {"ipv4": "auto", "ipv6": "auto"},
               "r3": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r2": {
                                   "dest_link": {
                                       "r1": {}
                                   }
                               },
                               "r3": {
                                   "dest_link": {
                                       "r1": {}
                                   }
                               }
                           }
                       }
                   }
               }
           }
       },
       "r2": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback"},
               "r1": {"ipv4": "auto", "ipv6": "auto"},
               "r3": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "redistribute": [
                               {
                                   "redist_type": "static"
                               }
                           ],
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r2": {}
                                   }
                               },
                               "r3": {
                                   "dest_link": {
                                       "r2": {}
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
       ...


BGP neighboship with loopback interface, sample JSON file::

   {
   "ipv4base": "192.168.0.0",
   "ipv4mask": 30,
   "ipv6base": "fd00::",
   "ipv6mask": 64,
   "link_ip_start": {"ipv4": "192.168.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 64},
   "lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 128},
   "routers": {
       "r1": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback",
                      "add_static_route":"yes"},
               "r2": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r2": {
                                   "dest_link": {
                                       "lo": {
                                           "source_link": "lo"
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           },
           "static_routes": [
               {
                   "network": "1.0.2.17/32",
                   "next_hop": "192.168.0.1
               }
           ]
       },
       "r2": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback",
                      "add_static_route":"yes"},
               "r1": {"ipv4": "auto", "ipv6": "auto"},
               "r3": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "redistribute": [
                               {
                                   "redist_type": "static"
                               }
                           ],
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "lo": {
                                           "source_link": "lo"
                                       }
                                   }
                               },
                               "r3": {
                                   "dest_link": {
                                       "lo": {
                                           "source_link": "lo"
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           },
           "static_routes": [
               {
                   "network": "192.0.20.1/32",
                   "no_of_ip": 9,
                   "admin_distance": 100,
                   "next_hop": "192.168.0.1",
                   "tag": 4001
               }
           ],
       }
       ...

BGP neighborship with Multiple phy-links, sample JSON file::

   {
   "ipv4base": "192.168.0.0",
   "ipv4mask": 30,
   "ipv6base": "fd00::",
   "ipv6mask": 64,
   "link_ip_start": {"ipv4": "192.168.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 64},
   "lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 128},
   "routers": {
       "r1": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback"},
               "r2-link1": {"ipv4": "auto", "ipv6": "auto"},
               "r2-link2": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r2": {
                                   "dest_link": {
                                       "r1-link1": {}
                                   }
                               }
                           }
                       }
                   }
               }
           }
       },
       "r2": {
           "links": {
               "lo": {"ipv4": "auto", "ipv6": "auto", "type": "loopback"},
               "r1-link1": {"ipv4": "auto", "ipv6": "auto"},
               "r1-link2": {"ipv4": "auto", "ipv6": "auto"},
               "r3-link1": {"ipv4": "auto", "ipv6": "auto"},
               "r3-link2": {"ipv4": "auto", "ipv6": "auto"}
           },
           "bgp": {
               "local_as": "64512",
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "redistribute": [
                               {
                                   "redist_type": "static"
                               }
                           ],
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r2-link1": {}
                                   }
                               },
                               "r3": {
                                   "dest_link": {
                                       "r2-link1": {}
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
       ...


JSON File Explained
"""""""""""""""""""

Mandatory keywords/options in JSON:

* ``ipv4base`` : base ipv4 address to generate ips,  ex - 192.168.0.0
* ``ipv4mask`` : mask for ipv4 address, ex - 30
* ``ipv6base`` : base ipv6 address to generate ips,  ex - fd00:
* ``ipv6mask`` : mask for ipv6 address, ex - 64
* ``link_ip_start`` : physical interface base ipv4 and ipv6 address
* ``lo_prefix`` : loopback interface base ipv4 and ipv6 address
* ``routers``   : user can add number of routers as per topology, router's name
  can be any logical name, ex- r1 or a0.
* ``r1`` : name of the router
* ``lo`` : loopback interface dict, ipv4 and/or ipv6 addresses generated automatically
* ``type`` : type of interface, to identify loopback interface
* ``links`` : physical interfaces dict, ipv4 and/or ipv6 addresses generated
  automatically
* ``r2-link1`` : it will be used when routers have multiple links. 'r2' is router
  name, 'link' is any logical name, '1' is to identify link number,
  router name and link must be seperated by hyphen (``-``), ex- a0-peer1

Optional keywords/options in JSON:

* ``bgp`` : bgp configuration
* ``local_as`` : Local AS number
* ``unicast`` : All SAFI configuration
* ``neighbor``: All neighbor details
* ``dest_link`` : Destination link to which router will connect
* ``router_id`` : bgp router-id
* ``source_link`` : if user wants to establish bgp neighborship with loopback
  interface, add ``source_link``: ``lo``
* ``keepalivetimer`` : Keep alive timer for BGP neighbor
* ``holddowntimer`` : Hold down timer for BGP neighbor
* ``static_routes`` : create static routes for routers
* ``redistribute`` : redistribute static and/or connected routes
* ``prefix_lists`` : create Prefix-lists for routers

Building topology and configurations
""""""""""""""""""""""""""""""""""""

Topology and initial configuration will be created in setup_module(). Following
is the sample code::

   class TemplateTopo(Topo):
       def build(self, *_args, **_opts):
       "Build function"
       tgen = get_topogen(self)

       # Building topology from json file
       build_topo_from_json(tgen, topo)

   def setup_module(mod):
       tgen = Topogen(TemplateTopo, mod.__name__)

       # Starting topology, create tmp files which are loaded to routers
       #  to start deamons and then start routers
       start_topology(tgen)

       # Creating configuration from JSON
       build_config_from_json(tgen, topo)

   def teardown_module(mod):
       tgen = get_topogen()

       # Stop toplogy and Remove tmp files
       stop_topology(tgen)


* Note: Topology will  be created in setup module but routers will not be
  started until we load zebra.conf and bgpd.conf to routers. For all routers
  dirs will be created in /tmp/topotests/<test_folder_name>/<router_name>
  zebra.conf and bgpd.conf empty files will be created and laoded to routers.
  All folder and files are deleted in teardown module..

Creating configuration files
""""""""""""""""""""""""""""

Router's configuration would be saved in config file frr_json.conf. Common
configurations are like, static routes, prefixlists and route maps etc configs,
these configs can be used by any other protocols as it is.
BGP config will be specific to BGP protocol testing.

* JSON file is passed to API build_config_from_json(), which looks for
  configuration tags in JSON file.
* If tag is found in JSON, configuration is created as per input and written
  to file frr_json.conf
* Once JSON parsing is over, frr_json.conf is loaded onto respective router.
  Config loading is done using 'vtysh -f <file>'. Initial config at this point
  is also saved frr_json_initial.conf. This file can be used to reset
  configuration on router, during the course of execution.
* Reset of configuration is done using frr "reload.py" utility, which
  calculates the difference between router's running config and user's config
  and loads delta file to router. API used - reset_config_on_router()

Writing Tests
"""""""""""""

Test topologies should always be bootstrapped from the
example-test/test_example.py, because it contains important boilerplate code
that can't be avoided, like:

imports: os, sys, pytest, topotest/topogen and mininet topology class

The global variable CWD (Current Working directory): which is most likely going
to be used to reference the routers configuration file location

Example:


* The topology class that inherits from Mininet Topo class;

  .. code-block:: python

     class TemplateTopo(Topo):
       def build(self, *_args, **_opts):
         tgen = get_topogen(self)
         # topology build code


* pytest setup_module() and teardown_module() to start the topology:

  .. code-block:: python

     def setup_module(_m):
       tgen = Topogen(TemplateTopo)

       # Starting topology, create tmp files which are loaded to routers
       #  to start deamons and then start routers
       start_topology(tgen, CWD)

     def teardown_module(_m):
       tgen = get_topogen()

       # Stop toplogy and Remove tmp files
       stop_topology(tgen, CWD)


* ``__main__`` initialization code (to support running the script directly)

  .. code-block:: python

     if **name** == '\ **main**\ ':
       sys.exit(pytest.main(["-s"]))

