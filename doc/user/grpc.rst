.. _grpc:

***************
Northbound gRPC
***************

.. program:: configure

*gRPC* provides a combined front end to all FRR daemons using the YANG
northbound. It is currently disabled by default due its experimental
stage, but it can be enabled with :option:`--enable-grpc` option in the
configure script.


.. _grpc-features:

Northbound gRPC Features
========================

* Get/set configuration using JSON/XML/XPath encondings.
* Execute YANG RPC calls.
* Lock/unlock configuration.
* Create/edit/load/update/commit candidate configuration.
* List/get transactions.


.. note::

   There is currently no support for YANG notifications.


.. note::

   You can find more information on how to code programs to interact
   with FRR by reading the gRPC Programming Language Bindings section
   in the `developer's documentation
   <http://docs.frrouting.org/projects/dev-guide/en/latest/grpc.html>`_.


.. _grpc-config:

Mgmtd gRPC Configuration
========================

The *gRPC* northbound runs only on **mgmtd**. It listens on a single port
and serves config/state for all daemons via the mgmtd frontend. Get requests
are fulfilled through mgmtd; CreateCandidate, Edit, Commit and other RPCs
may be extended to use mgmtd in a follow-up.

The *gRPC* module accepts the following run time option:

- ``port``: the port to listen on (defaults to ``50051``).


.. note::

   At the moment only localhost connections with no SSL/TLS are
   supported.


To enable gRPC you must load the module on **mgmtd** only, by appending
``-M grpc`` (or ``-M grpc:PORT``) to the mgmtd command line.

Example in ``/etc/frr/daemons``:

::

   # other daemons...
   mgmtd_options=" -M grpc:50051"
