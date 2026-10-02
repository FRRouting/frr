.. _grpc:

***************
Northbound gRPC
***************

.. program:: configure

*gRPC* provides a combined front end to all FRR daemons using the YANG
northbound. It is currently disabled by default due to its experimental
stage, but it can be enabled with :option:`--enable-grpc` option in the
configure script.


.. _grpc-features:

Northbound gRPC Features
========================

* Get/set configuration using JSON/XML/XPath encodings. When gRPC is loaded
  into ``mgmtd``, ``Get(CONFIG)`` reads from mgmtd's running datastore. The
  root path, or an omitted path, returns the whole running datastore. A
  non-root config path returns the YANG subtree rooted at that path.
* Execute YANG RPC calls. When gRPC is loaded into ``mgmtd``, daemon-owned
  RPCs are routed through mgmtd to the backend daemon that registered the RPC
  xpath.
* Subscribe to YANG notifications with ``Subscribe`` in ``ON_CHANGE`` mode.
* Subscribe to local operational-state snapshots with a ``sync_response``
  marker using ``STREAM`` mode.
* Subscribe to periodic local operational-state reads using ``SAMPLE`` mode
  and ``sample_interval_ms``.
* Request heartbeat messages on quiet Subscribe streams using
  ``heartbeat_interval_ms``.
* Lock/unlock configuration.
* Create/edit/load/update/commit candidate configuration.
* List/get transactions.


.. note::

   ``Subscribe`` currently supports ``ON_CHANGE`` notification delivery,
   ``STREAM`` operational-state snapshots, ``SAMPLE`` periodic reads and
   optional heartbeats.  The ``POLL`` mode is reserved for a future
   client-streaming Subscribe RPC shape.

   ``ON_CHANGE`` selectors must resolve to a loaded YANG node, or to a
   module-root shorthand such as ``/frr-ripd``.  When gRPC is loaded into
   ``mgmtd``, ``ON_CHANGE`` selectors are matched against backend
   notifications from any daemon through mgmtd's selector tree.  ``STREAM``
   and ``SAMPLE`` paths are local operational-state data paths in the daemon
   hosting the gRPC module.  Invalid selectors or paths are rejected with
   ``INVALID_ARGUMENT``.

   Each ``Subscribe`` stream has a bounded pending response queue.  If a
   client falls behind that bound, FRR closes the stream with ``OUT_OF_RANGE``.
   A client can reconnect, consume responses more quickly, or raise the
   ``subscribe-pending-limit`` module option when a larger burst buffer is
   appropriate.


.. note::

   You can find more information on how to code programs to interact
   with FRR by reading the gRPC Programming Language Bindings section
   in the `developer's documentation
   <http://docs.frrouting.org/projects/dev-guide/en/latest/grpc.html>`_.


.. _grpc-config:

Daemon gRPC Configuration
=========================

The *gRPC* module accepts the following run time option:

- ``port``: the port to listen to (defaults to ``50051``).
- ``subscribe-pending-limit``: optional maximum queued ``Subscribe``
  responses per stream (defaults to ``128``).


.. note::

   At the moment only localhost connections with no SSL/TLS are
   supported.


To configure FRR daemons to listen to gRPC you need to append the
following parameter to the daemon's command line: ``-M grpc``
(optionally ``-M grpc:PORT`` to specify listening port, or
``-M grpc:PORT,SUBSCRIBE-PENDING-LIMIT`` to tune the queued ``Subscribe``
response bound).

For example, ``-M grpc:50051,128`` listens on port ``50051`` and bounds each
``Subscribe`` stream to ``128`` queued responses.

To do that in production you need to edit the ``/etc/frr/daemons`` file
so the daemons get started with the command line argument. Example:

::

   # other daemons...
   bfdd_options="  --daemon -A 127.0.0.1 -M grpc"
