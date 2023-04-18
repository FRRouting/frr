.. _scripting-user:

*********
Scripting
*********

The behavior of FRR may be extended or customized using its built-in scripting
capabilities. The scripting language is Lua 5.3. This guide assumes Lua
knowledge. For more information on Lua, consult the Lua 5.3 reference manual, or
*Programming in Lua* (note that the free version covers only Lua 5.0).

https://www.lua.org/manual/5.3/

http://www.lua.org/pil/contents.html

Scripting
=========

.. seealso:: Developer docs for scripting

How to use
----------

1. Identify the Lua function name. See :ref:`lua-hook-calls`.

2. Write the Lua script

3. Configure FRR to use the Lua script

In order to use scripting, FRR must be built with ``--enable-scripting``.

.. note::

   Scripts are typically loaded just-in-time. This means you can change the
   contents of a script that is in use without restarting FRR. Not all
   scripting locations may behave this way; refer to the documentation for the
   particular location.


Example: on_rib_process_dplane_results
--------------------------------------

This example shows how to write a Lua script that logs changes when a route is
added.

First, identify the Lua hook call to attach a Lua function to: this will be the
name of the Lua function. In this case, since the hook call is
`on_rib_process_dplane_results`:

.. code-block:: lua

   function on_rib_process_dplane_results(ctx)
      log.info(ctx.rinfo.zd_dest.network)
      return {}


The documentation for :ref:`on-rib-process-dplane-results` tells us its
arguments. Here, the destination prefix for a route is being logged out.

Scripts live in :file:`/etc/frr/scripts/` by default. This is configurable at
compile time via ``--with-scriptdir``. It may be overridden at runtime with the
``--scriptdir`` daemon option.

The documentation for :ref:`on-rib-process-dplane-results` indicates that the
``script`` command should be used to set the script. Assuming that the above
function was created in :file:`/etc/frr/scripts/my_dplane_script.lua`, the
following vtysh command sets the script for the hook call:

.. code-block:: console

   script on_rib_process_dplane_results my_dplane_script


After the script is set, when the hook call is hit, FRR will look for a
*on_rib_process_dplane_results* function in
:file:`/etc/frr/scripts/my_dplane_script.lua` and run it with the ``ctx`` object
as its argument.


.. _lua-hook-calls:

Available Lua hook calls
========================

:ref:`on-rib-process-dplane-results`
