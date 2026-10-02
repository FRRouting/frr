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

At this point in time, the BGP code is in a usable state but is not considered
final form.  This may change based upon feedback or realizations of a broken
direction.  Appropriate warnings will be given.

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

BGP route-map ``match script``
------------------------------

When FRR is built with ``--enable-scripting``, BGP route-maps may use
``match script NAME`` to call a Lua ``route_match`` function. The script
receives the route prefix, a full ``attributes`` table (MED, communities,
nexthops, EVPN overlay fields, and other route-map-relevant attributes),
the peer, and a trailing ``path`` context table. Returning
``RM_MATCH_AND_CHANGE`` with a modified ``attributes`` table applies those
changes onto the route.

``NAME`` is the script file name without the ``.lua`` suffix. FRR loads
:file:`NAME.lua` from the script directory. That directory is
:file:`/etc/frr/scripts/` by default, configurable at compile time with
``--with-scriptdir`` and overridable at runtime with the ``--scriptdir``
daemon option. The Lua function inside the file **must** be named
``route_match``.

For example, ``match script set_customer_med`` loads
:file:`/etc/frr/scripts/set_customer_med.lua` (unless ``--with-scriptdir`` or
``--scriptdir`` points elsewhere) and calls ``route_match``.

The function must return a table with an ``action`` field set to one of
the status codes passed as arguments (``RM_NOMATCH``, ``RM_MATCH``,
``RM_MATCH_AND_CHANGE``, or ``RM_FAILURE``). When using
``RM_MATCH_AND_CHANGE``, also return the modified ``attributes`` table.

.. include:: ../developer/bgp-lua-attributes.rst

Example Lua script, saved as :file:`/etc/frr/scripts/set_customer_med.lua`:

.. code-block:: lua

   function route_match(prefix, attributes, peer,
         RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE, path)

      log.info("Evaluating " .. prefix.network ..
               " from AS " .. tostring(peer.remote_as))

      -- Permit this prefix unchanged.
      if prefix.network == "10.0.1.0/24" then
         return { action = RM_MATCH }
      end

      -- Match and set MED.
      if prefix.network == "10.0.3.0/24" then
         attributes.metric = 123
         return {
            action = RM_MATCH_AND_CHANGE,
            attributes = attributes
         }
      end

      -- Match a community and set local-pref plus a new community.
      if attributes.community
            and string.find(attributes.community, "65002:99", 1, true) then
         attributes.localpref = 200
         attributes.community = "65001:1"
         return {
            action = RM_MATCH_AND_CHANGE,
            attributes = attributes
         }
      end

      return { action = RM_NOMATCH }
   end

Example FRR configuration that uses the script on inbound BGP updates:

.. code-block:: frr

   route-map LUA permit 10
    match script set_customer_med
   !
   router bgp 65001
    bgp router-id 10.0.0.1
    neighbor 192.168.12.2 remote-as 65002
    !
    address-family ipv4 unicast
     neighbor 192.168.12.2 route-map LUA in
    exit-address-family
   !
