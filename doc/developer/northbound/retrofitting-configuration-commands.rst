
.. _nb-retrofit:

Retrofitting Configuration Commands
===================================

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 2

Retrofitting process
--------------------

This page explains how to convert existing CLI configuration commands to
the new northbound model. This documentation is meant to be the primary
reference for developers working on the northbound retrofitting process.
We’ll show several examples taken from the ripd northbound conversion to
illustrate some concepts described herein.

Step 1: writing a YANG module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first step is to write a YANG module that models faithfully the
commands that are going to be converted. As explained in the
[[Architecture]] page, the goal is to introduce the new YANG-based
Northbound API without introducing backward incompatible changes in the
CLI. The northbound retrofitting process should be completely
transparent to FRR users.

The developer is free to choose whether to write a full YANG module or a
partial YANG module and increment it gradually. For developers who lack
experience with YANG it’s probably a better idea to model one command at
time.

It’s recommended to reuse definitions from standard YANG models whenever
possible to facilitate the process of writing module translators using
the [[YANG module translator]]. As an example, the frr-ripd YANG module
incorporated several parts of the IETF RIP YANG module. The repositories
below contain big collections of YANG models that might be used as a
reference:

* https://github.com/YangModels/yang

* https://github.com/openconfig/public

When writing a YANG module, it’s highly recommended to follow the
guidelines from `RFC 6087 <https://tools.ietf.org/html/rfc6087>`__. In
general, most commands should be modeled fairly easy. Here are a few
guidelines specific to authors of FRR YANG models:

* Use presence-containers or lists to model commands that change the CLI node
  (e.g. ``router rip``, ``interface eth0``). This way, if the presence-container
  or list entry is removed, all configuration options below them are removed
  automatically (exactly like the CLI behaves when a configuration object is
  removed using a *no* command). This recommendation is orthogonal to the `YANG
  authoring guidelines for OpenConfig models
  <https://github.com/openconfig/public/blob/master/doc/openconfig_style_guide.md>`__
  where the use of presence containers is discouraged. OpenConfig YANG models
  however were not designed to replicate the behavior of legacy CLI commands.

* When using YANG lists, be careful to identify what should be the key leaves.
  In the ``offset-list WORD <in|out> (0-16) IFNAME`` command, for example, both
  the direction (``<in|out>``) and the interface name should be the keys of the
  list. This can be only known by analyzing the data structures used to store
  the commands.

* For clarity, use non-presence containers to group leaves that are associated
  to the same configuration command (as we’ll see later, this also facilitate
  the process of writing ``cli_show`` callbacks).

* YANG leaves of type *enumeration* should define explicitly the value of each
  *enum* option based on the value used in the FRR source code.

* Default values should be taken from the source code whenever they exist.

Some commands are more difficult to model and demand the use of more
advanced YANG constructs like *choice*, *when* and *must* statements.
**One key requirement is that it should be impossible to load an invalid
JSON/XML configuration to FRR**. The YANG modules should model exactly
what the CLI accepts in the form of commands, and all restrictions
imposed by the CLI should be defined in the YANG models whenever
possible. As we’ll see later, not all constraints can be expressed using
the YANG language and sometimes we’ll need to resort to code-level
validation in the northbound callbacks.

   Tip: the :doc:`yang-tools` page details several tools and commands that
   might be useful when writing a YANG module, like validating YANG
   files, indenting YANG files, validating instance data, etc.

In the example YANG snippet below, we can see the use of the *must*
statement that prevents ripd from redistributing RIP routes into itself.
Although ripd CLI doesn’t allow the operator to enter *redistribute rip*
under *router rip*, we don’t have the same protection when configuring
ripd using other northbound interfaces (e.g. NETCONF). So without this
constraint it would be possible to feed an invalid configuration to ripd
(i.e. a bug).

.. code:: yang

         list redistribute {
           key "protocol";
           description
             "Redistributes routes learned from other routing protocols.";
           leaf protocol {
             type frr-route-types:frr-route-types-v4;
             description
               "Routing protocol.";
             must '. != "rip"';
           }
           [snip]
         }

In the example below, we use the YANG *choice* statement to ensure that
either the ``password`` leaf or the ``key-chain`` leaf is configured,
but not both. This is in accordance to the sanity checks performed by
the *ip rip authentication* commands.

.. code:: yang

         choice authentication-data {
           description
             "Choose whether to use a simple password or a key-chain.";
           leaf authentication-password {
             type string {
               length "1..16";
             }
             description
               "Authentication string.";
           }
           leaf authentication-key-chain {
             type string;
             description
               "Key-chain name.";
           }
         }

Once finished, the new YANG model should be put into the FRR *yang/* top
level directory. This will ensure it will be installed automatically by
``make install``. It’s also encouraged (but not required) to put sample
configurations under *yang/examples/* using either JSON or XML files.

Step 2: generate skeleton northbound callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the *gen_northbound_callbacks* tool to generate skeleton callbacks
for the YANG module. Example:

.. code:: sh

   $ tools/gen_northbound_callbacks frr-ripd > ripd/rip_northbound.c

The tool will look for the given module in the ``YANG_MODELS_PATH``
directory defined during the installation. For each schema node of the
YANG module, the tool will generate skeleton callbacks based on the
properties of the node. Example:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/instance
    */
   static int ripd_instance_create(enum nb_event event,
                                   const struct lyd_node *dnode,
                                   union nb_resource *resource)
   {
           /* TODO: implement me. */
           return NB_OK;
   }

   static int ripd_instance_delete(enum nb_event event,
                                   const struct lyd_node *dnode)
   {
           /* TODO: implement me. */
           return NB_OK;
   }

   /*
    * XPath: /frr-ripd:ripd/instance/allow-ecmp
    */
   static int ripd_instance_allow_ecmp_modify(enum nb_event event,
                                              const struct lyd_node *dnode,
                                              union nb_resource *resource)
   {
           /* TODO: implement me. */
           return NB_OK;
   }

   [snip]

   const struct frr_yang_module_info frr_ripd_info = {
           .name = "frr-ripd",
           .nodes = {
                   {
                           .xpath = "/frr-ripd:ripd/instance",
                           .cbs.create = ripd_instance_create,
                           .cbs.delete = ripd_instance_delete,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/instance/allow-ecmp",
                           .cbs.modify = ripd_instance_allow_ecmp_modify,
                   },
                   [snip]
                   {
                           .xpath = "/frr-ripd:ripd/state/routes/route",
                           .cbs.get_next = ripd_state_routes_route_get_next,
                           .cbs.get_keys = ripd_state_routes_route_get_keys,
                           .cbs.lookup_entry = ripd_state_routes_route_lookup_entry,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/routes/route/prefix",
                           .cbs.get_elem = ripd_state_routes_route_prefix_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/routes/route/next-hop",
                           .cbs.get_elem = ripd_state_routes_route_next_hop_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/routes/route/interface",
                           .cbs.get_elem = ripd_state_routes_route_interface_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/routes/route/metric",
                           .cbs.get_elem = ripd_state_routes_route_metric_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:clear-rip-route",
                           .cbs.rpc = clear_rip_route_rpc,
                   },
                   [snip]

After the C source file is generated, it’s necessary to add a copyright
header on it and indent the code using ``clang-format``.

Step 3: update the *frr_yang_module_info* array of all relevant daemons
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We must inform the northbound about which daemons will implement the new
YANG module. This is done by updating the ``frr_daemon_info`` structure
of these daemons, with help of the ``FRR_DAEMON_INFO`` macro.

When a YANG module is specific to a single daemon, like the frr-ripd
module, then only the corresponding daemon should be updated. When the
YANG module is related to a subset of libfrr (e.g. route-maps), then all
FRR daemons that make use of that subset must be updated.

Example:

.. code:: c

   static const struct frr_yang_module_info *ripd_yang_modules[] = {
           &frr_interface_info,
           &frr_ripd_info,
   };
    
   FRR_DAEMON_INFO(ripd, RIP, .vty_port = RIP_VTY_PORT,
                   [snip]
                   .yang_modules = ripd_yang_modules,
                   .n_yang_modules = array_size(ripd_yang_modules), )

Step 4: implement the northbound configuration callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementing the northbound configuration callbacks consists mostly of
copying code from the corresponding CLI commands and make the required
adaptations.

It’s recommended to convert one command or a small group of related
commands per commit. Small commits are preferred to facilitate the
review process. Both “old” and “new” command can coexist without
problems, so the retrofitting process can happen gradually over time.

The configuration callbacks
^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are the four main northbound configuration callbacks, as defined
in the ``lib/northbound.h`` file:

.. code:: c

       /*
        * Configuration callback.
        *
        * A presence container, list entry, leaf-list entry or leaf of type
        * empty has been created.
        *
        * For presence-containers and list entries, the callback is supposed to
        * initialize the default values of its children (if any) from the YANG
        * models.
        *
        * event
        *    The transaction phase. Refer to the documentation comments of
        *    nb_event for more details.
        *
        * dnode
        *    libyang data node that is being created.
        *
        * resource
        *    Pointer to store resource(s) allocated during the NB_EV_PREPARE
        *    phase. The same pointer can be used during the NB_EV_ABORT and
        *    NB_EV_APPLY phases to either release or make use of the allocated
        *    resource(s). It's set to NULL when the event is NB_EV_VALIDATE.
        *
        * Returns:
        *    - NB_OK on success.
        *    - NB_ERR_VALIDATION when a validation error occurred.
        *    - NB_ERR_RESOURCE when the callback failed to allocate a resource.
        *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
        *    - NB_ERR for other errors.
        */
       int (*create)(enum nb_event event, const struct lyd_node *dnode,
                 union nb_resource *resource);

       /*
        * Configuration callback.
        *
        * The value of a leaf has been modified.
        *
        * List keys don't need to implement this callback. When a list key is
        * modified, the northbound treats this as if the list was deleted and a
        * new one created with the updated key value.
        *
        * event
        *    The transaction phase. Refer to the documentation comments of
        *    nb_event for more details.
        *
        * dnode
        *    libyang data node that is being modified
        *
        * resource
        *    Pointer to store resource(s) allocated during the NB_EV_PREPARE
        *    phase. The same pointer can be used during the NB_EV_ABORT and
        *    NB_EV_APPLY phases to either release or make use of the allocated
        *    resource(s). It's set to NULL when the event is NB_EV_VALIDATE.
        *
        * Returns:
        *    - NB_OK on success.
        *    - NB_ERR_VALIDATION when a validation error occurred.
        *    - NB_ERR_RESOURCE when the callback failed to allocate a resource.
        *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
        *    - NB_ERR for other errors.
        */
       int (*modify)(enum nb_event event, const struct lyd_node *dnode,
                 union nb_resource *resource);

       /*
        * Configuration callback.
        *
        * A presence container, list entry, leaf-list entry or optional leaf
        * has been deleted.
        *
        * The callback is supposed to delete the entire configuration object,
        * including its children when they exist.
        *
        * event
        *    The transaction phase. Refer to the documentation comments of
        *    nb_event for more details.
        *
        * dnode
        *    libyang data node that is being deleted.
        *
        * Returns:
        *    - NB_OK on success.
        *    - NB_ERR_VALIDATION when a validation error occurred.
        *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
        *    - NB_ERR for other errors.
        */
       int (*delete)(enum nb_event event, const struct lyd_node *dnode);

       /*
        * Configuration callback.
        *
        * A list entry or leaf-list entry has been moved. Only applicable when
        * the "ordered-by user" statement is present.
        *
        * event
        *    The transaction phase. Refer to the documentation comments of
        *    nb_event for more details.
        *
        * dnode
        *    libyang data node that is being moved.
        *
        * Returns:
        *    - NB_OK on success.
        *    - NB_ERR_VALIDATION when a validation error occurred.
        *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
        *    - NB_ERR for other errors.
        */
       int (*move)(enum nb_event event, const struct lyd_node *dnode);

Since skeleton northbound callbacks are generated automatically by the
*gen_northbound_callbacks* tool, the developer doesn’t need to worry
about which callbacks need to be implemented.

   NOTE: once a daemon starts, it reads its YANG modules and validates
   that all required northbound callbacks were implemented. If any
   northbound callback is missing, an error is logged and the program
   exists.

Transaction phases
^^^^^^^^^^^^^^^^^^

Configuration transactions and their phases were described in detail in
the [[Architecture]] page. Here’s the definition of the ``nb_event``
enumeration as defined in the *lib/northbound.h* file:

.. code:: c

   /* Northbound events. */
   enum nb_event {
           /*
            * The configuration callback is supposed to verify that the changes are
            * valid and can be applied.
            */
           NB_EV_VALIDATE,

           /*
            * The configuration callback is supposed to prepare all resources
            * required to apply the changes.
            */
           NB_EV_PREPARE,

           /*
            * Transaction has failed, the configuration callback needs to release
            * all resources previously allocated.
            */
           NB_EV_ABORT,

           /*
            * The configuration changes need to be applied. The changes can't be
            * rejected at this point (errors are logged and ignored).
            */
           NB_EV_APPLY,
   };

When converting a CLI command, we must identify all error-prone
operations and perform them in the ``NB_EV_PREPARE`` phase of the
northbound callbacks. When the operation in question involves the
allocation of a specific resource (e.g. file descriptors), we can store
the allocated resource in the ``resource`` variable given to the
callback. This way the allocated resource can be obtained in the other
phases of the transaction using the same parameter.

Here’s the ``create`` northbound callback associated to the
``router rip`` command:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/instance
    */
   static int ripd_instance_create(enum nb_event event,
                                   const struct lyd_node *dnode,
                                   union nb_resource *resource)
   {
           int socket;

           switch (event) {
           case NB_EV_VALIDATE:
                   break;
           case NB_EV_PREPARE:
                   socket = rip_create_socket();
                   if (socket < 0)
                           return NB_ERR_RESOURCE;
                   resource->fd = socket;
                   break;
           case NB_EV_ABORT:
                   socket = resource->fd;
                   close(socket);
                   break;
           case NB_EV_APPLY:
                   socket = resource->fd;
                   rip_create(socket);
                   break;
           }

           return NB_OK;
   }

Note that the socket creation is an error-prone operation since it
depends on the underlying operating system, so the socket must be
created during the ``NB_EV_PREPARE`` phase and stored in
``resource->fd``. This socket is then either closed or used depending on
the outcome of the preparation phase of the whole transaction.

During the ``NB_EV_VALIDATE`` phase, the northbound callbacks must
validate if the intended changes are valid. As an example, FRR doesn’t
allow the operator to deconfigure active interfaces:

.. code:: c

   static int lib_interface_delete(enum nb_event event,
                                   const struct lyd_node *dnode)
   {
           struct interface *ifp;

           ifp = yang_dnode_get_entry(dnode);

           switch (event) {
           case NB_EV_VALIDATE:
                   if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
                           zlog_warn("%s: only inactive interfaces can be deleted",
                                     __func__);
                           return NB_ERR_VALIDATION;
                   }
                   break;
           case NB_EV_PREPARE:
           case NB_EV_ABORT:
                   break;
           case NB_EV_APPLY:
                   if_delete(ifp);
                   break;
           }

           return NB_OK;
   }

Note however that it’s preferred to use YANG to model the validation
constraints whenever possible. Code-level validations should be used
only to validate constraints that can’t be modeled using the YANG
language.

Most callbacks don’t need to perform any validations nor perform any
error-prone operations, so in these cases we can use the following
pattern to return early if ``event`` is different than ``NB_EV_APPLY``:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/instance/distance/default
    */
   static int ripd_instance_distance_default_modify(enum nb_event event,
                                                    const struct lyd_node *dnode,
                                                    union nb_resource *resource)
   {
           if (event != NB_EV_APPLY)
                   return NB_OK;

           rip->distance = yang_dnode_get_uint8(dnode, NULL);

           return NB_OK;
   }

During development it’s recommend to use the *debug northbound* command
to debug configuration transactions and see what callbacks are being
called. Example:

::

   ripd# conf t
   ripd(config)# debug northbound
   ripd(config)# router rip
   ripd(config-router)# allow-ecmp
   ripd(config-router)# network eth0
   ripd(config-router)# redistribute ospf metric 2
   ripd(config-router)# commit
   % Configuration committed successfully.

   ripd(config-router)#

Now the ripd log:

::

   2018/09/23 12:43:59 RIP: northbound callback: event [validate] op [create] xpath [/frr-ripd:ripd/instance] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [validate] op [modify] xpath [/frr-ripd:ripd/instance/allow-ecmp] value [true]
   2018/09/23 12:43:59 RIP: northbound callback: event [validate] op [create] xpath [/frr-ripd:ripd/instance/interface[.='eth0']] value [eth0]
   2018/09/23 12:43:59 RIP: northbound callback: event [validate] op [create] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [validate] op [modify] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']/metric] value [2]
   2018/09/23 12:43:59 RIP: northbound callback: event [prepare] op [create] xpath [/frr-ripd:ripd/instance] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [prepare] op [modify] xpath [/frr-ripd:ripd/instance/allow-ecmp] value [true]
   2018/09/23 12:43:59 RIP: northbound callback: event [prepare] op [create] xpath [/frr-ripd:ripd/instance/interface[.='eth0']] value [eth0]
   2018/09/23 12:43:59 RIP: northbound callback: event [prepare] op [create] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [prepare] op [modify] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']/metric] value [2]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [create] xpath [/frr-ripd:ripd/instance] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [modify] xpath [/frr-ripd:ripd/instance/allow-ecmp] value [true]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [create] xpath [/frr-ripd:ripd/instance/interface[.='eth0']] value [eth0]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [create] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']] value [(none)]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [modify] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']/metric] value [2]
   2018/09/23 12:43:59 RIP: northbound callback: event [apply] op [apply_finish] xpath [/frr-ripd:ripd/instance/redistribute[protocol='ospf']] value [(null)]

Getting the data
^^^^^^^^^^^^^^^^

One parameter that is common to all northbound configuration callbacks
is the ``dnode`` parameter. This is a libyang data node structure that
contains information relative to the configuration change that is being
performed. For ``create`` callbacks, it contains the configuration node
that is being added. For ``delete`` callbacks, it contains the
configuration node that is being deleted. For ``modify`` callbacks, it
contains the configuration node that is being modified.

In order to get the actual data value out of the ``dnode`` variable, we
need to use the ``yang_dnode_get_*()`` wrappers documented in
*lib/yang_wrappers.h*.

The advantage of passing a ``dnode`` structure to the northbound
callbacks is that the whole candidate being committed is made available,
so the callbacks can obtain values from other portions of the
configuration if necessary. This can be done by providing an xpath
expression to the second parameter of the ``yang_dnode_get_*()``
wrappers to specify the element we want to get. The example below shows
a callback that gets the values of two leaves that are part of the same
list entry:

.. code:: c

   static int
   ripd_instance_redistribute_metric_modify(enum nb_event event,
                                            const struct lyd_node *dnode,
                                            union nb_resource *resource)
   {
           int type;
           uint8_t metric;

           if (event != NB_EV_APPLY)
                   return NB_OK;

           type = yang_dnode_get_enum(dnode, "../protocol");
           metric = yang_dnode_get_uint8(dnode, NULL);

           rip->route_map[type].metric_config = true;
           rip->route_map[type].metric = metric;
           rip_redistribute_conf_update(type);

           return NB_OK;
   }

..

   NOTE: if the wrong ``yang_dnode_get_*()`` wrapper is used, the code
   will log an error and abort. An example would be using
   ``yang_dnode_get_enum()`` to get the value of a boolean data node.

No need to check if the configuration value has changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A common pattern in CLI commands is this:

.. code:: c

   DEFUN (...)
   {
           [snip]
           if (new_value == old_value)
                   return CMD_SUCCESS;
           [snip]
   }

Several commands need to check if the new value entered by the user is
the same as the one currently configured. Then, if yes, ignore the
command since nothing was changed.

The northbound callbacks on the other hand don’t need to perform this
check since they act on effective configuration changes. Using the CLI
as an example, if the operator enters the same command multiple times,
the northbound layer will detect that nothing has changed in the
configuration and will avoid calling the northbound callbacks
unnecessarily.

In some cases, however, it might be desirable to check for
inconsistencies and notify the northbound when that happens:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/instance/interface
    */
   static int ripd_instance_interface_create(enum nb_event event,
                                             const struct lyd_node *dnode,
                                             union nb_resource *resource)
   {
           const char *ifname;

           if (event != NB_EV_APPLY)
                   return NB_OK;

           ifname = yang_dnode_get_string(dnode, NULL);

           return rip_enable_if_add(ifname);
   }

.. code:: c

   /* Add interface to rip_enable_if. */
   int rip_enable_if_add(const char *ifname)
   {
           int ret;

           ret = rip_enable_if_lookup(ifname);
           if (ret >= 0)
                   return NB_ERR_INCONSISTENCY;

           vector_set(rip_enable_interface,
                      XSTRDUP(MTYPE_RIP_INTERFACE_STRING, ifname));

           rip_enable_apply_all(); /* TODOVJ */

           return NB_OK;
   }

In the example above, the ``rip_enable_if_add()`` function should never
return ``NB_ERR_INCONSISTENCY`` in normal conditions. This is because
the northbound layer guarantees that the same interface will never be
added more than once (except when it’s removed and re-added again). But
to be on the safe side it’s probably wise to check for internal
inconsistencies to ensure everything is working as expected.

Default values
^^^^^^^^^^^^^^

Whenever creating a new presence-container or list entry, it’s usually
necessary to initialize certain variables to their default values. FRR
most of the time uses special constants for that purpose
(e.g. ``RIP_DEFAULT_METRIC_DEFAULT``, ``DFLT_BGP_HOLDTIME``, etc). Now
that we have YANG models, we want to fetch the default values from these
models instead. This will allow us to changes default values smoothly
without needing to touch the code. Better yet, it will allow users to
create YANG deviations to define custom default values easily.

To fetch default values from the loaded YANG models, use the
``yang_get_default_*()`` wrapper functions
(e.g. ``yang_get_default_bool()``) documented in *lib/yang_wrappers.h*.

Example:

.. code:: c

   int rip_create(int socket)
   {
           rip = XCALLOC(MTYPE_RIP, sizeof(struct rip));

           /* Set initial values. */
           rip->ecmp = yang_get_default_bool("%s/allow-ecmp", RIP_INSTANCE);
           rip->default_metric =
                   yang_get_default_uint8("%s/default-metric", RIP_INSTANCE);
           [snip]
   }

Configuration options are edited individually
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Several CLI commands edit multiple configuration options at the same
time. Some examples taken from ripd:

* ``timers basic (5-2147483647) (5-2147483647) (5-2147483647)``
  * */frr-ripd:ripd/instance/timers/flush-interval*
  * */frr-ripd:ripd/instance/timers/holddown-interval*
  * */frr-ripd:ripd/instance/timers/update-interval*

* ``distance (1-255) A.B.C.D/M [WORD]``
  * */frr-ripd:ripd/instance/distance/source/prefix*
  * */frr-ripd:ripd/instance/distance/source/distance*
  * */frr-ripd:ripd/instance/distance/source/access-list*

In the new northbound model, there’s one or more separate callbacks for
each configuration option. This usually has implications when converting
code from CLI commands to the northbound commands. An example of this is
the following commit from ripd:
`7cf2f2eaf <https://github.com/opensourcerouting/frr/commit/7cf2f2eaf43ef5df294625d1ab4c708db8293510>`__.
The ``rip_distance_set()`` and ``rip_distance_unset()`` functions were
torn apart and their code split into a few different callbacks.

For lists and presence-containers, it’s possible to use the
``yang_dnode_set_entry()`` function to attach user data to a libyang
data node, and then retrieve this value in the other callbacks (for the
same node or any of its children) using the ``yang_dnode_get_entry()``
function. Example:

.. code:: c

   static int ripd_instance_distance_source_create(enum nb_event event,
                                                   const struct lyd_node *dnode,
                                                   union nb_resource *resource)
   {
           struct prefix_ipv4 prefix;
           struct route_node *rn;

           if (event != NB_EV_APPLY)
                   return NB_OK;

           yang_dnode_get_ipv4p(&prefix, dnode, "./prefix");

           /* Get RIP distance node. */
           rn = route_node_get(rip_distance_table, (struct prefix *)&prefix);
           rn->info = rip_distance_new();
           yang_dnode_set_entry(dnode, rn);

           return NB_OK;
   }

.. code:: c

   static int
   ripd_instance_distance_source_distance_modify(enum nb_event event,
                                                 const struct lyd_node *dnode,
                                                 union nb_resource *resource)
   {
           struct route_node *rn;
           uint8_t distance;
           struct rip_distance *rdistance;

           if (event != NB_EV_APPLY)
                   return NB_OK;

           /* Set distance value. */
           rn = yang_dnode_get_entry(dnode);
           distance = yang_dnode_get_uint8(dnode, NULL);
           rdistance = rn->info;
           rdistance->distance = distance;

           return NB_OK;
   }

Commands that edit multiple configuration options at the same time can
also use the ``apply_finish`` optional callback, documented as follows
in the *lib/northbound.h* file:

.. code:: c

       /*
        * Optional configuration callback for YANG lists and containers.
        *
        * The 'apply_finish' callbacks are called after all other callbacks
        * during the apply phase (NB_EV_APPLY). These callbacks are called only
        * under one of the following two cases:
        * * The container or a list entry has been created;
        * * Any change is made within the descendants of the list entry or
        *   container (e.g. a child leaf was modified, created or deleted).
        *
        * This callback is useful in the cases where a single event should be
        * triggered regardless if the container or list entry was changed once
        * or multiple times.
        *
        * dnode
        *    libyang data node from the YANG list or container.
        */
       void (*apply_finish)(const struct lyd_node *dnode);

Here’s an example of how this callback can be used:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/instance/timers/
    */
   static void ripd_instance_timers_apply_finish(const struct lyd_node *dnode)
   {
           /* Reset update timer thread. */
           rip_event(RIP_UPDATE_EVENT, 0);
   }

.. code:: c

                   {
                           .xpath = "/frr-ripd:ripd/instance/timers",
                           .cbs.apply_finish = ripd_instance_timers_apply_finish,
                           .cbs.cli_show = cli_show_rip_timers,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/instance/timers/flush-interval",
                           .cbs.modify = ripd_instance_timers_flush_interval_modify,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/instance/timers/holddown-interval",
                           .cbs.modify = ripd_instance_timers_holddown_interval_modify,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/instance/timers/update-interval",
                           .cbs.modify = ripd_instance_timers_update_interval_modify,
                   },

In this example, we want to call the ``rip_event()`` function only once
regardless if all RIP timers were modified or only one of them. Without
the ``apply_finish`` callback we’d need to call ``rip_event()`` in the
``modify`` callback of each timer (a YANG leaf), resulting in redundant
call to the ``rip_event()`` function if multiple timers are changed at
once.

Bonus: libyang user types
^^^^^^^^^^^^^^^^^^^^^^^^^

When writing YANG modules, it’s advisable to create derived types for
data types that are used on multiple places (e.g. MAC addresses, IS-IS
networks, etc). Here’s how `RFC
7950 <https://tools.ietf.org/html/rfc7950#page-25>`__ defines derived
types: > YANG can define derived types from base types using the
“typedef” > statement. A base type can be either a built-in type or a
derived > type, allowing a hierarchy of derived types. > > A derived
type can be used as the argument for the “type” statement. > > YANG
Example: > > typedef percent { > type uint8 { > range “0 .. 100”; > } >
} > > leaf completed { > type percent; > }

Derived types are essentially built-in types with imposed restrictions.
As an example, the ``ipv4-address`` derived type from IETF is defined
using the ``string`` built-in type with a ``pattern`` constraint (a
regular expression):

::

      typedef ipv4-address {
        type string {
          pattern
            '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}'
          +  '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
          + '(%[\p{N}\p{L}]+)?';
        }
        description
          "The ipv4-address type represents an IPv4 address in
           dotted-quad notation.  The IPv4 address may include a zone
           index, separated by a % sign.

           The zone index is used to disambiguate identical address
           values.  For link-local addresses, the zone index will
           typically be the interface index number or the name of an
           interface.  If the zone index is not present, the default
           zone of the device will be used.

           The canonical format for the zone index is the numerical
           format";
      }

Sometimes, however, it’s desirable to have a binary representation of
the derived type that is different from the associated built-in type.
Taking the ``ipv4-address`` example above, it would be more convenient
to manipulate this YANG type using ``in_addr`` structures instead of
strings. libyang allow us to do that using the user types plugin:
https://netopeer.liberouter.org/doc/libyang/master/howtoschemaplugins.html#usertypes

Here’s how the the ``ipv4-address`` derived type is implemented in FRR
(*yang/libyang_plugins/frr_user_types.c*):

.. code:: c

   static int ipv4_address_store_clb(const char *type_name, const char *value_str,
                                     lyd_val *value, char **err_msg)
   {
           value->ptr = malloc(sizeof(struct in_addr));
           if (!value->ptr)
                   return 1;

           if (inet_pton(AF_INET, value_str, value->ptr) != 1) {
                   free(value->ptr);
                   return 1;
           }

           return 0;
   }

.. code:: c

   struct lytype_plugin_list frr_user_types[] = {
           {"ietf-inet-types", "2013-07-15", "ipv4-address",
            ipv4_address_store_clb, free},
           {"ietf-inet-types", "2013-07-15", "ipv4-address-no-zone",
            ipv4_address_store_clb, free},
           [snip]
           {NULL, NULL, NULL, NULL, NULL} /* terminating item */
   };

Now, in addition to the string representation of the data value, libyang
will also store the data in the binary format we specified (an
``in_addr`` structure).

Whenever a new derived type is implemented in FRR, it’s also recommended
to write new wrappers in the *lib/yang_wrappers.c* file
(e.g. ``yang_dnode_get_ipv4()``, ``yang_get_default_ipv4()``, etc).

Step 5: rewrite the CLI commands as dumb wrappers around the northbound callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the northbound callbacks are implemented, we need to rewrite the
associated CLI commands on top of the northbound layer. This is the
easiest part of the retrofitting process.

For protocol daemons, it’s recommended to put all CLI commands on a
separate C file (e.g. *ripd/rip_cli.c*). This helps to keep the code
more clean by separating the main protocol code from the user interface.
It should also help when moving the CLI to a separate program in the
future.

For libfrr commands, it’s not possible to centralize all commands in a
single file because the *extract.pl* script from *vtysh* treats commands
differently depending on the file in which they are defined (e.g. DEFUNs
from *lib/routemap.c* are installed using the ``VTYSH_RMAP_SHOW`` constant,
which identifies the daemons that support route-maps). In this case, the
CLI commands should be rewritten but maintained in the same file.

Since all CLI configuration commands from FRR will need to be rewritten,
this is an excellent opportunity to rework this part of the code to make
the commands easier to maintain and extend. These are the three main
recommendations:

#. Always use DEFPY instead of DEFUN to improve code readability
#. Always try to join multiple DEFUNs into a single DEFPY whenever possible. As
   an example, there’s no need to have both ``distance (1-255) A.B.C.D/M`` and
   ``distance (1-255) A.B.C.D/M WORD`` when a single ``distance (1-255)
   A.B.C.D/M [WORD]`` would suffice.
#. When making a negative form of a command, put ``[no]`` in the positive form
   and use ``![...]`` to mark portions of the command that should be optional
   only in the ``no`` version.

To rewrite a CLI command as a dumb wrapper around the northbound
callbacks, use the ``nb_cli_cfg_change()`` function. This function
accepts as a parameter an array of ``cli_config_change`` structures that
specify the changes that need to performed on the candidate
configuration. Here’s the declaration of this structure (taken from the
``lib/northbound_cli.h`` file):

.. code:: c

   struct cli_config_change {
           /*
            * XPath (absolute or relative) of the configuration option being
            * edited.
            */
           char xpath[XPATH_MAXLEN];

           /*
            * Operation to apply (either NB_OP_CREATE, NB_OP_MODIFY or
            * NB_OP_DESTROY).
            */
           enum nb_operation operation;

           /*
            * New value of the configuration option. Should be NULL for typeless
            * YANG data (e.g. presence-containers). For convenience, NULL can also
            * be used to restore a leaf to its default value.
            */
           const char *value;
   };

The ``nb_cli_cfg_change()`` function positions the CLI command on top on
top of the northbound layer. Instead of changing the running
configuration directly, this function changes the candidate
configuration instead, as described in the [[Transactional CLI]] page.
When the transactional CLI is not in use (i.e. the default mode), then
``nb_cli_cfg_change()`` performs an implicit ``commit`` operation after
changing the candidate configuration.

   NOTE: the ``nb_cli_cfg_change()`` function clones the candidate
   configuration before actually editing it. This way, if any error
   happens during the editing, the original candidate is restored to
   avoid inconsistencies. Either all changes from the configuration
   command are performed successfully or none are. It’s like a
   mini-transaction but happening on the candidate configuration (thus
   the northbound callbacks are not involved).

Other important details to keep in mind while rewriting the CLI
commands:

* ``nb_cli_cfg_change()`` returns CLI errors codes (e.g. ``CMD_SUCCESS``,
  ``CMD_WARNING``), so the return value of this function can be used as the
  return value of CLI commands.

* Calls to ``VTY_PUSH_CONTEXT`` and ``VTY_PUSH_CONTEXT_SUB`` should be converted
  to calls to ``VTY_PUSH_XPATH``. Similarly, the following macros aren’t
  necessary anymore and can be removed:

  * ``VTY_DECLVAR_CONTEXT``
  * ``VTY_DECLVAR_CONTEXT_SUB``
  * ``VTY_GET_CONTEXT``
  * ``VTY_CHECK_CONTEXT``.

  The ``nb_cli_cfg_change()`` functions uses the ``VTY_CHECK_XPATH`` macro to
  check if the data node being edited still exists before doing anything else.

The examples below provide additional details about how the conversion
should be done.

Example 1
^^^^^^^^^

In this first example, the *router rip* command becomes a dumb wrapper
around the ``ripd_instance_create()`` callback. Note that we don’t need
to check if the ``/frr-ripd:ripd/instance`` data path already exists
before trying to create it. The northbound will detect when this
presence-container already exists and do nothing. The
``VTY_PUSH_XPATH()`` macro is used to change the vty node and set the
context for other commands under *router rip*.

.. code:: c

   DEFPY_NOSH (router_rip,
          router_rip_cmd,
          "router rip",
          "Enable a routing process\n"
          "Routing Information Protocol (RIP)\n")
   {
           int ret;

           struct cli_config_change changes[] = {
                   {
                           .xpath = "/frr-ripd:ripd/instance",
                           .operation = NB_OP_CREATE,
                           .value = NULL,
                   },
           };

           ret = nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
           if (ret == CMD_SUCCESS)
                   VTY_PUSH_XPATH(RIP_NODE, changes[0].xpath);

           return ret;
   }

Example 2
^^^^^^^^^

Here we can see the use of relative xpaths (starting with ``./``), which
are more convenient that absolute xpaths (which would be
``/frr-ripd:ripd/instance/default-metric`` in this example). This is
possible because the use of ``VTY_PUSH_XPATH()`` in the *router rip*
command set the vty base xpath to ``/frr-ripd:ripd/instance``.

.. code:: c

   DEFPY (rip_default_metric,
          rip_default_metric_cmd,
          "default-metric (1-16)",
          "Set a metric of redistribute routes\n"
          "Default metric\n")
   {
           struct cli_config_change changes[] = {
                   {
                           .xpath = "./default-metric",
                           .operation = NB_OP_MODIFY,
                           .value = default_metric_str,
                   },
           };

           return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
   }

In the command below we the ``value`` to NULL to indicate that we want
to set this leaf to its default value. This is better than hardcoding
the default value because the default might change in the future. Also,
users might define custom defaults by using YANG deviations, so it’s
better to write code that works correctly regardless of the default
values defined in the YANG models.

.. code:: c

   DEFPY (no_rip_default_metric,
          no_rip_default_metric_cmd,
          "no default-metric [(1-16)]",
          NO_STR
          "Set a metric of redistribute routes\n"
          "Default metric\n")
   {
           struct cli_config_change changes[] = {
                   {
                           .xpath = "./default-metric",
                           .operation = NB_OP_MODIFY,
                           .value = NULL,
                   },
           };

           return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
   }

Example 3
^^^^^^^^^

This example shows how one command can change multiple leaves at the
same time.

.. code:: c

   DEFPY (rip_timers,
          rip_timers_cmd,
          "timers basic (5-2147483647)$update (5-2147483647)$timeout (5-2147483647)$garbage",
          "Adjust routing timers\n"
          "Basic routing protocol update timers\n"
          "Routing table update timer value in second. Default is 30.\n"
          "Routing information timeout timer. Default is 180.\n"
          "Garbage collection timer. Default is 120.\n")
   {
           struct cli_config_change changes[] = {
                   {
                           .xpath = "./timers/update-interval",
                           .operation = NB_OP_MODIFY,
                           .value = update_str,
                   },
                   {
                           .xpath = "./timers/holddown-interval",
                           .operation = NB_OP_MODIFY,
                           .value = timeout_str,
                   },
                   {
                           .xpath = "./timers/flush-interval",
                           .operation = NB_OP_MODIFY,
                           .value = garbage_str,
                   },
           };

           return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
   }

Example 4
^^^^^^^^^

This example shows how to create a list entry:

.. code:: c

   DEFPY (rip_distance_source,
          rip_distance_source_cmd,
          "distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
          "Administrative distance\n"
          "Distance value\n"
          "IP source prefix\n"
          "Access list name\n")
   {
           char xpath_list[XPATH_MAXLEN];
           struct cli_config_change changes[] = {
                   {
                           .xpath = ".",
                           .operation = NB_OP_CREATE,
                   },
                   {
                           .xpath = "./distance",
                           .operation = NB_OP_MODIFY,
                           .value = distance_str,
                   },
                   {
                           .xpath = "./access-list",
                           .operation = acl ? NB_OP_MODIFY : NB_OP_DESTROY,
                           .value = acl,
                   },
           };

           snprintf(xpath_list, sizeof(xpath_list), "./distance/source[prefix='%s']",
                    prefix_str);

           return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
   }

The ``xpath_list`` variable is used to hold the xpath that identifies
the list entry. The keys of the list entry should be embedded in this
xpath and don’t need to be part of the array of configuration changes.
All entries from the ``changes`` array use relative xpaths which are
based on the xpath of the list entry.

The ``access-list`` optional leaf can be either modified or deleted
depending whether the optional *WORD* parameter is present or not.

When deleting a list entry, all non-key leaves can be ignored:

.. code:: c

   DEFPY (no_rip_distance_source,
          no_rip_distance_source_cmd,
          "no distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
          NO_STR
          "Administrative distance\n"
          "Distance value\n"
          "IP source prefix\n"
          "Access list name\n")
   {
           char xpath_list[XPATH_MAXLEN];
           struct cli_config_change changes[] = {
                   {
                           .xpath = ".",
                           .operation = NB_OP_DESTROY,
                   },
           };

           snprintf(xpath_list, sizeof(xpath_list), "./distance/source[prefix='%s']",
                    prefix_str);

           return nb_cli_cfg_change(vty, xpath_list, changes, 1);
   }

Example 5
^^^^^^^^^

This example shows a DEFPY statement that performs two validations
before calling ``nb_cli_cfg_change()``:

.. code:: c

   DEFPY (ip_rip_authentication_string,
          ip_rip_authentication_string_cmd,
          "ip rip authentication string LINE$password",
          IP_STR
          "Routing Information Protocol\n"
          "Authentication control\n"
          "Authentication string\n"
          "Authentication string\n")
   {
           struct cli_config_change changes[] = {
                   {
                           .xpath = "./frr-ripd:rip/authentication/password",
                           .operation = NB_OP_MODIFY,
                           .value = password,
                   },
           };      
           
           if (strlen(password) > 16) {
                   vty_out(vty,
                           "%% RIPv2 authentication string must be shorter than 16\n");
                   return CMD_WARNING_CONFIG_FAILED;
           }
                                       
           if (yang_dnode_exists(vty->candidate_config->dnode, "%s%s",
                                 VTY_GET_XPATH,
                                 "/frr-ripd:rip/authentication/key-chain")) {
                   vty_out(vty, "%% key-chain configuration exists\n");
                   return CMD_WARNING_CONFIG_FAILED;
           }

           return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
   }       

These two validations are not strictly necessary since the configuration
change is validated using libyang afterwards. The issue with the libyang
validation is that the error messages from libyang are too verbose:

::

   ripd# conf t
   ripd(config)# interface eth0
   ripd(config-if)# ip rip authentication string XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   % Failed to edit candidate configuration.

   Value "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" does not satisfy the constraint "1..16" (range, length, or pattern).
   Failed to create node "authentication-password" as a child of "rip".
   YANG path: /frr-interface:lib/interface[name='eth0'][vrf='Default-IP-Routing-Table']/frr-ripd:rip/authentication-password

On the other hand, the original error message from ripd is much cleaner:

::

   ripd# conf t
   ripd(config)# interface eth0
   ripd(config-if)# ip rip authentication string XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   % RIPv2 authentication string must be shorter than 16

The second validation is a bit more complex. If we try to create the
``authentication/password`` leaf when the ``authentication/key-chain``
leaf already exists (both are under a YANG *choice* statement), libyang
will automatically delete the ``authentication/key-chain`` and create
``authentication/password`` on its place. This is different from the
original ripd behavior where the *ip rip authentication key-chain*
command must be removed before configuring the *ip rip authentication
string* command.

In the spirit of not introducing any backward-incompatible changes in
the CLI, converted commands should retain some of their validation
checks to preserve their original behavior.

Step 6: implement the ``cli_show`` callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The traditional method used by FRR to display the running configuration
consists of looping through all CLI nodes all call their ``func``
callbacks one by one, which in turn read the configuration from internal
variables and dump them to the terminal in the form of CLI commands.

The problem with this approach is twofold. First, since the callbacks
read the configuration from internal variables, they can’t display
anything other than the running configuration. Second, they don’t have
the ability to display default values when requested by the user
(e.g. *show configuration candidate with-defaults*).

The new northbound architecture solves these problems by introducing a
new callback: ``cli_show``. Here’s the signature of this function (taken
from the *lib/northbound.h* file):

.. code:: c

           /*
            * Optional callback to show the CLI command associated to the given
            * YANG data node.
            *
            * vty
            *    the vty terminal to dump the configuration to
            *
            * dnode
            *    libyang data node that should be shown in the form of a CLI
            *    command
            *
            * show_defaults
            *    specify whether to display default configuration values or not.
            *    This parameter can be ignored most of the time since the
            *    northbound doesn't call this callback for default leaves or
            *    non-presence containers that contain only default child nodes.
            *    The exception are commands associated to multiple configuration
            *    options, in which case it might be desirable to hide one or more
            *    parts of the command when this parameter is set to false.
            */
           void (*cli_show)(struct vty *vty, struct lyd_node *dnode,
                            bool show_defaults);

One of the main differences to the old CLI ``func`` callbacks is that
the ``cli_show`` callbacks are associated to YANG data paths and not to
CLI nodes. This means we can define one separate callback for each CLI
command, making the code more modular and easier to maintain (among
other advantages that will be more clear later). For enhanced code
readability, it’s recommended to position the ``cli_show`` callbacks
immediately after their associated command definitions (DEFPYs).

The ``cli_show`` callbacks are used by the ``nb_cli_show_config_cmds()``
function to display configurations stored inside ``nb_config``
structures. The configuration being displayed can be anything from the
running configuration (*show configuration running*), a candidate
configuration (*show configuration candidate*) or a rollback
configuration (*show configuration transaction (1-4294967296)*). The
``nb_cli_show_config_cmds()`` function works by iterating over all data
nodes from the given configuration and calling the ``cli_show`` callback
for the nodes where it’s defined. If a list has dozens of entries, the
``cli_show`` callback associated to this list will be called multiple
times with the ``dnode`` parameter pointing to different list entries on
each iteration.

For backward compatibility with the *show running-config* command, we
can’t get rid of the CLI ``func`` callbacks at this point in time.
However, we can make the CLI ``func`` callbacks call the corresponding
``cli_show`` callbacks to avoid code duplication. The
``nb_cli_show_dnode_cmds()`` function can be used for that purpose. Once
the CLI retrofitting process finishes for all FRR daemons, we can remove
the legacy CLI ``func`` callbacks and turn *show running-config* into a
shorthand for *show configuration running*.

Regarding displaying configuration with default values, this is
something that is taken care of by the ``nb_cli_show_config_cmds()``
function itself. When the *show configuration* command is used without
the *with-defaults* option, ``nb_cli_show_config_cmds()`` will skip
calling ``cli_show`` callbacks for data nodes that contain only default
values (e.g. default leaves or non-presence containers that contain only
default child nodes). There are however some exceptional cases where the
implementer of the ``cli_show`` callback should take into consideration
if default values should be displayed or not. This and other concepts
will be explained in more detail in the examples below.

.. _example-1-1:

Example 1
^^^^^^^^^

Command: ``default-metric (1-16)``

YANG representation:

.. code:: yang

         leaf default-metric {
           type uint8 {
             range "1..16";
           }
           default "1";
           description
             "Default metric of redistributed routes.";
         }

Placement of the ``cli_show`` callback:

.. code:: diff

           {
               .xpath = "/frr-ripd:ripd/instance/default-metric",
               .cbs.modify = ripd_instance_default_metric_modify,
   +           .cbs.cli_show = cli_show_rip_default_metric,
           },

Implementation of the ``cli_show`` callback:

.. code:: c

   void cli_show_rip_default_metric(struct vty *vty, struct lyd_node *dnode,
                                    bool show_defaults)
   {
           vty_out(vty, " default-metric %s\n",
                   yang_dnode_get_string(dnode, NULL));
   }

In this first example, the *default-metric* command was modeled using a
YANG leaf, and we added a new ``cli_show`` callback attached to the YANG
path of this leaf.

The callback makes use of the ``yang_dnode_get_string()`` function to
obtain the string value of the configuration option. The following would
also be possible:

.. code:: c

           vty_out(vty, " default-metric %u\n",
                   yang_dnode_get_uint8(dnode, NULL));

Both options are possible because libyang stores both a binary
representation and a textual representation of all values stored in a
data node (``lyd_node``). For simplicity, it’s recommended to always use
``yang_dnode_get_string()`` in the ``cli_show`` callbacks.

.. _example-2-1:

Example 2
^^^^^^^^^

Command: ``router rip``

YANG representation:

.. code:: yang

       container instance {
         presence "Present if the RIP protocol is enabled.";
         description
           "RIP routing instance.";
         [snip]
       }

Placement of the ``cli_show`` callback:

.. code:: diff

           {
               .xpath = "/frr-ripd:ripd/instance",
               .cbs.create = ripd_instance_create,
               .cbs.delete = ripd_instance_delete,
   +           .cbs.cli_show = cli_show_router_rip,
           },

Implementation of the ``cli_show`` callback:

.. code:: c

   void cli_show_router_rip(struct vty *vty, struct lyd_node *dnode,
                            bool show_defaults)
   {
           vty_out(vty, "!\n");
           vty_out(vty, "router rip\n");
   }

In this example, the ``cli_show`` callback doesn’t need to obtain any
value from the ``dnode`` parameter since presence-containers don’t hold
any data (apart from their child nodes, but they have their own
``cli_show`` callbacks).

.. _example-3-1:

Example 3
^^^^^^^^^

Command: ``timers basic (5-2147483647) (5-2147483647) (5-2147483647)``

YANG representation:

.. code:: yang

         container timers {
           description
             "Settings of basic timers";
           leaf flush-interval {
             type uint32 {
               range "5..2147483647";
             }
             units "seconds";
             default "120";
             description
               "Interval before a route is flushed from the routing
                table.";
           }
           leaf holddown-interval {
             type uint32 {
               range "5..2147483647";
             }
             units "seconds";
             default "180";
             description
               "Interval before better routes are released.";
           }
           leaf update-interval {
             type uint32 {
               range "5..2147483647";
             }
             units "seconds";
             default "30";
             description
               "Interval at which RIP updates are sent.";
           }
         }

Placement of the ``cli_show`` callback:

.. code:: diff

           {
   +           .xpath = "/frr-ripd:ripd/instance/timers",
   +           .cbs.cli_show = cli_show_rip_timers,
   +       },
   +       {
               .xpath = "/frr-ripd:ripd/instance/timers/flush-interval",
               .cbs.modify = ripd_instance_timers_flush_interval_modify,
           },
           {
               .xpath = "/frr-ripd:ripd/instance/timers/holddown-interval",
               .cbs.modify = ripd_instance_timers_holddown_interval_modify,
           },
           {
               .xpath = "/frr-ripd:ripd/instance/timers/update-interval",
               .cbs.modify = ripd_instance_timers_update_interval_modify,
           },

Implementation of the ``cli_show`` callback:

.. code:: c

   void cli_show_rip_timers(struct vty *vty, struct lyd_node *dnode,
                            bool show_defaults)
   {
           vty_out(vty, " timers basic %s %s %s\n",
                   yang_dnode_get_string(dnode, "./update-interval"),
                   yang_dnode_get_string(dnode, "./holddown-interval"),
                   yang_dnode_get_string(dnode, "./flush-interval"));
   }

This command is a bit different since it changes three leaves at the
same time. This means we need to have a single ``cli_show`` callback in
order to display the three leaves together in the same line.

The new ``cli_show_rip_timers()`` callback was added attached to the
*timers* non-presence container that groups the three leaves. Without
the *timers* non-presence container we’d need to display the *timers
basic* command inside the ``cli_show_router_rip()`` callback, which
would break our requirement of having a separate ``cli_show`` callback
for each configuration command.

.. _example-4-1:

Example 4
^^^^^^^^^

Command:
``redistribute <kernel|connected|static|ospf|isis|bgp|eigrp|nhrp|table|vnc|babel|sharp> [{metric (0-16)|route-map WORD}]``

YANG representation:

.. code:: yang

         list redistribute {
           key "protocol";
           description
             "Redistributes routes learned from other routing protocols.";
           leaf protocol {
             type frr-route-types:frr-route-types-v4;
             description
               "Routing protocol.";
             must '. != "rip"';
           }
           leaf route-map {
             type string {
               length "1..max";
             }
             description
               "Applies the conditions of the specified route-map to
                routes that are redistributed into the RIP routing
                instance.";
           }
           leaf metric {
             type uint8 {
               range "0..16";
             }
             description
               "Metric used for the redistributed route. If a metric is
                not specified, the metric configured with the
                default-metric attribute in RIP router configuration is
                used. If the default-metric attribute has not been
                configured, the default metric for redistributed routes
                is 0.";
           }
         }

Placement of the ``cli_show`` callback:

.. code:: diff

           {
               .xpath = "/frr-ripd:ripd/instance/redistribute",
               .cbs.create = ripd_instance_redistribute_create,
               .cbs.delete = ripd_instance_redistribute_delete,
   +           .cbs.cli_show = cli_show_rip_redistribute,
           },
           {
               .xpath = "/frr-ripd:ripd/instance/redistribute/route-map",
               .cbs.modify = ripd_instance_redistribute_route_map_modify,
               .cbs.delete = ripd_instance_redistribute_route_map_delete,
           },
           {
               .xpath = "/frr-ripd:ripd/instance/redistribute/metric",
               .cbs.modify = ripd_instance_redistribute_metric_modify,
               .cbs.delete = ripd_instance_redistribute_metric_delete,
           },

Implementation of the ``cli_show`` callback:

.. code:: c

   void cli_show_rip_redistribute(struct vty *vty, struct lyd_node *dnode,
                                  bool show_defaults)
   {
           vty_out(vty, " redistribute %s",
                   yang_dnode_get_string(dnode, "./protocol"));
           if (yang_dnode_exists(dnode, "./metric"))
                   vty_out(vty, " metric %s",
                           yang_dnode_get_string(dnode, "./metric"));
           if (yang_dnode_exists(dnode, "./route-map"))
                   vty_out(vty, " route-map %s",
                           yang_dnode_get_string(dnode, "./route-map"));
           vty_out(vty, "\n");
   }

Similar to the previous example, the *redistribute* command changes
several leaves at the same time, and we need a single callback to
display all leaves in a single line in accordance to the CLI command. In
this case, the leaves are already grouped by a YANG list so there’s no
need to add a non-presence container. The new ``cli_show`` callback was
attached to the YANG path of the list.

It’s also worth noting the use of the ``yang_dnode_exists()`` function
to check if optional leaves exist in the configuration before displaying
them.

.. _example-5-1:

Example 5
^^^^^^^^^

Command:
``ip rip authentication mode <md5 [auth-length <rfc|old-ripd>]|text>``

YANG representation:

.. code:: yang

         container authentication-scheme {
           description
             "Specify the authentication scheme for the RIP interface";
           leaf mode {
             type enumeration {
               [snip]
             }
             default "none";
             description
               "Specify the authentication mode.";
           }
           leaf md5-auth-length {
             when "../mode = 'md5'";
             type enumeration {
               [snip]
             }
             default "20";
             description
               "MD5 authentication data length.";
           }
         }

Placement of the ``cli_show`` callback:

.. code:: diff

   +       {
   +           .xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme",
   +           .cbs.cli_show = cli_show_ip_rip_authentication_scheme,
           },
           {
               .xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode",
               .cbs.modify = lib_interface_rip_authentication_scheme_mode_modify,
           },
           {
               .xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length",
               .cbs.modify = lib_interface_rip_authentication_scheme_md5_auth_length_modify,
               .cbs.delete = lib_interface_rip_authentication_scheme_md5_auth_length_delete,
           },

Implementation of the ``cli_show`` callback:

.. code:: c

   void cli_show_ip_rip_authentication_scheme(struct vty *vty,
                                              struct lyd_node *dnode,
                                              bool show_defaults)
   {
           switch (yang_dnode_get_enum(dnode, "./mode")) {
           case RIP_NO_AUTH:
                   vty_out(vty, " no ip rip authentication mode\n");
                   break;
           case RIP_AUTH_SIMPLE_PASSWORD:
                   vty_out(vty, " ip rip authentication mode text\n");
                   break;
           case RIP_AUTH_MD5:
                   vty_out(vty, " ip rip authentication mode md5");
                   if (show_defaults
                       || !yang_dnode_is_default(dnode, "./md5-auth-length")) {
                           if (yang_dnode_get_enum(dnode, "./md5-auth-length")
                               == RIP_AUTH_MD5_SIZE)
                                   vty_out(vty, " auth-length rfc");
                           else
                                   vty_out(vty, " auth-length old-ripd");
                   }
                   vty_out(vty, "\n");
                   break;
           }
   }

This is the most complex ``cli_show`` callback we have in ripd. Its
complexity comes from the following:

* The ``ip rip authentication mode ...`` command changes two YANG leaves at the
  same time.

* Part of the command should be hidden when the ``show_defaults`` parameter is
  set to false.

This is the behavior we want to implement:

::

   ripd(config)# interface eth0
   ripd(config-if)# ip rip authentication mode md5
   ripd(config-if)#
   ripd(config-if)# show configuration candidate
   Configuration:
   !
   [snip]
   !
   interface eth0
    ip rip authentication mode md5
   !
   end
   ripd(config-if)#
   ripd(config-if)# show configuration candidate with-defaults
   Configuration:
   !
   [snip]
   !
   interface eth0
    [snip]
    ip rip authentication mode md5 auth-length old-ripd
   !
   end

Note that ``auth-length old-ripd`` should be hidden unless the
configuration is shown using the *with-defaults* option. This is why the
``cli_show_ip_rip_authentication_scheme()`` callback needs to consult
the value of the *show_defaults* parameter. It’s expected that only a
very small minority of all ``cli_show`` callbacks will need to consult
the *show_defaults* parameter (there’s a chance this might be the only
case!)

In the case of the *timers basic* command seen before, we need to
display the value of all leaves even if only one of them has a value
different from the default. Hence the ``cli_show_rip_timers()`` callback
was able to completely ignore the *show_defaults* parameter.

Step 7: consolidation
~~~~~~~~~~~~~~~~~~~~~

As mentioned in the fourth step, the northbound retrofitting process can
happen gradually over time, since both “old” and “new” commands can
coexist without problems. Once all commands from a given daemon were
converted, we can proceed to the consolidation step, which consists of
the following:

* Remove the vty configuration lock, which is enabled by default in all daemons.
  Now multiple users should be able to edit the configuration concurrently,
  using either shared or private candidate configurations.

* Reference commit: `57dccdb1
  <https://github.com/opensourcerouting/frr/commit/57dccdb18b799556214dcfb8943e248c0bf1f6a6>`__.

* Stop using the qobj infrastructure to keep track of configuration objects.
  This is not necessary anymore, the northbound uses a similar mechanism to keep
  track of YANG data nodes in the candidate configuration.

* Reference commit: `4e6d63ce
  <https://github.com/opensourcerouting/frr/commit/4e6d63cebd988af650c1c29d0f2e5a251c8d2e7a>`__.

* Make the daemon SIGHUP handler re-read the configuration file (and ensure it’s
  not doing anything other than that).

* Reference commit: `5e57edb4
  <https://github.com/opensourcerouting/frr/commit/5e57edb4b71ff03f9a22d9ec1412c3c5167f90cf>`__.

Final Considerations
--------------------

Testing
~~~~~~~

Converting CLI commands to the new northbound model can be a complicated
task for beginners, but the more commands one converts, the easier it
gets. It’s highly recommended to perform as much testing as possible on
the converted commands to reduce the likelihood of introducing
regressions. Tools like topotests, ANVL and the `CLI
fuzzer <https://github.com/rwestphal/frr-cli-fuzzer>`__ can be used to
catch hidden bugs that might be present. As usual, it’s also recommended
to use valgrind and static code analyzers to catch other types of
problems like memory leaks.

Amount of work
~~~~~~~~~~~~~~

The output below gives a rough estimate of the total number of
configuration commands that need to be converted per daemon:

.. code:: sh

   $ for dir in lib zebra bgpd ospfd ospf6d isisd ripd ripngd eigrpd pimd pbrd ldpd nhrpd babeld ; do echo -n "$dir: " && cd $dir && grep -ERn "DEFUN|DEFPY" * | grep -Ev "clippy|show|clear" | wc -l && cd ..; done
   lib: 302
   zebra: 181
   bgpd: 569
   ospfd: 198
   ospf6d: 99
   isisd: 126
   ripd: 64
   ripngd: 44
   eigrpd: 58
   pimd: 113
   pbrd: 9
   ldpd: 46
   nhrpd: 24
   babeld: 28

As it can be seen, the northbound retrofitting process will demand a lot
of work from FRR developers and should take months to complete. Everyone
is welcome to collaborate!
