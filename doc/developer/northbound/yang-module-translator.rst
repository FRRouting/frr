YANG Module Translation
=======================

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 1

Introduction
------------

One key requirement for the FRR northbound architecture is that it
should be possible to configure/monitor FRR using different sets of YANG
models. This is especially important considering that the industry
hasn’t reached a consensus to provide a single source of standard models
for network management. At this moment both the IETF and OpenConfig
models are widely implemented and are unlikely to converge, at least not
in the short term. In the ideal scenario, management applications should
be able to use either IETF or OpenConfig models to configure and monitor
FRR programatically (or even both at the same time!).

But how can FRR support multiple sets of YANG models at the same time?
There must be only a single source of truth that models the existing
implementation accurately (the native models). Writing different code
paths or callbacks for different models would be inviable, it would lead
to a lot of duplicated code and extra maintenance overhead.

In order to support different sets of YANG modules without introducing
the overhead of writing additional code, the solution is to create a
mechanism that dynamically translates YANG instance data between
non-native models to native models and vice-versa. Based on this idea,
an experimental YANG module translator was implemented within the FRR
northbound layer. The translator works by translating XPaths at runtime
using translation tables provided by the user. The translator itself is
modeled using YANG and users can create translators using simple JSON
files.

A YANG module translator consists of two components: deviation modules
and translation tables.

Deviation Modules
-----------------

The first step when writing a YANG module translator is to create a
`deviations <https://tools.ietf.org/html/rfc7950#page-131>`__ module for
each module that is going be translated. This is necessary because in
most cases it won’t be possible to create a perfect translator that
covers the non-native models on their entirety. Some non-native modules
might contain nodes that can’t be mapped to a corresponding node in the
FRR native models. This is either because the corresponding
functionality is not implemented in FRR or because it’s modeled in a
different way that is incompatible.

An an example, *ripd* doesn’t have BFD support yet, so we need to create
a YANG deviation to modify the *ietf-rip* module and remove the ``bfd``
container from it:

.. code:: yang

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:interfaces/ietf-rip:interface/ietf-rip:bfd" {
       deviate not-supported;
     }

In the example below, while both the *frr-ripd* and *ietf-rip* modules
support RIP authentication, they model the authentication data in
different ways, making translation not possible given the constraints of
the current module translator. A new deviation is necessary to remove
the ``authentication`` container from the *ietf-rip* module:

.. code:: yang

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:interfaces/ietf-rip:interface/ietf-rip:authentication" {
       deviate not-supported;
     }

..

   NOTE: it should be possible to translate the
   ``ietf-rip:authentication`` container if the *frr-ripd* module is
   modified to model the corresponding data in a compatible way. Another
   option is to improve the module translator to make more complex
   translations possible, instead of requiring one-to-one XPath
   mappings.

Sometimes creating a mapping between nodes from the native and
non-native models is possible, but the nodes have different properties
that need to be normalized to allow the translation. In the example
below, a YANG deviation is used to change the type and the default value
from a node from the ``ietf-rip`` module.

.. code:: yang

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:timers/ietf-rip:flush-interval" {
       deviate replace {
         default "120";
       }
       deviate replace {
         type uint32;
       }
     }

The deviation modules allow the management applications to know which
parts of the custom modules (e.g. IETF/OC) can be used to configure and
monitor FRR.

In order to facilitate the process of creating YANG deviation modules,
the *gen_yang_deviations* tool was created to automate part of the
process. This tool creates a “not-supported” deviation for all nodes
from the given non-native module. Example:

::

   $ tools/gen_yang_deviations ietf-rip > yang/ietf/frr-deviations-ietf-rip.yang
   $ head -n 40 yang/ietf/frr-deviations-ietf-rip.yang
     deviation "/ietf-rip:clear-rip-route" {
       deviate not-supported;
     }

     deviation "/ietf-rip:clear-rip-route/ietf-rip:input" {
       deviate not-supported;
     }

     deviation "/ietf-rip:clear-rip-route/ietf-rip:input/ietf-rip:rip-instance" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:originate-default-route" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:originate-default-route/ietf-rip:enabled" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:originate-default-route/ietf-rip:route-policy" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:default-metric" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:distance" {
       deviate not-supported;
     }

     deviation "/ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol/ietf-rip:rip/ietf-rip:triggered-update-threshold" {
       deviate not-supported;
     }

Once all existing nodes are listed in the deviation module, it’s easy to
check the deviations that need to be removed or modified. This is more
convenient than starting with a blank deviations module and listing
manually all nodes that need to be deviated.

After removing and/or modifying the auto-generated deviations, the next
step is to write the module XPath translation table as we’ll see in the
next section. Before that, it’s possible to use the *yanglint* tool to
check how the non-native module looks like after applying the
deviations. Example:

::

   $ yanglint -f tree yang/ietf/ietf-rip@2018-02-03.yang yang/ietf/frr-deviations-ietf-rip.yang
   module: ietf-rip

     augment /ietf-routing:routing/ietf-routing:control-plane-protocols/ietf-routing:control-plane-protocol:
       +--rw rip
          +--rw originate-default-route
          |  +--rw enabled?   boolean <false>
          +--rw default-metric?            uint8 <1>
          +--rw distance?                  uint8 <0>
          +--rw timers
          |  +--rw update-interval?     uint32 <30>
          |  +--rw holddown-interval?   uint32 <180>
          |  +--rw flush-interval?      uint32 <120>
          +--rw interfaces
          |  +--rw interface* [interface]
          |     +--rw interface        ietf-interfaces:interface-ref
          |     +--rw split-horizon?   enumeration <simple>
          +--ro ipv4
             +--ro neighbors
             |  +--ro neighbor* [ipv4-address]
             |     +--ro ipv4-address        ietf-inet-types:ipv4-address
             |     +--ro last-update?        ietf-yang-types:date-and-time
             |     +--ro bad-packets-rcvd?   ietf-yang-types:counter32
             |     +--ro bad-routes-rcvd?    ietf-yang-types:counter32
             +--ro routes
                +--ro route* [ipv4-prefix]
                   +--ro ipv4-prefix    ietf-inet-types:ipv4-prefix
                   +--ro next-hop?      ietf-inet-types:ipv4-address
                   +--ro interface?     ietf-interfaces:interface-ref
                   +--ro metric?        uint8

     rpcs:
       +---x clear-rip-route

..

   NOTE: the same output can be obtained using the
   ``show yang module module-translator ietf ietf-rip tree`` command in
   FRR once the *ietf* module translator is loaded.

In the example above, it can be seen that the vast majority of the
*ietf-rip* nodes were removed because of the “not-supported” deviations.
When a module translator is loaded, FRR calculates the coverage of the
translator by dividing the number of YANG nodes before applying the
deviations by the number of YANG nodes after applying the deviations.
The calculated coverage is displayed in the output of the
``show yang module-translator`` command:

::

   ripd# show yang module-translator
    Family  Module           Deviations                      Coverage (%)
    -----------------------------------------------------------------------
    ietf    ietf-interfaces  frr-deviations-ietf-interfaces  3.92
    ietf    ietf-routing     frr-deviations-ietf-routing     1.56
    ietf    ietf-rip         frr-deviations-ietf-rip         13.60

As it can be seen in the output above, the *ietf* module translator
covers only ~13% of the original *ietf-rip* module. This is in part
because the *ietf-rip* module models both RIPv2 and RIPng. Also,
*ietf-rip.yang* contains several knobs that aren’t implemented in *ripd*
yet (e.g. BFD support, per-interface timers, statistics, etc). Work can
be done over time to increase the coverage to a more reasonable number.

Translation Tables
------------------

Below is an example of a translator for the IETF family of models:

.. code:: json

   {
     "frr-module-translator:frr-module-translator": {
       "family": "ietf",
       "module": [
         {
           "name": "ietf-interfaces@2018-01-09",
           "deviations": "frr-deviations-ietf-interfaces",
           "mappings": [
             {
               "custom": "/ietf-interfaces:interfaces/interface[name='KEY1']",
               "native": "/frr-interface:lib/interface[name='KEY1'][vrf='default']"
             },
             {
               "custom": "/ietf-interfaces:interfaces/interface[name='KEY1']/description",
               "native": "/frr-interface:lib/interface[name='KEY1'][vrf='default']/description"
             }
           ]
         },
         {
           "name": "ietf-routing@2018-01-25",
           "deviations": "frr-deviations-ietf-routing",
           "mappings": [
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']",
               "native": "/frr-ripd:ripd/instance"
             }
           ]
         },
         {
           "name": "ietf-rip@2018-02-03",
           "deviations": "frr-deviations-ietf-rip",
           "mappings": [
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/default-metric",
               "native": "/frr-ripd:ripd/instance/default-metric"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/distance",
               "native": "/frr-ripd:ripd/instance/distance/default"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/originate-default-route/enabled",
               "native": "/frr-ripd:ripd/instance/default-information-originate"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/timers/update-interval",
               "native": "/frr-ripd:ripd/instance/timers/update-interval"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/timers/holddown-interval",
               "native": "/frr-ripd:ripd/instance/timers/holddown-interval"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/timers/flush-interval",
               "native": "/frr-ripd:ripd/instance/timers/flush-interval"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/interfaces/interface[interface='KEY1']",
               "native": "/frr-ripd:ripd/instance/interface[.='KEY1']"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/interfaces/interface[interface='KEY1']/split-horizon",
               "native": "/frr-interface:lib/interface[name='KEY1'][vrf='default']/frr-ripd:rip/split-horizon"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/neighbors/neighbor[ipv4-address='KEY1']",
               "native": "/frr-ripd:ripd/state/neighbors/neighbor[address='KEY1']"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/neighbors/neighbor[ipv4-address='KEY1']/last-update",
               "native": "/frr-ripd:ripd/state/neighbors/neighbor[address='KEY1']/last-update"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/neighbors/neighbor[ipv4-address='KEY1']/bad-packets-rcvd",
               "native": "/frr-ripd:ripd/state/neighbors/neighbor[address='KEY1']/bad-packets-rcvd"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/neighbors/neighbor[ipv4-address='KEY1']/bad-routes-rcvd",
               "native": "/frr-ripd:ripd/state/neighbors/neighbor[address='KEY1']/bad-routes-rcvd"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/routes/route[ipv4-prefix='KEY1']",
               "native": "/frr-ripd:ripd/state/routes/route[prefix='KEY1']"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/routes/route[ipv4-prefix='KEY1']/next-hop",
               "native": "/frr-ripd:ripd/state/routes/route[prefix='KEY1']/next-hop"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/routes/route[ipv4-prefix='KEY1']/interface",
               "native": "/frr-ripd:ripd/state/routes/route[prefix='KEY1']/interface"
             },
             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/routes/route[ipv4-prefix='KEY1']/metric",
               "native": "/frr-ripd:ripd/state/routes/route[prefix='KEY1']/metric"
             },
             {
               "custom": "/ietf-rip:clear-rip-route",
               "native": "/frr-ripd:clear-rip-route"
             }
           ]
         }
       ]
     }
   }

The main motivation to use YANG itself to model YANG module translators
was a practical one: leverage *libyang* to validate the structure of the
user input (JSON files) instead of doing that manually in the
*lib/yang_translator.c* file (tedious and error-prone work).

Module translators can be loaded using the following CLI command:

::

   ripd(config)# yang module-translator load /usr/local/share/yang/ietf/frr-ietf-translator.json
   % Module translator "ietf" loaded successfully.

Module translators can also be loaded/unloaded programatically using the
``yang_translator_load()/yang_translator_unload()`` functions within the
northbound plugins. These functions are documented in the
*lib/yang_translator.h* file.

Each module translator must be assigned a “family” identifier
(e.g. IETF, OpenConfig), and can contain mappings for multiple
interrelated YANG modules. The mappings consist of pairs of
custom/native XPath expressions that should be equivalent, despite
belonging to different YANG modules.

Example:

.. code:: json

             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/default-metric",
               "native": "/frr-ripd:ripd/instance/default-metric"
             },

The nodes pointed by the custom and native XPaths must have compatible
types. In the case of the example above, both nodes point to a YANG leaf
of type ``uint8``, so the mapping is valid.

In the example below, the “custom” XPath points to a YANG list
(typeless), and the “native” XPath points to a YANG leaf-list of
strings. In this exceptional case, the types are also considered to be
compatible.

.. code:: json

             {
               "custom": "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip/interfaces/interface[interface='KEY1']",
               "native": "/frr-ripd:ripd/instance/interface[.='KEY1']"
             },

The ``KEY1..KEY4`` values have a special meaning and are used to
preserve the list keys while performing the XPath translation.

Once a YANG module translator is loaded and validated at a syntactic
level using *libyang*, further validations are performed to check for
missing mappings (after loading the deviation modules) and incompatible
YANG types. Example:

::

   ripd(config)# yang module-translator load /usr/local/share/yang/ietf/frr-ietf-translator.json
   % Failed to load "/usr/local/share/yang/ietf/frr-ietf-translator.json"

   Please check the logs for more details.

::

   2018/09/03 15:18:45 RIP: yang_translator_validate_cb: YANG types are incompatible (xpath: "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/default-metric")
   2018/09/03 15:18:45 RIP: yang_translator_validate_cb: missing mapping for "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/distance"
   2018/09/03 15:18:45 RIP: yang_translator_validate: failed to validate "ietf" module translator: 2 error(s)

Overall, this translation mechanism based on XPath mappings is simple
and functional, but only to a certain extent. The native models need to
be reasonably similar to the models that are going be translated,
otherwise the translation is compromised and a good coverage can’t be
achieved. Other translation techniques must be investigated to address
this shortcoming and make it possible to create more powerful YANG
module translators.

YANG module translators can be evaluated based on the following metrics:

* Translation potential: is it possible to make complex translations, taking
  several variables into account?

* Complexity: measure of how easy or hard it is to write a module translator.

* Speed: measure of how fast the translation can be achieved. Translation speed
  is of fundamental importance, especially for operational data.

* Robustness: can the translator be checked for inconsistencies at load time? A
  module translator based on scripts wouldn’t fare well on this metric.

* Round-trip conversions: can the translated data be translated back to the
  original format without information loss?

CLI Demonstration
-----------------

As of now the only northbound client that supports the YANG module
translator is the FRR embedded CLI. The confd and sysrepo plugins need
to be extended to support the module translator, which might be used not
only for configuration data, but also for operational data, RPCs and
notifications.

In this demonstration, we’ll use the CLI ``configuration load`` command
to load the following JSON configuration file specified using the IETF
data hierarchy:

.. code:: json

   {
       "ietf-interfaces:interfaces": {
           "interface": [
               {
                   "description": "Engineering",
                   "name": "eth0"
               }
           ]
       },
       "ietf-routing:routing": {
           "control-plane-protocols": {
               "control-plane-protocol": [
                   {
                       "name": "main",
                       "type": "ietf-rip:ripv2",
                       "ietf-rip:rip": {
                           "default-metric": "2",
                           "distance": "80",
                           "interfaces": {
                               "interface": [
                                   {
                                       "interface": "eth0",
                                       "split-horizon": "poison-reverse"
                                   }
                               ]
                           },
                           "originate-default-route": {
                               "enabled": "true"
                           },
                           "timers": {
                               "flush-interval": "241",
                               "holddown-interval": "181",
                               "update-interval": "31"
                           }
                       }
                   }
               ]
           }
       }
   }

In order to load this configuration file, it’s necessary to load the
IETF module translator first. Then, when entering the
``configuration load`` command, the ``translate ietf`` parameters must
be given to specify that the input needs to be translated using the
previously loaded ``ietf`` module translator. Example:

::

   ripd(config)# configuration load file json /mnt/renato/git/frr/yang/example/ietf-rip.json
   % Failed to load configuration:

   Unknown element "interfaces".
   ripd(config)# 
   ripd(config)# yang module-translator load /usr/local/share/yang/ietf/frr-ietf-translator.json
   % Module translator "ietf" loaded successfully.

   ripd(config)# 
   ripd(config)# configuration load file json translate ietf /mnt/renato/git/frr/yang/example/ietf-rip.json

Now let’s check the candidate configuration to see if the configuration
file was loaded successfully:

::

   ripd(config)# show configuration candidate     
   Configuration:
   !
   frr version 5.1-dev
   frr defaults traditional
   !
   interface eth0
    description Engineering
    ip rip split-horizon poisoned-reverse
   !
   router rip
    default-metric 2
    distance 80
    network eth0
    default-information originate
    timers basic 31 181 241
   !
   end
   ripd(config)# show configuration candidate json
   {
     "frr-interface:lib": {
       "interface": [
         {
           "name": "eth0",
           "vrf": "default",
           "description": "Engineering",
           "frr-ripd:rip": {
             "split-horizon": "poison-reverse"
           }
         }
       ]
     },
     "frr-ripd:ripd": {
       "instance": {
         "default-metric": 2,
         "distance": {
           "default": 80
         },
         "interface": [
           "eth0"
         ],
         "default-information-originate": true,
         "timers": {
           "flush-interval": 241,
           "holddown-interval": 181,
           "update-interval": 31
         }
       }
     }
   }

As it can be seen, the candidate configuration is identical to the one
defined in the *ietf-rip.json* file, only the structure is different.
This means that the *ietf-rip.json* file was translated successfully.

The ``ietf`` module translator can also be used to do the translation in
other direction: transform data from the native format to the IETF
format. This is shown below by altering the output of the
``show configuration candidate json`` command using the
``translate ietf`` parameter:

::

   ripd(config)# show configuration candidate json translate ietf
   {
     "ietf-interfaces:interfaces": {
       "interface": [
         {
           "name": "eth0",
           "description": "Engineering"
         }
       ]
     },
     "ietf-routing:routing": {
       "control-plane-protocols": {
         "control-plane-protocol": [
           {
             "type": "ietf-rip:ripv2",
             "name": "main",
             "ietf-rip:rip": {
               "interfaces": {
                 "interface": [
                   {
                     "interface": "eth0",
                     "split-horizon": "poison-reverse"
                   }
                 ]
               },
               "default-metric": 2,
               "distance": 80,
               "originate-default-route": {
                 "enabled": true
               },
               "timers": {
                 "flush-interval": 241,
                 "holddown-interval": 181,
                 "update-interval": 31
               }
             }
           }
         ]
       }
     }
   }

As expected, this output is exactly identical to the configuration
defined in the *ietf-rip.json* file. The module translator was able to
do a round-trip conversion without information loss.

Implementation Details
----------------------

A different libyang context is allocated for each YANG module
translator. This is important to avoid collisions and ensure that
non-native data can’t be instantiated in the running and candidate
configurations.
