Table of Contents
-----------------

-  `Introduction <#introduction>`__
-  `Configuration modes <#config-modes>`__
-  `New commands <#retrofitting-process>`__

   -  `commit check <#cmd1>`__
   -  `commit <#cmd2>`__
   -  `discard <#cmd3>`__
   -  `configuration database max-transactions <#cmd4>`__
   -  `configuration load <#cmd5>`__
   -  `rollback configuration <#cmd6>`__
   -  `show configuration candidate <#cmd7>`__
   -  `show configuration compare <#cmd8>`__
   -  `show configuration running <#cmd9>`__
   -  `show configuration transaction <#cmd10>`__
   -  `show yang module <#cmd11>`__
   -  `show yang module-translator <#cmd12>`__
   -  `update <#cmd13>`__
   -  `yang module-translator load <#cmd14>`__
   -  `yang module-translator unload <#cmd15>`__

Introduction
~~~~~~~~~~~~

All FRR daemons have built-in support for the CLI, which can be accessed
either through local telnet or via the vty socket (e.g. by using
*vtysh*). This will not change with the introduction of the Northbound
API. However, a new command-line option will be available for all FRR
daemons: ``--tcli``. When given, this option makes the daemon start with
a transactional CLI and configuration commands behave a bit different.
Instead of editing the running configuration, they will edit the
candidate configuration. In other words, the configuration commands
won’t be applied immediately, that has to be done on a separate step
using the new ``commit`` command.

The transactional CLI simply leverages the new capabilities provided by
the Northbound API and exposes the concept of candidate configurations
to CLI users too. When the transactional mode is not used, the
configuration commands also edit the candidate configuration, but
there’s an implicit ``commit`` after each command.

In order for the transactional CLI to work, all configuration commands
need to be converted to the new northbound model. Commands not converted
to the new northbound model will change the running configuration
directly since they bypass the FRR northbound layer. For this reason,
starting a daemon with the transactional CLI is not advisable unless all
of its commands have already been converted. When that’s not the case,
we can run into a situation like this:

::

   ospfd(config)# router ospf
   ospfd(config-router)# ospf router-id 1.1.1.1
   [segfault in ospfd]

The segfault above can happen if ``router ospf`` edits the candidate
configuration but ``ospf router-id 1.1.1.1`` edits the running
configuration. The second command tries to set
``ospf->router_id_static`` but, since the previous ``router ospf``
command hasn’t been commited yet, the ``ospf`` global variable is set to
NULL, which leads to the crash. Besides this problem, having a set of
commands that edit the candidate configuration and others that edit the
running configuration is confusing at best. The ``--tcli`` option should
be used only by developers until the northbound retrofitting process is
complete.

Configuration modes
~~~~~~~~~~~~~~~~~~~

When using the transactional CLI (``--tcli``), FRR supports three
different forms of the ``configure`` command: \* ``configure terminal``:
in this mode, a single candidate configuration is shared by all users.
This means that one user might delete a configuration object that’s
being edited by another user, in which case the CLI will detect and
report the problem. If one user issues the ``commit`` command, all
changes done by all users are committed. \* ``configure private``: users
have a private candidate configuration that is edited separately from
the other users. The ``commit`` command commits only the changes done by
the user. \* ``configure exclusive``: similar to ``configure private``,
but also locks the running configuration to prevent other users from
changing it. The configuration lock is released when the user exits the
configuration mode.

When using ``configure terminal`` or ``configure private``, the
candidate configuration being edited might become outdated if another
user commits a different candidate configuration on another session.
TODO: show image to illustrate the problem.

New commands
~~~~~~~~~~~~

The list below contains the new CLI commands introduced by Northbound
API. The commands are available when a daemon is started using the
transactional CLI (``--tcli``). Currently ``vtysh`` doesn’t support any
of these new commands.

Please refer to the [[Demos]] page to see a demo of the transactional
CLI in action.

--------------

``commit check``
''''''''''''''''

Check if the candidate configuration is valid or not.

``commit [force] [comment LINE...]``
''''''''''''''''''''''''''''''''''''

Commit the changes done in the candidate configuration into the running
configuration.

Options: \* ``force``: commit even if the candidate configuration is
outdated. It’s usually a better option to use the ``update`` command
instead. \* ``comment LINE...``: assign a comment to the configuration
transaction. This comment is displayed when viewing the recorded
transactions in the output of the ``show configuration transaction``
command.

``discard``
'''''''''''

Discard the changes done in the candidate configuration.

``configuration database max-transactions (1-100)``
'''''''''''''''''''''''''''''''''''''''''''''''''''

Set the maximum number of transactions to store in the rollback log.

``configuration load <file [<json|xml> [translate WORD]] FILENAME|transaction (1-4294967296)> [replace]``
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Load a new configuration into the candidate configuration. When loading
the configuration from a file, it’s assumed that the configuration will
be in the form of CLI commands by default. The ``json`` and ``xml``
options can be used to load configurations in the JSON and XML formats,
respectively. It’s also possible to load a configuration from a previous
transaction by specifying the desired transaction ID
(``(1-4294967296)``).

Options: \* ``translate WORD``: translate the JSON/XML configuration
file using the YANG module translator. \* ``replace``: replace the
candidate by the loaded configuration. The default is to merge the
loaded configuration into the candidate configuration.

``rollback configuration (1-4294967296)``
'''''''''''''''''''''''''''''''''''''''''

Roll back the running configuration to a previous configuration
identified by its transaction ID (``(1-4294967296)``).

``show configuration candidate [<json|xml> [translate WORD]] [<with-defaults|changes>]``
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Show the candidate configuration.

Options: \* ``json``: show the configuration in the JSON format. \*
``xml``: show the configuration in the XML format. \*
``translate WORD``: translate the JSON/XML output using the YANG module
translator. \* ``with-defaults``: show default values that are hidden by
default. \* ``changes``: show only the changes done in the candidate
configuration.

``show configuration compare <candidate|running|transaction (1-4294967296)> <candidate|running|transaction (1-4294967296)> [<json|xml> [translate WORD]]``
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Show the difference between two different configurations.

Options: \* ``json``: show the configuration differences in the JSON
format. \* ``xml``: show the configuration differences in the XML
format. \* ``translate WORD``: translate the JSON/XML output using the
YANG module translator.

``show configuration running [<json|xml> [translate WORD]] [with-defaults]``
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Show the running configuration.

Options: \* ``json``: show the configuration in the JSON format. \*
``xml``: show the configuration in the XML format. \*
``translate WORD``: translate the JSON/XML output using the YANG module
translator. \* ``with-defaults``: show default values that are hidden by
default.

   NOTE: ``show configuration running`` shows only the running
   configuration as known by the northbound layer. Configuration
   commands not converted to the new northbound model will not be
   displayed. To show the full running configuration, the legacy
   ``show running-config`` command must be used.

``show configuration transaction [(1-4294967296) [<json|xml> [translate WORD]] [changes]]``
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

When a transaction ID (``(1-4294967296)``) is given, show the
configuration associated to the previously committed transaction.

When a transaction ID is not given, show all recorded transactions in
the rollback log.

Options: \* ``json``: show the configuration in the JSON format. \*
``xml``: show the configuration in the XML format. \*
``translate WORD``: translate the JSON/XML output using the YANG module
translator. \* ``with-defaults``: show default values that are hidden by
default. \* ``changes``: show changes compared to the previous
transaction.

``show yang module [module-translator WORD] [WORD <summary|tree|yang|yin>]``
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

When a YANG module is not given, show all loaded YANG modules.
Otherwise, show detailed information about the given module.

Options: \* ``module-translator WORD``: change the context to modules
loaded by the specified YANG module translator. \* ``summary``: display
summary information about the module. \* ``tree``: display module in the
tree (RFC 8340) format. \* ``yang``: display module in the YANG format.
\* ``yin``: display module in the YIN format.

``show yang module-translator``
'''''''''''''''''''''''''''''''

Show all loaded YANG module translators.

``update``
''''''''''

Rebase the candidate configuration on top of the latest running
configuration. Conflicts are resolved automatically by giving preference
to the changes done in the candidate configuration.

The candidate configuration might be outdated if the running
configuration was updated after the candidate was created.

``yang module-translator load FILENAME``
''''''''''''''''''''''''''''''''''''''''

Load a YANG module translator from the filesystem.

``yang module-translator unload WORD``
''''''''''''''''''''''''''''''''''''''

Unload a YANG module translator identified by its name.
