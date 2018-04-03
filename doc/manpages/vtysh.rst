*****
VTYSH
*****

.. include:: defines.rst
.. |DAEMON| replace:: vtysh

SYNOPSIS
========
vtysh [ -b ]

vtysh [ -E ] [ -d *daemon* ] [ -c *command* ]

DESCRIPTION
===========
vtysh is an integrated shell for the FRRouting suite of protocol daemons.

OPTIONS
=======
OPTIONS available for the vtysh command:

.. option:: -b, --boot

   Execute boot startup configuration. It makes sense only if integrated config file is in use (not default in FRRouting). See Info file frr for more info.

.. option:: -c, --command command

   Specify command to be executed under batch mode. It behaves like -c option in any other shell - command is executed and vtysh exits.

   It's useful for gathering info from FRRouting daemons or reconfiguring daemons from inside shell scripts, etc. Note that multiple commands may be executed by using more than one -c option and/or embedding linefeed characters inside the command string.

.. option:: -d, --daemon daemon_name

   Specify which daemon to connect to. By default, vtysh attempts to connect to all FRRouting daemons running on the system. With this flag, one can specify a single daemon to connect to instead. For example, specifying '-d ospfd' will connect only to ospfd. This can be particularly useful inside scripts with -c where the command is targeted for a single daemon.

.. option:: -e, --execute command

   Alias for -c. It's here only for compatibility with Zebra routing software and older FRR versions. This will be removed in future.

.. option:: -E, --echo

   When the -c option is being used, this flag will cause the standard vtysh prompt and command to be echoed prior to displaying the results. This is particularly useful to separate the results when executing multiple commands.

.. option:: -C, --dryrun

   When the -C option is being used, this flag will check the config for syntatic validity.

.. option:: -m, --markfile

   Mark the input file with context ends, useful for cleanup of a config file that has a lot of extraneous space and end markers

.. option:: -n, --noerror

   When executing cli that does not invoke a vtysh shell, if an error ocurrs ignore it for purposes of return codes from vtysh.

.. option:: -u, --user

   Restrict access to configuration commands by preventing use of the "enable" command. This option provides the same limited "security" as password-protected telnet access. *This security should not be relied on in production environments.*

   Caveat emptor: VTYSH was never designed to be a privilege broker and is not built using secure coding practices. No guarantees of security are provided for this option and under no circumstances should this option be used to provide any semblance of secure read-only access to FRR.

.. option:: -h, --help

   Display a usage message on standard output and exit.

ENVIRONMENT VARIABLES
=====================
VTYSH_PAGER
   This should be the name of the pager to use. Default is more.

FILES
=====
|INSTALL_PREFIX_SBIN|/vtysh
   The default location of the vtysh binary.

|INSTALL_PREFIX_ETC|/vtysh.conf
   The default location of the vtysh config file.

|INSTALL_PREFIX_ETC|/frr.conf
   The default location of the integrated FRRouting routing engine config file if integrated config file is in use.

${HOME}/.history_frr
   Location of history of commands entered via cli

$(PWD)/|DAEMON|.log
   If the |DAEMON| process is configured to output logs to a file, then you
   will find this file in the directory where you started |DAEMON|.

.. include:: epilogue.rst

