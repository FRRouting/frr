.. index:: Bug Reports
.. index:: Reporting bugs

.. _bug-reports:

**************
Reporting Bugs
**************

This file describes the procedure for reporting FRRouting bugs.  You are asked
to follow this format when submitting bug reports.

Bugs submitted with woefully incomplete information will receive little
attention and are likely to be closed. If you hit a suspected bug in an older
version, you may be asked to test with a later version in your environment.

Often you may be asked for additional information to help solve the bug. Bugs
may be closed after 30 days of non-response to requests to reconfirm or supply
additional information.

Please report bugs on the project GitHub issue tracker at
https://github.com/frrouting/frr/issues

Report Format & Requested Information
=====================================

When reporting a bug, please provide the following information.

#. Your FRR version if it is a release build, or the commit hash if you built
   from source.

#. If you compiled from source, please provide your ``./configure`` line,
   including all option flags.

#. A full list of the FRR daemons you run.

#. Your platform name and version, e.g. ``Ubuntu 18.04``.

#. Problem description.

   - Provide as much information as possible.
   - Copy and paste relevant commands and their output to describe your network
     setup.
   - Topology diagrams are helpful when reporting bugs involving more than one
     box.
   - Platform routing tables and interface configurations are useful if you are
     reporting a routing issue.

   *Please be sure to review the provided information and censor any sensitive
   material.*

#. All FRR configuration files you use. Again, please be sure to censor any
   sensitive information. For sensitive v4 / v6 addresses, we ask that you
   censor the inner octets; e.g., ``192.XXX.XXX.32/24``.

#. If you are reporting a crash and have a core file, please supply a stack
   trace using GDB:

   ::

      $ gdb exec_file core_file
        (gdb) bt .

#. Run all FRR daemons with full debugging on and send *only* the portion of
   logs which are relevant to your problem.

#. Patches, workarounds, and fixes are always welcome.

.. seealso:: :ref:`basic-config-commands`

