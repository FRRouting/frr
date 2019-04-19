.. _pm:

**
PM
**

:abbr:`PM (Path Monitoring)` is a daemon that provides path monitoring
functionality to track connectivity and performance measurements linked
with a remote IP address.

.. _starting-pm:

Starting PM
===========

Default configuration file for *pmd* is :file:`pmd.conf`.  The typical
location of :file:`pmd.conf` is |INSTALL_PREFIX_ETC|/pmd.conf.

If the user is using integrated config, then :file:`pmd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: pmd

:abbr:`PM` supports all the common FRR daemon start options which are
documented elsewhere.

.. _using-pm:

Using PM
========

All pm commands are under the enable node and preceeded by the ``pm``
keyword.
