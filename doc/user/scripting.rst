.. _scripting:

*********
Scripting
*********

The behavior of FRR may be extended or customized using its built-in scripting
capabilities.

Some configuration commands accept the name of a Lua script to call to perform
some task or make some decision. These scripts have their environments
populated with some set of inputs, and are expected to populate some set of
output variables, which are read by FRR after the script completes. The names
and expected contents of these scripts are documented alongside the commands
that support them.

These scripts live in :file:`/etc/frr/scripts/` by default. This is
configurable at compile time via ``--with-scriptdir``. It may be
overriden at runtime with the ``--scriptdir`` daemon option.

In order to use scripting, FRR must be built with ``--enable-scripting``.

.. note::

   Scripts are typically loaded just-in-time. This means you can change the
   contents of a script that is in use without restarting FRR. Not all
   scripting locations may behave this way; refer to the documentation for the
   particular location.
