..
.. January 12 2024, Christian Hopps <chopps@labn.net>
..
.. Copyright (c) 2024, LabN Consulting, L.L.C.
..
..

Prior versions of FRR supported reading and writing per-daemon config files;
however, with the introduction of the centralized management daemon ``mgmtd``
this could no longer be supported.

In order to allow for an orderly transition from per-daemon config files to the
integrated config file, FRR daemons will continue to try and **read** their
specific per-daemon configuration file as before. Additionally the config can
still be loaded directly using the ``-f`` or ``--config-file`` CLI options;
however, these files will **not** be updated when the configuration is written
(e.g., with the ``write mem`` command).

.. warning::

   Per-daemon files will **no longer** be updated when the user issues a ``write
   memory`` command. Therefore these per-daemon config files should only be used
   as a mechanism for transitioning to the integrated config, and then removed.
