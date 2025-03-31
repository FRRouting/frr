.. _static-linking:

Static Linking
==============

This document describes how to build FRR without hard dependencies on shared
libraries. Note that it's not possible to build FRR *completely* statically.
This document just covers how to statically link the dependencies that aren't
likely to be present on a given platform - libfrr and libyang. The resultant
binaries should still be fairly portable. For example, here is the DSO
dependency list for `bgpd` after using these steps:

.. code-block:: shell

   $ ldd bgpd
        linux-vdso.so.1 (0x00007ffe3a989000)
        libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f9dc10c0000)
        libcap.so.2 => /lib/x86_64-linux-gnu/libcap.so.2 (0x00007f9dc0eba000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f9dc0b1c000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f9dc0918000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f9dc06e0000)
        libjson-c.so.3 => /lib/x86_64-linux-gnu/libjson-c.so.3 (0x00007f9dc04d5000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f9dc02cd000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f9dc00ae000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f9dbfe96000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9dbfaa5000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9dc1449000)

Procedure
---------
Note that these steps have only been tested with LLVM 9 / clang.

Today, libfrr can already be statically linked by passing these configure
options::

   --enable-static --enable-static-bin --enable-shared

libyang is more complicated. You must build and install libyang as a static
library. To do this, follow the usual libyang build procedure as listed in the
FRR developer docs, but set the ``ENABLE_STATIC`` option in your cmake
invocation. You also need to build with PIC enabled, which today is disabled
when building libyang statically.

The resultant cmake command is::

   cmake -DENABLE_STATIC=ON -DENABLE_LYD_PRIV=ON \
         --install-prefix /usr \
         -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
         -DCMAKE_BUILD_TYPE:String="Release" ..

This produces a bunch of ``.a`` static archives that need to ultimately be linked
into FRR. However, not only is it 6 archives rather than the usual ``libyang.so``,
you will now also need to link FRR with ``libpcre.a``. Ubuntu's ``libpcre3-dev``
package provides this, but it hasn't been built with PIC enabled, so it's not
usable for our purposes. So download ``libpcre`` from
`SourceForge <https://sourceforge.net/projects/pcre/>`_, and build it
like this:

.. code-block:: shell

   ./configure --with-pic
   make

Hopefully you get a nice, usable, PIC ``libpcre.a``.

So now we have to link all these static libraries into FRR. Rather than modify
FRR to accommodate this, the best option is to create an archive with all of
libyang's dependencies. Then to avoid making any changes to FRR build foo,
rename this ``libyang.a`` and copy it over the usual static library location.
Ugly but it works. To do this, go into your libyang build directory, which
should have a bunch of ``.a`` files.  Copy ``libpcre.a`` into this directory.
Write the following into a shell script and run it:

.. code-block:: shell

   #!/bin/bash
   ar -M <<EOM
     CREATE libyang_fat.a
     ADDLIB libyang.a
     ADDLIB libyangdata.a
     ADDLIB libmetadata.a
     ADDLIB libnacm.a
     ADDLIB libuser_inet_types.a
     ADDLIB libuser_yang_types.a
     ADDLIB libpcre.a
     SAVE
     END
   EOM
   ranlib libyang_fat.a

``libyang_fat.a`` is your archive. Now copy this over your install
``libyang.a``, which on my machine is located at
``/usr/lib/x86_64-linux-gnu/libyang.a`` (try ``locate libyang.a`` if not).

Now when you build FRR with the static options enabled as above, clang should
pick up the static libyang and link it, leaving you with FRR binaries that have
no hard DSO dependencies beyond common system libraries. To verify, run ``ldd``
over the resultant binaries.
