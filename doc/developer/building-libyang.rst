FRR depends on the relatively new ``libyang`` library to provide YANG/NETCONF
support. Unfortunately, most distributions do not yet offer a ``libyang``
package from their repositories. Therefore we offer two options to install this
library.

**Option 1: Binary Install**

The FRR project builds binary ``libyang`` packages, which we offer for download
`here <https://ci1.netdef.org/browse/LIBYANG-YANGRELEASE/latestSuccessful/artifact>`_.

.. warning::

   ``libyang`` version 0.16.105 or newer is required to build FRR.

.. note::

   The ``libyang`` development packages need to be installed in addition to the
   libyang core package in order to build FRR successfully. Make sure to
   download and install those from the link above alongside the binary
   packages.

   Depending on your platform, you may also need to install the PCRE
   development package. Typically this is ``libpcre-dev`` or ``pcre-devel``.

.. note::

   For Debian-based systems, the official ``libyang`` package requires recent
   versions of ``swig`` (3.0.12) and ``debhelper`` (11) which are only
   available in Debian buster (10).  However, ``libyang`` packages built on
   Debian buster can be installed on both Debian jessie (8) and Debian stretch
   (9), as well as various Ubuntu systems.  The ``python3-yang`` package will
   not work, but the other packages (``libyang-dev`` is the one needed for FRR)
   will.

**Option 2: Source Install**

.. note::

   Ensure that the `libyang build requirements
   <https://github.com/CESNET/libyang/blob/master/README.md#build-requirements>`_
   are met before continuing. Usually this entails installing ``cmake`` and
   ``libpcre-dev`` or ``pcre-devel``.

.. code-block:: console

   git clone https://github.com/CESNET/libyang.git
   cd libyang
   mkdir build; cd build
   cmake -DENABLE_LYD_PRIV=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr \
         -D CMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install

When building ``libyang`` version ``0.16.x`` it's also necessary to pass the
``-DENABLE_CACHE=OFF`` parameter to ``cmake`` to work around a
`known bug <https://github.com/CESNET/libyang/issues/752>`_ in libyang.

