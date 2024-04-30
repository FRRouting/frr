FRR depends on the relatively new ``libyang`` library to provide YANG/NETCONF
support. Unfortunately, most distributions do not yet offer a ``libyang``
package from their repositories. Therefore we offer two options to install this
library.

**Option 1: Binary Install**

The FRR project builds some binary ``libyang`` packages.

RPM packages are at our `RPM repository <https://rpm.frrouting.org>`_.

DEB packages are available as CI artifacts `here
<https://ci1.netdef.org/browse/LIBYANG-LIBYANG21/latestSuccessful/artifact>`_.

.. warning::

   ``libyang`` version 2.1.128 or newer is required to build FRR.

.. note::

   The ``libyang`` development packages need to be installed in addition to the
   libyang core package in order to build FRR successfully. Make sure to
   download and install those from the link above alongside the binary
   packages.

   Depending on your platform, you may also need to install the PCRE
   development package. Typically this is ``libpcre2-dev`` or ``pcre2-devel``.

**Option 2: Source Install**

.. note::

   Ensure that the `libyang build requirements
   <https://github.com/CESNET/libyang/#build-requirements>`_
   are met before continuing. Usually this entails installing ``cmake`` and
   ``libpcre2-dev`` or ``pcre2-devel``.

.. code-block:: console

   git clone https://github.com/CESNET/libyang.git
   cd libyang
   git checkout v2.1.128
   mkdir build; cd build
   cmake -D CMAKE_INSTALL_PREFIX:PATH=/usr \
         -D CMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install
