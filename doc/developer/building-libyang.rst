FRR depends on the ``libyang`` library to provide YANG/NETCONF support. Some
distributions do not offer a ``libyang`` package or offer old versions.
Therefore we provide two options below to install this library.

.. note::

   ``libyang`` version 2.1.128 or newer is required to build FRR.

   ``libyang`` version 3 is recommended, with support added in FRR 10.2.

   ``libyang`` version 4 is not preferred to version 3. V4 has placed
   restrictions on the use of the internal binary encoding format (LYD_LYB). As
   a result internal FRR messages have to fall back to using either JSON or XML
   encoding.

   ``libyang`` version 5 restores support for using the binary encoding that was
   removed in version 4, however, a few minor changes in FRR are required before
   it will again be taken advantage of.

**Option 1: Binary Install**

The FRR project builds some binary ``libyang`` packages.

RPM packages are available in our `RPM repository <https://rpm.frrouting.org>`_.

DEB packages are available in our `DEB repository <https://deb.frrouting.org>`_.

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
   git checkout v3.13.6
   mkdir build; cd build
   cmake --install-prefix /usr \
         -D CMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install

.. note::

   The git tag used above is just a suggestion, not a requirement. Feel free to
   change it to newer or older version 3 release tags if you wish.
