The libyang library can be installed from third-party packages available `here
<https://ci1.netdef.org/browse/LIBYANG-YANGRELEASE/latestSuccessful/artifact>`_.

Note: the libyang dev/devel packages need to be installed in addition
to the libyang core package in order to build FRR successfully.

.. warning::
   libyang ABI version 0.16.74 or newer will be required to build FRR in the
   near future since it significantly eases build and installation
   considerations.  "0.16-r3" is equal to 0.16.105 and will work, "0.16-r2"
   is equal to 0.16.52 and will stop working.  The CI artifacts will be
   updated shortly.

For example, for CentOS 7.x:

.. code-block:: shell

   wget https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/CentOS-7-x86_64-Packages/libyang-0.16.46-0.x86_64.rpm
   wget https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/CentOS-7-x86_64-Packages/libyang-devel-0.16.46-0.x86_64.rpm
   sudo rpm -i libyang-0.16.46-0.x86_64.rpm libyang-devel-0.16.46-0.x86_64.rpm

or Ubuntu 18.04:

.. code-block:: shell

   wget https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/Ubuntu-18.04-x86_64-Packages/libyang-dev_0.16.46_amd64.deb
   wget https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/Ubuntu-18.04-x86_64-Packages/libyang_0.16.46_amd64.deb
   sudo apt install libpcre3-dev
   sudo dpkg -i libyang-dev_0.16.46_amd64.deb libyang_0.16.46_amd64.deb

.. note::
   For Debian-based systems, the official libyang package requires recent
   versions of swig (3.0.12) and debhelper (11) which are only available in
   Debian buster (10).  However, libyang packages built on Debian buster can
   be installed on both Debian jessie (8) and Debian stretch (9), as well as
   various Ubuntu systems.  The python3-yang package will not work, but the
   other packages (libyang-dev is the one needed for FRR) will.

Alternatively, libyang can be built and installed manually by following
the steps below:

.. code-block:: shell

   git clone https://github.com/opensourcerouting/libyang
   cd libyang
   git checkout -b tmp origin/tmp
   mkdir build; cd build
   cmake -DENABLE_LYD_PRIV=ON ..
   make
   sudo make install

When building libyang on CentOS 6, it's also necessary to pass the
``-DENABLE_CACHE=OFF`` parameter to cmake.

Note: please check the `libyang build requirements
<https://github.com/CESNET/libyang/blob/master/README.md#build-requirements>`_
first.
