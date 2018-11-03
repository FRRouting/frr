The libyang library can be installed from third-party packages available `here
<https://ci1.netdef.org/browse/LIBYANG-YANGRELEASE/latestSuccessful/artifact>`_.

Note: the libyang dev/devel packages need to be installed in addition
to the libyang core package in order to build FRR successfully.

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
