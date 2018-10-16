The libyang library can be installed from third-party packages available `here
<https://ci1.netdef.org/browse/LIBYANG-YANGRELEASE/latestSuccessful/artifact>`_.

Note: the libyang dev/devel packages need to be installed in addition
to the libyang core package in order to build FRR successfully.

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
