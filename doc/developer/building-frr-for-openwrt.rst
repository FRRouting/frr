OpenWRT
=======

Prepare build environment
-------------------------

For Debian based distributions, run:

::

    sudo apt-get install git build-essential libssl-dev libncurses5-dev \
       unzip gawk zlib1g-dev subversion mercurial

For other environments, instructions can be found in the
`official documentation
<https://wiki.openwrt.org/doc/howto/buildroot.exigence#examples_of_package_installations>`_.


Get OpenWRT Sources (from Git)
------------------------------

.. note::
   The OpenWRT build will fail if you run it as root. So take care to run it as a nonprivileged user.

Clone the OpenWRT sources and retrieve the package feeds

::

    git clone https://github.com/openwrt/openwrt.git
    cd openwrt
    ./scripts/feeds update -a
    ./scripts/feeds install -a
    cd feeds/routing
    git fetch origin pull/319/head
    git read-tree --prefix=frr/ -u FETCH_HEAD:frr
    cd ../../package/feeds/routing/
    ln -sv ../../../feeds/routing/frr .
    cd ../../..

Configure OpenWRT for your target and select the needed FRR packages in Network -> Routing and Redirection -> frr,
exit and save

::

    make menuconfig

Then, to compile either a complete OpenWRT image, or the FRR packages, run:

::

    make or make package/frr/compile

It may be possible that on first build ``make package/frr/compile`` not
to work and it may be needed to run a ``make`` for the entire build
environment. Add ``V=s`` to get more debugging output.

Work with sources
-----------------

To update to a newer version, or change other options, you need to edit the ``feeds/routing/frr/Makefile``.

Usage
-----

Edit ``/usr/sbin/frr.init`` and add/remove the daemons name in section
``DAEMONS=`` or don't install unneded packages For example: zebra bgpd ldpd
isisd nhrpd ospfd ospf6d pimd ripd ripngd

Enable the serivce
^^^^^^^^^^^^^^^^^^

-  ``service frr enable``

Start the service
^^^^^^^^^^^^^^^^^

-  ``service frr start``
