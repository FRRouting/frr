OpenWrt
=======

General info about OpenWrt buildsystem: `link <https://openwrt.org/docs/guide-developer/build-system/start>`_.

Prepare build environment
-------------------------

For Debian based distributions, run:

::

    sudo apt-get install git build-essential libssl-dev libncurses5-dev \
       unzip zlib1g-dev subversion mercurial

For other environments, instructions can be found in the
`official documentation
<https://openwrt.org/docs/guide-developer/build-system/install-buildsystem#examples_of_package_installations>`_.


Get OpenWrt Sources (from Git)
------------------------------

.. note::
   The OpenWrt build will fail if you run it as root. So take care to run it as a nonprivileged user.

Clone the OpenWrt sources and retrieve the package feeds

::

    git clone https://github.com/openwrt/openwrt.git
    cd openwrt
    ./scripts/feeds update -a
    ./scripts/feeds install -a

Configure OpenWrt for your target and select the needed FRR packages in Network -> Routing and Redirection -> frr,
exit and save

::

    make menuconfig

Then, to compile either a complete OpenWrt image, or the FRR packages, run:

::

    make or make package/frr/compile

It may be possible that on first build ``make package/frr/compile`` not
to work and it may be needed to run a ``make`` for the entire build
environment. Add ``V=s`` to get more debugging output.

More information about OpenWrt buildsystem can be found `here
<https://openwrt.org/docs/guide-developer/build-system/use-buildsystem>`__.

Work with sources
-----------------

To update to a newer version, or change other options, you need to edit the ``feeds/packages/frr/Makefile``.

More information about working with patches in OpenWrt buildsystem can be found `here
<https://openwrt.org/docs/guide-developer/build-system/use-patches-with-buildsystem>`__.

Usage
-----

Edit ``/usr/sbin/frr.init`` and add/remove the daemons name in section
``DAEMONS=`` or don't install unneeded packages For example: zebra bgpd ldpd
isisd nhrpd ospfd ospf6d pimd ripd ripngd

Enable the service
^^^^^^^^^^^^^^^^^^

-  ``service frr enable``

Start the service
^^^^^^^^^^^^^^^^^

-  ``service frr start``
