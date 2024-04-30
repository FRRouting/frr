Plugins Sysrepo
===============

Installation
------------

Required dependencies
^^^^^^^^^^^^^^^^^^^^^
Install FRR build required dependencies, check `Building FRR 
<https://docs.frrouting.org/projects/dev-guide/en/latest/building.html>`_ document for specific platform required packages.  
Below are debian systems required packages: 

.. code-block:: console

   sudo apt-get install git autoconf automake libtool make \
                          libprotobuf-c-dev protobuf-c-compiler build-essential \
                          python3-dev python3-pytest python3-sphinx libjson-c-dev \
                          libelf-dev libreadline-dev cmake libcap-dev bison flex \
                          pkg-config texinfo gdb libgrpc-dev python3-grpc-tools libpcre2-dev

libyang
^^^^^^^

.. note::

   FRR requires version 2.1.128 or newer, in this document we will 
   be compiling and installing libyang version 2.1.148.

.. code-block:: console

   git clone https://github.com/CESNET/libyang.git
   cd libyang
   git checkout v2.1.148
   mkdir build; cd build
   cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
         -DCMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install

Sysrepo
^^^^^^^

.. note::

   The following code block assumes you have installed libyang v2.1.148, if you have 
   libyang v2.1.128 change sysrepo version to 2.2.105.

.. code-block:: console

   git clone https://github.com/sysrepo/sysrepo.git
   cd sysrepo/
   git checkout v2.2.150
   mkdir build; cd build
   cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
         -DCMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install

Verify that sysrepo is installed correctly:

.. code-block:: console

   sudo sysrepoctl -l

FRR
^^^

Follow the steps of `Building FRR 
<https://docs.frrouting.org/projects/dev-guide/en/latest/building.html>`_


Make sure to use  ``--enable-sysrepo`` configure-time option while building FRR.

Below is an example of frr configure-time options, your options 
might vary, however in order to allow sysrepo plugin you have
to keep ``--enable-sysrepo`` option:

.. code-block:: console

   ./bootstrap.sh
   ./configure \
       --localstatedir=/var/opt/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --enable-configfile-mask=0640 \
       --enable-logfile-mask=0640 \
       --enable-fpm \
       --enable-sysrepo \
       --with-pkg-git-version \
       --with-pkg-extra-version=-MyOwnFRRVersion
   make
   make check
   sudo make install


Initialization
--------------

Install FRR YANG modules in Sysrepo datastore:

.. code-block:: console

   cd frr/yang/
   sudo sysrepoctl -i ./ietf/ietf-interfaces.yang -o frr -g frr
   sudo sysrepoctl -i frr-vrf.yang -o frr -g frr
   sudo sysrepoctl -i frr-interface.yang -o frr -g frr
   sudo sysrepoctl -i frr-route-types.yang -o frr -g frr
   sudo sysrepoctl -i frr-filter.yang -o frr -g frr
   sudo sysrepoctl -i frr-route-map.yang -o frr -g frr
   sudo sysrepoctl -i frr-isisd.yang -o frr -g frr
   sudo sysrepoctl -i frr-bfdd.yang -o frr -g frr
   sudo sysrepoctl -i ./ietf/ietf-routing-types.yang -o frr -g frr
   sudo sysrepoctl -i  frr-nexthop.yang -o frr -g frr
   sudo sysrepoctl -i  frr-if-rmap.yang -o frr -g frr
   sudo sysrepoctl -i  frr-ripd.yang -o frr -g frr
   sudo sysrepoctl -i  frr-ripngd.yang -o frr -g frr
   sudo sysrepoctl -i  frr-affinity-map.yang -o frr -g frr
   sudo sysrepoctl -i ./ietf/frr-deviations-ietf-interfaces.yang -o frr -g frr


Start FRR daemons with sysrepo plugin:

.. code-block:: console

   sudo /usr/lib/frr/isisd -M sysrepo --log stdout

Any daemon running with ``-M sysrepo`` will subscribe to its frr yang moduels 
on sysrepo and you be able to configure it by editing module configuration on sysrepo.

Managing the configuration
--------------------------

Testing
^^^^^^^

To test FRR intergartion with sysrepo, ``sysrepocfg`` tool can be used 
to edit frr configuration on sysrepo

Example:

Edit sysrepo running datastore configuration for the desiged frr module:

.. code-block:: console

   sudo sysrepocfg -E nano -d running -m frr-isisd -f json

Paste the following json configuration:

.. code-block:: console

   {
     "frr-isisd:isis": {
       "instance": [
         {
           "area-tag": "testnet",
           "vrf": "default",
           "is-type": "level-1"
         }
       ]
     }
   }

Exit and save config to the same file.

After that, this configuration should get reflected to vtysh:

.. code-block:: console

  show run
  Building configuration...
  
  Current configuration:
  !
  frr version 9.2-dev-MyOwnFRRVersion
  frr defaults traditional
  hostname bullseye
  !
  router isis testnet
   is-type level-1
  exit
  !
  end

NETCONF
^^^^^^^

To manage sysrepo configuration through netconf
you can use `netopeer2 <https://github.com/CESNET/netopeer2>`_ as a netfconf server that can 
be easily integrated with sysrepo.
