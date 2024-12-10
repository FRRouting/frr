<<<<<<< HEAD
=======
Plugins Sysrepo
===============

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
Installation
------------

Required dependencies
^^^^^^^^^^^^^^^^^^^^^
<<<<<<< HEAD

::

   # apt-get install git cmake build-essential bison flex libpcre3-dev libev-dev \
                     libavl-dev libprotobuf-c-dev protobuf-c-compiler libcmocka0 \
                     libcmocka-dev doxygen libssl-dev libssl-dev libssh-dev
=======
Install FRR build required dependencies, check `Building FRR 
<https://docs.frrouting.org/projects/dev-guide/en/latest/building.html>`_ document for specific platform required packages.  
Below are debian systems required packages: 

.. code-block:: console

   sudo apt-get install git autoconf automake libtool make \
                          libprotobuf-c-dev protobuf-c-compiler build-essential \
                          python3-dev python3-pytest python3-sphinx libjson-c-dev \
                          libelf-dev libreadline-dev cmake libcap-dev bison flex \
                          pkg-config texinfo gdb libgrpc-dev python3-grpc-tools libpcre2-dev
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

libyang
^^^^^^^

<<<<<<< HEAD
::

   # apt-get install libyang0.16 libyang-dev
=======
.. note::

   FRR requires version 2.1.128 or newer, in this document we will 
   be compiling and installing libyang version 2.1.148.

.. code-block:: console

   git clone https://github.com/CESNET/libyang.git
   cd libyang
   git checkout v2.1.148
   mkdir build; cd build
   cmake --install-prefix /usr \
         -DCMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

Sysrepo
^^^^^^^

<<<<<<< HEAD
::

   $ git clone https://github.com/sysrepo/sysrepo.git
   $ cd sysrepo/
   $ mkdir build; cd build
   $ cmake -DCMAKE_BUILD_TYPE=Release -DGEN_LANGUAGE_BINDINGS=OFF .. && make
   # make install

libnetconf2
^^^^^^^^^^^

::

   $ git clone https://github.com/CESNET/libnetconf2.git
   $ cd libnetconf2/
   $ mkdir build; cd build
   $ cmake .. && make
   # make install

netopeer2
^^^^^^^^^

::

   $ git clone https://github.com/CESNET/Netopeer2.git
   $ cd Netopeer2
   $ cd server
   $ mkdir build; cd build
   $ cmake .. && make
   # make install

**Note:** If ``make install`` fails as it can’t find
``libsysrepo.so.0.7``, then run ``ldconfig`` and try again as it might
not have updated the lib search path
=======
.. note::

   The following code block assumes you have installed libyang v2.1.148, if you have 
   libyang v2.1.128 change sysrepo version to 2.2.105.

.. code-block:: console

   git clone https://github.com/sysrepo/sysrepo.git
   cd sysrepo/
   git checkout v2.2.150
   mkdir build; cd build
   cmake --install-prefix /usr \
         -DCMAKE_BUILD_TYPE:String="Release" ..
   make
   sudo make install

Verify that sysrepo is installed correctly:

.. code-block:: console

   sudo sysrepoctl -l
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

FRR
^^^

<<<<<<< HEAD
Build and install FRR using the ``--enable-sysrepo`` configure-time
option.
=======
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

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

Initialization
--------------

<<<<<<< HEAD
Install the FRR YANG modules in the Sysrepo datastore:

::

   # sysrepoctl --install /usr/local/share/yang/ietf-interfaces@2018-01-09.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-vrf.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-interface.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-route-types.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-filter.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-route-map.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-isisd.yang 
   # sysrepoctl --install /usr/local/share/yang/frr-ripd.yang
   # sysrepoctl --install /usr/local/share/yang/frr-ripngd.yang
   # sysrepoctl -c frr-vrf --owner frr --group frr
   # sysrepoctl -c frr-interface --owner frr --group frr
   # sysrepoctl -c frr-route-types --owner frr --group frr
   # sysrepoctl -c frr-filter --owner frr --group frr
   # sysrepoctl -c frr-route-map --owner frr --group frr
   # sysrepoctl -c frr-isisd --owner frr --group frr
   # sysrepoctl -c frr-ripd --owner frr --group frr
   # sysrepoctl -c frr-ripngd --owner frr --group frr

Start netopeer2-server:

::

   # netopeer2-server -d &

Start the FRR daemons with the sysrepo module:

::

   # isisd -M sysrepo --log=stdout
=======
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
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

Managing the configuration
--------------------------

<<<<<<< HEAD
The following NETCONF scripts can be used to show and edit the FRR
configuration:
https://github.com/rzalamena/ietf-hackathon-brazil-201907/tree/master/netconf-scripts

Example:

::

   # ./netconf-edit.py 127.0.0.1
   # ./netconf-get-config.py 127.0.0.1
   <?xml version="1.0" encoding="UTF-8"?><data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><isis xmlns="http://frrouting.org/yang/isisd"><instance><area-tag>testnet</area-tag><is-type>level-1</is-type></instance></isis></data>

..

   NOTE: the ncclient library needs to be installed first:
   ``apt install -y python3-ncclient``

The *sysrepocfg* tool can also be used to show/edit the FRR
configuration. Example:

::

   # sysrepocfg --format=json --import=frr-isisd.json --datastore=running frr-isisd
   # sysrepocfg --format=json --export --datastore=running frr-isisd
=======
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

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
   {
     "frr-isisd:isis": {
       "instance": [
         {
           "area-tag": "testnet",
<<<<<<< HEAD
=======
           "vrf": "default",
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
           "is-type": "level-1"
         }
       ]
     }
   }
<<<<<<< HEAD
=======

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
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
