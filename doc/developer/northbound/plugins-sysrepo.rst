Installation
------------

Required dependencies
^^^^^^^^^^^^^^^^^^^^^

::

   # apt-get install git cmake build-essential bison flex libpcre3-dev libev-dev \
                     libavl-dev libprotobuf-c-dev protobuf-c-compiler libcmocka0 \
                     libcmocka-dev doxygen libssl-dev libssl-dev libssh-dev

libyang
^^^^^^^

::

   # apt-get install libyang0.16 libyang-dev

Sysrepo
^^^^^^^

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

FRR
^^^

Build and install FRR using the ``--enable-sysrepo`` configure-time
option.

Initialization
--------------

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

Managing the configuration
--------------------------

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
   {
     "frr-isisd:isis": {
       "instance": [
         {
           "area-tag": "testnet",
           "is-type": "level-1"
         }
       ]
     }
   }
