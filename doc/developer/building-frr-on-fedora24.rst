Fedora 24
=========================================

(As an alternative to this installation, you may prefer to create a FRR
rpm package yourself and install that package instead. See instructions
in redhat/README.rpm\_build.md on how to build a rpm package)

Install required packages
-------------------------

Add packages:

::

    sudo dnf install git autoconf automake libtool make gawk \
      readline-devel texinfo net-snmp-devel groff pkgconfig \
      json-c-devel pam-devel perl-XML-LibXML pytest bison flex \
      c-ares-devel python3-devel python3-sphinx

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr groups and user
^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo groupadd -g 92 frr
    sudo groupadd -r -g 85 frrvt
    sudo useradd -u 92 -g 92 -M -r -G frrvt -s /sbin/nologin \
      -c "FRR FRRouting suite" -d /var/run/frr frr

Download Source, configure and compile it
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(You may prefer different options on configure statement. These are just
an example.)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    ./configure \
        --bindir=/usr/bin \
        --sbindir=/usr/lib/frr \
        --sysconfdir=/etc/frr \
        --libdir=/usr/lib/frr \
        --libexecdir=/usr/lib/frr \
        --localstatedir=/var/run/frr \
        --with-moduledir=/usr/lib/frr/modules \
        --enable-pimd \
        --enable-snmp=agentx \
        --enable-multipath=64 \
        --enable-ospfclient=yes \
        --enable-ospfapi=yes \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvt \
        --enable-rtadv \
        --disable-exampledir \
        --enable-watchfrr \
        --enable-ldpd \
        --enable-fpm \
        --enable-nhrpd \
        --enable-eigrpd \
        --enable-babeld \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    make
    make check
    sudo make install

Create empty FRR configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo mkdir /var/log/frr
    sudo mkdir /etc/frr
    sudo touch /etc/frr/zebra.conf
    sudo touch /etc/frr/bgpd.conf
    sudo touch /etc/frr/ospfd.conf
    sudo touch /etc/frr/ospf6d.conf
    sudo touch /etc/frr/isisd.conf
    sudo touch /etc/frr/ripd.conf
    sudo touch /etc/frr/ripngd.conf
    sudo touch /etc/frr/pimd.conf
    sudo touch /etc/frr/ldpd.conf
    sudo touch /etc/frr/nhrpd.conf
    sudo touch /etc/frr/eigrpd.conf
    sudo touch /etc/frr/babeld.conf
    sudo chown -R frr:frr /etc/frr/
    sudo touch /etc/frr/vtysh.conf
    sudo chown frr:frrvt /etc/frr/vtysh.conf
    sudo chmod 640 /etc/frr/*.conf

Install daemon config file
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo install -p -m 644 redhat/daemons /etc/frr/
    sudo chown frr:frr /etc/frr/daemons

Edit /etc/frr/daemons as needed to select the required daemons
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Look for the section with ``watchfrr_enable=...`` and ``zebra=...`` etc.
Enable the daemons as required by changing the value to ``yes``

Enable IP & IPv6 forwarding (and MPLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a new file ``/etc/sysctl.d/90-routing-sysctl.conf`` with the
following content: (Please make sure to list all interfaces with
required MPLS similar to ``net.mpls.conf.eth0.input=1``)

::

    # Sysctl for routing
    #
    # Routing: We need to forward packets
    net.ipv4.conf.all.forwarding=1
    net.ipv6.conf.all.forwarding=1
    #
    # Enable MPLS Label processing on all interfaces
    net.mpls.conf.eth0.input=1
    net.mpls.conf.eth1.input=1
    net.mpls.conf.eth2.input=1
    net.mpls.platform_labels=100000

Load the modifed sysctl's on the system:

::

    sudo sysctl -p /etc/sysctl.d/90-routing-sysctl.conf

Create a new file ``/etc/modules-load.d/mpls.conf`` with the following
content:

::

    # Load MPLS Kernel Modules
    mpls-router
    mpls-iptunnel

And load the kernel modules on the running system:

::

    sudo modprobe mpls-router mpls-iptunnel

Install frr Service and redhat init files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo install -p -m 644 redhat/frr.service /usr/lib/systemd/system/frr.service
    sudo install -p -m 755 redhat/frr.init /usr/lib/frr/frr

Enable required frr at startup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo systemctl enable frr

Reboot or start FRR manually
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo systemctl start frr
