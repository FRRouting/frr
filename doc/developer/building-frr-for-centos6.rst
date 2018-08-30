CentOS 6
========================================

(As an alternative to this installation, you may prefer to create a FRR
rpm package yourself and install that package instead. See instructions
in redhat/README.rpm\_build.md on how to build a rpm package)

Instructions are tested with ``CentOS 6.8`` on ``x86_64`` platform

Warning:
--------
``CentOS 6`` is very old and not fully supported by the FRR community
anymore. Building FRR takes multiple manual steps to update the build
system with newer packages than what's available from the archives.
However, the built packages can still be installed afterwards on
a standard ``CentOS 6`` without any special packages.

Support for CentOS 6 is now on a best-effort base by the community.

CentOS 6 restrictions:
----------------------

-  PIMd is not supported on ``CentOS 6``. Upgrade to ``CentOS 7`` if
   PIMd is needed
-  MPLS is not supported on ``CentOS 6``. MPLS requires Linux Kernel 4.5
   or higher (LDP can be built, but may have limited use without MPLS)
-  Zebra is unable to detect what bridge/vrf an interface is associcated
   with (IFLA\_INFO\_SLAVE\_KIND does not exist in the kernel headers,
   you can use a newer kernel + headers to get this functionality)
-  frr\_reload.py will not work, as this requires Python 2.7, and CentOS
   6 only has 2.6. You can install Python 2.7 via IUS, but it won't work
   properly unless you compile and install the ipaddr package for it.
-  Building the package requires Sphinx >= 1.1. Only a non-standard
   package provides a newer sphinx and requires manual installation
   (see below)


Install required packages
-------------------------

Add packages:

::

    sudo yum install git autoconf automake libtool make gawk \
      readline-devel texinfo net-snmp-devel groff pkgconfig \
      json-c-devel pam-devel flex epel-release perl-XML-LibXML \
      c-ares-devel

Install newer version of bison (CentOS 6 package source is too old) from
CentOS 7

::

    sudo yum install rpm-build
    curl -O http://vault.centos.org/7.0.1406/os/Source/SPackages/bison-2.7-4.el7.src.rpm
    rpmbuild --rebuild ./bison-2.7-4.el7.src.rpm
    sudo yum install ./rpmbuild/RPMS/x86_64/bison-2.7-4.el6.x86_64.rpm
    rm -rf rpmbuild

Install newer version of autoconf and automake (Package versions are too
old)

::

    curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
    tar xvf autoconf-2.69.tar.gz
    cd autoconf-2.69
    ./configure --prefix=/usr
    make
    sudo make install
    cd ..

    curl -O http://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
    tar xvf automake-1.15.tar.gz
    cd automake-1.15
    ./configure --prefix=/usr
    make
    sudo make install
    cd ..

Install ``Python 2.7`` in parallel to default 2.6. Make sure you've
install EPEL (``epel-release`` as above). Then install current
``python27``, ``python27-devel`` and ``pytest``

::

    sudo rpm -ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
    sudo rpm -ivh https://centos6.iuscommunity.org/ius-release.rpm
    sudo yum install python27 python27-pip python27-devel
    sudo pip2.7 install pytest

Please note that ``CentOS 6`` needs to keep python pointing to version
2.6 for ``yum`` to keep working, so don't create a symlink for python2.7
to python

Install newer ``Sphinx-Build`` based on ``Python 2.7``

Create a new repo ``/etc/yum.repos.d/puias6.repo`` with the following contents:

::

    ### Name: RPM Repository for RHEL 6 - PUIAS (used for Sphinx-Build)
    ### URL: http://springdale.math.ias.edu/data/puias/computational
    [puias-computational]
    name = RPM Repository for RHEL 6 - Sphinx-Build
    baseurl = http://springdale.math.ias.edu/data/puias/computational/$releasever/$basearch
    #mirrorlist =
    enabled = 1
    protect = 0
    gpgkey =
    gpgcheck = 0

Update rpm database & Install newer sphinx

::

    sudo yum update
    sudo yum install python27-sphinx

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
        --disable-pimd \
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
        --disable-ldpd \
        --enable-fpm \
        --enable-nhrpd \
        --enable-eigrpd \
        --enable-babeld \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    make SPHINXBUILD=sphinx-build2.7
    make check PYTHON=/usr/bin/python2.7 SPHINXBUILD=sphinx-build2.7
    sudo make SPHINXBUILD=sphinx-build2.7 install

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

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Edit ``/etc/sysctl.conf`` and set the following values (ignore the other
settings)

::

    # Controls IP packet forwarding
    net.ipv4.ip_forward = 1
    net.ipv6.conf.all.forwarding=1

    # Controls source route verification
    net.ipv4.conf.default.rp_filter = 0

Load the modifed sysctl's on the system:

::

    sudo sysctl -p /etc/sysctl.d/90-routing-sysctl.conf

Add init.d startup files
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo install -p -m 755 redhat/frr.init /etc/init.d/frr
    sudo chkconfig --add frr

Enable frr daemon at startup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo chkconfig frr on

Start FRR manually (or reboot)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo /etc/init.d/frr start
