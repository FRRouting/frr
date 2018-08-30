OmniOS (OpenSolaris)
====================================================

OmniOS restrictions:
--------------------

-  MPLS is not supported on ``OmniOS`` or ``Solaris``. MPLS requires a
   Linux Kernel (4.5 or higher). LDP can be built, but may have limited
   use without MPLS

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    routeadm -e ipv4-forwarding
    routeadm -e ipv6-forwarding

Install required packages
-------------------------

Add packages:

::

    pkg install \
      developer/build/autoconf \
      developer/build/automake \
      developer/lexer/flex \
      developer/parser/bison \
      developer/object-file \
      developer/linker \
      developer/library/lint \
      developer/build/gnu-make \
      developer/gcc51 \
      library/idnkit \
      library/idnkit/header-idnkit \
      system/header \
      system/library/math/header-math \
      git libtool gawk pkg-config

Add additional Solaris packages:

::

    pkgadd -d http://get.opencsw.org/now
    /opt/csw/bin/pkgutil -U
    /opt/csw/bin/pkgutil -y -i texinfo
    /opt/csw/bin/pkgutil -y -i perl
    /opt/csw/bin/pkgutil -y -i libjson_c_dev
    /opt/csw/bin/pkgutil -y -i python27 py_pip python27_dev

Add libjson to Solaris equivalent of ld.so.conf

::

    crle -l /opt/csw/lib -u

Add pytest:

::

    pip install pytest

Install Sphinx:::

   pip install sphinx

Select Python 2.7 as default (required for pytest)

::

    rm -f /usr/bin/python
    ln -s /opt/csw/bin/python2.7 /usr/bin/python

Fix PATH for all users and non-interactive sessions. Edit
``/etc/default/login`` and add the following default PATH:

::

    PATH=/usr/gnu/bin:/usr/bin:/usr/sbin:/sbin:/opt/csw/bin

Edit ``~/.profile`` and add the following default PATH:

::

    PATH=/usr/gnu/bin:/usr/bin:/usr/sbin:/sbin:/opt/csw/bin

Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not
using any packages**

Add frr group and user
^^^^^^^^^^^^^^^^^^^^^^

::

    sudo groupadd -g 93 frr
    sudo groupadd -g 94 frrvty
    sudo useradd -g 93 -u 93 -G frrvty -c "FRR suite" \
        -d /nonexistent -s /bin/false frr

(You may prefer different options on configure statement. These are just
an example)

::

    git clone https://github.com/frrouting/frr.git frr
    cd frr
    ./bootstrap.sh
    export MAKE=gmake
    export LDFLAGS="-L/opt/csw/lib"
    export CPPFLAGS="-I/opt/csw/include"
    export PKG_CONFIG_PATH=/opt/csw/lib/pkgconfig
    ./configure \
        --sysconfdir=/etc/frr \
        --enable-exampledir=/usr/share/doc/frr/examples/ \
        --localstatedir=/var/run/frr \
        --sbindir=/usr/lib/frr \
        --enable-vtysh \
        --enable-watchfrr \
        --enable-ospfclient=yes \
        --enable-ospfapi=yes \
        --enable-multipath=64 \
        --enable-user=frr \
        --enable-group=frr \
        --enable-vty-group=frrvty \
        --enable-configfile-mask=0640 \
        --enable-logfile-mask=0640 \
        --enable-rtadv \
        --enable-fpm \
        --with-pkg-git-version \
        --with-pkg-extra-version=-MyOwnFRRVersion
    gmake
    gmake check
    sudo gmake install

Enable IP & IPv6 forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    routeadm -e ipv4-forwarding
    routeadm -e ipv6-forwarding
