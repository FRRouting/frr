OpenWRT/LEDE
=============================================

-  for the moment because of cross compile problems, master is not
   supported, only up to 3.0
-  LDP can't be built because of missing Perl-XML-LibXML in OpenWRT/LEDE
   tree

Prepare build environment
-------------------------

https://lede-project.org/docs/guide-developer/install-buildsystem

for

Ubuntu 12.04LTS:

::

    sudo apt-get install build-essential subversion git-core \
       libncurses5-dev zlib1g-dev gawk flex quilt libssl-dev xsltproc \
       libxml-parser-perl mercurial bzr ecj cvs unzip python3-sphinx

Ubuntu 64bit:

::

    sudo apt-get install build-essential subversion libncurses5-dev zlib1g-dev \
       gawk gcc-multilib flex git-core gettext libssl-dev python3-sphinx

Debian 8 Jessie:

::

    sudo apt-get install build-essential libncurses5-dev gawk git subversion \
       libssl-dev gettext unzip zlib1g-dev file python python3-sphinx

Debian 9 Stretch:

::

    sudo apt-get install build-essential libncurses5-dev gawk git subversion \
       libssl-dev gettext zlib1g-dev python3-sphinx

Centos x86-64 (some packages require EPEL):

::

    yum install subversion binutils bzip2 gcc gcc-c++ gawk gettext flex \
       ncurses-devel zlib-devel zlib-static make patch unzip glibc glibc-devel \
       perl-ExtUtils-MakeMaker glibc-static quilt ncurses-libs sed sdcc bison \
       intltool sharutils wget git-core openssl-devel xz python-sphinx

Fedora 24 - 64Bit:

::

    dnf install -y subversion binutils bzip2 gcc gcc-c++ gawk gettext git-core \
       unzip ncurses-devel ncurses-compat-libs zlib-devel zlib-static make \
       flex patch perl-ExtUtils-MakeMaker perl-Thread-Queue glibc glibc-devel \
       glibc-static quilt sed sdcc intltool sharutils bison wget openssl-devel \
       python3-sphinx

Get LEDE Sources (from Git)
---------------------------

LEDE and OpenWRT is planned to remerge and won't cover the similar
OpenWRT build As normal user: git clone
https://git.lede-project.org/source.git lede cd lede ./scripts/feeds
update -a ./scripts/feeds install -a cd feeds/routing git pull origin
pull/319/head ln -s ../../../feeds/routing/frr/
../../package/feeds/routing/ cd ../.. make menuconfig

Select the needed target then select needed packages in Network ->
Routing and Redirection -> frr, exit and save

::

    make or make package/frr/compile

It may be possible that on first build ``make package/frr/compile`` not
to work and it may be needed to run a ``make`` for the entire build
envronment, add V=s for debugging

Work with sources
-----------------

To update the rc1 version or add other options, the Makefile is found in
feeds/routing/frr

edit: PKG\_VERSION:= PKG\_SOURCE\_VERSION:=

Usage
-----

Edit ``/usr/sbin/frr.init`` and add/remove the daemons name in section
DAEMONS= or don't install unneded packages For example: zebra bgpd ldpd
isisd nhrpd ospfd ospf6d pimd ripd ripngd

Enable the serivce
^^^^^^^^^^^^^^^^^^

-  service frr enable

Start the service
^^^^^^^^^^^^^^^^^

-  service frr start
