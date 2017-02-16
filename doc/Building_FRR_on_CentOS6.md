Building FRR on CentOS 6 from Git Source
========================================

Instructions are tested with `CentOS 6.8` on `x86_64` platform

CentOS 6 restrictions:
----------------------

- PIMd is not supported on `CentOS 6`. Upgrade to `CentOS 7` if PIMd is needed
- MPLS is not supported on `CentOS 6`. MPLS requires Linux Kernel 4.5 or higher
  (LDP can be built, but may have limited use without MPLS)

Install required packages
-------------------------
		
Add packages:

	sudo yum install git autoconf automake libtool make gawk readline-devel \
	  texinfo net-snmp-devel groff pkgconfig json-c-devel pam-devel \
	  flex pytest

Install newer version of bison (CentOS 6 package source is too old)	from CentOS 7

	curl -O http://vault.centos.org/7.0.1406/os/Source/SPackages/bison-2.7-4.el7.src.rpm
	rpmbuild --rebuild ./bison-2.7-4.el7.src.rpm
	sudo yum install ./rpmbuild/RPMS/x86_64/bison-2.7-4.el6.x86_64.rpm
	rm -rf rpmbuild

Install newer version of autoconf and automake (Package versions are too old)

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

Install `Python 2.7` in parallel to default 2.6 (needed for `make check` to run unittests). 
Pick correct EPEL based on CentOS version used. Then install current `pytest`

	rpm -ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
	rpm -ivh https://centos6.iuscommunity.org/ius-release.rpm
	yum install python27 python27-pip
	pip2.7 install pytest

Please note that `CentOS 6` needs to keep python pointing to version 2.6 for `yum` to keep
working, so don't create a symlink for python2.7 to python
	
Get FRR, compile it and install it (from Git)
---------------------------------------------

**This assumes you want to build and install FRR from source and not using any packages**

### Add frr groups and user

	sudo groupadd -g 92 frr
	sudo groupadd -r -g 85 frrvt
	sudo useradd -u 92 -g 92 -M -r -G frrvt -s /sbin/nologin \
	  -c "FRR FreeRangeRouting suite" -d /var/run/frr frr

### Download Source, configure and compile it
(You may prefer different options on configure statement. These are just an example.)

You may want to pay special attention to `/usr/lib64` paths and change them if you are not building on a x86_64 architecture

	git clone https://github.com/freerangerouting/frr.git frr
	cd frr
	git checkout stable/2.0
	./bootstrap.sh
	./configure \
    	--sysconfdir=/etc/frr \
    	--libdir=/usr/lib64/frr \
		--libexecdir=/usr/lib64/frr \
		--localstatedir=/var/run/frr \
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
    	--enable-tcp-zebra \
    	--enable-fpm \
	    --with-pkg-git-version \
	    --with-pkg-extra-version=-MyOwnFRRVersion	
	make
	make check PYTHON=/usr/bin/python2.7
	sudo make install

### Create empty FRR configuration files
	sudo mkdir /var/log/frr
	sudo mkdir /etc/frr
	sudo touch /etc/frr/zebra.conf
	sudo touch /etc/frr/bgpd.conf
	sudo touch /etc/frr/ospfd.conf
	sudo touch /etc/frr/ospf6d.conf
	sudo touch /etc/frr/isisd.conf
	sudo touch /etc/frr/ripd.conf
	sudo touch /etc/frr/ripngd.conf
	sudo chown -R frr:frr /etc/frr/
	sudo touch /etc/frr/vtysh.conf
	sudo chown frr:frrvt /etc/frr/vtysh.conf
	sudo chmod 640 /etc/frr/*.conf

### Enable IP & IPv6 forwarding

Edit `/etc/sysctl.conf` and set the following values (ignore the other settings)

	# Controls IP packet forwarding
	net.ipv4.ip_forward = 1
	net.ipv6.conf.all.forwarding=1

	# Controls source route verification
	net.ipv4.conf.default.rp_filter = 0

**Reboot** or use `sysctl` to apply the same config to the running system

### Add init.d startup files
	sudo cp redhat/bgpd.init /etc/init.d/bgpd
	sudo cp redhat/isisd.init /etc/init.d/isisd
	sudo cp redhat/ospfd.init /etc/init.d/ospfd
	sudo cp redhat/ospf6d.init /etc/init.d/ospf6d
	sudo cp redhat/ripngd.init /etc/init.d/ripngd
	sudo cp redhat/ripd.init /etc/init.d/ripd
	sudo cp redhat/zebra.init /etc/init.d/zebra
	sudo chkconfig --add zebra 
	sudo chkconfig --add ripd
	sudo chkconfig --add ripngd
	sudo chkconfig --add ospf6d
	sudo chkconfig --add ospfd
	sudo chkconfig --add bgpd
	sudo chkconfig --add isisd

### Enable required daemons at startup
Only enable zebra and the daemons which are needed for your setup

	sudo chkconfig zebra on
	sudo chkconfig ospfd on
	sudo chkconfig bgpd on
	[...] etc (as needed)
