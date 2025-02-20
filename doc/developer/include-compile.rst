Clone the FRR git repo and use the included ``configure`` script to configure
FRR's build time options to your liking. The full option listing can be
obtained by running ``./configure -h``. The options shown below are examples.

.. code-block:: console

   git clone https://github.com/frrouting/frr.git frr
   cd frr
   ./bootstrap.sh
   ./configure \
       --prefix=/usr \
       --includedir=\${prefix}/include \
       --bindir=\${prefix}/bin \
       --sbindir=\${prefix}/lib/frr \
       --libdir=\${prefix}/lib/frr \
       --libexecdir=\${prefix}/lib/frr \
       --sysconfdir=/etc \
       --localstatedir=/var \
       --with-moduledir=\${prefix}/lib/frr/modules \
       --enable-configfile-mask=0640 \
       --enable-logfile-mask=0640 \
       --enable-snmp=agentx \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --with-pkg-git-version \
       --with-pkg-extra-version=-MyOwnFRRVersion
   make
   sudo make install
