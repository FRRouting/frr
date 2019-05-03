Clone the FRR git repo and use the included ``configure`` script to configure
FRR's build time options to your liking. The full option listing can be
obtained by running ``./configure -h``. The options shown below are examples.

.. note::

   If your platform uses ``systemd``, please make sure to add
   ``--enable-systemd=yes`` to your configure options.

.. code-block:: console

   git clone https://github.com/frrouting/frr.git frr
   cd frr
   ./bootstrap.sh
   ./configure \
       --prefix=/usr \
       --includedir=\${prefix}/include \
       --enable-exampledir=\${prefix}/share/doc/frr/examples \
       --bindir=\${prefix}/bin \
       --sbindir=\${prefix}/lib/frr \
       --libdir=\${prefix}/lib/frr \
       --libexecdir=\${prefix}/lib/frr \
       --localstatedir=/var/run/frr \
       --sysconfdir=/etc/frr \
       --with-moduledir=\${prefix}/lib/frr/modules \
       --with-libyang-pluginsdir=\${prefix}/lib/frr/libyang_plugins \
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
