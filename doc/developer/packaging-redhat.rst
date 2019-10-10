.. _packaging-redhat:

Packaging Red Hat
=================

Tested on CentOS 6, CentOS 7 and Fedora 24.

1. On CentOS 6, refer to :ref:`building-centos6` for details on installing
   sufficiently up-to-date package versions to enable building FRR.

   Newer automake/autoconf/bison is only needed to build the RPM and is **not**
   needed to install the binary RPM package.

2. Install the build dependencies for your platform. Refer to the
   platform-specific build documentation on how to do this.

3. Install the following additional packages::

      yum install rpm-build net-snmp-devel pam-devel libcap-devel

   If your platform uses systemd::

      yum install systemd-devel

   If ``yum`` is not present on your system, use ``dnf`` instead.

3. Checkout FRR::

      git clone https://github.com/frrouting/frr.git frr

4. Run Bootstrap and make distribution tar.gz::

      cd frr
      ./bootstrap.sh
      ./configure --with-pkg-extra-version=-MyRPMVersion
      make dist

   .. note::

      The only ``configure`` option respected when building RPMs is
      ``--with-pkg-extra-version``.

5. Create RPM directory structure and populate with sources::

     mkdir rpmbuild
     mkdir rpmbuild/SOURCES
     mkdir rpmbuild/SPECS
     cp redhat/*.spec rpmbuild/SPECS/
     cp frr*.tar.gz rpmbuild/SOURCES/

6. Edit :file:`rpm/SPECS/frr.spec` with configuration as needed.

   Look at the beginning of the file and adjust the following parameters to
   enable or disable features as required::

      ############### FRRouting (FRR) configure options #################
      # with-feature options
      %{!?with_pam:           %global  with_pam           0 }
      %{!?with_ospfclient:    %global  with_ospfclient    1 }
      %{!?with_ospfapi:       %global  with_ospfapi       1 }
      %{!?with_irdp:          %global  with_irdp          1 }
      %{!?with_rtadv:         %global  with_rtadv         1 }
      %{!?with_ldpd:          %global  with_ldpd          1 }
      %{!?with_nhrpd:         %global  with_nhrpd         1 }
      %{!?with_eigrp:         %global  with_eigrpd        1 }
      %{!?with_shared:        %global  with_shared        1 }
      %{!?with_multipath:     %global  with_multipath     256 }
      %{!?frr_user:           %global  frr_user           frr }
      %{!?vty_group:          %global  vty_group          frrvty }
      %{!?with_fpm:           %global  with_fpm           0 }
      %{!?with_watchfrr:      %global  with_watchfrr      1 }
      %{!?with_bgp_vnc:       %global  with_bgp_vnc       0 }
      %{!?with_pimd:          %global  with_pimd          1 }
      %{!?with_rpki:          %global  with_rpki          0 }

7. Build the RPM::

      rpmbuild --define "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/frr.spec

   If building with RPKI, then download and install the additional RPKI
   packages from
   https://ci1.netdef.org/browse/RPKI-RTRLIB/latestSuccessful/artifact

If all works correctly, then you should end up with the RPMs under
:file:`rpmbuild/RPMS` and the source RPM under :file:`rpmbuild/SRPMS`.
