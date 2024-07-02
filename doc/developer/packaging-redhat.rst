.. _packaging-redhat:

Packaging Red Hat
=================

Tested on CentOS 6, CentOS 7, CentOS 8 and Fedora 24.

1. On CentOS 6, refer to :ref:`building-centos6` for details on installing
   sufficiently up-to-date package versions to enable building FRR.

   Newer automake/autoconf/bison is only needed to build the RPM and is **not**
   needed to install the binary RPM package.

2. Install the build dependencies for your platform. Refer to the
   platform-specific build documentation on how to do this.

3. Install the following additional packages::

      yum install rpm-build net-snmp-devel pam-devel libcap-devel

   For CentOS 7 and CentOS 8, the package will be built using python3
   and requires additional python3 packages::

       yum install python3-devel python3-sphinx

   .. note::

     For CentOS 8 you need to install ``platform-python-devel`` package
     to provide ``/usr/bin/pathfix.py``::

       yum install platform-python-devel


   If ``yum`` is not present on your system, use ``dnf`` instead.

   You should enable ``PowerTools`` repo if using CentOS 8 which
   is disabled by default.

4. Checkout FRR::

      git clone https://github.com/frrouting/frr.git frr

5. Run Bootstrap and make distribution tar.gz::

      cd frr
      ./bootstrap.sh
      ./configure --with-pkg-extra-version=-MyRPMVersion
      make dist

   .. note::

      The only ``configure`` option respected when building RPMs is
      ``--with-pkg-extra-version``.

6. Create RPM directory structure and populate with sources::

     mkdir rpmbuild
     mkdir rpmbuild/SOURCES
     mkdir rpmbuild/SPECS
     cp redhat/*.spec rpmbuild/SPECS/
     cp frr*.tar.gz rpmbuild/SOURCES/

7. Edit :file:`rpm/SPECS/frr.spec` with configuration as needed.

   Look at the beginning of the file and adjust the following parameters to
   enable or disable features as required::

      ############### FRRouting (FRR) configure options #################
      # with-feature options
      %{!?with_babeld:        %global  with_babeld        1 }
      %{!?with_bfdd:          %global  with_bfdd          1 }
      %{!?with_bgp_vnc:       %global  with_bgp_vnc       0 }
      %{!?with_cumulus:       %global  with_cumulus       0 }
      %{!?with_eigrpd:        %global  with_eigrpd        1 }
      %{!?with_fpm:           %global  with_fpm           1 }
      %{!?with_mgmtd_test_be_client: %global with_mgmtd_test_be_client 0 }
      %{!?with_ldpd:          %global  with_ldpd          1 }
      %{!?with_multipath:     %global  with_multipath     256 }
      %{!?with_nhrpd:         %global  with_nhrpd         1 }
      %{!?with_ospfapi:       %global  with_ospfapi       1 }
      %{!?with_ospfclient:    %global  with_ospfclient    1 }
      %{!?with_pam:           %global  with_pam           0 }
      %{!?with_pbrd:          %global  with_pbrd          1 }
      %{!?with_pimd:          %global  with_pimd          1 }
      %{!?with_pim6d:         %global  with_pim6d         1 }
      %{!?with_vrrpd:         %global  with_vrrpd         1 }
      %{!?with_rtadv:         %global  with_rtadv         1 }
      %{!?with_watchfrr:      %global  with_watchfrr      1 }
      %{!?with_pathd:         %global  with_pathd         1 }
      %{!?with_grpc:          %global  with_grpc          0 }

8. Build the RPM::

      rpmbuild --define "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/frr.spec

   If building with RPKI, then download and install the additional RPKI
   packages from
   https://ci1.netdef.org/browse/RPKI-RTRLIB/latestSuccessful/artifact

If all works correctly, then you should end up with the RPMs under
:file:`rpmbuild/RPMS` and the source RPM under :file:`rpmbuild/SRPMS`.
