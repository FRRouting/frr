Debian
======

(Tested on Ubuntu 12.04, 14.04, 16.04, 17.10, 18.04, Debian 8 and 9)

.. note::

   If you try to build for a different distro, then it will most likely fail
   because of the missing backport. See :ref:`deb-backports` about adding a new
   backport.

1. Install build dependencies for your platform as outlined in :ref:`building`.

2. Install the following additional packages:

   - on Ubuntu 12.04, 14.04, 16.04, 17.10, Debian 8 and 9:

   .. code-block:: shell

      apt-get install realpath equivs groff fakeroot debhelper devscripts

   - on Ubuntu 18.04: (realpath is now part of preinstalled by coreutils)

   .. code-block:: shell

      apt-get install equivs groff fakeroot debhelper devscripts

3. Checkout FRR under a **unprivileged** user account:

   .. code-block:: shell

      git clone https://github.com/frrouting/frr.git frr
      cd frr

   If you wish to build a package for a branch other than master:

   .. code-block:: shell

      git checkout <branch>

4. Run ``bootstrap.sh`` and make a dist tarball:

   .. code-block:: shell

      ./bootstrap.sh
      ./configure --with-pkg-extra-version=-MyDebPkgVersion
      make dist

   .. note::

      Configure parameters are not important for the Debian Package building -
      except the `with-pkg-extra-version` if you want to give the Debian
      package a specific name to mark your own unoffical build.

5. Edit :file:`debianpkg/rules` and set the configuration as needed.

   Look for section ``dh_auto_configure`` to modify the configure options as
   needed. Options might be different between the top-level ``rules``` and
   :file:`backports/XXXX/debian/rules`. Please adjust as needed on all files.

6. Create backports debian sources

   Rename the :file:`debianpkg` directory to :file:`debian` and create the
   backports (Debian requires to not ship a :file:`debian` directory inside the
   source directory to avoid build conflicts with the reserved ``debian``
   subdirectory name during the build):

   .. code-block:: shell

      mv debianpkg debian
      make -f debian/rules backports

   This will create a :file:`frr_*.orig.tar.gz` with the source (same as the
   dist tarball), as well as multiple :file:`frr_*.debian.tar.xz` and
   :file:`frr_*.dsc` corresponding to each distribution for which a backport is
   available.

7. Create a new directory to build the package and populate with package
   source.

   .. code-block:: shell

      mkdir frrpkg
      cd frrpkg
      tar xf ~/frr/frr_*.orig.tar.gz
      cd frr*
      . /etc/os-release
      tar xf ~/frr/frr_*${ID}${VERSION_ID}*.debian.tar.xz

8. Build Debian package dependencies and install them as needed.

   .. code-block:: shell

      sudo mk-build-deps --install debian/control

9. Build Debian Package

   Building with standard options:

   .. code-block:: shell

      debuild -b -uc -us

   Or change some options (see `rules` file for available options):

   .. code-block:: shell

      debuild --set-envvar=WANT_BGP_VNC=1 --set-envvar=WANT_CUMULUS_MODE=1 -b -uc -us

   To build with RPKI:

   - Download the librtr packages from
     https://ci1.netdef.org/browse/RPKI-RTRLIB/latestSuccessful/artifact

   - install librtr-dev on the build server

   Then build with:

   .. code-block:: shell

      debuild --set-envvar=WANT_RPKI=1 -b -uc -us

   RPKI packages have an additonal dependency of ``librtr0`` which can be found
   at the same URL.

10. Done!

If all worked correctly, then you should end up with the Debian packages under
:file:`frrpkg`. If distributed, please make sure you distribute it together
with the sources (``frr_*.orig.tar.gz``, ``frr_*.debian.tar.xz`` and
``frr_*.dsc``)

.. _deb-backports:

Debian Backports
----------------

The :file:`debianpkg/backports` directory contains the Debian directories for
backports to other Debian platforms.  These are built via the ``3.0 (custom)``
source format, which allows one to build a source package directly out of
tarballs (e.g. an orig.tar.gz tarball and a debian.tar.gz file), at which point
the format can be changed to a real format (e.g. ``3.0 (quilt)``).

Source packages are assembled via targets of the same name as the system to
which the backport is done (e.g. ``precise``), included in :file:`debian/rules`.

To create a new Debian backport:

- Add its name to ``KNOWN_BACKPORTS``, defined in :file:`debian/rules`.
- Create a directory of the same name in :file:`debian/backports`.
- Add the files ``exclude``, ``versionext``, and ``debian/source/format`` under
  this directory.

For the last point, these files should contain the following:

``exclude``
   Contains whitespace-separated paths (relative to the root of the source dir)
   that should be excluded from the source package (e.g.
   :file:`debian/patches`).

``versionext``
   Contains the suffix added to the version number for this backport's build.
   Distributions often have guidelines for what this should be. If left empty,
   no new :file:`debian/changelog` entry is created.

``debian/source/format``
   Contains the source format of the resulting source package.  As of of the
   writing of this document the only supported format is ``3.0 (quilt)``.

- Add appropriate files under the :file:`debian/` subdirectory.  These will be
  included in the source package, overriding any top-level :file:`debian/`
  files with equivalent paths.

