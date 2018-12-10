Packaging Debian
================

(Tested on Ubuntu 14.04, 16.04, 17.10, 18.04, Debian jessie, stretch and
buster.)

1. Install build dependencies for your platform as outlined in :ref:`building`.

2. Install the general Debian package building tools:

   .. code-block:: shell

      apt-get install equivs fakeroot debhelper devscripts

3. Checkout FRR under a **unprivileged** user account:

   .. code-block:: shell

      git clone https://github.com/frrouting/frr.git frr
      cd frr

   If you wish to build a package for a branch other than master:

   .. code-block:: shell

      git checkout <branch>

4. Build Debian package dependencies and install them as needed.

   .. code-block:: shell

      sudo mk-build-deps --install debian/control

5. Run ``tools/tarsource.sh -V``:

   .. code-block:: shell

      ./tools/tarsource.sh -V

   This script sets up the `debian/changelog-auto` file with proper version
   information.  If you want to append a local build identifier, look at the
   `-e` option.

6. Build Debian Package

   Building with standard options:

   .. code-block:: shell

      debuild -b -uc -us

7. Done!

If all worked correctly, then you should end up with the Debian packages in
the parent directory.  If distributed, please make sure you distribute it
together with the sources (``frr_*.orig.tar.gz``, ``frr_*.debian.tar.xz`` and
``frr_*.dsc``)
