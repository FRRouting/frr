Debian
======

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

5. Run ``bootstrap.sh``:

   (This step should be omitted if you are using a "debian" branch, as opposed
   to the "master", a "stable/X.X" or any other non-"debian" branch.)

   .. code-block:: shell

      ./bootstrap.sh
      ./configure --with-pkg-extra-version=-MyDebPkgVersion

   .. note::

      Configure parameters are not important for the Debian Package building -
      except the `with-pkg-extra-version` if you want to give the Debian
      package a specific name to mark your own unoffical build.

6. Build Debian Package

   Building with standard options:

   .. code-block:: shell

      debuild -b -uc -us

7. Done!

If all worked correctly, then you should end up with the Debian packages in
the parent directory.  If distributed, please make sure you distribute it
together with the sources (``frr_*.orig.tar.gz``, ``frr_*.debian.tar.xz`` and
``frr_*.dsc``)
