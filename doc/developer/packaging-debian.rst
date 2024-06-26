.. _packaging-debian:

Packaging Debian
================

(Tested on Ubuntu 14.04, 16.04, 17.10, 18.04, Debian jessie, stretch and
buster.)

1. Install the Debian packaging tools:

   .. code-block:: shell

      sudo apt install fakeroot debhelper devscripts

2. Checkout FRR under an **unprivileged** user account:

   .. code-block:: shell

      git clone https://github.com/frrouting/frr.git frr
      cd frr

   If you wish to build a package for a branch other than master:

   .. code-block:: shell

      git checkout <branch>

3. Install build dependencies using the  `mk-build-deps` tool from the
   `devscripts` package:

   .. code-block:: shell

      sudo mk-build-deps --install --remove debian/control

   Alternatively, you can manually install build dependencies for your
   platform as outlined in :ref:`building`.

4. Install `git-buildpackage` package:

   .. code-block:: shell

      sudo apt-get install git-buildpackage

5. (optional) Append a distribution identifier if needed (see below under
   :ref:`multi-dist`.)

6. Build Debian Binary and/or Source Packages:

   .. code-block:: shell

      gbp buildpackage --git-builder=dpkg-buildpackage --git-debian-branch="$(git rev-parse --abbrev-ref HEAD)" $options

   Where `$options` may contain any or all of the following items:

   * build profiles specified with ``-P``, e.g.
     ``-Ppkg.frr.nortrlib,pkg.frr.rtrlib``.
     Multiple values are separated by commas and there must not be a space
     after the ``-P``.

     The following build profiles are currently available:

     +----------------+-------------------+-----------------------------------------+
     | Profile        | Negation          | Effect                                  |
     +================+===================+=========================================+
     | pkg.frr.rtrlib | pkg.frr.nortrlib  | builds frr-rpki-rtrlib package (or not) |
     +----------------+-------------------+-----------------------------------------+
     | pkg.frr.lua    | pkg.frr.nolua     | builds lua scripting extension          |
     +----------------+-------------------+-----------------------------------------+
     | pkg.frr.pim6d  | pkg.frr.nopim6d   | builds pim6d (default enabled)          |
     +----------------+-------------------+-----------------------------------------+
     | pkg.frr.grpc   | pkg.frr.nogrpc    | builds with grpc support (default: no)  |
     +----------------+-------------------+-----------------------------------------+

   * the ``-uc -us`` options to disable signing the packages with your GPG key

     (git builds of the `master` or `stable/X.X` branches won't be signed by
     default since their target release is set to ``UNRELEASED``.)

   * the ``--build=type`` accepts following options (see ``dpkg-buildpackage`` manual page):

     * ``source`` builds the source package
     * ``any`` builds the architecture specific binary packages
     * ``all`` build the architecture independent binary packages
     * ``binary`` build the architecture specific and independent binary packages (alias for ``any,all``)
     * ``full`` builds everything (alias for ``source,any,all``)

   Alternatively, you might want to replace ``dpkg-buildpackage`` with
   ``debuild`` wrapper that also runs ``lintian`` and ``debsign`` on the final
   packages.

7. Done!

   If all worked correctly, then you should end up with the Debian packages in
   the parent directory of where `debuild` ran.  If distributed, please make sure
   you distribute it together with the sources (``frr_*.orig.tar.xz``,
   ``frr_*.debian.tar.xz`` and ``frr_*.dsc``)

.. note::

   A package created from `master` or `stable/X.X` is slightly different from
   a package created from the `debian` branch.  The changelog for the former
   is autogenerated and sets the Debian revision to ``-0``, which causes an
   intentional lintian warning.  The `debian` branch on the other hand has
   a manually maintained changelog that contains proper Debian release
   versioning.


.. _multi-dist:

Multi-Distribution builds
=========================

You can optionally append a distribution identifier in case you want to
make multiple versions of the package available in the same repository.

.. code-block:: shell

   dch -l '~deb8u' 'build for Debian 8 (jessie)'
   dch -l '~deb9u' 'build for Debian 9 (stretch)'
   dch -l '~ubuntu14.04.' 'build for Ubuntu 14.04 (trusty)'
   dch -l '~ubuntu16.04.' 'build for Ubuntu 16.04 (xenial)'
   dch -l '~ubuntu18.04.' 'build for Ubuntu 18.04 (bionic)'

Between building packages for specific distributions, the only difference
in the package itself lies in the automatically generated shared library
dependencies, e.g. libjson-c2 or libjson-c3.  This means that the
architecture independent packages should **not** have a suffix appended.
Also, the current Debian testing/unstable releases should not have any suffix
appended.

For example, at the end of 2018 (i.e. ``buster``/Debian 10 is the current
"testing" release), the following is a complete list of `.deb` files for
Debian 8, 9 and 10 packages for FRR 6.0.1-1 with RPKI support::

   frr_6.0.1-1_amd64.deb
   frr_6.0.1-1~deb8u1_amd64.deb
   frr_6.0.1-1~deb9u1_amd64.deb
   frr-dbg_6.0.1-1_amd64.deb
   frr-dbg_6.0.1-1~deb8u1_amd64.deb
   frr-dbg_6.0.1-1~deb9u1_amd64.deb
   frr-rpki-rtrlib_6.0.1-1_amd64.deb
   frr-rpki-rtrlib_6.0.1-1~deb8u1_amd64.deb
   frr-rpki-rtrlib_6.0.1-1~deb9u1_amd64.deb
   frr-doc_6.0.1-1_all.deb
   frr-pythontools_6.0.1-1_all.deb

Note that there are no extra versions of the `frr-doc` and `frr-pythontools`
packages (because they are for architecture ``all``, not ``amd64``), and the
version for Debian 10 does **not** have a ``~deb10u1`` suffix.

.. warning::

   Do not use the ``-`` character in the version suffix.  The last ``-`` in
   the version number is the separator between upstream version and Debian
   version.  ``6.0.1-1~foobar-2`` means upstream version ``6.0.1-1~foobar``,
   Debian version ``2``.  This is not what you want.

   The only allowed characters in the Debian version are ``0-9 A-Z a-z + . ~``

.. note::

   The separating character for the suffix **must** be the tilde (``~``)
   because the tilde is ordered in version-comparison before the empty
   string.  That means the order of the above packages is the following:

   ``6.0.1-1`` newer than ``6.0.1-1~deb9u1`` newer than ``6.0.1-1~deb8u1``

   If you use another character (e.g. ``+``), the untagged version will be
   regarded as the "oldest"!
