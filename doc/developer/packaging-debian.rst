Debian
======

(Tested on Ubuntu 14.04, 16.04, 17.10, 18.04, Debian 8 and 9)

.. note::

   These instructions are for building from a git checkout.  You should
   always either build from git, or be working as a Debian maintainer and
   thus using quilt to maintain local changes (in which case these
   instructions do not apply.)

1. Install the Debian packaging tools:

   .. code-block:: shell

      sudo apt install fakeroot debhelper devscripts

2. Install build dependencies for your platform as outlined in :ref:`building`.

   Alternatively, use the `mk-build-deps` tool from the `devscripts` package:

   .. code-block:: shell

      sudo mk-build-deps --install debianpkg/control

3. Checkout FRR under a **unprivileged** user account:

   .. code-block:: shell

      git clone https://github.com/frrouting/frr.git frr
      cd frr

   If you wish to build a package for a branch other than master:

   .. code-block:: shell

      git checkout <branch>

4. Create a Debian source using the `tools/tarsource.sh` script:

   .. code-block:: shell

      tools/tarsource.sh -D -o ..

   You may want to look at the additional options supported by this script
   by invoking it with the `--help` option.

   .. note::

      The `tarsource.sh` script will try to identify whether you are
      building an FRR release (i.e. you are on a release tag.)  If you
      are not on a release, it will append a date-stamp to the version
      number.

5. Unpack the Debian source:

   .. code-block:: shell

      cd ..
      dpkg-source -x frr*.dsc
      cd frr-*/

   If you want to build for multiple distributions, refer to
   :ref:`multi-dist` below.

6. Build:

   .. code-block:: shell

      debuild $options

   Where `$options` may contain any or all of the following items:

   * the ``-uc -us`` options to disable signing the packages with your GPG key

   * build profiles specified with ``-P``, e.g.
     ``-Ppkg.frr.rtrlib,pkg.frr.snmp``.
     Multiple values are separated by commas and there must not be a space
     after the ``-P``.

     The following build profiles are currently available:

     +----------------+-------------------+-----------------------------------------+
     | Profile        | Negation          | Effect                                  |
     +================+===================+=========================================+
     | pkg.frr.rtrlib | pkg.frr.nortrlib  | builds frr-rpki-rtrlib package (or not) |
     +----------------+-------------------+-----------------------------------------+
     | pkg.frr.snmp   | pkg.frr.nosnmp    | builds frr-snmp package (or not)        |
     +----------------+-------------------+-----------------------------------------+
     |                | pkg.frr.nosystemd | removes libsystemd dependency and       |
     |                |                   | disables unit file installation         |
     +----------------+-------------------+-----------------------------------------+

     .. warning::

        A package built with the ``pkg.frr.snmp`` profile is not legal to
        distribute in binary form due to a license conflict between the GPLv2
        and the OpenSSL license.

     .. note::

        The ``pkg.frr.nosystemd`` option is only intended to support Ubuntu
        14.04 (and should be enabled when building for that.)

   * environment variables controlling other aspects of the FRR build::

        --set-envvar=WANT_BGP_VNC=1
        --set-envvar=WANT_CUMULUS_MODE=1
        --set-envvar=WANT_OSPFAPI=0
        --set-envvar=WANT_MULTIPATH=0
        --set-envvar=WANT_WERROR=1

6. Done!

   If all worked correctly, then you should end up with the Debian packages in
   the parent directory of where `debuild` ran.  If distributed, please make sure
   you distribute it together with the sources (``frr_*.orig.tar.xz``,
   ``frr_*.debian.tar.xz`` and ``frr_*.dsc``)

.. _multi-dist:

Multi-Distribution builds
=========================

You can optionally append a distribution identifier in case you want to
make multiple versions of the package available in the same repository.
Do the following after unpacking the source with ``deb-source -x``:

.. code-block:: shell

   dch -l '~deb8u' 'build for Debian 8 (jessie)'
   dch -l '~deb9u' 'build for Debian 9 (stretch)'
   dch -l '~0ubuntu0.14.04.' 'build for Ubuntu 14.04 (trusty)'
   dch -l '~0ubuntu0.16.04.' 'build for Ubuntu 16.04 (xenial)'
   dch -l '~0ubuntu0.18.04.' 'build for Ubuntu 18.04 (bionic)'

Between building packages for specific distributions, the only difference
in the package itself lies in the automatically generated shared library
dependencies, e.g. libjson-c2 or libjson-c3.  This means that the
architecture independent packages should **not** have a suffix appended.
Also, the current Debian "testing" release should not have any suffix
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
