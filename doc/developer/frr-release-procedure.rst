.. _frr-release-procedure:

FRR Release Procedure
=====================

``<version>`` - version to be released, e.g. 7.3
``origin`` - FRR upstream repository

#. Checkout the existing ``dev/<version>`` branch.

   .. code-block:: console

      git checkout dev/<version>

#. Create and push a new branch called ``stable/<version>`` based on the
   ``dev/<version>`` branch.

   .. code-block:: console

      git checkout -b stable/<version>
      git push origin stable/<version>:refs/heads/stable/<version>

#. Remove the development branch called ``dev/<version>``

   .. code-block:: console

      git push origin --delete dev/<version>

#. Update Changelog for Red Hat Packages:

   Edit :file:`redhat/frr.spec.in` and look for the ``%changelog`` section:

   - Change last (top of list) entry from ``%{version}`` to the **last**
     released version number. For example, if ``<version>`` is ``7.3`` and the
     last public release was ``7.2``, you would use ``7.2``, changing the file
     like so::

        * Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - %{version}

     to::

        * Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - 7.2

   - Add new entry to the top of the list with ``%{version}`` tag.  Make sure
     to watch the format, i.e. the day is always 2 characters, with the 1st
     character being a space if the day is one digit.

   - Add the changelog text below this entry.

#. Update Changelog for Debian Packages:

   Update :file:`debian/changelog`:

   - Run following with **last** release version number and debian revision
     (usually -1) as argument to ``dch --newversion VERSION``. For example, if
     ``<version>`` is ``7.3`` then you will run ``dch --newversion 7.3-1``.

   - The ``dch`` will run an editor, and you should add the changelog text below
     this entry, usually that would be: **New upstream version**.

   - Verify the changelog format using ``dpkg-parsechangelog``. In the
     repository root:

     .. code-block:: console

        dpkg-parsechangelog

     You should see output like this::

        vagrant@local ~/frr> dpkg-parsechangelog
        Source: frr
        Version: 7.3-dev-0
        Distribution: UNRELEASED
        Urgency: medium
        Maintainer: FRRouting-Dev <dev@lists.frrouting.org>
        Timestamp: 1540478210
        Date: Thu, 25 Oct 2018 16:36:50 +0200
        Changes:
         frr (7.3-dev-0) RELEASED; urgency=medium
         .
           * Your Changes Here

#. Commit the changes, adding the changelog to the commit message. Follow all
   existing commit guidelines. The commit message should be akin to::

      debian, redhat: updating changelog for new release

#. Create a new branch based on ``master``, cherry-pick the commit made in step
   6, and use it to create a PR against ``master``. This way ``master`` has the
   latest changelog for the next cycle.

#. Change main version number:

   - Edit :file:`configure.ac` and change version in the ``AC_INIT`` command
     to ``<version>``

   Add and commit this change. This commit should be separate from the commit
   containing the changelog. The commit message should be::

      FRR Release <version>

   The version field should be complete; i.e. for ``8.0.0``, the version should
   be ``8.0.0`` and not ``8.0`` or ``8``.

#. Push the stable branch to a new remote branch prefixed with ``rc``::

      git push origin stable/<version>:rc/version

   This will trigger the NetDEF CI, which serve as a sanity check on the
   release branch. Verify that all tests pass and that all package builds are
   successful.

#. Create and push a git tag for the version:

   .. code-block:: console

      git tag -a frr-<version> -m "FRRouting Release <version>"
      git push origin frr-<version>

#. Kick off the Release build plan on the CI system for the correct release.
   Contact Martin Winter for this step. Ensure all release packages build
   successfully.

#. Kick off the Snapcraft build plan for the release.

#. Acquire the release RPM binary packages from Martin Winter.

#. On GitHub, go to the <https://github.com/FRRouting/frr/releases>_ and click
   "Draft a new release". Write a release announcement. The release
   announcement should follow the template in
   ``release-announcement-template.md``, located next to this document. Check
   for spelling errors, and optionally (but preferably) have other maintainers
   proofread the announcement text.

   Attach **only** the binary RPM packages to the GitHub release using
   GitHub's attachment functionality. Do not attach Debian packages. Do not
   attach source tarballs - these will be generated and attached by GitHub
   automatically. Do not publish the release yet.

#. Contact the current Debian maintainer for FRR to get new Debian packages
   built and published on our APT repository at https://deb.frrouting.net/.
   Ensure the webpage text is updated. Verify that new packages install
   successfully on a vanilla Debian installation using the instructions on the
   webpage.

#. Deploy Snapcraft release (after CI system finishes the tests for snapcraft
   testplan).

#. Log in to the Read The Docs instance. in the "FRRouting" project, navigate
   to the "Overview" tab. Ensure there is a ``stable-<version>`` version listed
   and that it is enabled. Go to "Admin" and then "Advanced Settings". Change
   "Default version" to the new version. This ensures that the documentation
   shown to visitors is that of the latest release by default.

   This step must be performed by someone with administrative access to the
   Read the Docs instance.

#. Publish the GitHub release.

#. Clone the ``frr-www`` repository:

   .. code-block:: console

      git clone https://github.com/FRRouting/frr-www.git

#. Add a new release announcement, using a previous announcement as template:

   .. code-block:: console

      cp <old-version>-launch.md <version>-launch.md

   Paste the GitHub release announcement text into this document, and **remove
   line breaks**. In other words, this::

      This is one continuous
      sentence that should be
      rendered on one line

   Needs to be changed to this::

      This is one continuous sentence that should be rendered on one line

   This is very important otherwise the announcement will be unreadable on the
   website.

   Make sure to add a link to the GitHub releases page at the top.

   Once finished, manually add a new entry into ``index.html`` to link to this
   new announcement. Look at past commits to see how to do this.

#. Deploy the updated ``frr-www`` on the frrouting.org web server and verify
   that the announcement text is visible.

#. Send an email to ``announce@lists.frrouting.org``. The text of this email
   should include the text from the GitHub release.

#. Update masters version of the changelog-auto.in

   Take the change data and cut-n-paste the changes into the master version
   below the @VERSION@-0 lines.  So we have the history of the previous
   release.
