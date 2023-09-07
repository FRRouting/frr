.. _frr-release-procedure:

FRR Release Procedure
=====================

``<version>`` - version to be released, e.g. 7.3
``origin`` - FRR upstream repository

Stage 1 - Preparation
---------------------

#. Prepare changelog for the new release

   Note: use ``tools/release_notes.py`` to help draft release notes changelog

#. Checkout the existing ``dev/<version>`` branch.

   .. code-block:: console

      git checkout dev/<version>

#. Create and push a new branch called ``stable/<version>`` based on the
   ``dev/<version>`` branch.

   .. code-block:: console

      git checkout -b stable/<version>

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

#. Change main version number:

   - Edit :file:`configure.ac` and change version in the ``AC_INIT`` command
     to ``<version>``

   Add and commit this change. This commit should be separate from the commit
   containing the changelog. The commit message should be::

      FRR Release <version>

   The version field should be complete; i.e. for ``8.0.0``, the version should
   be ``8.0.0`` and not ``8.0`` or ``8``.


Stage 2 - Staging
-----------------

#. Push the stable branch to a new remote branch prefixed with ``rc``::

      git push origin stable/<version>:rc/version

   This will trigger the NetDEF CI, which serve as a sanity check on the
   release branch. Verify that all tests pass and that all package builds are
   successful. To do this, go to the NetDEF CI located here:

   https://ci1.netdef.org/browse/FRR-FRR

   In the top left, look for ``rc-<version>`` in the "Plan branch" dropdown.
   Select this version. Note that it may take a few minutes for the CI to kick
   in on this new branch and appear in the list.

#. Push the stable branch:

   .. code-block:: console

      git push origin stable/<version>:refs/heads/stable/<version>

#. Create and push a git tag for the version:

   .. code-block:: console

      git tag -a frr-<version> -m "FRRouting Release <version>"
      git push origin frr-<version>

#. Create a new branch based on ``master``, cherry-pick the commit made earlier
   that added the changelogs, and use it to create a PR against ``master``.
   This way ``master`` has the latest changelog for the next cycle.

#. Kick off the "Release" build plan on the CI system for the correct release.
   Contact Martin Winter for this step. Ensure all release packages build
   successfully.

#. Kick off the Snapcraft build plan for the release.

#. Build Docker images

   1. Log into the Netdef Docker build VM
   2. ``sudo -su builduser``
   3. Suppose we are releasing 8.5.0, then ``X.Y.Z`` is ``8.5.0``. Run this:

      .. code-block:: console

         cd /home/builduser/frr
         TAG=X.Y.Z
         git fetch --all
         git checkout frr-$TAG
         docker buildx build --platform linux/amd64,linux/arm64,linux/ppc64le,linux/s390x,linux/arm/v7,linux/arm/v6 -f docker/alpine/Dockerfile -t quay.io/frrouting/frr:$TAG --push .
         git tag docker/$TAG
         git push origin docker/$TAG

      This will build a multi-arch image and upload it to Quay, as well as
      create a git tag corresponding to the commit that the image was built
      from and upload that to Github. It's important that the git tag point to
      the exact codebase that was used to build the docker image, so if any
      changes need to be made on top of the ``frr-$TAG`` release tag, make
      sure these changes are committed and pointed at by the ``docker/X.Y.Z``
      tag.


Stage 3 - Publish
-----------------

#. Upload both the Debian and RPM packages to their respective repositories.

#. Coordinate with the maintainer of FRR's RPM repository to publish the RPM
   packages on that repository. Update the repository webpage. Verify that the
   instructions on the webpage work and that FRR is installable from the
   repository on a Red Hat system.

   Current maintainer: *Martin Winter*

#. Coordinate with the maintainer of FRR Debian package to publish the Debian
   packages on that repository. Update the repository webpage. Verify that the
   instructions on the webpage work and that FRR is installable from the
   repository on a Debian system.

   Current maintainer: *Jafar Al-Gharaibeh*

#. Log in to the Read The Docs instance. in the "FRRouting" project, navigate
   to the "Overview" tab. Ensure there is a ``stable-<version>`` version listed
   and that it is enabled. Go to "Admin" and then "Advanced Settings". Change
   "Default version" to the new version. This ensures that the documentation
   shown to visitors is that of the latest release by default.

   This step must be performed by someone with administrative access to the
   Read the Docs instance.

#. On GitHub, go to the <https://github.com/FRRouting/frr/releases>_ and click
   "Draft a new release". Write a release announcement. The release
   announcement should follow the template in
   ``release-announcement-template.md``, located next to this document. Check
   for spelling errors, and optionally (but preferably) have other maintainers
   proofread the announcement text.

   Do not attach any packages or source tarballs to the GitHub release.

   Publish the release once it is reviewed.

#. Deploy Snapcraft release. Remember that this will automatically upgrade Snap
   users.

   Current maintainer: *Martin Winter*

#. Build and publish the Docker containers.

   Current maintainer: *Quentin Young*

#. Clone the ``frr-www`` repository:

   .. code-block:: console

      git clone https://github.com/FRRouting/frr-www.git

#. Add a new release announcement, using a previous announcement as template:

   .. code-block:: console

      cp content/release/<old-version>.md content/release/<new-version>.md

   Paste the GitHub release announcement text into this document, and **remove
   line breaks**. In other words, this::

      This is one continuous
      sentence that should be
      rendered on one line

   Needs to be changed to this::

      This is one continuous sentence that should be rendered on one line

   This is very important otherwise the announcement will be unreadable on the
   website.

   To get the number of commiters and commits, here is a couple of handy commands:

   .. code-block:: console

      # The number of commits
      % git log --oneline --no-merges base_8.2...base_8.1 | wc -l

      # The number of commiters
      % git shortlog --summary --no-merges base_8.2...base_8.1 | wc -l

   Make sure to add a link to the GitHub releases page at the top.

#. Deploy the updated ``frr-www`` on the frrouting.org web server and verify
   that the announcement text is visible.

#. Update readthedocs.org (Default Version) for https://docs.frrouting.org to
   be the version of this latest release.

#. Send an email to ``announce@lists.frrouting.org``. The text of this email
   should include text as appropriate from the GitHub release and a link to the
   GitHub release, Debian repository, and RPM repository.
