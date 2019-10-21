.. _frr-release-procedure:

FRR Release Procedure
=====================

``<version>`` - version to be released, e.g. 7.3
``origin`` - FRR upstream repository

1. Checkout ``dev/<version>``.

   .. code-block:: console

      git checkout dev/<version>

2. Create and push a new branch called ``stable/<version>`` based on the
   ``dev/<version>`` branch.

   .. code-block:: console

      git checkout -b stable/<version>
      git push origin stable/<version>:refs/heads/stable/<version>

3. Update Changelog for Red Hat Packages:

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

4. Update Changelog for Debian Packages:

   Edit :file:`changelog-auto.in`:

   - Change last (top of list) entry from ``@VERSION@`` to the **last**
     released version number. For example, if ``<version>`` is ``7.3`` and the
     last public release was ``7.2``, you would use ``7.2``, changing the file
     like so::

        frr (@VERSION@) RELEASED; urgency=medium

     to::

        frr (7.2) RELEASED; urgency=medium

   - Add a new entry to the top of the list with a ``@VERSION@`` tag. Make sure
     to watch the format.

   - Add the changelog text below this entry.

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

5. Change main version number:

    - Edit :file:`configure.ac` and change version in the ``AC_INIT`` command
      to ``<version>``

6. Commit the changes, adding the changelog to the commit message. Follow all
   existing commit guidelines.

7. Create and submit a GitHub pull request, with the ``HEAD`` set to
   ``stable/<version>`` and the base set to the upstream ``master`` branch.
   Allow NetDef CI to complete its run and verify that all package builds were
   successful.

8. Create a git tag for the version:

   .. code-block:: console

      git tag -a frr-<version> -m "FRRouting Release <version>"

9. Push the commit and new tag.

   .. code-block:: console

      git push origin stable/<version>:refs/head/stable/<version>
      git push origin frr-<version>

10. Kick off the Release build plan on the CI system for the correct release.
    Contact Martin Winter for this step. Ensure all release packages build
    successfully.

11. Kick off the Snapcraft build plan for the release.

12. Acquire the release RPM binary packages from Martin Winter.

13. On GitHub, go to the <https://github.com/FRRouting/frr/releases>_ and click
    "Draft a new release". Write a release announcement. The release
    announcement should follow the template in
    ``release-announcement-template.md``, located next to this document. Check
    for spelling errors, and optionally (but preferably) have other maintainers
    proofread the announcement text.

    Attach **only** the binary RPM packages to the GitHub release using
    GitHub's attachment functionality. Do not attach Debian packages. Do not
    attach source tarballs - these will be generated and attached by GitHub
    automatically. Do not publish the release yet.

14. Contact the current Debian maintainer for FRR to get new Debian packages
    built and published on our APT repository at https://deb.frrouting.net/.
    Ensure the webpage text is updated. Verify that new packages install
    successfully on a vanilla Debian installation using the instructions on the
    webpage.

15. Deploy Snapcraft release (after CI system finishes the tests for snapcraft
    testplan).

16. Update the Read The Docs instance to being publishing documentation built
    off the ``stable/<version>`` branch. Contact Quentin Young for this step.

17. Publish the GitHub release.

18. Clone the ``frr-www`` repository:

    .. code-block:: console

       git clone https://github.com/FRRouting/frr-www.git

19. Add a new release announcement, using a previous announcement as template:

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

20. Deploy the updated ``frr-www`` on the frrouting.org web server and verify
    that the announcement text is visible.

21. Send an email to ``announce@lists.frrouting.org``. The text of this email
    should include the text from the GitHub release.
