Release Build Procedure for FRR maintainers
=========================================================

1) Rename branch (if needed)

.. code-block:: shell

        git clone git@github.com:FRRouting/frr.git
        cd frr
        git checkout dev/5.0
        git push origin :refs/heads/dev/5.0
        git push origin dev/5.0:refs/heads/stable/5.0

2) Checkout the new stable branch:

.. code-block:: shell

        git checkout stable/5.0

3) Update Changelog for RedHat Package:

        Edit :file:`redhat/frr.spec.in` and look for %changelog section:

        - Change last (top of list) entry from %{version} to previous
          fixed version number, ie

          ``* Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - %{version}``

          to

          ``* Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - 3.0.2``

        - Add new entry (top of list) with ``%{version}`` tag and changelog
          for version.
          Make sure to watch for format, ie day is always 2 chars, with 1st
          char a space if single digit

4) Update Changelog for Debian Packages:

        Edit :file:`debianpkg/changelog.in`:

        - Change last (top of list) entry from @VERSION@ to previous
          fixed version number, ie

          ``frr (@VERSION@) RELEASED; urgency=medium``

          to

          ``frr (3.0.2) RELEASED; urgency=medium``

        - Add new entry (top of list) with @VERSION@ tag and changelog for version

5) Change main version number:

    - Edit :file:`configure.ac` and change version in ``AC_INIT`` command
    - Create new entry with version as ``%{version}`` tag

6) Test building at least a Redhat and a Ubuntu Package (or create a PR
   to have the CI system test them)

7) Commit the changes (add changelog to commit message)

8) Create Tag for Version:

.. code-block:: shell

        git tag -a frr-5.0 -m "FRRouting Release 5.0"

9) Push commit and Tags and watch for errors on CI

.. code-block:: shell

        git push
        git push --tags

10) Kick off the Release build plan on the CI system for the correct release

11) Send Release Announcement with changes to ``announce@lists.frrouting.org``

12) Kick off the Snapcraft build plan for the correct release

13) After CI plans succeed, release on github.

        Go to https://github.com/FRRouting/frr/releases and select "Draft a new release"

14) Deploy Snapcraft Release (after CI system finishes the tests for snapcraft testplan)
