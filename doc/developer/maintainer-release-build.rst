Release Build Procedure for FRR Maintainers
===========================================

1. Rename branch (if needed)

.. code-block:: shell

   git clone git@github.com:FRRouting/frr.git
   cd frr
   git checkout dev/5.0
   git push origin :refs/heads/dev/5.0
   git push origin dev/5.0:refs/heads/stable/5.0

2. Checkout the new stable branch:

.. code-block:: shell

   git checkout stable/5.0

3. Update Changelog for RedHat Package:

   Edit :file:`redhat/frr.spec.in` and look for the ``%changelog`` section:

   - Change last (top of list) entry from ``%{version}`` to previous fixed
     version number, i.e.::

        * Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - %{version}

     to::

        * Tue Nov  7 2017 Martin Winter <mwinter@opensourcerouting.org> - 3.0.2

   - Add new entry to the top of the list with ``%{version}`` tag and changelog
     for version.
     Make sure to watch the format, i.e. the day is always 2 characters, with
     the 1st character being a space if the day is one digit.

4. Update Changelog for Debian Packages:

   Edit :file:`debian/changelog-auto.in`:

   - Change last (top of list) entry from ``@VERSION@`` to previous fixed
     version number, i.e.::

        frr (@VERSION@) RELEASED; urgency=medium

     to::

        frr (3.0.2) RELEASED; urgency=medium

   - Add a new entry to the top of the list with a ``@VERSION@`` tag and
     changelog for version.

5. Change main version number:

    - Edit :file:`configure.ac` and change version in the ``AC_INIT`` command
    - Create a new entry with the version as ``%{version}`` tag

6. Test building at least a Red Hat and Ubuntu package (or create a PR to have
   the CI system test them)

7. Commit the changes, adding the changelog to the commit message

8. Create a git tag for the version:

   .. code-block:: shell

      git tag -a frr-5.0 -m "FRRouting Release 5.0"

9. Push the commit and tag(s) and watch for errors on CI:

   .. code-block:: shell

      git push
      git push --tags

10. Kick off the Release build plan on the CI system for the correct release

11. Send a Release Announcement with changes to
    ``announce@lists.frrouting.org``

12. Kick off the Snapcraft build plan for the correct release

13. After CI plans succeed, release on GitHub by going to
    https://github.com/FRRouting/frr/releases and selecting "Draft a new
    release".

14. Deploy Snapcraft release (after CI system finishes the tests for snapcraft
    testplan)
