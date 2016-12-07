# Developing for PROJECT (DRAFT)

[TOC]

## Git Structure

The master Git for PROJECT resides on Github at
[https://github.com/PROJECT/XXX](https://github.com/PROJECT/XXX)

![git branches continually merging to the left from 3 lanes; float-right](doc/git_branches.svg
"git branch mechanics")

There are 3 main branches for development and a release branch for each
major release.

New contributions are done against the head of the Develop branch. The CI
systems will pick up the Github Pull Requests or the new patch from
Patchwork, run some basic build and functional tests and will merge them
into the branch automatically on success.

Code on the develop branch will then be further tested and reviewed by the
community and merged to master on a regular interval.

For each major release (1.0, 1.1 etc) a new release branch is created based
on the master.


## Programming language, Tools and Libraries

The core of PROJECT is written in C (gcc or clang supported). A few
non-essential scripts are implemented in Perl and Python. PROJECT requires
the following tools to build distribution packages: automake, autoconf,
texinfo, libtool and gawk and various libraries (i.e. libpam and libjson-c).

If your contribution requires a new library or other tool, then please
highlight this in your description of the change. Also make sure it’s
supported by all PROJECT platform OSes or provide a way to build without the
library (potentially without the new feature) on the other platforms.

Documentation should be written in Tex (.texi) or Markdown (.md) format with
preference on Markdown.


## Before Submitting your changes

* Format code (see [Code Styling requirements](#code-styling-requirements))
* Verify and acknowledge license (see [License for contributions](#license-for-contributions))
* Test building with various configurations:
    * `buildtest.sh`
* Verify building source distribution:
    * `make dist` (and try rebuilding from the resulting tar file)
* Run DejaGNU unit tests:
    * `make test`
* Document Regression Runs and plans for continued maintenance of the feature

### Changelog

The changelog will be the base for the release notes. A changelog entry for
your changes is usually not required and will be added based on your commit
messages by the maintainers. However, you are free to include an update to
the changelog with some better description. The changelog will be the base
for the release notes.


## Submitting Patches and Enhancements

### License for contributions

PROJECT is under a “GPLv2 or later” license. Any code submitted must be
released under the same license (preferred) or any license which allows
redistribution under this GPLv2 license (eg MIT License).

### Signed-off required

Submissions to PROJECT require a “Signed-off” in the patch or git commit.
We follow the same standard as the Linux Kernel Development.

> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

#### Using this Process

We have the same requirements for using the signed-off-by process as the Linux
kernel. In short, you need to include a signed-off-by tag in every patch:

* `Signed-off-by:` this is a developer's certification that he or she has the
right to submit the patch for inclusion into the project. It is an agreement to
the Developer's Certificate of Origin (above). Code without a proper signoff
cannot be merged into the mainline.

Please make sure to have a `Signed-off-by:` in each commit/patch or the patches
will be rejected until this is added.

If you are unfamiliar with this process, you should read the [official policy
at kernel.org](http://www.kernel.org/doc/Documentation/SubmittingPatches) and
you might find this article about [participating in the Linux community on the
Linux Foundation
website](http://www.linuxfoundation.org/content/how-participate-linux-community-0)
to be a helpful resource.


### Code submission - Github Pull Request (Strongly Preferred)

Preferred submission of code is by using a Github Pull Request against the
Develop branch. Code submitted by Pull Request will have an email generated to
the PROJECT-devel mailing list for review and the submission will be
automatically tested by one or more CI systems. Only after this test succeeds
(and the submission is based on the head of the develop branch), then it will
be automatically merged into the develop branch. In case of failed tests, it is
up to the submitter to either amend the request with further commits or close,
fix and create a new pull request.

Further (manual) code review and discussion happens after the merge into the
develop branch.


### Code submission - Mailing Patch to PROJECT-Devel list

As an alternative submission, a patch can be mailed to the PROJECT-Devel
mailing list. Preferred way to send the patch is using git send-mail. Patches
received on the mailing list will be picked up by Patchwork and tested against
the latest develop branch. After a further ACK by someone on the mailing list,
the patch is then merged into the develop branch.

Further (manual) code review and discussion happens after the merge into the
develop branch.

#### Sending patch to mailing list

The recommended way to send the patch (or series of NN patches) to the list is
by using ‘git send-email’ as follows (assuming they are the most recent NN
commit(s) in your git history:

```
git send-email -NN --annotate --to=XXX-Devel@XXX.org
```

If your commits do not already contain a `Signed-off-by` line, then use the
following version to add it (after making sure to be able to agree to the
Developer Certificate of Origin as outlined above):

```
git send-email -NN --annotate --signoff --to=XXX-Devel@XXX.org
```

Submitting multi-commit patches as a Github Pull Request is strongly encouraged
and will allow your changes to merge faster


## After submitting your changes

* Watch for Continuous Integration (CI) Test results
    * You should automatically receive an email with the test results within
      less than 2 hrs of the submission. If you don’t get the email, then check
      status on the github pull request (if submitted by pull request) or on
      Patchwork at
      [https://patchwork.PROJECT.org](https://patchwork.PROJECT.org) (if
      submitted as patch to mailing list).
    * Please notify PROJECT-Devel mailing list if you think something doesn’t
      work
* If the tests failed:
    * In general, expect the community to ignore the submission until the tests
      pass.
    * It is up to you to fix and resubmit.
        * This includes fixing existing dejagnu (“make test”) tests if your
          changes broke or changed them.
        * It also includes fixing distribution packages for the failing
          platforms (ie if new libraries are required)
        * Feel free to ask for help on PROJECT-Devel list
    * Go back to the submission process and repeat until the tests pass.
* If the tests pass:
    * If the changes are done as a pull request, then they should be
      automatically merged to the develop branch.
    * Changes sent to mailing list require a manual ACK to be merged and should
      be merged within 2 weeks. If you don’t see the merge or any
      reason/discussion on PROJECT-Devel, then please ask.
* Watch out for questions on the mailing list. At this time there will be a
  manual code review and further (longer) tests by various community members.
* Your submission is done once it is merged to the master branch. (which should
  happen every few weeks from the develop branch)


## Code Styling requirements

### File header required for new files added

New files need to have a Copyright header (see [License for
contributions](#license-for-contributions) above) added to the file. Preferred
form of the header is as follows:

```
/*
  Title/Function of file
  Copyright (C) 2016  Author’s Name

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
 */

#include <zebra.h>
```

### Adding Copyright claims to already existing file

When adding copyright claims for modifications to an existing file, please
preface the claim with "Portions: " on a line before it and indent the
"Copyright ..." string. If such a case already exists, add your indented claim
immediately after. E.g.:

```
Portions:
  Copyright (C) 2010 Entity A ....
  Copyright (C) 2016 Your name [optional brief change description]
```

### Code styling / format

GNU coding standards apply. Indentation follows the result of invoking GNU
indent (as of 2.2.8a) with the `-nut -nfc1` arguments.

```
indent -nut -nfc1 file_for_submission.c
```

Please don’t reformat existing files (or only sections modified by your
changes), even if they don’t follow the standard. This makes it very hard to
highlight the changes

### Changing / Deprecate an existing exported interface

If changing an exported interface, please try to deprecate the interface in an
orderly manner. If at all possible, try to retain the old deprecated interface
as is, or functionally equivalent. Make a note of when the interface was
deprecated and guard the deprecated interface definitions in the header file,
i.e.:

```
/* Deprecated: 20050406 */
#if !defined(QUAGGA_NO_DEPRECATED_INTERFACES)
#warning "Using deprecated <libname> (interface(s)|function(s))"
...
#endif /* QUAGGA_NO_DEPRECATED_INTERFACES */
```

This is to ensure that the core Quagga sources do not use the deprecated
interfaces (you should update Quagga sources to use new interfaces, if
applicable), while allowing external sources to continue to build. Deprecated
interfaces should be excised in the next unstable cycle.

Note: If you wish, you can test for GCC and use a function marked with the
`deprecated` attribute. However, you must provide the warning for other
compilers.  If changing or removing a command definition, ensure that you
properly deprecate it - use the `_DEPRECATED` form of the appropriate `DEFUN`
macro. This is critical. Even if the command can no longer function, you MUST
still implement it as a do-nothing stub.

Failure to follow this causes grief for systems administrators, as an upgrade
may cause daemons to fail to start because of unrecognised commands. Deprecated
commands should be excised in the next unstable cycle. A list of deprecated
commands should be collated for each release.


### Compile-Time conditional code

Many users access PROJECT via binary packages from 3rd party sources;
compile-time code puts inclusion/exclusion in the hands of the package
maintainer.  Please think very carefully before making code conditional at
compile time, as it increases regression testing, maintenance burdens, and user
confusion. In particular, please avoid gratuitous --enable-… switches to the
configure script - typically code should be good enough to be in PROJECT, or it
shouldn’t be there at all.

When code must be compile-time conditional, try have the compiler make it
conditional rather than the C pre-processor - so that it will still be checked
by the compiler, even if disabled. I.e. this:

```
if (SOME_SYMBOL)
      frobnicate();
```

rather than

```
#ifdef SOME_SYMBOL
frobnicate ();
#endif /* SOME_SYMBOL */
```

Note that the former approach requires ensuring that `SOME_SYMBOL` will be
defined (watch your `AC_DEFINE`s).

### Debug-Guards in code

Debugs are an important methodology to allow developers to fix issues
found in the code after it has been released.  The caveat here is
that the developer must remember that people will be using the code
at scale and in ways that can be unexpected for the original implementor.
As such debugs MUST be guarded in such a way that they can be turned off.
This PROJECT has the ability to turn on/off debugs from the CLI and it is
expected that the developer will use this convention to allow control
of their debugs.