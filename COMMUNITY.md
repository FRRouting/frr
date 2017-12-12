Developing for FRRouting
=========================

## Table of Contents

[TOC]

## General note on this document

This document is "descriptive/post-factual" in that it documents pratices that
are in use; it is not "definitive/pre-factual" in prescribing practices.

This means that when a procedure changes, it is agreed upon, then put into
practice, and then documented here.  If this document doesn't match reality,
it's the document that needs to be updated, not reality.


## Git Structure

The master Git for FRRouting resides on Github at
[https://github.com/frrouting/frr](https://github.com/FRRouting/frr)

![git branches continually merging to the left from 3 lanes; float-right](doc/git_branches.svg
"git branch mechanics")

There is one main branch for development and a release branch for each major
release.

New contributions are done against the head of the master branch. The CI
systems will pick up the Github Pull Requests or the new patch from Patchwork,
run some basic build and functional tests.

For each major release (1.0, 1.1 etc) a new release branch is created based on
the master.

There was an attempt to use a "develop" branch automatically maintained by the
CI system.  This is not currently in active use, though the system is
operational.  If the "develop" branch is in active use and this paragraph is
still here, this document obviously wasn't updated.


## Programming language, Tools and Libraries

The core of FRRouting is written in C (gcc or clang supported) and makes use of
GNU compiler extensions. A few non-essential scripts are implemented in Perl
and Python. FRRouting requires the following tools to build distribution
packages: automake, autoconf, texinfo, libtool and gawk and various libraries
(i.e. libpam and libjson-c).

If your contribution requires a new library or other tool, then please
highlight this in your description of the change. Also make sure it’s supported
by all FRRouting platform OSes or provide a way to build without the library
(potentially without the new feature) on the other platforms.

Documentation should be written in Tex (.texi) or Markdown (.md) format with a
preference for Markdown.


## Mailing lists

Italicized lists are private.

| Topic                          | List                         |
|--------------------------------|------------------------------|
| Development                    | dev@lists.frrouting.org      |
| Users & Operators              | frog@lists.frrouting.org     |
| Announcements                  | announce@lists.frrouting.org |
| _Security_                     | security@lists.frrouting.org |
| _Technical Steering Committee_ | tsc@lists.frrouting.org      |

The Development list is used to discuss and document general issues
related to project development and governance. The public Slack
instance, frrouting.slack.com, and weekly technical meetings provide a
higher bandwidth channel for discussions.  The results of such
discussions must be reflected in updates, as appropriate, to code (i.e.,
merges), [github](https://github.com/FRRouting/frr/issues) tracked
issues, and for governance or process changes, updates to the
Development list and either this file or information posted at
[https://frrouting.org/](https://frrouting.org/).


### Changelog

The changelog will be the base for the release notes. A changelog entry for
your changes is usually not required and will be added based on your commit
messages by the maintainers. However, you are free to include an update to
the changelog with some better description. The changelog will be the base
for the release notes.


## Submitting Patches and Enhancements

### Pre-submission Checklist

* Format code (see [Developer's Guidelines](#developers-guidelines))
* Verify and acknowledge license (see [License for contributions](#license-for-contributions))
* Ensure you have properly signed off (see [Signing Off](#signing-off))
* Test building with various configurations:
    * `buildtest.sh`
* Verify building source distribution:
    * `make dist` (and try rebuilding from the resulting tar file)
* Run unit tests:
    * `make test`
* Document Regression Runs and plans for continued maintenance of the feature

### License for contributions

FRRouting is under a “GPLv2 or later” license. Any code submitted must be
released under the same license (preferred) or any license which allows
redistribution under this GPLv2 license (eg MIT License).

### Signing Off

Code submitted to FRRouting must be signed off. We have the same requirements
for using the signed-off-by process as the Linux kernel. In short, you must
include a signed-off-by tag in every patch.

`Signed-off-by:` this is a developer's certification that he or she has the
right to submit the patch for inclusion into the project. It is an agreement to
the Developer's Certificate of Origin (below). Code without a proper signoff
can not and will not be merged.

If you are unfamiliar with this process, you should read the [official policy
at kernel.org](https://www.kernel.org/doc/html/latest/process/submitting-patches.html) and
you might find this article about [participating in the Linux community on the
Linux Foundation
website](http://www.linuxfoundation.org/content/how-participate-linux-community-0)
to be a helpful resource.

In short, when you sign off on a commit, you assert your agreement to all of
the following:

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

### What do I submit my changes against?

We've documented where we would like to have the different fixes applied at
https://github.com/FRRouting/frr/wiki/Where-Do-I-create-a-Pull-Request-against%3F
If you are unsure where your submission goes, look at that document or ask a
project maintainer.

### Github pull requests

The preferred method of submitting changes is a Github pull request. Code
submitted by pull request will be automatically tested by one or more CI
systems. Once the automated tests succeed, other developers will review your
code for quality and correctness. After any concerns are resolved, your code
will be merged into the branch it was submitted against.

### Patch submission via mailing list

As an alternative submission method, a patch can be mailed to the development
mailing list. Patches received on the mailing list will be picked up by
Patchwork and tested against the latest development branch.

The recommended way to send the patch (or series of NN patches) to the list is
by using `git send-email` as follows (assuming they are the N most recent
commit(s) in your git history:

```
git send-email -NN --annotate --to=dev@lists.frrouting.org
```

If your commits do not already contain a `Signed-off-by` line, then use the
following command to add it (after making sure you agree to the Developer
Certificate of Origin as outlined above):

```
git send-email -NN --annotate --signoff --to=dev@lists.frrouting.org
```

Submitting multi-commit patches as a Github pull request is **strongly
encouraged** and increases the probability of your patch getting reviewed and
merged in a timely manner.


## After submitting your changes

* Watch for Continuous Integration (CI) Test results
    * You should automatically receive an email with the test results within
      less than 2 hrs of the submission. If you don’t get the email, then check
      status on the github pull request (if submitted by pull request) or on
      Patchwork at
      [https://patchwork.frrouting.org](https://patchwork.frrouting.org) (if
      submitted as patch to mailing list).
    * Please notify the development mailing list if you think something doesn’t
      work.
* If the tests failed:
    * In general, expect the community to ignore the submission until the tests
      pass.
    * It is up to you to fix and resubmit.
        * This includes fixing existing unit (“make test”) tests if your
          changes broke or changed them.
        * It also includes fixing distribution packages for the failing
          platforms (ie if new libraries are required).
        * Feel free to ask for help on the development list.
    * Go back to the submission process and repeat until the tests pass.
* If the tests pass:
    * Wait for reviewers. Someone will review your code or be assigned to
      review your code.
    * Respond to any comments or concerns the reviewer has.
    * After all comments and concerns are addressed, expect your patch to be
      merged.
* Watch out for questions on the mailing list. At this time there will be a
  manual code review and further (longer) tests by various community members.
* Your submission is done once it is merged to the master branch.


## Developer's Guidelines

### Commit messages

Commit messages should be formatted in the same way as Linux kernel commit
messages. The format is roughly

```
dir: short summary

extended summary
```

`dir` should be the top level source directory under which the change was made.
For example, a change in bgpd/rfapi would be formatted as:

`bgpd: short summary`

The first line should be no longer than 50 characters. Subsequent lines should
be wrapped to 72 characters.

### Source file header

New files need to have a Copyright header (see [License for
contributions](#license-for-contributions) above) added to the file. Preferred
form of the header is as follows:

```
/*
 * Title/Function of file
 * Copyright (C) YEAR  Author’s Name
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
```

### Adding copyright claims to existing files

When adding copyright claims for modifications to an existing file, please
preface the claim with "Portions: " on a line before it and indent the
"Copyright ..." string. If such a case already exists, add your indented claim
immediately after. E.g.:

```
Portions:
  Copyright (C) 2010 Entity A ....
  Copyright (C) 2016 Your name [optional brief change description]
```

### Code formatting

FRR uses Linux kernel style except where noted below. Code which does not
comply with these style guidelines will not be accepted.

To assist with compliance, in the project root there is a .clang-format
configuration file which can be used with the `clang-format` tool from the LLVM
project. In the `tools/` directory there is a Python script named `indent.py`
that wraps clang-format and handles some edge cases specific to FRR. If you are
submitting a new file, it is recommended to run that script over the new file
after ensuring that the latest stable release of `clang-format` is in your
PATH.

**Whitespace changes in untouched parts of the code are not acceptable in
patches that change actual code.**  To change/fix formatting issues, please
create a separate patch that only does formatting changes and nothing else.

#### Style documentation
Kernel and BSD styles are documented externally:

* [https://www.kernel.org/doc/html/latest/process/coding-style.html](https://www.kernel.org/doc/html/latest/process/coding-style.html)
* [http://man.openbsd.org/style](http://man.openbsd.org/style)

For GNU coding style, use `indent` with the following invocation:

```
indent -nut -nfc1 file_for_submission.c
```

#### Exceptions

FRR project code comes from a variety of sources, so there are some stylistic
exceptions in place. They are organized here by branch.

**For `master`:**

BSD coding style applies to:

* `ldpd/`

`babeld` uses, approximately, the following style:

* K&R style braces
* Indents are 4 spaces
* Function return types are on their own line


**For `stable/3.0` and `stable/2.0`:**

GNU coding style apply to the following parts:

* `lib/`
* `zebra/`
* `bgpd/`
* `ospfd/`
* `ospf6d/`
* `isisd/`
* `ripd/`
* `ripngd/`
* `vtysh/`

BSD coding style applies to:

* `ldpd/`


### Documentation

FRRouting is a large and complex software project developed by many different
people over a long period of time. Without adequate documentation, it can be
exceedingly difficult to understand code segments, APIs and other interfaces.
In the interest of keeping the project healthy and maintainable, you should
make every effort to document your code so that other people can understand
what it does without needing to closely read the code itself.

Some specific guidelines that contributors should follow are:

* Functions exposed in header files should have descriptive comments above
  their signatures in the header file. At a minimum, a function comment should
  contain information about the return value, parameters, and a general summary
  of the function's purpose. Documentation on parameter values can be omitted
  if it is (very) obvious what they are used for.

  Function comments must follow the style for multiline comments laid out in
  the kernel style guide.

Example:

```
/*
 * Determines whether or not a string is cool.
 *
 * @param text - the string to check for coolness
 * @param is_clccfc - whether capslock is cruise control for cool
 * @return 7 if the text is cool, 0 otherwise
 */
int check_coolness(const char *text, bool is_clccfc);
```

The Javadoc-style annotations are not required, but you should still strive to
make it equally clear what parameters and return values are used for.

* Static functions should have descriptive comments in the same form as above
  if what they do is not immediately obvious. Use good engineering judgement
  when deciding whether a comment is necessary. If you are unsure, document
  your code.

* Global variables, static or not, should have a comment describing their use.

* **For new code in `lib/`, these guidelines are hard requirements.**


If you are contributing code that adds significant user-visible functionality
or introduces a new API, please document it in `doc/`.  Markdown and LaTeX are
acceptable formats, although Markdown is currently preferred for new
documentation. This may change in the near future.

Finally, if you come across some code that is undocumented and feel like going
above and beyond, document it! We absolutely appreciate and accept patches that
document previously undocumented code.

### Compile-time conditional code

Many users access FRR via binary packages from 3rd party sources; compile-time
code puts inclusion/exclusion in the hands of the package maintainer.  Please
think very carefully before making code conditional at compile time, as it
increases regression testing, maintenance burdens, and user confusion. In
particular, please avoid gratuitous `--enable-…` switches to the configure
script - in general, code should be of high quality and in working condition,
or it shouldn’t be in FRR at all.

When code must be compile-time conditional, try have the compiler make it
conditional rather than the C pre-processor so that it will still be checked by
the compiler, even if disabled. For example,

```
if (SOME_SYMBOL)
      frobnicate();
```

is preferred to

```
#ifdef SOME_SYMBOL
frobnicate ();
#endif /* SOME_SYMBOL */
```

Note that the former approach requires ensuring that `SOME_SYMBOL` will be
defined (watch your `AC_DEFINE`s).

### Debug-guards in code

Debugging statements are an important methodology to allow developers to fix
issues found in the code after it has been released.  The caveat here is that
the developer must remember that people will be using the code at scale and in
ways that can be unexpected for the original implementor.  As such debugs
**MUST** be guarded in such a way that they can be turned off.  FRR has the
ability to turn on/off debugs from the CLI and it is expected that the
developer will use this convention to allow control of their debugs.

### CLI changes

CLI's are a complicated ugly beast.  Additions or changes to the CLI should use
a DEFUN to encapsulate one setting as much as is possible.  Additionally as new
DEFUN's are added to the system, documentation should be provided for the new
commands.

### Backwards Compatibility

As a general principle, changes to CLI and code in the lib/ directory should be
made in a backwards compatible fashion. This means that changes that are purely
stylistic in nature should be avoided, e.g., renaming an existing macro or
library function name without any functional change. When adding new parameters
to common functions, it is also good to consider if this too should be done in
a backward compatible fashion, e.g., by preserving the old form in addition to
adding the new form.

This is not to say that minor or even major functional changes to CLI and
common code should be avoided, but rather that the benefit gained from a change
should be weighed against the added cost/complexity to existing code.  Also,
that when making such changes, it is good to preserve compatibility when
possible to do so without introducing maintenance overhead/cost.  It is also
important to keep in mind, existing code includes code that may reside in
private repositories (and is yet to be submitted) or code that has yet to be
migrated from Quagga to FRR.

That said, compatibility measures can (and should) be removed when either:

* they become a significant burden, e.g. when data structures change and the
  compatibility measure would need a complex adaptation layer or becomes
  flat-out impossible
* some measure of time (dependent on the specific case) has passed, so that the
  compatibility grace period is considered expired.

In all cases, compatibility pieces should be marked with compiler/preprocessor
annotations to print warnings at compile time, pointing to the appropriate
update path.  A `-Werror` build should fail if compatibility bits are used.

### Miscellaneous

When in doubt, follow the guidelines in the Linux kernel style guide, or ask on
the development mailing list / public Slack instance.
