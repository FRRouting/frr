Specific Feature Development Branch
===================================

This document describes the process to request and manage a dedicated branch
on the FRR GitHub repo for the development of new features.

Why dedicated branch to develop new feature?
--------------------------------------------

Some new features need to be developed in a collaborative way
e.g. IS-IS Segment Routing, BGP-LS, PCC … and this specific development will
take time.

Providing a common Git reference will ease cooperation between partners.
Indeed, it is hard to synchronise independent Git Repo. Only main FRR GitHub
repo are known by everybody and private forks to create Pull Request are not
known by everybody. In addition, there no space on FRR web site or wiki to
publicly announce that someone is working on a given feature. FRR community
is, in general, aware about the development of a feature when Pull Request is
published, which is be too late for good cooperation.

Feature Branch characteristics
------------------------------

A dedicated branch for a specific feature collaborative development is created
as follow in the GitHub FRR repo (http://github.com/FRRouting/frr):

- dev-XXX where XXX is the acronyme of the feature e.g. dev-bgpls
- Feature branch is not linked to CI/CD chain, so will not trigger any tests
  not compilation when a Pull Request is submitted to this branch
- The README.md file from master branch is modified as follow:

::

  FRRouting XXX Development Branch
  ================================

  This special FRRouting branch is dedicated to the development of XXX.
  The code located under this branch is a **Work In Progress**. The code may
  compile or not, may run or not. In any case, this code **MUST NOT BE USED IN
  PRODUCTION**.

  FRRouting
  ---------

  FRR is free software that implements a ...


Process to Request Feature Branch
---------------------------------

Only feature listed in FRR Wiki Features Requests
(see https://github.com/FRRouting/frr/wiki/Feature-Requests) can be subject of
this process.

Everybody *(NOTE: another option is to limit this possibility to the mainteners
only which will simplify the process, but close the door to not mainteners)*
could ask for a new feature branch by following the bellow process:

- **Prerequisit:** If feature is not listed in FRR Wiki Features Requests,
  first create a new issue in FRR GitHub to request the new feature and wait
  the feature is added to the Wiki
- **Request:** [Send a simple mail is send to @frr-dev mailing list | Fill a
  new issue | Update issue of the feature] *(NOTE: we need to choose the
  appropriate method)* with a short description of the devlopment with the
  issue number *(if mail method is choosen)*, and, if known, the list of
  partners that express to work on. *(NOTE: these are the minimum information
  I thought of. Of course additional information could be added)*
- **Examination**: Request is disscussed during [the regular Tuesday meeting |
  the TSC meeting] *(NOTE: we need to choose between the 2 options)*.
- **Decision**: If request is approved, corresponding branch is created (see
  below). A mail is sent to the @frr-dev mailing list to announce the creation
  of the new branch and a link to that branch is added to the issue and the
  FRR Wiki Features Requests page. If it is rejected, a mail with the reasons
  of the rejection is also sent to the @frr-dev mailing list *(NOTE: if GitHub
  issue method is choosen for the request, above text must be adapted, but,
  I think that we could keep the announcement throuhg the mailing list)*.
- **Creation**: If the request is approved, branch **dev-XXX** is created by
  a TSC member or any personn that have the right to do it. A Owner of the
  feature branch is designated as the responsible of this new feature branch.
  The Owner is [a maintainers designated to shepherd the development on this
  feature branch | the requester of the feature branch who is promoted as
  maintainer to get commit rights on this branch] *(NOTE: we must decide if
  we go for a shepherded maintainer or promote the requester if (s)he is not
  already)*.


Feature Branch Life Cycle
-------------------------

Once created the Feature Branch is used as follow:

- Pull Requests are tagged with the corresponding “dev label” and assigned to
  the owner of the feature branch or the shepherded maintainer
- Optional: a light review is performed by contributors interested by this 
  development
- [Owner of the feature branch | Shepherded maintainers] *(NOTE: depends of
  what has been choosen previously)* commit the Pull Request
- Owner of the feature branch, if (s)he as the rights (i.e. the Owner is a
  maintainer or (s)he has been promoted - see above) could directly commit code

Once development is finished, README.md is replaced by the version from master
branch and a final rebase againts master (eventually after squashing, commit
cleaning, commit reordering …) is performed in order to submit a Pull Request
as usual.

Once the corresponding Pull Request is merged on the master, the feature branch
is removed. It is the responsability of the Owner of the feature branch to
backup the branch before its removal.
