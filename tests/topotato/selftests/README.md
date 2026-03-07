topotato self-tests
===================


This is a bunch of tests that test some of **topotato's functionality itself**.
I.e. these are not topotato tests, but rather tests that topotato works
correctly.

**These tests are only relevant when making changes to topotato itself.  Some
pytest knowledge and python debugging skills are expected.**


Installation
============

Follow regular topotato installation instructions.  **If you run into any
issues, you are expected to be able to debug them yourself.**

Running tests
=============

```sh
cd selftests
python3 -mpytest
```
