TOPOTATO TESTING FRAMEWORK (WORK IN PROGRESS)
==========================


TODOs / Known issues
====================

- skipping further tests after a TopotatoModifier failure is not implemented.
  A TopotatoModifier failure should skip everything after it since a failed
  modifier means the testbed is in an indeterminate state.
- some style requirements should be automatically enforced, e.g. missing
  docstrings should cause a failure.
- ExaBGP support is work in progress.
- terminal-on-failure (potatool) is work in progress.
- integrated-config mode for FRR needs to be supported.
- FreeBSD support has not been tested & updated in ages and is probably just
  completely broken right now.
- `pytest-xdist` interop has not been tested & updated in ages, it probably
  also breaks in funny and hilarious ways.
- add more self-tests
- protomato.js needs a bunch more work.
    - re-add xrefs lookup to source code
    - short-decode more protocols
- an `index.html` file should be generated with an overview of a test run.
- add a bunch of attributes on the JUnit XML with machine parseable exception
  location.


Installation
============

Requirements
- Python >= 3.8

Commands:

```sh
sysctl -w kernel.unprivileged_userns_clone=1
mkdir /etc/frr

# In case you don't want to follow the <<apt install steps>> install these manually:
# unshare - run program with some namespaces unshared from parent
# nsenter - run program with namespaces of other processes
# tini - https://github.com/krallin/tini
# dumpcap - Dump network traffic
# ip - show / manipulate routing, network devices, interfaces and tunnels

apt-get satisfy \
    'graphviz' 'tshark (>=4.0)' 'wireshark-common (>=4.0)' 'tini' \
    'python3 (>=3.8)' \
    'python3-pytest (>=6.1)' 'python3-pytest-xdist' \
    'python3-typing-extensions' 'python3-docutils' 'python3-pyinotify' \
    'python3-scapy (>=2.4.5)' 'python3-exabgp (>=4.2)' \
    'python3-jinja2 (>=3.1)' 'python3-lxml' 'python3-markupsafe' \
    #
```

Running tests
=============

To run the whole test suite:

```sh
./run_userns.sh --frr-builddir=/path/to/frr/build --log-cli-level=DEBUG -v -v -x
```

To test a single file:

```sh
# ./run_userns.sh --frr-builddir=/path/to/frr/build --log-cli-level=DEBUG -v -v -x <<FILENAME.py>>
./run_userns.sh --frr-builddir=/home/brunobernard/frr/ --log-cli-level=DEBUG -v -v -x test_demo.py 
```

Coding style
============

topotato is aiming for (though not achieving everywhere) the following style
guidelines:

- black code formatting should be applied to topotato core files (`topotato/*.py`)
    - not all files meet this formatting requirement yet
    - TODO: make some decision about topotato tests; unfortunately black makes
      them look kinda shitty...

- pylint should be clean, with some rules disabled:
  `pylint -d too-few-public-methods,invalid-name,missing-class-docstring,missing-function-docstring,line-too-long,consider-using-f-string`
    - add `# pylint:` comments where needed.  But use the "long" names, not the short like "C0301".

- mypy should be clean
    - FIXME: currently broken by missing scapy type annotations

Files should have a header consisting of the following things, in order:

1. `#!/usr/bin/env python3` if the file is executable
    - TBD: remove `env`?
2. `# SPDX-License-Identifier: GPL-2.0-or-later` (other licenses should not be used for topotato)
3. `# Copyright (C) ...` (the SPDX identifier does NOT replace this)
4. docstring for the test or module
5. for tests: `from topotato.v1 import *`
6. other imports


Development Environment (VM)
============

Topotato has support for VM, it uses Vagrant to support those different environment:

### Installation

- Download Vagrant (https://developer.hashicorp.com/vagrant/downloads)
- Ensure that the `vagrant` cli is ready. (type `vagrant` command)
- Ubuntu Host
  - Install virtualbox provider `sudo apt install virtualbox`
  - Install vb-guest: `vagrant plugin install vagrant-vbguest`
  - Do `vagrant up --provider virtualbox`


TODO (for tests):

- maybe `__topotato_version__ = 1234`?
  (for future updates to the topotato core to keep compatibility)
- maybe `__topotests_file__ = 'foo/bar.py'`?
  (file under `tests/topotests` in FRR that matches this test)
- maybe `__topotests_gitrev__ = '94cd8f24b8fba3d113951418bc4216540bac5ea2'`?
  (revision of FRR git where topotests matches)

(These would be placed **above** `from topotato.v1 import *`)

FRR workflow applies to commit message text, i.e.:

- Subject line should start with `topotato: ` (or `topotato/something:`)
- `Signed-off-by:` is required


Alternate setup if distro packages are unavailable or too old
=============================================================

- Installation of packages[^1]:

```sh
pip install -U setuptools # exabgp has some issues installing without them
pip install -r requirements.txt
```

[^1]: In case, python modules cannot be installed into the system.
    ```sh
    apt-get install python3-venv
    python3 -m venv .venv
    source .venv/bin/activate
    ```
