TOPOTATO TESTING FRAMEWORK (WORK IN PROGRESS)
==========================


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

apt-get install graphviz tshark python3-venv wireshark-common
wget https://github.com/krallin/tini/releases/download/v0.19.0/tini -O /bin/local/tini
```

Setup environments:
===================

- Installation of packages[^1]:

```sh
pip install -r requirements.txt
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




[^1]: In case, python modules cannot be installed into the system.
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate
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
5. for tests: `from topotato import *`
6. other imports

TODO (for tests):

- maybe `__topotato_version__ = 1234`?
  (for future updates to the topotato core to keep compatibility)
- maybe `__topotests_file__ = 'foo/bar.py'`?
  (file under `tests/topotests` in FRR that matches this test)
- maybe `__topotests_gitrev__ = '94cd8f24b8fba3d113951418bc4216540bac5ea2'`?
  (revision of FRR git where topotests matches)

(These would be placed **above** `from topotato import *`)

FRR workflow applies to commit message text, i.e.:

- Subject line should start with `topotato: ` (or `topotato/something:`)
- `Signed-off-by:` is required
