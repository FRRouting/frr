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