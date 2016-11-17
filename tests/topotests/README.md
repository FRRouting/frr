# Quagga Topology Tests with Mininet

## Installation of Mininet for running tests
Only tested with Ubuntu 16.04

Instructions are the same for all setups (ie ExaBGP is only used for BGP tests)

### Installing Mininet Infrastructure:

1. apt-get install mininet
2. apt-get install python-pip
3. apt-get install iproute
4. pip install ipaddr
5. pip install exabgp
6. useradd -d /var/run/exabgp/ -s /bin/false exabgp

### Quagga Installation
Quagga needs to be installed separatly. It is assume to be configured like the standard Ubuntu Packages:

- Binaries in /usr/lib/quagga
- Running under user quagga, group quagga
- vtygroup: quaggavty
- config directory: /etc/quagga

No Quagga config needs to be done and no Quagga daemons should be run ahead
of the test. They are all started as part of the test

## Executing Tests

Go to test directory and execute python script. 
Test will run all on it's own and return non-zero exit code if it fails.

For the simulated topology, see the description in the python file
