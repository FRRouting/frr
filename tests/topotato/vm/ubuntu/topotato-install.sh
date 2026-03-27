#!/bin/bash

cd /home/vagrant/dev/topotato
sudo sysctl -w kernel.unprivileged_userns_clone=1

echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections

sudo DEBIAN_FRONTEND=noninteractive apt install graphviz tshark \
   python3-venv wireshark-common python3-pip tini -y

pip install -r requirements.txt
