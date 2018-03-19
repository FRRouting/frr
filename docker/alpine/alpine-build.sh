#!/bin/sh

set -e

cd /dist

sudo apk --update add alpine-conf
sudo setup-apkcache /var/cache/apk
abuild-keygen -a -n
abuild checksum
abuild -r -P /pkgs/apk
