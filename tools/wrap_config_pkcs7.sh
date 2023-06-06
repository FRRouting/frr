#!/bin/sh
# Example script for "service wrap-config".  Uses OpenSSL to do PKCS7.
#
# required key & cert creation:
#   openssl genrsa -out test.key 4096
#   openssl x509 -new -key test.key -subj '/CN=test' -out test.crt

key="/etc/frr/test.key"
crt="/etc/frr/test.crt"

case "$1" in
load)
	exec openssl smime -decrypt -inform PEM -inkey "$key"
	;;
save)
	exec openssl smime -encrypt -outform PEM "$crt"
	;;
esac
exit 1
