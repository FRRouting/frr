import pytest
from lutil import luCommand

cmd='if [ ! -e ~frr/.ssh ] ; then  mkdir ~frr/.ssh ; openssl genpkey -algorithm RSA -out ~frr/.ssh/frr ; chown -R frr.frr ~frr/.ssh ; chmod -R go-rwx ~frr/.ssh ; fi ; ls -al ~frr/.ssh'
for r in range(0, 8):
    luCommand('r{}'.format(r),cmd,'frr$','pass','key file found')
