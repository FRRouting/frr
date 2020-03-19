#currently fails if key created after startup
from lutil import luCommand
cmd='mv ~frr/.ssh/frr- ~frr/.ssh/frr ; ls -al ~frr/.ssh'
for r in range(0, 8):
    luCommand('r{}'.format(r),cmd,'frr$','pass','key file found')
