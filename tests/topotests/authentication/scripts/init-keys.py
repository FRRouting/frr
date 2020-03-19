import pytest
from lutil import luCommand
import KFvars

# only create keyfile if it does not already exist
cmd = 'if [ ! -e {} ] ; then ({}) ; fi; ls -al {}'.format(KFvars.KFfile, KFvars.KFmk, KFvars.KFdir)
pattern = ' {}'.format(KFvars.KFbase)

for r in range(0, 8):
    luCommand('r{}'.format(r),cmd, pattern, 'pass','key file found')
