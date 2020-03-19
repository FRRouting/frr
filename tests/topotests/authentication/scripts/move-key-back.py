from lutil import luCommand
import KFvars

cmd = 'mv {}- {} ; ls -al {}'.format(KFvars.KFfile, KFvars.KFfile, KFvars.KFdir)
pattern = ' {}'.format(KFvars.KFbase)

for r in range(0, 8):
    luCommand('r{}'.format(r),cmd, pattern,'pass','key file found')
