import frrtest
import pytest
import os
import pwd
import grp
import subprocess

class TestLblmgr(frrtest.TestRefOut):
    program = './test_lblmgr'

    def test_refout(self):
        user = pwd.getpwuid(os.getuid())[0]
        group = grp.getgrgid(os.getgid()).gr_name
        subprocess.call(["../zebra/zebra", "-u", user, "-g", group, "-z", "/tmp/zserv.api", "-d"])
        r =  super(TestLblmgr, self).test_refout()
        #subprocess.call(["pkill", "-9", "zebra"])
        p = subprocess.check_output(["ps", "-C", "lt-zebra", "-o", "pid="]).split()[0]
        subprocess.call(["kill", "-9", p])
        return r
