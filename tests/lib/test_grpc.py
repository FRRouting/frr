import inspect
import os
import subprocess

import frrtest
import pytest


class TestGRPC(object):
    program = "./test_grpc"

    @pytest.mark.skipif(
        'S["GRPC_TRUE"]=""\n' not in open("../config.status").readlines(),
        reason="GRPC not enabled",
    )
    @pytest.mark.skipif(
        not os.path.isdir("/usr/share/yang"),
        reason="YANG models aren't installed in /usr/share/yang",
    )
    def test_exits_cleanly(self):
        basedir = os.path.dirname(inspect.getsourcefile(type(self)))
        program = os.path.join(basedir, self.program)
        proc = subprocess.Popen(
            [frrtest.binpath(program)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output, _ = proc.communicate()
        self.exitcode = proc.wait()
        if self.exitcode != 0:
            print("OUTPUT:\n" + output.decode("ascii"))
            raise frrtest.TestExitNonzero(self)
