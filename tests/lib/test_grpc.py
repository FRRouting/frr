import inspect
import os
import subprocess
import pytest
import frrtest

class TestGRPC(object):
    program = "./test_grpc"

    @pytest.mark.skipif(
        'S["GRPC_TRUE"]=""\n' not in open("../config.status").readlines(),
        reason="GRPC not enabled",
    )
    def test_exits_cleanly(self):
        basedir = os.path.dirname(inspect.getsourcefile(type(self)))
        program = os.path.join(basedir, self.program)
        proc = subprocess.Popen(
            [frrtest.binpath(program)], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        output, _ = proc.communicate()
        self.exitcode = proc.wait()
        if self.exitcode != 0:
            raise frrtest.TestExitNonzero(self)
