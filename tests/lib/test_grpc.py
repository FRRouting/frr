import inspect
import os
import subprocess

import frrtest
import pytest


class TestGRPC(object):
    program = "./test_grpc"

    grpc_enabled = pytest.mark.skipif(
        'S["GRPC_TRUE"]=""\n' not in open("../config.status").readlines(),
        reason="GRPC not enabled",
    )

    yang_installed = pytest.mark.skipif(
        not os.path.isdir("/usr/share/yang"),
        reason="YANG models aren't installed in /usr/share/yang",
    )

    def _get_program_path(self):
        basedir = os.path.dirname(inspect.getsourcefile(type(self)))
        return os.path.join(basedir, self.program)

    @grpc_enabled
    @yang_installed
    def test_exits_cleanly(self):
        "Original baseline test"
        program = self._get_program_path()
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
    
    @grpc_enabled
    @yang_installed
    @pytest.mark.parametrize(
        "valid_arg, connect_addr",
        [
            ("50051", "127.0.0.1:50051"),
            ("127.0.0.1:50052", "127.0.0.1:50052"),
            ("[::1]:50053", "ipv6:[::1]:50053")
        ]
    )
    def test_valid_grpc_args(self, valid_arg, connect_addr):
        "Verify server binds properly with valid gRPC arguments"
        program = self._get_program_path()
        cmd = [
            frrtest.binpath(program),
            "--grpc-arg",
            valid_arg,
            "--grpc-connect",
            connect_addr
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output, _ = proc.communicate(timeout=10)
        self.exitcode = proc.wait()
        if self.exitcode != 0:
            print("OUTPUT:\n" + output.decode("ascii"))
            raise frrtest.TestExitNonzero(self)
    
    @grpc_enabled
    @yang_installed
    @pytest.mark.parametrize(
        "invalid_arg",
        [
            # Port boundary checks (< 1024 or > 65535)
            "0",
            "1023",
            "65536",
            "70000",
            "127.0.0.1:80",
            "127.0.0.1:65536",
            "[::1]:80",
            "[::1]:65536",

            # IPv4 syntax errors
            ":50051",
            "127.0.0.1:abc",
            "127.0.0.1:50051:extra",

            # IPv6 syntax errors
            "::1:50051",
            "[::1]",
            "[::1]:",
            "[::1:50051",
            "[]:50051",
            "[::1]:abc",
        ]
    )
    def test_invalid_grpc_args(self, invalid_arg):
        "Verify server fails to bind with invalid gRPC arguments"
        program = self._get_program_path()
        cmd = [
            frrtest.binpath(program),
            "--grpc-arg",
            invalid_arg,
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            output, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()

        self.exitcode = proc.wait()
        out_str = output.decode("ascii", errors="replace")

        # For invalid args, a non-zero exit or an explicit initialization error is expected
        if (
            self.exitcode == 0
            and "failed to initialize the gRPC module" not in out_str
            and "Failed to load grpc module" not in out_str
        ):
            print(f"FAILED (unexpected success for invalid arg '{invalid_arg}'):\n" + out_str)
            raise frrtest.TestExitNonzero(self)
