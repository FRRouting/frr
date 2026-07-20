#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_vtysh.py
#

"""
test_vtysh.py: Test some basic vtysh commands
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Import topogen and topotest helpers
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.mgmtd]


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config(
            daemons=[("zebra", "-s 90000000")],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ping_command():
    "Test the vtysh ping command with all the available options"

    tgen = get_topogen()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _cmp_ping_output(router, cmd):
        output = router.vtysh_cmd(cmd)
        if "192.168.0.1 ping statistics" in output:
            return None
        else:
            return output

    test_func = partial(
        _cmp_ping_output, r1, "ping 192.168.0.1 source r1-eth0 count 3 dontfragment"
    )
    result, diff = topotest.run_and_expect(test_func, None, count=20, wait=3)

    assert result, "'ping' output mismatch: \n{}".format(diff)


def test_batch_basic():
    "Test that vtysh -B executes commands piped through stdin"

    tgen = get_topogen()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("pipe a batch of show commands into vtysh -B")
    output = r1.cmd_raises("printf 'show version\\nshow running-config\\n' | vtysh -B")
    assert "FRRouting" in output, "'show version' output missing: \n{}".format(output)
    assert "hostname r1" in output, "'show running-config' output missing: \n{}".format(
        output
    )


def test_batch_config():
    "Test that configuration commands piped into vtysh -B are applied"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("configure a static route through vtysh -B")
    r1.cmd_raises(
        "printf 'configure\\nip route 10.99.99.0/24 blackhole\\nexit\\n'" " | vtysh -B"
    )

    step("verify the static route was installed")

    def _route_installed(router):
        output = router.vtysh_cmd("show ip route 10.99.99.0/24")
        if "blackhole" in output:
            return None
        return output

    test_func = partial(_route_installed, r1)
    result, diff = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result, "static route not installed: \n{}".format(diff)


def test_batch_persistent_pipe():
    "Test that vtysh -B waits for further commands until stdin is closed"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    fifo = "/tmp/vtysh_batch_r1.fifo"
    outf = "/tmp/vtysh_batch_r1.out"
    flag = "/tmp/vtysh_batch_r1.flag"

    step("start vtysh -B reading from a fifo")
    r1.cmd_raises("rm -f {0} {1} {2} && mkfifo {0}".format(fifo, outf, flag))
    r1.cmd_raises(
        "( vtysh -B -E < {0} > {1} 2>&1; echo EXITCODE:$? >> {1} )"
        " > /dev/null 2>&1 < /dev/null &".format(fifo, outf)
    )

    # The writer sends one command, holds the fifo open until the flag file
    # shows up, then sends a second command and closes the fifo.
    r1.cmd_raises(
        "( exec 3>{0}; echo 'show version' >&3;"
        " n=0; while [ ! -f {1} ] && [ $n -lt 300 ]; do sleep 0.2; n=$((n+1)); done;"
        " echo 'show running-config' >&3; exec 3>&- )"
        " > /dev/null 2>&1 < /dev/null &".format(fifo, flag)
    )

    step("verify the first command was executed and its output flushed")

    def _first_command_done(router):
        output = router.run("cat {}".format(outf))
        if "FRRouting" in output:
            return None
        return output

    test_func = partial(_first_command_done, r1)
    result, diff = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result, "first command output missing: \n{}".format(diff)

    step("verify vtysh is still waiting for input, not exited")
    output = r1.run("cat {}".format(outf))
    assert (
        "EXITCODE:" not in output
    ), "vtysh exited instead of waiting for more input: \n{}".format(output)
    assert "# show version" in output, "-E did not echo the command: \n{}".format(
        output
    )

    step("release the second command and close the fifo")
    r1.cmd_raises("touch {}".format(flag))

    def _second_command_done(router):
        output = router.run("cat {}".format(outf))
        if "hostname r1" in output and "EXITCODE:0" in output:
            return None
        return output

    test_func = partial(_second_command_done, r1)
    result, diff = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result, "second command output or clean exit missing: \n{}".format(diff)

    r1.run("rm -f {0} {1} {2}".format(fifo, outf, flag))


def test_batch_exit_codes():
    "Test vtysh -B exit codes and option conflicts"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("a failing command must stop execution and exit non-zero")
    rc, output, _ = r1.net.cmd_status(
        "printf 'show garbage nonsense\\nshow version\\n' | vtysh -B", warn=False
    )
    assert rc != 0, "vtysh -B did not exit non-zero on unknown command"
    assert (
        "FRRouting" not in output
    ), "vtysh -B kept executing after a failed command: \n{}".format(output)

    step("with -n a failing command must not affect the exit code")
    rc, _, _ = r1.net.cmd_status(
        "printf 'show garbage nonsense\\nshow version\\n' | vtysh -B -n", warn=False
    )
    assert rc == 0, "vtysh -B -n exited non-zero: {}".format(rc)

    step("-B must be rejected in combination with -c")
    rc, _, error = r1.net.cmd_status("vtysh -B -c 'show version'", warn=False)
    assert rc != 0, "vtysh accepted -B combined with -c"
    assert "combination" in error, "missing option conflict error: \n{}".format(error)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
