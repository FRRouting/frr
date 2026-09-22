#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Ming Han Chan <s10159021@gmail.com>
#

"""
test_frr_reload_vrf_section_deletion.py

test frr-reload.py on 'vrf' section deletion.

frr-reload.py used to delete only the lines inside a removed "vrf" stanza and
leave the stanza itself behind, so "show running-config" kept printing an
empty "vrf NAME / exit-vrf" block. Every reload that churned vrfs left another
one behind, growing the configuration without bound.

1. Save clean configuration to 'frr-clean.conf'
2. Add a vrf device and configure an L3VNI under it.
3. Save configuration to 'frr-with-vrf.conf'
4. Use frr-reload.py to load 'frr-clean.conf' - the whole vrf stanza must be
   gone, not just its contents.
5. Use frr-reload.py to load 'frr-with-vrf.conf' - the vrf comes back.
6. Delete the vrf device and reload 'frr-clean.conf' again - no errors.

Under the vrf-lite backend "no vrf NAME" also destroys the "interface NAME"
node. Two more tests cover that:

- The new configuration still wants "interface NAME": frr-reload must not emit
  "no vrf NAME", so the interface configuration survives.
- "interface NAME" goes too while the device is up: "no vrf NAME" is refused.
  That must neither fail the reload nor keep another vrf dropped in the same
  reload configured, and a reload after the device is gone removes the vrf.
"""

import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

VRF_NAME = "vrftest"
VRF_TABLE = "1001"
VRF_VNI = "1001"

# A second, independent vrf for the "interface NAME survives" case, so it does
# not depend on any state left behind by the first test.
GUARD_VRF_NAME = "vrfguard"
GUARD_VRF_TABLE = "1002"
GUARD_VRF_VNI = "1002"
GUARD_IFACE_DESC = "frr-reload vrf guard test"

# Two vrfs dropped in the same reload, one of them refused while its device is
# up.
BUSY_VRF_NAME = "vrfbusy"
BUSY_VRF_TABLE = "1003"
BUSY_VRF_VNI = "1003"
BUSY_IFACE_DESC = "frr-reload vrf busy test"
IDLE_VRF_NAME = "vrfidle"
IDLE_VRF_TABLE = "1004"
IDLE_VRF_VNI = "1004"


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def configure(router, config, applied):
    """Send config until applied() returns None; returns its last result.

    Right after startup mgmtd holds the running datastore lock while it sends
    each backend its initial config, and a "configure terminal" in that window
    fails with "could not lock running DS" without being retried.
    """

    def _apply():
        if applied() is None:
            return None
        router.vtysh_cmd("configure terminal\n" + config)
        return applied()

    _, result = topotest.run_and_expect(_apply, None, count=30, wait=1)
    return result


def test_frr_reload_vrf_section_deletion():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # "vrf <name>" as its own stanza header, at the start of a line.
    vrf_stanza = re.compile(r"^vrf %s\s*$" % VRF_NAME, re.MULTILINE)

    def running_config():
        return r1.vtysh_cmd("show running-config")

    def vrf_present():
        if vrf_stanza.search(running_config()):
            return None
        return "vrf %s stanza missing from running-config" % VRF_NAME

    def vrf_absent():
        if not vrf_stanza.search(running_config()):
            return None
        return "vrf %s stanza still present in running-config" % VRF_NAME

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    frrreload = frrdir + "/frr-reload.py --reload"

    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-clean.conf")

    r1.cmd_raises("ip link add %s type vrf table %s" % (VRF_NAME, VRF_TABLE))
    r1.cmd_raises("ip link set %s up" % VRF_NAME)

    vrf_with_vni = re.compile(r"^vrf %s\n vni %s$" % (VRF_NAME, VRF_VNI), re.MULTILINE)

    def vrf_configured():
        if vrf_with_vni.search(running_config()):
            return None
        return "vrf %s with vni %s missing from running-config" % (VRF_NAME, VRF_VNI)

    result = configure(
        r1, "vrf %s\n vni %s\nexit-vrf\n" % (VRF_NAME, VRF_VNI), vrf_configured
    )
    assert result is None, "vrf not configured to begin with"
    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-with-vrf.conf")

    # The regression: reloading a config without the vrf must remove the whole
    # stanza, not leave an empty "vrf <name> / exit-vrf" block behind.
    r1.cmd_raises("%s frr-clean.conf" % frrreload)
    _, result = topotest.run_and_expect(vrf_absent, None, count=30, wait=1)
    assert result is None, "empty vrf stanza left behind after reload to clean"

    r1.cmd_raises("%s frr-with-vrf.conf" % frrreload)
    _, result = topotest.run_and_expect(vrf_present, None, count=30, wait=1)
    assert result is None, "vrf not restored after reload to config with vrf"

    # Reloading to clean while the kernel device is gone must not error either.
    r1.cmd_raises("ip link delete %s" % VRF_NAME)
    r1.cmd_raises("%s frr-clean.conf" % frrreload)
    _, result = topotest.run_and_expect(vrf_absent, None, count=30, wait=1)
    assert result is None, "vrf stanza present after device deletion and reload"


def test_frr_reload_vrf_section_deletion_keeps_named_interface():
    """Removing a vrf stanza must not take the same-named interface with it.

    Under the vrf-lite backend "no vrf NAME" also destroys
    /frr-interface:lib/interface[name='NAME'], so frr-reload deliberately does
    not emit it while the new configuration still contains "interface NAME".
    The empty vrf stanza is kept in that case; losing interface configuration
    the operator asked for would be the worse outcome.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    iface_stanza = re.compile(r"^interface %s\b" % GUARD_VRF_NAME, re.MULTILINE)
    iface_desc = re.compile(r"^\s*description %s\s*$" % GUARD_IFACE_DESC, re.MULTILINE)

    def running_config():
        return r1.vtysh_cmd("show running-config")

    def iface_config_intact():
        cfg = running_config()
        if not iface_stanza.search(cfg):
            return "interface %s stanza was removed" % GUARD_VRF_NAME
        if not iface_desc.search(cfg):
            return "interface %s description was removed" % GUARD_VRF_NAME
        return None

    def vni_absent():
        if re.search(r"^\s*vni %s\s*$" % GUARD_VRF_VNI, running_config(), re.MULTILINE):
            return "vni %s still present" % GUARD_VRF_VNI
        return None

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    frrreload = frrdir + "/frr-reload.py --reload"

    r1.cmd_raises(
        "ip link add %s type vrf table %s" % (GUARD_VRF_NAME, GUARD_VRF_TABLE)
    )
    r1.cmd_raises("ip link set %s up" % GUARD_VRF_NAME)

    # Desired end state: the interface stanza, and no vrf stanza.
    result = configure(
        r1,
        "interface %s\n description %s\nexit\n" % (GUARD_VRF_NAME, GUARD_IFACE_DESC),
        iface_config_intact,
    )
    assert result is None, "interface config missing before the vrf was added"
    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-iface-only.conf")

    # Now add the vrf stanza on top, so reloading back drops only the vrf.
    def vrf_configured():
        if re.search(
            r"^vrf %s\n vni %s$" % (GUARD_VRF_NAME, GUARD_VRF_VNI),
            running_config(),
            re.MULTILINE,
        ):
            return None
        return "vrf %s with vni %s missing" % (GUARD_VRF_NAME, GUARD_VRF_VNI)

    result = configure(
        r1,
        "vrf %s\n vni %s\nexit-vrf\n" % (GUARD_VRF_NAME, GUARD_VRF_VNI),
        vrf_configured,
    )
    assert result is None, "vrf not configured to begin with"

    # The safeguard: the vrf stanza disappears from the desired config while
    # "interface <name>" stays. frr-reload must empty the vrf stanza without
    # issuing "no vrf <name>", so the interface config survives.
    r1.cmd_raises("%s frr-iface-only.conf" % frrreload)

    _, result = topotest.run_and_expect(iface_config_intact, None, count=30, wait=1)
    assert result is None, "interface config destroyed by vrf stanza removal"

    # The vrf contents are still torn down, only the empty stanza is kept.
    _, result = topotest.run_and_expect(vni_absent, None, count=30, wait=1)
    assert result is None, "vrf contents were not removed"

    r1.cmd_raises("ip link delete %s" % GUARD_VRF_NAME)


def test_frr_reload_vrf_section_deletion_refused():
    """A "no vrf NAME" refused while the vrf device is up is not a failure.

    Here "interface NAME" goes away together with the vrf stanza. frr-reload
    empties it, the interface node stays (vtysh no longer shows it), and while
    the device is up "no vrf NAME" is refused with "only inactive interfaces
    can be deleted". The reload must still succeed, and must still remove a
    second vrf dropped at the same time although both "no vrf" commands share
    one batch. Once the device is gone, a reload removes the first vrf too.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def running_config():
        return r1.vtysh_cmd("show running-config")

    def configured():
        cfg = running_config()
        for name, vni in ((BUSY_VRF_NAME, BUSY_VRF_VNI), (IDLE_VRF_NAME, IDLE_VRF_VNI)):
            if not re.search(r"^vrf %s\n vni %s$" % (name, vni), cfg, re.MULTILINE):
                return "vrf %s with vni %s missing" % (name, vni)
        if not re.search(r"^ description %s$" % BUSY_IFACE_DESC, cfg, re.MULTILINE):
            return "interface %s description missing" % BUSY_VRF_NAME
        return None

    def vrf_absent(name):
        def _check():
            if re.search(r"^vrf %s\s*$" % name, running_config(), re.MULTILINE):
                return "vrf %s stanza still present in running-config" % name
            return None

        return _check

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    frrreload = frrdir + "/frr-reload.py --reload"

    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-refused-clean.conf")

    for name, table in (
        (BUSY_VRF_NAME, BUSY_VRF_TABLE),
        (IDLE_VRF_NAME, IDLE_VRF_TABLE),
    ):
        r1.cmd_raises("ip link add %s type vrf table %s" % (name, table))
        r1.cmd_raises("ip link set %s up" % name)

    result = configure(
        r1,
        "vrf %s\n vni %s\nexit-vrf\n" % (BUSY_VRF_NAME, BUSY_VRF_VNI)
        + "vrf %s\n vni %s\nexit-vrf\n" % (IDLE_VRF_NAME, IDLE_VRF_VNI)
        + "interface %s\n description %s\nexit\n" % (BUSY_VRF_NAME, BUSY_IFACE_DESC),
        configured,
    )
    assert result is None, result

    # cmd_raises: the refused "no vrf" must not make frr-reload exit non-zero.
    r1.cmd_raises("%s frr-refused-clean.conf" % frrreload)

    _, result = topotest.run_and_expect(
        vrf_absent(IDLE_VRF_NAME), None, count=30, wait=1
    )
    assert result is None, "a refused 'no vrf' kept another vrf configured"

    r1.cmd_raises("ip link delete %s" % BUSY_VRF_NAME)
    r1.cmd_raises("%s frr-refused-clean.conf" % frrreload)

    _, result = topotest.run_and_expect(
        vrf_absent(BUSY_VRF_NAME), None, count=30, wait=1
    )
    assert result is None, "vrf stanza present after device deletion and reload"

    r1.cmd_raises("ip link delete %s" % IDLE_VRF_NAME)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
