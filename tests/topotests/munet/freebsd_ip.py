#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# ip(8) subset for the FreeBSD topotest jail. Copied into each jail as
# /topotest/bin/ip. Absolute /sbin/ifconfig and /sbin/route so it does not
# depend on PATH beyond the python3 used by the shebang.
"""Translate the ip(8) invocations the FreeBSD topotest harness needs."""

import sys


class Usage(Exception):
    """A command this shim will not translate."""


def die(msg):
    sys.stderr.write(f"ip: {msg}\n")
    raise SystemExit(2)


def _run(cmd, capture=False):
    import subprocess

    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode:
        sys.stderr.write(proc.stderr or proc.stdout or "")
        raise SystemExit(proc.returncode)
    if capture:
        return proc.stdout or ""
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.stdout or ""


def split_global(argv):
    """Return (family, remaining) after leading ip(8) flags."""
    family = None
    args = list(argv)
    while args:
        tok = args[0]
        if tok in ("-4", "-6"):
            family = "inet" if tok == "-4" else "inet6"
            args = args[1:]
            continue
        if tok == "-family" and len(args) > 1:
            family = "inet6" if args[1] in ("inet6", "6") else "inet"
            args = args[2:]
            continue
        if tok in ("-o", "-d", "-s", "-br", "-force", "-batch"):
            args = args[1:]
            continue
        if tok in ("-n", "--netns"):
            raise Usage("network namespaces are not available on FreeBSD")
        break
    return family, args


def _skip_addr_noise(args, i):
    """Skip ip-address tokens that ifconfig does not need."""
    tok = args[i]
    if tok in ("noprefixroute", "nodad", "home", "permanent"):
        return i + 1
    if tok in (
        "broadcast",
        "brd",
        "label",
        "scope",
        "preferred_lft",
        "valid_lft",
        "proto",
        "metric",
    ):
        return i + 2
    return None


def parse_addr(args, family, deleting):
    """Return the ifconfig argv for addr add/del."""
    if not args:
        raise Usage("address add/del is missing arguments")
    if args[0] == "dev":
        iface = args[1]
        addr = args[2]
        rest = args[3:]
    else:
        addr = args[0]
        if "dev" not in args:
            raise Usage("address add/del is missing dev")
        dev_at = args.index("dev")
        iface = args[dev_at + 1]
        rest = args[1:dev_at] + args[dev_at + 2 :]
    i = 0
    while i < len(rest):
        nxt = _skip_addr_noise(rest, i)
        if nxt is None:
            raise Usage(f"unsupported address keyword {rest[i]}")
        i = nxt
    fam = family
    if fam is None:
        fam = "inet6" if ":" in addr.split("/")[0] else "inet"
    cmd = ["/sbin/ifconfig", iface, fam, addr]
    if deleting:
        cmd.append("delete")
    return [cmd]


def flush_commands(iface, family, scope, ifconfig_text):
    """Return ifconfig delete commands for one interface."""
    cmds = []
    for line in ifconfig_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        kind, addr = parts[0], parts[1]
        if family in (None, "inet") and kind == "inet":
            if addr.startswith("127."):
                continue
            cmds.append(["/sbin/ifconfig", iface, "inet", addr, "delete"])
        elif family in (None, "inet6") and kind == "inet6":
            bare = addr.split("%", 1)[0]
            if bare == "::1":
                continue
            if scope == "global" and bare.lower().startswith("fe80:"):
                continue
            cmds.append(["/sbin/ifconfig", iface, "inet6", bare, "delete"])
    return cmds


def parse_route(args, family):
    """Return the route(8) argv for add/del."""
    if not args:
        raise Usage("route command is missing arguments")
    action = args[0]
    if action not in ("add", "del", "delete", "replace", "change"):
        raise Usage(f"unsupported route command {action}")
    dest = None
    gw = None
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "via":
            gw = args[i + 1]
            i += 2
        elif tok == "dev":
            i += 2
        elif tok in ("proto", "metric", "scope", "src", "mtu", "advmss", "weight"):
            i += 2
        elif tok == "table":
            raise Usage("route tables are not implemented on FreeBSD")
        elif tok == "nexthop":
            raise Usage("nexthop groups are not implemented on FreeBSD")
        elif tok in ("onlink",):
            i += 1
        elif dest is None:
            dest = tok
            i += 1
        else:
            raise Usage(f"unsupported route keyword {tok}")
    if dest is None:
        raise Usage("route command is missing a destination")
    if action == "replace":
        action = "add"
    verb = "delete" if action in ("del", "delete") else "add"
    if verb == "add" and gw is None:
        raise Usage("route add is missing via")
    cmd = ["/sbin/route"]
    if family == "inet6":
        cmd.append("-inet6")
    elif family == "inet":
        cmd.append("-inet")
    cmd.append(verb)
    cmd.append(dest)
    if gw:
        cmd.append(gw)
    return [cmd]


def parse_link_set(args):
    """Return ifconfig commands for `ip link set`."""
    if not args:
        raise Usage("link set is missing arguments")
    if args[0] in ("up", "down"):
        op = args[0]
        rest = args[1:]
        if rest and rest[0] == "dev":
            rest = rest[1:]
        if not rest:
            raise Usage("link set is missing an interface")
        iface = rest[0]
        rest = [op] + rest[1:]
    else:
        if args[0] == "dev":
            args = args[1:]
        if not args:
            raise Usage("link set is missing an interface")
        iface = args[0]
        rest = args[1:]
    cmds = []
    i = 0
    while i < len(rest):
        op = rest[i]
        if op in ("up", "down"):
            cmds.append(["/sbin/ifconfig", iface, op])
            i += 1
        elif op == "mtu":
            cmds.append(["/sbin/ifconfig", iface, "mtu", rest[i + 1]])
            i += 2
        elif op == "master":
            cmds.append(["/sbin/ifconfig", rest[i + 1], "addm", iface])
            i += 2
        elif op == "nomaster":
            cmds.append(["__nomaster__", iface])
            i += 1
        elif op == "name":
            cmds.append(["/sbin/ifconfig", iface, "name", rest[i + 1]])
            iface = rest[i + 1]
            i += 2
        elif op == "netns":
            raise Usage(
                "netns is not available; move interfaces with ifconfig IF vnet JAIL"
            )
        elif op == "dev":
            raise Usage("unexpected dev in link set")
        else:
            raise Usage(f"unsupported link set keyword {op}")
    if not cmds:
        raise Usage("link set has no operation")
    return cmds


def parse_link_del(args):
    if args and args[0] == "dev":
        args = args[1:]
    if not args:
        raise Usage("link delete is missing an interface")
    return [["/sbin/ifconfig", args[0], "destroy"]]


def bridge_for_member(ifconfig_text, iface):
    """Return the bridge that has iface as a member, or None."""
    current = None
    found = None
    for line in ifconfig_text.splitlines():
        if line and not line[0].isspace() and ":" in line:
            current = line.split(":", 1)[0]
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "member:" and parts[1] == iface:
            found = current
    return found


def _create_renamed(kind, name):
    text = _run(["/sbin/ifconfig", kind, "create"], capture=True)
    created = text.strip().split()[-1]
    if not created:
        die(f"ifconfig {kind} create returned no name")
    if created != name:
        _run(["/sbin/ifconfig", created, "name", name])
    return name


def _link_add(args):
    parent = None
    name = None
    typ = None
    vlan_id = None
    vlan_filter = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "link":
            parent = args[i + 1]
            i += 2
        elif tok == "name":
            name = args[i + 1]
            i += 2
        elif tok == "type":
            typ = args[i + 1]
            i += 2
        elif tok == "id":
            vlan_id = args[i + 1]
            i += 2
        elif tok == "vlan_filtering":
            vlan_filter = args[i + 1] not in ("0", "off", "false")
            i += 2
        elif name is None:
            name = tok
            i += 1
        else:
            die(f"unsupported link add keyword {tok}")
    if not name or not typ:
        die("link add needs a name and a type")
    if typ == "vrf":
        die("Linux VRF devices are not available on FreeBSD")
    if typ == "veth":
        die("veth is not available; the harness uses epair(4)")
    if typ == "dummy":
        _create_renamed("lo", name)
        return
    if typ == "bridge":
        _create_renamed("bridge", name)
        if vlan_filter:
            _run(["/sbin/ifconfig", name, "vlanfilter"])
        return
    if typ == "vlan":
        if not parent or vlan_id is None:
            die("vlan link add needs link PARENT and id VLAN")
        created = (
            _run(["/sbin/ifconfig", "vlan", "create"], capture=True).strip().split()[-1]
        )
        _run(["/sbin/ifconfig", created, "vlan", vlan_id, "vlandev", parent])
        if created != name:
            _run(["/sbin/ifconfig", created, "name", name])
        return
    die(f"unsupported link type {typ}")


def _execute_link_set(cmds):
    for cmd in cmds:
        if cmd and cmd[0] == "__nomaster__":
            iface = cmd[1]
            text = _run(["/sbin/ifconfig", "-a"], capture=True)
            bridge = bridge_for_member(text, iface)
            if bridge:
                _run(["/sbin/ifconfig", bridge, "delm", iface])
            continue
        _run(cmd)


def _address_flush(args, family):
    if args and args[0] == "dev":
        args = args[1:]
    if not args:
        die("address flush is missing an interface")
    iface = args[0]
    scope = None
    i = 1
    while i < len(args):
        if args[i] == "scope":
            scope = args[i + 1]
            i += 2
        else:
            die(f"unsupported address flush keyword {args[i]}")
    text = _run(["/sbin/ifconfig", iface], capture=True)
    for cmd in flush_commands(iface, family, scope, text):
        _run(cmd)


def dispatch(argv):
    """Run one ip(8) invocation. argv does not include the program name."""
    try:
        family, args = split_global(argv)
    except Usage as exc:
        die(str(exc))
    if not args:
        die("missing object")
    obj = args[0]
    rest = args[1:]
    try:
        if obj in ("link", "l"):
            if not rest:
                die("missing link command")
            cmd = rest[0]
            if cmd == "set":
                _execute_link_set(parse_link_set(rest[1:]))
                return
            if cmd in ("del", "delete"):
                for one in parse_link_del(rest[1:]):
                    _run(one)
                return
            if cmd == "add":
                _link_add(rest[1:])
                return
            die(f"unsupported link command {cmd}")
        if obj in ("addr", "address", "a"):
            if not rest:
                die("missing address command")
            cmd = rest[0]
            if cmd == "add":
                for one in parse_addr(rest[1:], family, deleting=False):
                    _run(one)
                return
            if cmd in ("del", "delete"):
                for one in parse_addr(rest[1:], family, deleting=True):
                    _run(one)
                return
            if cmd == "flush":
                _address_flush(rest[1:], family)
                return
            die(f"unsupported address command {cmd}")
        if obj in ("route", "r"):
            for one in parse_route(rest, family):
                _run(one)
            return
    except Usage as exc:
        die(str(exc))
    die(f"unsupported object {obj}")


def _self_test():
    assert parse_link_set(["dev", "eth0", "up"]) == [["/sbin/ifconfig", "eth0", "up"]]
    assert parse_link_set(["dev", "eth0", "down"]) == [
        ["/sbin/ifconfig", "eth0", "down"]
    ]
    assert parse_link_set(["up", "dev", "eth0"]) == [["/sbin/ifconfig", "eth0", "up"]]
    assert parse_link_set(["eth0", "mtu", "1400"]) == [
        ["/sbin/ifconfig", "eth0", "mtu", "1400"]
    ]
    assert parse_link_set(["dev", "eth0", "master", "br0"]) == [
        ["/sbin/ifconfig", "br0", "addm", "eth0"]
    ]
    assert parse_link_del(["dev", "eth0"]) == [["/sbin/ifconfig", "eth0", "destroy"]]
    assert parse_addr(["10.0.0.1/24", "dev", "eth0"], None, False) == [
        ["/sbin/ifconfig", "eth0", "inet", "10.0.0.1/24"]
    ]
    assert parse_addr(["dev", "eth0", "10.0.0.1/8"], "inet", False) == [
        ["/sbin/ifconfig", "eth0", "inet", "10.0.0.1/8"]
    ]
    assert parse_addr(["2001:db8::1/64", "dev", "eth0"], "inet6", True) == [
        ["/sbin/ifconfig", "eth0", "inet6", "2001:db8::1/64", "delete"]
    ]
    sample = "\n".join(
        [
            "epair0a: flags=1",
            "\tinet 10.0.0.1 netmask 0xffffff00",
            "\tinet6 fe80::1%epair0a prefixlen 64 scopeid 0x2",
            "\tinet6 2001:db8::1 prefixlen 64",
        ]
    )
    assert flush_commands("epair0a", "inet", None, sample) == [
        ["/sbin/ifconfig", "epair0a", "inet", "10.0.0.1", "delete"]
    ]
    assert flush_commands("epair0a", "inet6", "global", sample) == [
        ["/sbin/ifconfig", "epair0a", "inet6", "2001:db8::1", "delete"]
    ]
    assert parse_route(["add", "default", "via", "10.0.0.1"], None) == [
        ["/sbin/route", "add", "default", "10.0.0.1"]
    ]
    assert parse_route(["del", "default", "via", "10.0.0.1"], "inet") == [
        ["/sbin/route", "-inet", "delete", "default", "10.0.0.1"]
    ]
    assert parse_route(["add", "10.1.0.0/24", "via", "10.0.0.1"], None) == [
        ["/sbin/route", "add", "10.1.0.0/24", "10.0.0.1"]
    ]
    assert parse_route(["add", "default", "via", "fe80::1"], "inet6") == [
        ["/sbin/route", "-inet6", "add", "default", "fe80::1"]
    ]
    text = "\n".join(
        [
            "bridge0: flags=1",
            "\tmember: r1-eth0 flags=143",
            "epair0a: flags=1",
        ]
    )
    assert bridge_for_member(text, "r1-eth0") == "bridge0"
    assert bridge_for_member(text, "missing") is None
    family, args = split_global(["-4", "address", "flush", "eth0"])
    assert family == "inet" and args == ["address", "flush", "eth0"]
    print("freebsd_ip self-test ok")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--self-test"]:
        _self_test()
        return 0
    dispatch(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
