# SPDX-License-Identifier: ISC
"""Kernel routing table in iproute2 JSON form.

``kernel_routes()`` is the topotest helper for "what is installed in the
kernel". On Linux it returns the parsed output of ``ip -j route show``. On
FreeBSD it runs ``netstat --libxo json -rn`` and builds the same shape.

Only values netstat actually reports are filled in. Linux fields with no
FreeBSD equivalent (``protocol``, ``metric``, ``pref``, ``flags``, ``nhid``,
``scope``, ``prefsrc``) are omitted rather than invented. A few encodings are
normalized so the same route is written the way iproute2 writes it:

* ``0.0.0.0/0`` and ``::/0`` become ``default``
* host routes drop a trailing ``/32`` or ``/128``
* IPv6 zone indexes (``fe80::1%em0``) are removed; the interface stays in ``dev``
* a ``link#N`` gateway is an interface route, so no ``gateway`` key is emitted
* routes that share a destination and ``nhg-kidx`` become one object with a
  ``nexthops`` array (``weight`` is kept there, as in iproute2)
* ``RTF_BLACKHOLE`` / ``RTF_REJECT`` become ``type`` ``blackhole`` /
  ``unreachable``

FreeBSD keeps interface host routes in the same FIB. Linux ``ip route show``
leaves those in the local table, so a FreeBSD result includes them. Select a
FIB with ``table`` (a FIB number). A Linux VRF name has no netstat equivalent.
"""

import json
import re
import shlex
import sys


_LINK_GATEWAY = re.compile(r"^link#\d+$")
_ZONE = re.compile(r"%[^/%]+")
_IPV4_ADDR = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

_FAMILY_BY_AF = {
    "Internet": "ipv4",
    "inet": "ipv4",
    "Internet6": "ipv6",
    "inet6": "ipv6",
}


class KernelRoutesError(ValueError):
    """kernel_routes() could not return a routing table."""


def kernel_routes(node, vrf=None, table=None, family="ipv4"):
    """Return kernel routes as a list of iproute2 JSON objects.

    ``family`` is ``ipv4`` (the default, ``ip -j route show``), ``ipv6``
    (``ip -j -6 route show``), or ``all``.

    ``vrf`` is a Linux VRF name (``ip route show vrf NAME``). On FreeBSD only
    ``None`` and ``"default"`` are accepted; pass ``table`` set to the FIB
    number instead. ``table`` is an iproute2 table (``main``, ``local``, an
    id, ...) or, on FreeBSD, a FIB number. ``main`` and ``default`` select
    the FIB ``netstat`` shows without ``-F``.

    ``node`` is a topotest router. The command runs inside that router.
    """
    family = _normalize_family(family)
    if sys.platform.startswith("freebsd"):
        return _kernel_routes_freebsd(node, vrf, table, family)
    return _kernel_routes_linux(node, vrf, table, family)


def _normalize_family(family):
    if family in ("ipv4", "inet", "4", 4):
        return "ipv4"
    if family in ("ipv6", "inet6", "6", 6):
        return "ipv6"
    if family == "all":
        return "all"
    raise KernelRoutesError(
        "family must be 'ipv4', 'ipv6', or 'all', not %r" % (family,)
    )


def _node_stdout(node, argv):
    """Run argv inside the router. Prefer cmd_raises, which takes a list."""
    if hasattr(node, "cmd_raises"):
        return node.cmd_raises(argv)
    command = " ".join(shlex.quote(str(arg)) for arg in argv)
    if hasattr(node, "run"):
        return node.run(command)
    return node.cmd(command)


def _load_json(text, what):
    if isinstance(text, bytes):
        text = text.decode()
    text = (text or "").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise KernelRoutesError("invalid JSON from %s" % (what,)) from exc


def _linux_argv(vrf, table, family):
    argv = ["ip", "-j", "-4" if family == "ipv4" else "-6", "route", "show"]
    if vrf is not None:
        argv.extend(("vrf", str(vrf)))
    if table is not None:
        argv.extend(("table", str(table)))
    return argv


def _kernel_routes_linux(node, vrf, table, family):
    families = ("ipv4", "ipv6") if family == "all" else (family,)
    routes = []
    for one in families:
        argv = _linux_argv(vrf, table, one)
        parsed = _load_json(_node_stdout(node, argv), " ".join(argv))
        if not isinstance(parsed, list):
            raise KernelRoutesError(
                "ip route JSON is not a list: %s" % (" ".join(argv),)
            )
        routes.extend(parsed)
    return routes


def _freebsd_fib(table):
    """Return the ``netstat -F`` argument, or None for the current FIB."""
    if table is None:
        return None
    if isinstance(table, str) and table in ("main", "default"):
        return None
    if isinstance(table, bool) or not isinstance(table, (int, str)):
        raise KernelRoutesError(
            "FreeBSD routing tables are FIB numbers, not %r" % (table,)
        )
    if isinstance(table, int) or (isinstance(table, str) and table.isdigit()):
        return str(table)
    raise KernelRoutesError(
        "FreeBSD routing tables are FIB numbers; %r is a Linux table name"
        % (table,)
    )


def _freebsd_argv(vrf, table, family):
    if vrf not in (None, "default"):
        raise KernelRoutesError(
            "FreeBSD selects a kernel routing table by FIB number; "
            "pass table=<fib> instead of vrf=%r" % (vrf,)
        )
    argv = ["netstat", "--libxo", "json", "-rn"]
    if family == "ipv4":
        argv.extend(("-f", "inet"))
    elif family == "ipv6":
        argv.extend(("-f", "inet6"))
    fib = _freebsd_fib(table)
    if fib is not None:
        argv.extend(("-F", fib))
    return argv


def _kernel_routes_freebsd(node, vrf, table, family):
    argv = _freebsd_argv(vrf, table, family)
    parsed = _load_json(_node_stdout(node, argv), " ".join(argv))
    if parsed == []:
        return []
    return _routes_from_netstat(parsed, family)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _routes_from_netstat(payload, family):
    """Convert ``netstat --libxo json -rn`` JSON to iproute2 route objects."""
    try:
        table = payload["statistics"]["route-information"]["route-table"]
    except (KeyError, TypeError) as exc:
        raise KernelRoutesError(
            "netstat JSON is missing statistics/route-information/route-table"
        ) from exc

    routes = []
    for fam in _as_list(table.get("rt-family")):
        if not isinstance(fam, dict):
            continue
        ipfam = _FAMILY_BY_AF.get(fam.get("address-family"))
        if ipfam is None:
            continue
        if family != "all" and ipfam != family:
            continue
        routes.extend(_collapse_family(_as_list(fam.get("rt-entry")), ipfam))
    return routes


def _collapse_family(entries, family):
    """Merge ECMP members that share a destination and nexthop-group index."""
    groups = []
    position = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("destination"):
            continue
        nhg = entry.get("nhg-kidx")
        if nhg is not None:
            key = (entry.get("destination"), str(nhg))
            slot = position.get(key)
            if slot is not None:
                groups[slot].append(entry)
                continue
            position[key] = len(groups)
        groups.append([entry])
    return [_emit_route(group, family) for group in groups]


def _normalize_dst(dest, family):
    dest = _ZONE.sub("", dest)
    if dest in ("default", "0.0.0.0/0", "::/0"):
        return "default"
    if family == "ipv4" and dest.endswith("/32"):
        return dest[:-3]
    if family == "ipv6" and dest.endswith("/128"):
        return dest[:-4]
    return dest


def _normalize_gateway(gateway):
    if not gateway or _LINK_GATEWAY.match(gateway):
        return None
    gateway = _ZONE.sub("", gateway)
    if ":" in gateway or _IPV4_ADDR.match(gateway):
        return gateway
    return None


def _route_type(entry):
    pretty = entry.get("flags_pretty") or []
    if isinstance(pretty, str):
        pretty = pretty.split()
    names = {str(flag).lower() for flag in pretty}
    if "blackhole" in names:
        return "blackhole"
    if "reject" in names:
        return "unreachable"
    return None


def _emit_route(group, family):
    first = group[0]
    route = {}
    rtype = _route_type(first)
    if rtype:
        route["type"] = rtype
    route["dst"] = _normalize_dst(first["destination"], family)
    if len(group) == 1:
        gateway = _normalize_gateway(first.get("gateway"))
        if gateway:
            route["gateway"] = gateway
        dev = first.get("interface-name")
        if dev:
            route["dev"] = dev
        return route

    nexthops = []
    for entry in group:
        nh = {}
        gateway = _normalize_gateway(entry.get("gateway"))
        if gateway:
            nh["gateway"] = gateway
        dev = entry.get("interface-name")
        if dev:
            nh["dev"] = dev
        if entry.get("weight") is not None:
            nh["weight"] = entry["weight"]
        nexthops.append(nh)
    route["nexthops"] = nexthops
    return route
