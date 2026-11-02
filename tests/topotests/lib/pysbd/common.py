# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Constants and helpers shared by all modules."""

from __future__ import annotations

import socket
import time
from typing import Dict, NoReturn, Optional, Tuple, Union

from .console import console

# Special IP encapsulation protocols.
#: IP encapsulation protocol number for sending packets.
IP_ENCAP_ROUTING = 249
#: IP encapsulation protocol number for OSPF SPF packets.
OSPF_IP_ENCAP_SPF = 248
#: IP encapsulation protocol number for OSPF DR packets.
OSPF_IP_ENCAP_DR = 250
#: IP encapsulation protocol for receiving IGMP packets.
PIM_IP_ENCAP_IGMP = 251
#: IP encapsulation protocol for receiving PIM packets.
PIM_IP_ENCAP_PIM = 252
#: MLDv1/MLDv2 encapsulation protocol.
PIM_IPV6_ENCAP_MLD = 240

IPPROTO_OSPF = 89
IPPROTO_PIM = 103

#: Encapsulation ToS value.
IPV4_ENCAP_TOS = 0xC0
#: Encapsulation magic value.
IP_ENCAP_MAGIC_VALUE = 0x676F6C64
#: Encapsulation destination address (127.130.1.254).
IPV4_ENCAP_DST = bytes([127, 130, 1, 254])
#: Outer IPv4 header plus version, interface index and magic.
IPV4_ENCAP_DATA_SIZE = 28
IPV4_LOOPBACK = bytes([127, 0, 0, 1])
IPV4_NONE = bytes(4)
IPV6_LOOPBACK = socket.inet_pton(socket.AF_INET6, "::1")
IPV6_NONE = bytes(16)

IN6_ALL_SPF_ROUTERS = socket.inet_pton(socket.AF_INET6, "ff02::5")
IN6_ALL_DR_ROUTERS = socket.inet_pton(socket.AF_INET6, "ff02::6")

#: pimreg interface index value for southbound.
PIM_REG_IF_IDX = 0x7FFF0000

FPM_DEFAULT_PORT = 2620
PIMSB_DEFAULT_PORT = 2650
PIM6SB_DEFAULT_PORT = 2651
NETLINK_PROXY_PORT = 2630

# Socket options the `socket` module may not have.
IP_MULTICAST_ALL = getattr(socket, "IP_MULTICAST_ALL", 49)
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
IPV6_RECVHOPOPTS = getattr(socket, "IPV6_RECVHOPOPTS", 53)
IPV6_HOPOPTS = getattr(socket, "IPV6_HOPOPTS", 54)
IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 67)
IPV6_CHECKSUM = getattr(socket, "IPV6_CHECKSUM", 7)
IPV6_ADD_MEMBERSHIP = getattr(socket, "IPV6_JOIN_GROUP", 20)
ICMP6_FILTER = 1
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
PACKET_OUTGOING = 4

# Debug flags.
DEBUG_PACKETS = 0x00000001
DEBUG_PACKETS_DUMP = 0x00000002
DEBUG_NETLINK = 0x00000004
DEBUG_NETLINK_PROXY = 0x00000008
DEBUG_FPM_DUMP = 0x00000010
DEBUG_NETLINK_PROXY_DUMP = 0x00000020
DEBUG_EMULATION = 0x00000040

#: Debug flags by their command name (`debug NAME on|off`).
DEBUG_NAMES = {
    "packets": DEBUG_PACKETS,
    "packets-dump": DEBUG_PACKETS_DUMP,
    "netlink": DEBUG_NETLINK,
    "netlink-proxy": DEBUG_NETLINK_PROXY,
    "netlink-proxy-dump": DEBUG_NETLINK_PROXY_DUMP,
    "fpm-dump": DEBUG_FPM_DUMP,
    "emulation": DEBUG_EMULATION,
}

#: Raw packet data.
Buffer = Union[bytes, bytearray, memoryview]
#: Unix socket path or (host, port).
SocketAddress = Union[str, Tuple[str, int]]


class DebugFlags:
    """Enabled debug flags (they may change at run time)."""

    def __init__(self) -> None:
        self.value = 0

    def enabled(self, flag: int) -> bool:
        return bool(self.value & flag)

    def set(self, flag: int, enable: bool) -> None:
        if enable:
            self.value |= flag
        else:
            self.value &= ~flag


debug = DebugFlags()


def debug_packets() -> bool:
    return debug.enabled(DEBUG_PACKETS)


def debug_packets_dump() -> bool:
    return debug.enabled(DEBUG_PACKETS_DUMP)


def debug_netlink() -> bool:
    return debug.enabled(DEBUG_NETLINK)


def debug_netlink_proxy() -> bool:
    return debug.enabled(DEBUG_NETLINK_PROXY)


def debug_netlink_proxy_dump() -> bool:
    return debug.enabled(DEBUG_NETLINK_PROXY_DUMP)


def debug_fpm_dump() -> bool:
    return debug.enabled(DEBUG_FPM_DUMP)


def debug_emulation() -> bool:
    return debug.enabled(DEBUG_EMULATION)


def out(text: str = "") -> None:
    """Print to standard output (`printf`)."""
    console.write(text)


def err(text: str) -> None:
    """Print to standard error (`fprintf(stderr, ...)`)."""
    console.write(text, error=True)


def warn(text: str, error: Optional[OSError] = None) -> None:
    """Print a warning, with the error description when given (`warn`)."""
    if error is not None:
        reason = error.strerror or str(error)
        text = "{}: {}".format(text, reason)
    err("pysbd: " + text)


#: Last time each rate limited warning was printed.
_warned: Dict[str, float] = {}
WARN_INTERVAL = 10.0


def warn_ratelimited(key: str, text: str, error: Optional[OSError] = None) -> None:
    """`warn`, but at most once every `WARN_INTERVAL` seconds per `key`."""
    now = time.monotonic()
    if now - _warned.get(key, -WARN_INTERVAL) < WARN_INTERVAL:
        return
    _warned[key] = now
    warn(text, error)


class FatalError(SystemExit):
    pass


def fatal(text: str, error: Optional[OSError] = None) -> NoReturn:
    """Print the error and exit (`err`/`errx`)."""
    warn(text, error)
    raise FatalError(1)


class ConfigError(ValueError):
    """Invalid command line or command argument."""


def ntop(family: int, data: Buffer) -> str:
    size = 4 if family == socket.AF_INET else 16
    return socket.inet_ntop(family, bytes(data[:size]))


def ntop4(data: Buffer) -> str:
    return socket.inet_ntop(socket.AF_INET, bytes(data[:4]))


def ntop6(data: Buffer) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(data[:16]))


def pton(family: int, text: str) -> Optional[bytes]:
    """Convert an address to bytes, `None` when invalid."""
    try:
        return socket.inet_pton(family, text)
    except (OSError, ValueError):
        return None


def address_size(family: int) -> int:
    return 4 if family == socket.AF_INET else 16


def zero_address(family: int) -> bytes:
    return IPV4_NONE if family == socket.AF_INET else IPV6_NONE


def is_forwardable_group(family: int, group: bytes) -> bool:
    """Multicast group routers forward (not link-local scoped)."""
    if family == socket.AF_INET:
        return 224 <= group[0] <= 239 and group[:3] != b"\xe0\x00\x00"
    return group[0] == 0xFF and (group[1] & 0x0F) > 2


def is_routable_source(family: int, source: bytes) -> bool:
    """Unicast source routers forward traffic from."""
    if family == socket.AF_INET:
        return source != IPV4_NONE and source[0] < 224 and source[0] != 127
    return (
        source != IPV6_NONE
        and source != IPV6_LOOPBACK
        and source[0] != 0xFF
        and not (source[0] == 0xFE and source[1] & 0xC0 == 0x80)
    )


def strtoul(text: str) -> Optional[int]:
    """
    Parse an unsigned integer like `strtoul(text, &end, 0)` and return it
    truncated to 32 bits, `None` when the text is not entirely a number.
    """
    value = text.strip()
    negative = False
    if value[:1] in ("+", "-"):
        negative = value[0] == "-"
        value = value[1:]

    try:
        if value[:2].lower() == "0x":
            number = int(value[2:], 16)
        elif len(value) > 1 and value[0] == "0":
            number = int(value[1:], 8)
        else:
            number = int(value, 10)
    except ValueError:
        return None

    if negative:
        number = -number
    return number & 0xFFFFFFFF


def strtonum(text: str, minval: int, maxval: int) -> Tuple[int, Optional[str]]:
    """Parse an integer like OpenBSD `strtonum`: returns (value, error)."""
    try:
        value = int(text, 10)
    except ValueError:
        return 0, "invalid"
    if value < minval:
        return 0, "too small"
    if value > maxval:
        return 0, "too large"
    return value, None


def address_parse(arg: str, default_port: int) -> Tuple[int, SocketAddress, bool]:
    """
    Parse `type:address[:port]` (`unix`, `unixc`, `ipv4`, `ipv4c`, `ipv6`,
    `ipv6c`; IPv6 addresses go inside brackets).

    Returns (family, address, is_client) where address is a unix socket path
    or a (host, port) tuple. Raises `ConfigError` when invalid.
    """
    if ":" not in arg:
        raise ConfigError("invalid address: {}".format(arg))

    kind, addr = arg.split(":", 1)
    is_client = kind.endswith("c")

    if kind in ("unix", "unixc"):
        return socket.AF_UNIX, addr, is_client

    if kind in ("ipv4", "ipv4c"):
        port = default_port
        if ":" in addr:
            addr, port_str = addr.split(":", 1)
            port, errp = strtonum(port_str, 1, 65535)
            if errp:
                raise ConfigError("invalid port: {}".format(errp))

        if pton(socket.AF_INET, addr) is None:
            raise ConfigError("invalid address {}".format(addr))

        return socket.AF_INET, (addr, port), is_client

    if kind in ("ipv6", "ipv6c"):
        if not addr.startswith("[") or "]" not in addr:
            raise ConfigError("invalid IPv6 address format: {}".format(addr))

        end = addr.rindex("]")
        host = addr[1:end]
        port = default_port
        rest = addr[end + 1 :]
        if ":" in rest:
            port, errp = strtonum(rest[rest.rindex(":") + 1 :], 1, 65535)
            if errp:
                raise ConfigError("invalid port: {}".format(errp))

        if pton(socket.AF_INET6, host) is None:
            raise ConfigError("invalid address {}".format(host))

        return socket.AF_INET6, (host, port), is_client

    raise ConfigError("invalid socket type: {}".format(kind))


def if_indextoname(index: int) -> Optional[str]:
    try:
        return socket.if_indextoname(index)
    except OSError:
        return None


def set_keepalive(sock: Optional[socket.socket]) -> None:
    """Notice a peer that went away silently (in about 25 seconds)."""
    if sock is None or sock.family not in (socket.AF_INET, socket.AF_INET6):
        return

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except (AttributeError, OSError) as error:
        warn("failed to enable TCP keepalives: {}".format(error))
