# SPDX-License-Identifier: ISC
"""A socket peer for the AF_BRIDGE messages exchanged with fpmsyncd."""

import errno
import socket
import struct
import time
from dataclasses import dataclass

import pytest

from munet import linux

RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
NDA_DST = 1
NDA_LLADDR = 2
NDA_VLAN = 5
NDA_MASTER = 9
NDA_SRC_VNI = 11
NDA_PROTOCOL = 12
NDA_NH_ID = 13
NDA_FLAGS_EXT = 15
NUD_REACHABLE = 0x02
NUD_NOARP = 0x40
NTF_MASTER = 0x04
NTF_EXT_LEARNED = 0x10
NTF_STICKY = 0x40
NLMSG_ERROR = 2
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_REPLACE = 0x100
NLM_F_CREATE = 0x400
NTF_E_MH_PEER_SYNC = 0x04  # include/linux/neighbour.h

FPM_HEADER = struct.Struct("!BBH")
NL_HEADER = struct.Struct("=IHHII")
NDMSG = struct.Struct("=BBHiHBB")
ATTRIBUTE = struct.Struct("=HH")


def _socket_in_router(router, family, kind, protocol=0):
    with open("/proc/self/ns/net", "rb") as current:
        with open(f"/proc/{router.net.pid}/ns/net", "rb") as target:
            linux.setns(target.fileno(), linux.CLONE_NEWNET)
            try:
                return socket.socket(family, kind, protocol)
            finally:
                linux.setns(current.fileno(), linux.CLONE_NEWNET)


def _mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def _attribute(kind, value):
    size = ATTRIBUTE.size + len(value)
    return ATTRIBUTE.pack(size, kind) + value + bytes(-size % 4)


def _neighbor(
    op, ifindex, mac, vid, sticky=False, attributes=b"", request=NLM_F_REQUEST
):
    state = NUD_REACHABLE | (NUD_NOARP if sticky else 0)
    flags = NTF_MASTER | NTF_EXT_LEARNED | (NTF_STICKY if sticky else 0)
    body = NDMSG.pack(socket.AF_BRIDGE, 0, 0, ifindex, state, flags, 0)
    body += _attribute(NDA_LLADDR, _mac_bytes(mac))
    body += _attribute(NDA_VLAN, struct.pack("=H", vid))
    body += attributes
    return NL_HEADER.pack(NL_HEADER.size + len(body), op, request, 1, 0) + body


@dataclass
class MacMessage:
    op: int
    ifindex: int
    state: int
    attributes: dict


class FpmPeer:
    def __init__(self, router):
        self.listener = _socket_in_router(router, socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.connection = None
        self.messages = []

    @property
    def port(self):
        return self.listener.getsockname()[1]

    def accept(self):
        self.connection, _ = self.listener.accept()

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def close(self):
        self.disconnect()
        self.listener.close()

    def send(self, op, ifindex, mac, vid, sticky=False):
        message = _neighbor(op, ifindex, mac, vid, sticky=sticky)
        header = FPM_HEADER.pack(1, 1, FPM_HEADER.size + len(message))
        self.connection.sendall(header + message)

    def _read(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("waiting for FPM frame")
            self.connection.settimeout(remaining)
            chunk = self.connection.recv(size - len(data))
            assert chunk, "FPM connection closed while receiving a frame"
            data.extend(chunk)
        return data

    def receive(self, mac, op):
        mac_value = _mac_bytes(mac)
        deadline = time.monotonic() + 20
        start = len(self.messages)
        try:
            while True:
                version, kind, size = FPM_HEADER.unpack(
                    self._read(FPM_HEADER.size, deadline)
                )
                assert (version, kind) == (1, 1)
                assert size >= FPM_HEADER.size + NL_HEADER.size
                data = self._read(size - FPM_HEADER.size, deadline)
                matched = None
                for message in _decode(data):
                    self.messages.append(message)
                    if (
                        matched is None
                        and message.attributes.get(NDA_LLADDR) == mac_value
                    ):
                        matched = message
                if matched is not None:
                    assert matched.op == op, matched
                    assert NDA_PROTOCOL not in matched.attributes, matched
                    return matched
        except TimeoutError:
            pytest.fail(
                f"Missing FPM operation {op} for {mac}. Received {self.messages[start:]}"
            )


def _decode(data):
    offset = 0
    while offset + NL_HEADER.size <= len(data):
        size, op, _, _, _ = NL_HEADER.unpack_from(data, offset)
        assert NL_HEADER.size <= size <= len(data) - offset
        body = memoryview(data)[offset + NL_HEADER.size : offset + size]
        offset += (size + 3) & ~3
        if op not in (RTM_NEWNEIGH, RTM_DELNEIGH):
            continue
        family, _, _, ifindex, state, _, _ = NDMSG.unpack_from(body)
        if family != socket.AF_BRIDGE:
            continue
        attributes = {}
        position = NDMSG.size
        while position + ATTRIBUTE.size <= len(body):
            length, kind = ATTRIBUTE.unpack_from(body, position)
            assert ATTRIBUTE.size <= length <= len(body) - position
            attributes[kind] = bytes(
                body[position + ATTRIBUTE.size : position + length]
            )
            position += (length + 3) & ~3
        yield MacMessage(op, ifindex, state, attributes)


def probe_peer_sync(router, port, ifindex, bridge_ifindex, vid):
    """Check the kernel ACK to an otherwise valid FDB write with peer-sync."""
    mac = "02:00:00:00:ff:fe"
    attributes = _attribute(NDA_MASTER, struct.pack("=I", bridge_ifindex))

    def send(sock, extra):
        request = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        packet = _neighbor(
            RTM_NEWNEIGH,
            ifindex,
            mac,
            vid,
            attributes=attributes + extra,
            request=request,
        )
        sock.sendto(packet, (0, 0))
        ack = sock.recv(4096)
        _, kind, _, seq, _ = NL_HEADER.unpack_from(ack)
        assert (kind, seq) == (NLMSG_ERROR, 1), ack
        return -struct.unpack_from("=i", ack, NL_HEADER.size)[0]

    with _socket_in_router(
        router, socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sock:
        sock.settimeout(10)
        sock.bind((0, 0))
        assert send(sock, b"") == 0, "kernel rejected the ordinary FDB probe"
        try:
            assert (
                send(sock, b"") == 0
            ), "kernel rejected replacement of the probe entry"
            result = send(
                sock, _attribute(NDA_FLAGS_EXT, struct.pack("=I", NTF_E_MH_PEER_SYNC))
            )
        finally:
            router.cmd_raises(f"bridge fdb del {mac} dev {port} master vlan {vid}")

    reason = errno.errorcode.get(result, result)
    if result in (errno.EINVAL, errno.EOPNOTSUPP):
        pytest.skip(f"kernel rejected the EVPN-MH peer-sync FDB attribute ({reason})")
    assert result == 0, f"unexpected peer-sync FDB probe result ({reason})"
