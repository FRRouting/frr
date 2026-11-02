# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Operating system interfaces and their multicast interface numbers."""

from __future__ import annotations

import socket
from typing import Any, Dict, Iterator, List, Optional

from .common import debug_netlink, ntop4, out

try:
    from typing import Protocol
except ImportError:  # Python < 3.8
    Protocol = object  # type: ignore

from .mroute import MulticastRouting


class Interface:
    def __init__(self, name: str, index: int) -> None:
        #: Interface name.
        self.name = name
        #: Interface unique index.
        self.index = index
        #: IPv4 multicast interface number (VIF), 0 for none.
        self.vif = 0
        #: IPv6 multicast interface number (MIF), 0 for none.
        self.mif = 0
        #: IPv4 addresses, in the order they were added.
        self.addresses: List[bytes] = []
        #: Packet socket capturing the interface traffic.
        self.capture: Optional[socket.socket] = None

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "index": self.index,
            "vif": self.vif,
            "mif": self.mif,
            "addresses": [ntop4(address) for address in self.addresses],
        }


class InterfaceHooks(Protocol):
    def interface_added(self, interface: Interface) -> None: ...

    def interface_removed(self, interface: Interface) -> None: ...

    def interface_ipv4_enabled(self, interface: Interface) -> None: ...


def _usable_address(address: bytes) -> bool:
    # Loopback addresses never get a multicast interface.
    return address[0] != 127


class Interfaces:
    """
    Interface registry: every interface gets an IPv6 multicast interface,
    the ones with an IPv4 address (other than loopback ones) an IPv4 one.
    """

    def __init__(self, routing: MulticastRouting, hooks: InterfaceHooks) -> None:
        self.routing = routing
        self.hooks = hooks
        self._by_index: Dict[int, Interface] = {}

    def __iter__(self) -> Iterator[Interface]:
        return iter(sorted(self._by_index.values(), key=lambda i: i.index))

    def __len__(self) -> int:
        return len(self._by_index)

    def find_index(self, index: int) -> Optional[Interface]:
        return self._by_index.get(index)

    def find_name(self, name: str) -> Optional[Interface]:
        for interface in self._by_index.values():
            if interface.name == name:
                return interface
        return None

    def name(self, index: int) -> Optional[str]:
        interface = self._by_index.get(index)
        return interface.name if interface else None

    def ifi2vif(self, index: int) -> int:
        interface = self._by_index.get(index)
        return interface.vif if interface else 0

    def ifi2mif(self, index: int) -> int:
        interface = self._by_index.get(index)
        return interface.mif if interface else 0

    def vif2ifi(self, vif: int) -> int:
        for interface in self._by_index.values():
            if vif and interface.vif == vif:
                return interface.index
        return 0

    def mif2ifi(self, mif: int) -> int:
        for interface in self._by_index.values():
            if mif and interface.mif == mif:
                return interface.index
        return 0

    #
    # Links.
    #
    def link(self, index: int, name: str) -> None:
        """An interface exists (new, renamed or unchanged)."""
        interface = self._by_index.get(index)
        if interface is not None:
            if interface.name != name:
                out(
                    "interface {} index {} renamed to {}".format(
                        interface.name, index, name
                    )
                )
                interface.name = name
            return

        # The name moved to another index (we missed the removal).
        stale = self.find_name(name)
        if stale is not None:
            self.unlink(stale.index)

        interface = Interface(name, index)
        self._by_index[index] = interface
        # IPv6 multicast only needs the interface (link-local addresses).
        interface.mif = self.routing.mif_add(index)
        self.hooks.interface_added(interface)

        if debug_netlink():
            out(
                "interface_add: new interface {} index {} mif {}".format(
                    name, index, interface.mif
                )
            )

    def unlink(self, index: int) -> None:
        """The interface is gone."""
        interface = self._by_index.pop(index, None)
        if interface is None:
            return

        out("interface {} index {} removed".format(interface.name, index))
        self.routing.vif_del(index, interface.vif)
        self.routing.mif_del(index, interface.mif)
        interface.vif = 0
        interface.mif = 0
        self.hooks.interface_removed(interface)

    def sync_links(self, links: Dict[int, str]) -> None:
        """Make the interfaces match a full dump."""
        for index in [index for index in self._by_index if index not in links]:
            self.unlink(index)
        for index, name in links.items():
            self.link(index, name)

    #
    # IPv4 addresses.
    #
    def address_add(self, index: int, address: bytes) -> None:
        interface = self._by_index.get(index)
        if interface is None:
            if debug_netlink():
                out("address {} for unknown interface {}".format(ntop4(address), index))
            return
        if not _usable_address(address) or address in interface.addresses:
            return

        interface.addresses.append(address)
        if interface.vif:
            if debug_netlink():
                out(
                    "  => interface {} index {} has address {}".format(
                        interface.name, index, ntop4(address)
                    )
                )
            return

        # One multicast interface per interface, whatever the address.
        interface.vif = self.routing.vif_add(index, address)
        out(
            "  => interface {} index {} address {} vif {}".format(
                interface.name, index, ntop4(address), interface.vif
            )
        )
        if interface.vif:
            self.hooks.interface_ipv4_enabled(interface)

    def address_del(self, index: int, address: bytes) -> None:
        interface = self._by_index.get(index)
        if interface is None or address not in interface.addresses:
            return

        interface.addresses.remove(address)
        if interface.addresses or not interface.vif:
            return

        out(
            "  => disable interface {} index {} address {} vif {}".format(
                interface.name, index, ntop4(address), interface.vif
            )
        )
        self.routing.vif_del(index, interface.vif)
        interface.vif = 0

    def sync_addresses(self, addresses: Dict[int, List[bytes]]) -> None:
        """Make the IPv4 addresses match a full dump."""
        for interface in list(self._by_index.values()):
            current = addresses.get(interface.index, [])
            for address in list(interface.addresses):
                if address not in current:
                    self.address_del(interface.index, address)
            for address in current:
                self.address_add(interface.index, address)

    def shutdown(self) -> None:
        """Remove the multicast interfaces (the routes go with them)."""
        for interface in self._by_index.values():
            self.routing.vif_del(interface.index, interface.vif)
            self.routing.mif_del(interface.index, interface.mif)
            interface.vif = 0
            interface.mif = 0

    def describe(self) -> List[Dict[str, Any]]:
        return [interface.describe() for interface in self]
