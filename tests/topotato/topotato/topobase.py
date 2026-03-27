#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Abstract base classes for NetworkInstance/SwitchyNS/RouterNS

This module defines the interface exposed by the OS-specific network instance
and virtual router wrappers.  The :py:mod:`topotato.osdep` module selects the
appropriate implementation at runtime.  For type checking, only the methods
and attributes defined here should be used outside OS-specific code.
"""

from abc import ABC, abstractmethod
import typing
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Tuple,
    Union,
)
from typing_extensions import Protocol

if typing.TYPE_CHECKING:
    from typing import (
        Self,
        TypeAlias,
    )
    import subprocess
    from . import toponom
    from .timeline import Timeline


class BaseNS(ABC):
    """
    Common interface to a virtual host/router.

    Note that this is intentionally generic in not assuming code can be
    executed on that virtual system.  At some point in the future, topotato
    might add support for "external" DUTs with limited interfaces.

    .. todo::

       Tighter integration with :py:class:`Timeline`?
    """

    instance: "NetworkInstance"

    def __init__(self, _instance: "NetworkInstance", name: str) -> None:
        pass

    @abstractmethod
    def tempfile(self, name: str) -> str:
        """
        Get a path for a temporary file.
        """

    @abstractmethod
    def start(self) -> None:
        """
        Start this virtual system.
        """

    def start_post(self, timeline: "Timeline", failed: List[Tuple[str, str]]) -> None:
        """
        Perform post-start checks.  Empty by default.

        .. todo::

           rework/remove "failed" parameter.
        """

    @abstractmethod
    def end_prep(self) -> None:
        """
        Prepare for shutdown.
        """

    @abstractmethod
    def end(self) -> None:
        """
        Stop this virtual system.
        """


class SwitchyNS(BaseNS):
    """
    Virtual switch at the center of an emulated network.

    This doesn't have any specific extra methods to it.
    """


class RouterNS(BaseNS):
    """
    Virtual router or host of some type in this network instance.
    """

    name: str
    """
    All virtual routers/hosts have at least a name.
    """

    @abstractmethod
    def interactive_state(self) -> Dict[str, Any]:
        """
        Retrieve state for interactive / potatool access.
        """

    @abstractmethod
    def report_state(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve state for HTML test report.
        """

    @abstractmethod
    def routes(
        self, af: Union[Literal[4], Literal[6]] = 4, local=False
    ) -> Dict[str, Any]:
        """
        Retrieve kernel routing table from this system.

        .. todo::

           Implement a type/protocol for the return value.
        """

    @abstractmethod
    def link_set(self, iface: "toponom.LinkIface", state: bool) -> None:
        """
        Set one of this systems interfaces up or down.
        """


class CallableNS(Protocol):
    """
    Typing protocol for virtual routers that can execute programs.

    Implementing this protocol is a requirement for all uses currently.
    """

    def check_call(self, cmdline: List[str], *args, **kwargs) -> None:
        ...

    def check_output(self, cmdline: List[str], *args, **kwargs) -> Tuple[bytes, bytes]:
        ...

    def popen(self, cmdline: List[str], *args, **kwargs) -> "subprocess.Popen":
        ...


class NetworkInstance(ABC):
    """
    A possibly-running virtual network for a test.
    """

    network: "toponom.Network"
    switch_ns: Optional[SwitchyNS]
    routers: Mapping[str, RouterNS]

    RouterNS: "TypeAlias" = RouterNS
    """
    To be overridden by concrete implementations, the virtual router type
    generally assumed by this instance.
    """
    SwitchyNS: "TypeAlias" = SwitchyNS
    """
    To be overridden by concrete implementations.
    """

    def __init__(self, network: "toponom.Network") -> None:
        super().__init__()
        self.network = network
        self.switch_ns = None
        self.routers = {}

    def make(self, name: str) -> RouterNS:
        """
        Overrideable method to instantiate a virtual router in this instance.

        Subclasses further down the chain may want to use custom subclasses
        for specific virtual routers.  This enables that.
        """
        # pylint: disable=abstract-class-instantiated
        return self.RouterNS(self, name)  # type: ignore

    @abstractmethod
    def tempfile(self, name: str) -> str:
        """
        Get a path for a temporary file.
        """

    def prepare(self) -> "Self":
        """
        Execute setup (create switch & router objects) for this network instance.
        """
        # pylint: disable=abstract-class-instantiated
        self.switch_ns = self.SwitchyNS(self, "switch-ns")  # type: ignore

        # self.routers is immutable, assign as a whole
        routers = {}
        for r in self.network.routers.values():
            routers[r.name] = self.make(r.name)
        self.routers = routers
        return self

    @abstractmethod
    def start(self) -> None:
        """
        Start this network instance.
        """

    @abstractmethod
    def stop(self) -> None:
        """
        Stop this network instance.
        """
