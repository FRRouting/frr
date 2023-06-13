#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2023  David Lamparter for NetDEF, Inc.
"""
Jinja2 templating for FRR configurations.
"""

from dataclasses import dataclass
import typing
from typing import (
    Callable,
    List,
    Literal,
    Set,
    Tuple,
    Union,
    cast,
)

from .. import jinlinja

if typing.TYPE_CHECKING:
    from .. import toponom

jenv = jinlinja.InlineEnv()

# TBD: might be more accessible to just put these in a templates/ dir
_templates = {
    "boilerplate.conf": """
        log record-priority
        log timestamp precision 6
        !
        hostname {{ router.name }}
        service advanced-vty
        !
        #% block main
        #% endblock
        !
        line vty
        !
        """.replace(
        "\n        ", "\n"
    ).lstrip(
        "\n"
    ),
}

jenv.register_templates(_templates.items())


@dataclass
class TemplateUtils:
    router: "toponom.Router"
    daemon: str

    def static_route_for(
        self,
        dst: "toponom.AnyNetwork",
        *,
        rtr_filter: Callable[["toponom.Router"], bool] = lambda nbr: True,
    ):
        """
        Calculate and output a staticd route for given destination.

        Current router is used as starting point.  Uses a simple
        breath-first search, only one route will be output (no ECMP.)
        If the destination is directly connected, output is a comment.
        """
        visited: Set["toponom.Router"] = set()
        queue: List[
            Tuple[
                "toponom.Router",
                List[Tuple["toponom.LinkIface", "toponom.LinkIface"]],
            ]
        ] = [(self.router, [])]

        assert dst.version in [4, 6]
        ipv = cast(Union[Literal[4], Literal[6]], dst.version)

        while queue:
            rtr, path = queue.pop(0)
            if rtr in visited:
                continue
            visited.add(rtr)
            for addr in rtr.addrs(ipv):
                if dst == addr.network:
                    if not path:
                        return f"! {dst!s} is directly connected"
                    if_self, if_other = path[0]
                    if dst.version == 6:
                        return f"ipv6 route {dst!s} {if_other.ll6!s} {if_self.ifname}"
                    return f"ip route {dst!s} {if_other.ip4[0].ip!s} {if_self.ifname}"
            for iface, nbr_iface, nbr in rtr.neighbors(rtr_filter=rtr_filter):
                nbr_path = path + [(iface, nbr_iface)]
                queue.append((nbr, nbr_path))

        raise RuntimeError(f"no route for {dst!r} on {self.router!r}")
