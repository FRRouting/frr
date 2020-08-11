#!/usr/bin/env python

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#


""" These procedures are used in 5549 automation and are local"""

from lib.common_config import get_frr_ipv6_linklocal
from lib.topogen import get_topogen
from lib.topolog import logger


def get_llip(topo, onrouter, intf, vrf=None):
    """
    API to get the link local ipv6 address of a perticular interface

    Parameters
    ----------
    * `topo`: topo details.
    * `onrouter`: Source node
    * `intf` : interface for which link local ip needs to be returned.
    * `vrf` : VRF if interface is configured on vrf.

    Usage
    -----
    result = get_llip('r1', 'r2-link0')

    Returns
    -------
    1) link local ipv6 address from the interface.
    2) None - when link local ip not found.
    """
    tgen = get_topogen()
    intf = topo["routers"][onrouter]["links"][intf]["interface"]
    if vrf:
        llip = get_frr_ipv6_linklocal(tgen, onrouter, intf, vrf)
    else:
        llip = get_frr_ipv6_linklocal(tgen, onrouter, intf)
    if llip:
        logger.info("llip ipv6 address to be set as NH is %s", llip)
        return llip
    return None


def get_glipv6(topo, onrouter, intf, addr_type="ipv6"):
    """
    API to get the global ipv6 address of a perticular interface

    Parameters
    ----------
    * `topo`: topo details.
    * `onrouter`: Source node
    * `intf` : interface for which link local ip needs to be returned.
    * `addr_type` : Address type of the address to be returned.

    Usage
    -----
    result = get_glipv6('r1', 'r2-link0')

    Returns
    -------
    1) global ipv4/ipv6 address from the interface.
    2) None when nexthop not found.
    """
    glipv6 = (topo["routers"][onrouter]["links"][intf][addr_type]).split("/")[0]
    if glipv6:
        logger.info("Global %s address to be set as NH is %s", addr_type, glipv6)
        return glipv6
    return None
