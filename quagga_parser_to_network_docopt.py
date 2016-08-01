#!/usr/bin/env python

"""
The primary use case of this tool is to print a network-docopt compatible
docstring that covers all bgp and ospf commands in quagga.
"""

import argparse
import logging
import os
import re
import sys
from pprint import pprint, pformat

# All of the clear commands in bgp_clear_ignore will be covered by these clear commands:
#     quagga clear bgp (<ipv4>|<ipv6>|<interface>|*)
#     quagga clear bgp (<ipv4>|<ipv6>|<interface>|*) soft [in|out]
#     quagga clear bgp prefix <ipv4/prefixlen>
bgp_clear_ignore = """    quagga clear bgp (<ipv4>|<ipv6>|<interface>)
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) in
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) in prefix-filter
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) out
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) soft
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) soft in
    quagga clear bgp (<ipv4>|<ipv6>|<interface>) soft out
    quagga clear bgp *
    quagga clear bgp * in
    quagga clear bgp * in prefix-filter
    quagga clear bgp * out
    quagga clear bgp * soft
    quagga clear bgp * soft in
    quagga clear bgp * soft out
    quagga clear bgp <1-4294967295>
    quagga clear bgp <1-4294967295> in
    quagga clear bgp <1-4294967295> in prefix-filter
    quagga clear bgp <1-4294967295> out
    quagga clear bgp <1-4294967295> soft
    quagga clear bgp <1-4294967295> soft in
    quagga clear bgp <1-4294967295> soft out
    quagga clear bgp BGP_INSTANCE_CMD *
    quagga clear bgp BGP_INSTANCE_CMD * soft
    quagga clear bgp BGP_INSTANCE_CMD * soft in
    quagga clear bgp BGP_INSTANCE_CMD * soft out
    quagga clear bgp external
    quagga clear bgp external in
    quagga clear bgp external in prefix-filter
    quagga clear bgp external out
    quagga clear bgp external soft
    quagga clear bgp external soft in
    quagga clear bgp external soft out
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>)
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) in
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) in prefix-filter
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) out
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) soft
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) soft in
    quagga clear bgp ipv6 (<ipv4>|<ipv6>|<interface>) soft out
    quagga clear bgp ipv6 (unicast|multicast) prefix <ipv6/prefixlen>
    quagga clear bgp ipv6 *
    quagga clear bgp ipv6 * in
    quagga clear bgp ipv6 * in prefix-filter
    quagga clear bgp ipv6 * out
    quagga clear bgp ipv6 * soft
    quagga clear bgp ipv6 * soft in
    quagga clear bgp ipv6 * soft out
    quagga clear bgp ipv6 <1-4294967295>
    quagga clear bgp ipv6 <1-4294967295> in
    quagga clear bgp ipv6 <1-4294967295> in prefix-filter
    quagga clear bgp ipv6 <1-4294967295> out
    quagga clear bgp ipv6 <1-4294967295> soft
    quagga clear bgp ipv6 <1-4294967295> soft in
    quagga clear bgp ipv6 <1-4294967295> soft out
    quagga clear bgp ipv6 external
    quagga clear bgp ipv6 external WORD in
    quagga clear bgp ipv6 external WORD out
    quagga clear bgp ipv6 external in prefix-filter
    quagga clear bgp ipv6 external soft
    quagga clear bgp ipv6 external soft in
    quagga clear bgp ipv6 external soft out
    quagga clear bgp ipv6 peer-group WORD
    quagga clear bgp ipv6 peer-group WORD in
    quagga clear bgp ipv6 peer-group WORD in prefix-filter
    quagga clear bgp ipv6 peer-group WORD out
    quagga clear bgp ipv6 peer-group WORD soft
    quagga clear bgp ipv6 peer-group WORD soft in
    quagga clear bgp ipv6 peer-group WORD soft out
    quagga clear bgp peer-group WORD
    quagga clear bgp peer-group WORD in
    quagga clear bgp peer-group WORD in prefix-filter
    quagga clear bgp peer-group WORD out
    quagga clear bgp peer-group WORD soft
    quagga clear bgp peer-group WORD soft in
    quagga clear bgp peer-group WORD soft out
    quagga clear ip bgp (<ipv4>|<interface>) in
    quagga clear ip bgp (<ipv4>|<interface>) in prefix-filter
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) in
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) out
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) soft
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) soft in
    quagga clear ip bgp (<ipv4>|<interface>) ipv4 (unicast|multicast) soft out
    quagga clear ip bgp (<ipv4>|<interface>) out
    quagga clear ip bgp (<ipv4>|<interface>) soft
    quagga clear ip bgp (<ipv4>|<interface>) soft in
    quagga clear ip bgp (<ipv4>|<interface>) soft out
    quagga clear ip bgp (<ipv4>|<interface>) vpnv4 unicast in
    quagga clear ip bgp (<ipv4>|<interface>) vpnv4 unicast out
    quagga clear ip bgp (<ipv4>|<interface>) vpnv4 unicast soft
    quagga clear ip bgp (<ipv4>|<interface>) vpnv4 unicast soft in
    quagga clear ip bgp (<ipv4>|<interface>) vpnv4 unicast soft out
    quagga clear ip bgp (<ipv4>|<ipv6>|<interface>)
    quagga clear ip bgp *
    quagga clear ip bgp * in
    quagga clear ip bgp * in prefix-filter
    quagga clear ip bgp * ipv4 (unicast|multicast) in
    quagga clear ip bgp * ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp * ipv4 (unicast|multicast) out
    quagga clear ip bgp * ipv4 (unicast|multicast) soft
    quagga clear ip bgp * ipv4 (unicast|multicast) soft in
    quagga clear ip bgp * ipv4 (unicast|multicast) soft out
    quagga clear ip bgp * out
    quagga clear ip bgp * soft
    quagga clear ip bgp * soft in
    quagga clear ip bgp * soft out
    quagga clear ip bgp * vpnv4 unicast in
    quagga clear ip bgp * vpnv4 unicast out
    quagga clear ip bgp * vpnv4 unicast soft
    quagga clear ip bgp * vpnv4 unicast soft in
    quagga clear ip bgp * vpnv4 unicast soft out
    quagga clear ip bgp <1-4294967295>
    quagga clear ip bgp <1-4294967295> in
    quagga clear ip bgp <1-4294967295> in prefix-filter
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) in
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) out
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft in
    quagga clear ip bgp <1-4294967295> ipv4 (unicast|multicast) soft out
    quagga clear ip bgp <1-4294967295> out
    quagga clear ip bgp <1-4294967295> soft
    quagga clear ip bgp <1-4294967295> soft in
    quagga clear ip bgp <1-4294967295> soft out
    quagga clear ip bgp <1-4294967295> vpnv4 unicast in
    quagga clear ip bgp <1-4294967295> vpnv4 unicast out
    quagga clear ip bgp <1-4294967295> vpnv4 unicast soft
    quagga clear ip bgp <1-4294967295> vpnv4 unicast soft in
    quagga clear ip bgp <1-4294967295> vpnv4 unicast soft out
    quagga clear ip bgp BGP_INSTANCE_CMD *
    quagga clear ip bgp BGP_INSTANCE_CMD * in prefix-filter
    quagga clear ip bgp BGP_INSTANCE_CMD * ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp BGP_INSTANCE_CMD * ipv4 (unicast|multicast) soft
    quagga clear ip bgp BGP_INSTANCE_CMD * ipv4 (unicast|multicast) soft in
    quagga clear ip bgp BGP_INSTANCE_CMD * ipv4 (unicast|multicast) soft out
    quagga clear ip bgp BGP_INSTANCE_CMD * soft
    quagga clear ip bgp BGP_INSTANCE_CMD * soft in
    quagga clear ip bgp BGP_INSTANCE_CMD * soft out
    quagga clear ip bgp dampening
    quagga clear ip bgp dampening <ipv4/prefixlen>
    quagga clear ip bgp dampening <ipv4>
    quagga clear ip bgp dampening <ipv4> <ipv4>
    quagga clear ip bgp external
    quagga clear ip bgp external in
    quagga clear ip bgp external in prefix-filter
    quagga clear ip bgp external ipv4 (unicast|multicast) in
    quagga clear ip bgp external ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp external ipv4 (unicast|multicast) out
    quagga clear ip bgp external ipv4 (unicast|multicast) soft
    quagga clear ip bgp external ipv4 (unicast|multicast) soft in
    quagga clear ip bgp external ipv4 (unicast|multicast) soft out
    quagga clear ip bgp external out
    quagga clear ip bgp external soft
    quagga clear ip bgp external soft in
    quagga clear ip bgp external soft out
    quagga clear ip bgp peer-group WORD
    quagga clear ip bgp peer-group WORD in
    quagga clear ip bgp peer-group WORD in prefix-filter
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) in
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) in prefix-filter
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) out
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft in
    quagga clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft out
    quagga clear ip bgp peer-group WORD out
    quagga clear ip bgp peer-group WORD soft
    quagga clear ip bgp peer-group WORD soft in
    quagga clear ip bgp peer-group WORD soft out
    quagga clear ip bgp prefix <ipv4/prefixlen>""".splitlines()

# All of the debug commands in bgp_debug_ignore will be covered by these debug commands:
#    quagga (add|del) debug bgp bestpath <ip/prefixlen>
#    quagga (add|del) debug bgp keepalives (<ipv4>|<ipv6>|<interface>)
#    quagga (add|del) debug bgp neighbor-events (<ipv4>|<ipv6>|<interface>)
#    quagga (add|del) debug bgp nht
#    quagga (add|del) debug bgp update-groups
#    quagga (add|del) debug bgp updates prefix <ip/prefixlen>
#    quagga (add|del) debug bgp zebra prefix <ip/prefixlen>
bgp_debug_ignore = """    quagga debug bgp as4
    quagga debug bgp as4 segment
    quagga debug bgp bestpath (<ipv4/prefixlen>|<ipv6/prefixlen>)
    quagga debug bgp keepalives
    quagga debug bgp keepalives (<ipv4>|<ipv6>|<interface>)
    quagga debug bgp neighbor-events
    quagga debug bgp neighbor-events (<ipv4>|<ipv6>|<interface>)
    quagga debug bgp nht
    quagga debug bgp update-groups
    quagga debug bgp updates
    quagga debug bgp updates (in|out)
    quagga debug bgp updates (in|out) (<ipv4>|<ipv6>|<interface>)
    quagga debug bgp updates prefix (<ipv4/prefixlen>|<ipv6/prefixlen>)
    quagga debug bgp zebra
    quagga debug bgp zebra prefix (<ipv4/prefixlen>|<ipv6/prefixlen>)""".splitlines()


bgp_show_ignore = """    quagga show bgp (ipv4) (vpnv4) statistics
    quagga show bgp (ipv4|ipv6) (unicast|multicast) statistics
    quagga show bgp (ipv4|ipv6) (unicast|multicast) update-groups
    quagga show bgp (ipv4|ipv6) (unicast|multicast) update-groups (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp (ipv4|ipv6) (unicast|multicast) update-groups SUBGROUP-ID
    quagga show bgp (ipv4|ipv6) (unicast|multicast) update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp <ipv6/prefixlen> (bestpath|multipath) [json]
    quagga show bgp <ipv6/prefixlen> [json]
    quagga show bgp <ipv6/prefixlen> longer-prefixes
    quagga show bgp <ipv6> (bestpath|multipath) [json]
    quagga show bgp <ipv6> [json]
    quagga show bgp BGP_INSTANCE_CMD (ipv4) (vpnv4) statistics
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) community
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) (advertised-routes|received-routes) [json]
    quagga show bgp BGP_INSTANCE_CMD (ipv4|ipv6) (unicast|multicast) statistics
    quagga show bgp BGP_INSTANCE_CMD <ipv6/prefixlen> (bestpath|multipath) [json]
    quagga show bgp BGP_INSTANCE_CMD <ipv6/prefixlen> [json]
    quagga show bgp BGP_INSTANCE_CMD <ipv6/prefixlen> longer-prefixes
    quagga show bgp BGP_INSTANCE_CMD <ipv6> (bestpath|multipath) [json]
    quagga show bgp BGP_INSTANCE_CMD <ipv6> [json]
    quagga show bgp BGP_INSTANCE_CMD [json]
    quagga show bgp BGP_INSTANCE_CMD community-list (<1-500>|WORD)
    quagga show bgp BGP_INSTANCE_CMD filter-list WORD
    quagga show bgp BGP_INSTANCE_CMD ipv6 (unicast|multicast) summary [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 <ipv6/prefixlen> (bestpath|multipath) [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 <ipv6/prefixlen> [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 <ipv6/prefixlen> longer-prefixes
    quagga show bgp BGP_INSTANCE_CMD ipv6 <ipv6> (bestpath|multipath) [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 <ipv6> [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 community-list (<1-500>|WORD)
    quagga show bgp BGP_INSTANCE_CMD ipv6 filter-list WORD
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) dampened-routes [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) flap-statistics [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 neighbors [json]
    quagga show bgp BGP_INSTANCE_CMD ipv6 prefix-list WORD
    quagga show bgp BGP_INSTANCE_CMD ipv6 route-map WORD
    quagga show bgp BGP_INSTANCE_CMD ipv6 summary [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) dampened-routes [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) flap-statistics [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show bgp BGP_INSTANCE_CMD neighbors [json]
    quagga show bgp BGP_INSTANCE_CMD prefix-list WORD
    quagga show bgp BGP_INSTANCE_CMD route-map WORD
    quagga show bgp BGP_INSTANCE_CMD summary [json]
    quagga show bgp BGP_INSTANCE_CMD update-groups
    quagga show bgp BGP_INSTANCE_CMD update-groups (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp BGP_INSTANCE_CMD update-groups SUBGROUP-ID
    quagga show bgp BGP_INSTANCE_CMD update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp [json]
    quagga show bgp community
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp community-list (<1-500>|WORD)
    quagga show bgp community-list (<1-500>|WORD) exact-match
    quagga show bgp filter-list WORD
    quagga show bgp ipv4 (unicast|multicast) <ipv4/prefixlen> (bestpath|multipath) [json]
    quagga show bgp ipv4 (unicast|multicast) <ipv4/prefixlen> [json]
    quagga show bgp ipv4 (unicast|multicast) <ipv4> (bestpath|multipath) [json]
    quagga show bgp ipv4 (unicast|multicast) <ipv4> [json]
    quagga show bgp ipv4 (unicast|multicast) [json]
    quagga show bgp ipv4 (unicast|multicast) summary [json]
    quagga show bgp ipv6 (unicast|multicast) <ipv6/prefixlen> (bestpath|multipath) [json]
    quagga show bgp ipv6 (unicast|multicast) <ipv6/prefixlen> [json]
    quagga show bgp ipv6 (unicast|multicast) <ipv6> (bestpath|multipath) [json]
    quagga show bgp ipv6 (unicast|multicast) <ipv6> [json]
    quagga show bgp ipv6 (unicast|multicast) [json]
    quagga show bgp ipv6 (unicast|multicast) summary [json]
    quagga show bgp ipv6 <ipv6/prefixlen> (bestpath|multipath) [json]
    quagga show bgp ipv6 <ipv6/prefixlen> [json]
    quagga show bgp ipv6 <ipv6/prefixlen> longer-prefixes
    quagga show bgp ipv6 <ipv6> (bestpath|multipath) [json]
    quagga show bgp ipv6 <ipv6> [json]
    quagga show bgp ipv6 [json]
    quagga show bgp ipv6 community
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show bgp ipv6 community-list (<1-500>|WORD)
    quagga show bgp ipv6 community-list (<1-500>|WORD) exact-match
    quagga show bgp ipv6 filter-list WORD
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) dampened-routes [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) flap-statistics [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show bgp ipv6 neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show bgp ipv6 neighbors [json]
    quagga show bgp ipv6 prefix-list WORD
    quagga show bgp ipv6 regexp LINE
    quagga show bgp ipv6 route-map WORD
    quagga show bgp ipv6 summary [json]
    quagga show bgp memory
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) dampened-routes [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) flap-statistics [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show bgp neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show bgp neighbors [json]
    quagga show bgp prefix-list WORD
    quagga show bgp regexp LINE
    quagga show bgp route-map WORD
    quagga show bgp summary [json]
    quagga show bgp update-groups
    quagga show bgp update-groups (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp update-groups SUBGROUP-ID
    quagga show bgp update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)
    quagga show bgp view WORD ipv4 (unicast|multicast) summary [json]
    quagga show bgp views
    quagga show bgp vrfs [json]
    quagga show debugging bgp
    quagga show ip as-path-access-list
    quagga show ip as-path-access-list WORD
    quagga show ip bgp <ipv4/prefixlen> (bestpath|multipath) [json]
    quagga show ip bgp <ipv4/prefixlen> [json]
    quagga show ip bgp <ipv4/prefixlen> longer-prefixes
    quagga show ip bgp <ipv4> (bestpath|multipath) [json]
    quagga show ip bgp <ipv4> [json]
    quagga show ip bgp BGP_INSTANCE_CMD <ipv4/prefixlen> (bestpath|multipath) [json]
    quagga show ip bgp BGP_INSTANCE_CMD <ipv4/prefixlen> [json]
    quagga show ip bgp BGP_INSTANCE_CMD <ipv4/prefixlen> longer-prefixes
    quagga show ip bgp BGP_INSTANCE_CMD <ipv4> (bestpath|multipath) [json]
    quagga show ip bgp BGP_INSTANCE_CMD <ipv4> [json]
    quagga show ip bgp BGP_INSTANCE_CMD [json]
    quagga show ip bgp BGP_INSTANCE_CMD community-list (<1-500>|WORD)
    quagga show ip bgp BGP_INSTANCE_CMD filter-list WORD
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes route-map WORD [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) received-routes route-map WORD [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show ip bgp BGP_INSTANCE_CMD neighbors [json]
    quagga show ip bgp BGP_INSTANCE_CMD nexthop
    quagga show ip bgp BGP_INSTANCE_CMD nexthop detail
    quagga show ip bgp BGP_INSTANCE_CMD peer-group
    quagga show ip bgp BGP_INSTANCE_CMD peer-group WORD
    quagga show ip bgp BGP_INSTANCE_CMD prefix-list WORD
    quagga show ip bgp BGP_INSTANCE_CMD route-map WORD
    quagga show ip bgp BGP_INSTANCE_CMD summary [json]
    quagga show ip bgp BGP_INSTANCE_CMD update-groups
    quagga show ip bgp BGP_INSTANCE_CMD update-groups (advertise-queue|advertised-routes|packet-queue)
    quagga show ip bgp BGP_INSTANCE_CMD update-groups SUBGROUP-ID
    quagga show ip bgp BGP_INSTANCE_CMD update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)
    quagga show ip bgp [json]
    quagga show ip bgp attribute-info
    quagga show ip bgp cidr-only
    quagga show ip bgp community
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp community-info
    quagga show ip bgp community-list (<1-500>|WORD)
    quagga show ip bgp community-list (<1-500>|WORD) exact-match
    quagga show ip bgp dampened-paths
    quagga show ip bgp filter-list WORD
    quagga show ip bgp flap-statistics
    quagga show ip bgp flap-statistics <ipv4/prefixlen>
    quagga show ip bgp flap-statistics <ipv4/prefixlen> longer-prefixes
    quagga show ip bgp flap-statistics <ipv4>
    quagga show ip bgp flap-statistics cidr-only
    quagga show ip bgp flap-statistics filter-list WORD
    quagga show ip bgp flap-statistics prefix-list WORD
    quagga show ip bgp flap-statistics regexp LINE
    quagga show ip bgp flap-statistics route-map WORD
    quagga show ip bgp ipv4 (unicast|multicast) <ipv4/prefixlen> (bestpath|multipath) [json]
    quagga show ip bgp ipv4 (unicast|multicast) <ipv4/prefixlen> [json]
    quagga show ip bgp ipv4 (unicast|multicast) <ipv4/prefixlen> longer-prefixes
    quagga show ip bgp ipv4 (unicast|multicast) <ipv4> [json]
    quagga show ip bgp ipv4 (unicast|multicast) [json]
    quagga show ip bgp ipv4 (unicast|multicast) cidr-only
    quagga show ip bgp ipv4 (unicast|multicast) community
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)
    quagga show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) exact-match
    quagga show ip bgp ipv4 (unicast|multicast) filter-list WORD
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes route-map WORD [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) received-routes route-map WORD [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show ip bgp ipv4 (unicast|multicast) neighbors [json]
    quagga show ip bgp ipv4 (unicast|multicast) paths
    quagga show ip bgp ipv4 (unicast|multicast) prefix-list WORD
    quagga show ip bgp ipv4 (unicast|multicast) regexp LINE
    quagga show ip bgp ipv4 (unicast|multicast) route-map WORD
    quagga show ip bgp ipv4 (unicast|multicast) summary [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes route-map WORD [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) dampened-routes [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) flap-statistics [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) received prefix-filter [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) received-routes route-map WORD [json]
    quagga show ip bgp neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show ip bgp neighbors [json]
    quagga show ip bgp nexthop
    quagga show ip bgp nexthop detail
    quagga show ip bgp paths
    quagga show ip bgp peer-group
    quagga show ip bgp peer-group WORD
    quagga show ip bgp prefix-list WORD
    quagga show ip bgp regexp LINE
    quagga show ip bgp route-map WORD
    quagga show ip bgp summary [json]
    quagga show ip bgp update-groups
    quagga show ip bgp update-groups (advertise-queue|advertised-routes|packet-queue)
    quagga show ip bgp update-groups SUBGROUP-ID
    quagga show ip bgp update-groups SUBGROUP-ID (advertise-queue|advertised-routes|packet-queue)
    quagga show ip bgp view WORD ipv4 (unicast|multicast) summary [json]
    quagga show ip bgp vpnv4 all
    quagga show ip bgp vpnv4 all <ipv4/prefixlen> [json]
    quagga show ip bgp vpnv4 all <ipv4> [json]
    quagga show ip bgp vpnv4 all neighbors (<ipv4>|<ipv6>|<interface>) prefix-counts [json]
    quagga show ip bgp vpnv4 all neighbors <ipv4> [json]
    quagga show ip bgp vpnv4 all neighbors <ipv4> advertised-routes [json]
    quagga show ip bgp vpnv4 all neighbors <ipv4> routes [json]
    quagga show ip bgp vpnv4 all neighbors [json]
    quagga show ip bgp vpnv4 all summary [json]
    quagga show ip bgp vpnv4 all tags
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn <ipv4/prefixlen> [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn <ipv4> [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors <ipv4> [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors <ipv4> advertised-routes [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors <ipv4> routes [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn summary [json]
    quagga show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn tags
    quagga show ip community-list
    quagga show ip community-list (<1-500>|WORD)
    quagga show ip extcommunity-list
    quagga show ip extcommunity-list (<1-500>|WORD)
    quagga show ipv6 bgp <ipv6/prefixlen> [json]
    quagga show ipv6 bgp <ipv6/prefixlen> longer-prefixes
    quagga show ipv6 bgp <ipv6> [json]
    quagga show ipv6 bgp [json]
    quagga show ipv6 bgp community
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 bgp community-list WORD
    quagga show ipv6 bgp community-list WORD exact-match
    quagga show ipv6 bgp filter-list WORD
    quagga show ipv6 bgp neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show ipv6 bgp neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show ipv6 bgp neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show ipv6 bgp prefix-list WORD
    quagga show ipv6 bgp regexp LINE
    quagga show ipv6 bgp summary [json]
    quagga show ipv6 mbgp <ipv6/prefixlen> [json]
    quagga show ipv6 mbgp <ipv6/prefixlen> longer-prefixes
    quagga show ipv6 mbgp <ipv6> [json]
    quagga show ipv6 mbgp [json]
    quagga show ipv6 mbgp community
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match
    quagga show ipv6 mbgp community-list WORD
    quagga show ipv6 mbgp community-list WORD exact-match
    quagga show ipv6 mbgp filter-list WORD
    quagga show ipv6 mbgp neighbors (<ipv4>|<ipv6>|<interface>) advertised-routes [json]
    quagga show ipv6 mbgp neighbors (<ipv4>|<ipv6>|<interface>) received-routes [json]
    quagga show ipv6 mbgp neighbors (<ipv4>|<ipv6>|<interface>) routes [json]
    quagga show ipv6 mbgp prefix-list WORD
    quagga show ipv6 mbgp regexp LINE
    quagga show ipv6 mbgp summary [json]""".splitlines()

bgp_config_ignore = """    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) activate
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) addpath-tx-all-paths
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) addpath-tx-bestpath-per-AS
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) allowas-in
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) allowas-in <1-10>
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) as-override
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged (as-path|next-hop|med)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged as-path (next-hop|med)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged as-path med next-hop
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged as-path next-hop med
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged med (as-path|next-hop)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged med as-path next-hop
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged med next-hop as-path
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged next-hop (as-path|med)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged next-hop as-path med
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) attribute-unchanged next-hop med as-path
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) capability orf prefix-list (both|send|receive)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) default-originate
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) default-originate route-map WORD
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) distribute-list (<1-199>|<1300-2699>|WORD) (in|out)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) filter-list WORD (in|out)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295>
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295> <1-100>
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295> <1-100> restart <1-65535>
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295> <1-100> warning-only
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295> restart <1-65535>
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) maximum-prefix <1-4294967295> warning-only
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) next-hop-self
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) next-hop-self force
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) peer-group WORD
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) prefix-list WORD (in|out)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) remove-private-AS
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) remove-private-AS all
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) remove-private-AS all replace-AS
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) remove-private-AS replace-AS
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) route-map WORD (in|out)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) route-reflector-client
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) route-server-client
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) send-community
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) send-community (both|extended|standard)
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) soft-reconfiguration inbound
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ipv4>|<ipv6>|<interface>) unsuppress-map WORD
    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] table-map WORD
    quagga (add|del) bgp [ipv4|ipv6] unicast maximum-paths <1-255>
    quagga (add|del) bgp [ipv4|ipv6] unicast maximum-paths ibgp <1-255>
    quagga (add|del) bgp [ipv4|ipv6] unicast maximum-paths ibgp <1-255> equal-cluster-length
    quagga (add|del) bgp always-compare-med
    quagga (add|del) bgp bestpath as-path confed
    quagga (add|del) bgp bestpath as-path ignore
    quagga (add|del) bgp bestpath as-path multipath-relax [as-set|no-as-set]
    quagga (add|del) bgp bestpath compare-routerid
    quagga (add|del) bgp bestpath med (confed|missing-as-worst)
    quagga (add|del) bgp bestpath med confed missing-as-worst
    quagga (add|del) bgp bestpath med missing-as-worst confed
    quagga (add|del) bgp client-to-client reflection
    quagga (add|del) bgp cluster-id <1-4294967295>
    quagga (add|del) bgp cluster-id <ipv4>
    quagga (add|del) bgp confederation identifier <1-4294967295>
    quagga (add|del) bgp confederation peers . <1-4294967295>
    quagga (add|del) bgp default ipv4-unicast
    quagga (add|del) bgp default local-preference <0-4294967295>
    quagga (add|del) bgp default show-hostname
    quagga (add|del) bgp default subgroup-pkt-queue-max <20-100>
    quagga (add|del) bgp deterministic-med
    quagga (add|del) bgp disable-ebgp-connected-route-check
    quagga (add|del) bgp enforce-first-as
    quagga (add|del) bgp fast-external-failover
    quagga (add|del) bgp graceful-restart
    quagga (add|del) bgp graceful-restart stalepath-time <1-3600>
    quagga (add|del) bgp listen limit <1-5000>
    quagga (add|del) bgp listen range (<ipv4/prefixlen>|<ipv6/prefixlen>) peer-group WORD
    quagga (add|del) bgp log-neighbor-changes
    quagga (add|del) bgp max-med administrative
    quagga (add|del) bgp max-med administrative <0-4294967294>
    quagga (add|del) bgp max-med on-startup <5-86400>
    quagga (add|del) bgp max-med on-startup <5-86400> <0-4294967294>
    quagga (add|del) bgp network import-check
    quagga (add|del) bgp route-map delay-timer <0-600>
    quagga (add|del) bgp route-reflector allow-outbound-policy
    quagga (add|del) bgp router-id <ipv4>
    quagga (add|del) bgp coalesce-time <0-4294967295>
    quagga (add|del) bgp distance <1-255> <ipv4/prefixlen>
    quagga (add|del) bgp distance <1-255> <ipv4/prefixlen> WORD
    quagga (add|del) bgp distance bgp <1-255> <1-255> <1-255>
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4/prefixlen>
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4/prefixlen> as-set
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4/prefixlen> as-set summary-only
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4/prefixlen> summary-only
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4/prefixlen> summary-only as-set
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4> <ipv4>
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4> <ipv4> as-set
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4> <ipv4> as-set summary-only
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4> <ipv4> summary-only
    quagga (add|del) bgp ipv4 [unicast|multicast] aggregate-address <ipv4> <ipv4> summary-only as-set
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4/prefixlen>
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4/prefixlen> route-map WORD
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4>
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4> prefixlen <ipv4>
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4> prefixlen <ipv4> route-map WORD
    quagga (add|del) bgp ipv4 [unicast|multicast] network <ipv4> route-map WORD
    quagga (add|del) bgp ipv4 unicast bgp dampening
    quagga (add|del) bgp ipv4 unicast bgp dampening <1-45>
    quagga (add|del) bgp ipv4 unicast bgp dampening <1-45> <1-20000> <1-20000> <1-255>
    quagga (add|del) bgp ipv4 unicast redistribute (kernel|connected|static|rip|ospf|isis)
    quagga (add|del) bgp ipv4 unicast redistribute (kernel|connected|static|rip|ospf|isis) metric <0-4294967295>
    quagga (add|del) bgp ipv4 unicast redistribute (kernel|connected|static|rip|ospf|isis) metric <0-4294967295> route-map WORD
    quagga (add|del) bgp ipv4 unicast redistribute (kernel|connected|static|rip|ospf|isis) route-map WORD
    quagga (add|del) bgp ipv4 unicast redistribute (kernel|connected|static|rip|ospf|isis) route-map WORD metric <0-4294967295>
    quagga (add|del) bgp ipv4 unicast redistribute (ospf|table) <1-65535>
    quagga (add|del) bgp ipv4 unicast redistribute (ospf|table) <1-65535> metric <0-4294967295>
    quagga (add|del) bgp ipv4 unicast redistribute (ospf|table) <1-65535> metric <0-4294967295> route-map WORD
    quagga (add|del) bgp ipv4 unicast redistribute (ospf|table) <1-65535> route-map WORD
    quagga (add|del) bgp ipv4 unicast redistribute (ospf|table) <1-65535> route-map WORD metric <0-4294967295>
    quagga (add|del) bgp ipv6 [unicast|multicast] network <ipv6/prefixlen>
    quagga (add|del) bgp ipv6 bgp aggregate-address <ipv6/prefixlen>
    quagga (add|del) bgp ipv6 bgp aggregate-address <ipv6/prefixlen> summary-only
    quagga (add|del) bgp ipv6 bgp network <ipv6/prefixlen>
    quagga (add|del) bgp ipv6 unicast aggregate-address <ipv6/prefixlen>
    quagga (add|del) bgp ipv6 unicast aggregate-address <ipv6/prefixlen> summary-only
    quagga (add|del) bgp ipv6 unicast neighbor (<ipv4>|<ipv6>|<interface>) nexthop-local unchanged
    quagga (add|del) bgp ipv6 unicast network <ipv6/prefixlen> route-map WORD
    quagga (add|del) bgp ipv6 unicast redistribute (kernel|connected|static|ripng|ospf6|isis)
    quagga (add|del) bgp ipv6 unicast redistribute (kernel|connected|static|ripng|ospf6|isis) metric <0-4294967295>
    quagga (add|del) bgp ipv6 unicast redistribute (kernel|connected|static|ripng|ospf6|isis) metric <0-4294967295> route-map WORD
    quagga (add|del) bgp ipv6 unicast redistribute (kernel|connected|static|ripng|ospf6|isis) route-map WORD
    quagga (add|del) bgp ipv6 unicast redistribute (kernel|connected|static|ripng|ospf6|isis) route-map WORD metric <0-4294967295>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>) interface WORD
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>) port <0-65535>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>) strict-capability-match
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) advertisement-interval <0-600>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) bfd
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) bfd <2-255> BFD_CMD_MIN_RX_RANGE <50-60000>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) capability dynamic
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) capability extended-nexthop
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) description LINE
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) disable-connected-check
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) dont-capability-negotiate
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) ebgp-multihop
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) ebgp-multihop <1-255>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) enforce-multihop
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) local-as <1-4294967295>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) local-as <1-4294967295> no-prepend
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) local-as <1-4294967295> no-prepend replace-as
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) override-capability
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) passive
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) password LINE
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) remote-as (<1-4294967295>|external|internal)
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) shutdown
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) solo
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) timers <0-65535> <0-65535>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) timers connect <1-65535>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) ttl-security hops <1-254>
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) update-source (<ipv4>|<ipv6>|<interface>)
    quagga (add|del) bgp neighbor (<ipv4>|<ipv6>|<interface>) weight <0-65535>
    quagga (add|del) bgp neighbor WORD interface
    quagga (add|del) bgp neighbor WORD interface peer-group WORD
    quagga (add|del) bgp neighbor WORD interface v6only
    quagga (add|del) bgp neighbor WORD interface v6only peer-group WORD
    quagga (add|del) bgp neighbor WORD peer-group
    quagga (add|del) bgp network <ipv4/prefixlen> backdoor
    quagga (add|del) bgp network <ipv4> backdoor
    quagga (add|del) bgp network <ipv4> prefixlen <ipv4> backdoor
    quagga (add|del) bgp timers bgp <0-65535> <0-65535>
    quagga (add|del) bgp update-delay <0-3600>
    quagga (add|del) bgp update-delay <0-3600> <1-3600>
    quagga (add|del) bgp write-quanta <1-10000>""".splitlines()

ospf_clear_ignore = ["    quagga clear ip ospf interface [IFNAME]", ]

ospf_debug_ignore = """    quagga debug ospf <1-65535> event
    quagga debug ospf <1-65535> ism
    quagga debug ospf <1-65535> ism (status|events|timers)
    quagga debug ospf <1-65535> lsa
    quagga debug ospf <1-65535> lsa (generate|flooding|install|refresh)
    quagga debug ospf <1-65535> nsm
    quagga debug ospf <1-65535> nsm (status|events|timers)
    quagga debug ospf <1-65535> nssa
    quagga debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all)
    quagga debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)
    quagga debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)
    quagga debug ospf <1-65535> zebra
    quagga debug ospf <1-65535> zebra (interface|redistribute)
    quagga debug ospf event
    quagga debug ospf ism
    quagga debug ospf ism (status|events|timers)
    quagga debug ospf lsa
    quagga debug ospf lsa (generate|flooding|install|refresh)
    quagga debug ospf nsm
    quagga debug ospf nsm (status|events|timers)
    quagga debug ospf nssa
    quagga debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)
    quagga debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)
    quagga debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)
    quagga debug ospf zebra
    quagga debug ospf zebra (interface|redistribute)""".splitlines()

ospf_show_ignore = """    quagga show debugging ospf
    quagga show debugging ospf <1-65535>
    quagga show ip ospf <1-65535> [json]
    quagga show ip ospf <1-65535> border-routers
    quagga show ip ospf <1-65535> database
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) (self-originate|)
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4>
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4> (self-originate|)
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4> adv-router <ipv4>
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) adv-router <ipv4>
    quagga show ip ospf <1-65535> database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as|max-age|self-originate)
    quagga show ip ospf <1-65535> interface [INTERFACE] [json]
    quagga show ip ospf <1-65535> neighbor <ipv4> [json]
    quagga show ip ospf <1-65535> neighbor IFNAME [json]
    quagga show ip ospf <1-65535> neighbor IFNAME detail [json]
    quagga show ip ospf <1-65535> neighbor [json]
    quagga show ip ospf <1-65535> neighbor all [json]
    quagga show ip ospf <1-65535> neighbor detail [json]
    quagga show ip ospf <1-65535> neighbor detail all [json]
    quagga show ip ospf <1-65535> route
    quagga show ip ospf [json]
    quagga show ip ospf border-routers
    quagga show ip ospf database
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) (self-originate|)
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4>
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4> (self-originate|)
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) <ipv4> adv-router <ipv4>
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) adv-router <ipv4>
    quagga show ip ospf database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as|max-age|self-originate)
    quagga show ip ospf interface [INTERFACE] [json]
    quagga show ip ospf neighbor <ipv4> [json]
    quagga show ip ospf neighbor IFNAME [json]
    quagga show ip ospf neighbor IFNAME detail [json]
    quagga show ip ospf neighbor [json]
    quagga show ip ospf neighbor all [json]
    quagga show ip ospf neighbor detail [json]
    quagga show ip ospf neighbor detail all [json]
    quagga show ip ospf route
    quagga show mpls-te interface [INTERFACE]
    quagga show mpls-te router""".splitlines()

ospf_config_ignore = """    quagga (add|del) <interface> ip ospf <1-65535> area (<ipv4>|<0-4294967295>)
    quagga (add|del) <interface> ip ospf area (<ipv4>|<0-4294967295>)
    quagga (add|del) <interface> ip ospf authentication
    quagga (add|del) <interface> ip ospf authentication (null|message-digest)
    quagga (add|del) <interface> ip ospf authentication (null|message-digest) <ipv4>
    quagga (add|del) <interface> ip ospf authentication <ipv4>
    quagga (add|del) <interface> ip ospf authentication-key AUTH_KEY
    quagga (add|del) <interface> ip ospf authentication-key AUTH_KEY <ipv4>
    quagga (add|del) <interface> ip ospf bfd
    quagga (add|del) <interface> ip ospf bfd <2-255> BFD_CMD_MIN_RX_RANGE <50-60000>
    quagga (add|del) <interface> ip ospf cost <1-65535>
    quagga (add|del) <interface> ip ospf cost <1-65535> <ipv4>
    quagga (add|del) <interface> ip ospf dead-interval <1-65535>
    quagga (add|del) <interface> ip ospf dead-interval <1-65535> <ipv4>
    quagga (add|del) <interface> ip ospf dead-interval minimal hello-multiplier <1-10>
    quagga (add|del) <interface> ip ospf dead-interval minimal hello-multiplier <1-10> <ipv4>
    quagga (add|del) <interface> ip ospf hello-interval <1-65535>
    quagga (add|del) <interface> ip ospf hello-interval <1-65535> <ipv4>
    quagga (add|del) <interface> ip ospf message-digest-key <1-255> md5 KEY
    quagga (add|del) <interface> ip ospf message-digest-key <1-255> md5 KEY <ipv4>
    quagga (add|del) <interface> ip ospf mtu-ignore
    quagga (add|del) <interface> ip ospf mtu-ignore <ipv4>
    quagga (add|del) <interface> ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)
    quagga (add|del) <interface> ip ospf priority <0-255>
    quagga (add|del) <interface> ip ospf priority <0-255> <ipv4>
    quagga (add|del) <interface> ip ospf retransmit-interval <3-65535>
    quagga (add|del) <interface> ip ospf retransmit-interval <3-65535> <ipv4>
    quagga (add|del) <interface> ip ospf transmit-delay <1-65535>
    quagga (add|del) <interface> ip ospf transmit-delay <1-65535> <ipv4>
    quagga (add|del) <interface> mpls-te link max-bw BANDWIDTH
    quagga (add|del) <interface> mpls-te link max-rsv-bw BANDWIDTH
    quagga (add|del) <interface> mpls-te link metric <0-4294967295>
    quagga (add|del) <interface> mpls-te link rsc-clsclr BITPATTERN
    quagga (add|del) <interface> mpls-te link unrsv-bw <0-7> BANDWIDTH
    quagga (add|del) ospf abr-type (cisco|ibm|shortcut|standard)
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) authentication
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) authentication message-digest
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) default-cost <0-16777215>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) export-list NAME
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) filter-list prefix WORD (in|out)
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) import-list NAME
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) nssa
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) nssa (translate-candidate|translate-never|translate-always)
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) nssa (translate-candidate|translate-never|translate-always) no-summary
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) nssa no-summary
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen> advertise
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen> advertise cost <0-16777215>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen> cost <0-16777215>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen> not-advertise
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) range <ipv4/prefixlen> substitute <ipv4/prefixlen>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) shortcut (default|enable|disable)
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) stub
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) stub no-summary
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) virtual-link <ipv4>
    quagga (add|del) ospf area (<ipv4>|<0-4294967295>) virtual-link <ipv4>
    quagga (add|del) ospf auto-cost reference-bandwidth <1-4294967>
    quagga (add|del) ospf capability opaque
    quagga (add|del) ospf compatible rfc1583
    quagga (add|del) ospf default-information originate
    quagga (add|del) ospf default-metric <0-16777214>
    quagga (add|del) ospf distance <1-255>
    quagga (add|del) ospf distance <1-255> <ipv4/prefixlen>
    quagga (add|del) ospf distance <1-255> <ipv4/prefixlen> WORD
    quagga (add|del) ospf distance ospf
    quagga (add|del) ospf distribute-list WORD out QUAGGA_REDIST_STR_OSPFD
    quagga (add|del) ospf log-adjacency-changes
    quagga (add|del) ospf log-adjacency-changes detail
    quagga (add|del) ospf max-metric router-lsa administrative
    quagga (add|del) ospf max-metric router-lsa on-shutdown <5-100>
    quagga (add|del) ospf max-metric router-lsa on-startup <5-86400>
    quagga (add|del) ospf mpls-te
    quagga (add|del) ospf mpls-te on
    quagga (add|del) ospf mpls-te router-address <ipv4>
    quagga (add|del) ospf neighbor <ipv4>
    quagga (add|del) ospf neighbor <ipv4> poll-interval <1-65535>
    quagga (add|del) ospf neighbor <ipv4> poll-interval <1-65535> priority <0-255>
    quagga (add|del) ospf neighbor <ipv4> priority <0-255>
    quagga (add|del) ospf neighbor <ipv4> priority <0-255> poll-interval <1-65535>
    quagga (add|del) ospf network <ipv4/prefixlen> area (<ipv4>|<0-4294967295>)
    quagga (add|del) ospf opaque-lsa
    quagga (add|del) ospf passive-interface IFNAME
    quagga (add|del) ospf passive-interface IFNAME <ipv4>
    quagga (add|del) ospf passive-interface default
    quagga (add|del) ospf redistribute (ospf|table) <1-65535>
    quagga (add|del) ospf redistribute QUAGGA_REDIST_STR_OSPFD
    quagga (add|del) ospf rfc1583compatibility
    quagga (add|del) ospf router-id <ipv4>
    quagga (add|del) ospf timers lsa arrival <0-1000>
    quagga (add|del) ospf timers lsa min-arrival <0-600000>
    quagga (add|del) ospf timers throttle lsa all <0-5000>
    quagga (add|del) ospf timers throttle spf <0-600000> <0-600000> <0-600000>
    quagga (add|del) ospf write-multiplier <1-100>
    quagga (add|del) ospf write-multiplier <1-100>""".splitlines()

def replace_constants(line):
    line = line.replace('NO_NEIGHBOR_CMD2', 'no neighbor (A.B.C.D|X:X::X:X|WORD) ')
    line = line.replace('NEIGHBOR_CMD2', 'neighbor (A.B.C.D|X:X::X:X|WORD) ')
    line = line.replace('NO_NEIGHBOR_CMD', 'no neighbor (A.B.C.D|X:X::X:X) ')
    line = line.replace('NEIGHBOR_CMD', 'neighbor (A.B.C.D|X:X::X:X) ')
    line = line.replace('CMD_AS_RANGE', '<1-4294967295>')
    line = line.replace('LISTEN_RANGE_CMD', 'bgp listen range (A.B.C.D/M|X:X::X:X/M) ')
    line = line.replace('DYNAMIC_NEIGHBOR_LIMIT_RANGE', '<1-5000>')
    line = line.replace('QUAGGA_IP_REDIST_STR_BGPD', '(kernel|connected|static|rip|ospf|isis)')
    line = line.replace('QUAGGA_IP6_REDIST_STR_BGPD', '(kernel|connected|static|ripng|ospf6|isis)')
    line = line.replace('QUAGGA_IP6_REDIST_STR_ZEBRA', '(kernel|connected|static|ripng|ospf6|isis|bgp)')
    line = line.replace('QUAGGA_IP_REDIST_STR_ZEBRA', '(kernel|connected|static|rip|ospf|isis|bgp)')
    line = line.replace('OSPF_LSA_TYPES_CMD_STR', 'asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as')
    line = line.replace('CMD_RANGE_STR(1, MULTIPATH_NUM)', '<1-255>')
    line = line.replace('CMD_RANGE_STR(1, MAXTTL)', '<1-255>')
    line = line.replace('BFD_CMD_DETECT_MULT_RANGE', '<2-255>')
    line = line.replace('BFD_CMD_MIN_TX_RANGE', '<50-60000>')
    line = line.replace('BGP_UPDATE_SOURCE_REQ_STR', '(A.B.C.D|X:X::X:X|WORD)')
    line = line.replace('BGP_UPDATE_SOURCE_OPT_STR', '{A.B.C.D|X:X::X:X|WORD}')
    line = line.replace('.LINE', 'LINE')
    line = line.replace('.AA:NN', 'AA:NN')
    # line = line.replace('', '')
    return line


ignore = {}
ignore['bgpd'] = []
ignore['bgpd'].append('address-family ipv4')
ignore['bgpd'].append('address-family ipv4 (unicast|multicast)')
ignore['bgpd'].append('address-family ipv6')
ignore['bgpd'].append('address-family ipv6 (unicast|multicast)')
ignore['bgpd'].append('address-family vpnv4')
ignore['bgpd'].append('address-family vpnv4 unicast')
ignore['bgpd'].append('exit-address-family')

ignore['ospfd'] = []


class Command(object):

    def __init__(self, defun, text, line_number):
        self.defun = defun
        self.text = text
        self.line_number = line_number
        self.context = []
        self.docstring = None

    def __str__(self):
        return "%s - %s" % (self.context, self.text)

    def set_docstring(self):
        ds = self.text

        if self.text in ignore['bgpd']:
            return None

        # For these two WORD means an interface name
        ds = ds.replace('A.B.C.D|X:X::X:X|WORD', '<ipv4>|<ipv6>|<interface>')
        ds = ds.replace('A.B.C.D|WORD', '<ipv4>|<interface>')

        ds = ds.replace('A.B.C.D/M', '<ipv4/prefixlen>')
        ds = ds.replace('A.B.C.D', '<ipv4>')
        ds = ds.replace('X:X::X:X/M', '<ipv6/prefixlen>')
        ds = ds.replace('X:X::X:X', '<ipv6>')
        ds = ds.replace('{json}', '[json]')
        ds = ds.replace('{', '[')
        ds = ds.replace('}', ']')
        ds = ds.replace(' PATH ', ' <text> ')

        afis = []
        safis = []

        if 'BGP_IPV4_NODE' in self.context:
            afis.append('ipv4')
            safis.append('unicast')

        if 'BGP_IPV4M_NODE' in self.context:
            afis.append('ipv4')
            safis.append('multicast')

        if 'BGP_IPV6_NODE' in self.context:
            afis.append('ipv6')
            safis.append('unicast')

        if 'BGP_IPV6M_NODE' in self.context:
            afis.append('ipv6')
            safis.append('multicast')

        afis = list(set(afis))
        safis = list(set(safis))

        # clear, debug, show, etc
        if 'ENABLE_NODE' in self.context:
            pass

        # config command so need to add (add|del) and maybe afi/safi
        else:
            if afis:
                if len(afis) > 1:
                    afi_string = "[%s]" % '|'.join(afis)
                else:
                    afi_string = afis[0]

                if len(safis) > 1:
                    safi_string = "[%s]" % '|'.join(safis)
                else:
                    safi_string = safis[0]

                ds = "(add|del) bgp %s %s " % (afi_string, safi_string) + ds

            elif 'BGP_NODE' in self.context:
                if ds.startswith('bgp'):
                    ds = "(add|del) " + ds
                else:
                    ds = "(add|del) bgp " + ds

            elif 'INTERFACE_NODE' in self.context:
                ds = "(add|del) <interface> " + ds

            elif 'OSPF_NODE' in self.context:
                if ds.startswith('ospf'):
                    ds = "(add|del) " + ds
                else:
                    ds = "(add|del) ospf " + ds

            # Ignore the route-map commands, ip community-list, etc for now
            else:
                ds = None

        if ds:
            ds = ds.rstrip()
            self.docstring = '    quagga ' + ds


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Parse the quagga parser')
    parser.add_argument('directory', help='quagga directory')
    parser.add_argument('daemon', help='bgpd, ospfd, etc')
    parser.add_argument('--print-quagga', action='store_true', help='print the raw quagga commands')
    parser.add_argument('--print-docstring', action='store_true', help='print a docstring for network-docopt')
    parser.add_argument('--print-context', action='store_true', help='print quagga commands with their context')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)7s: %(message)s')
    log = logging.getLogger(__name__)

    # Color the errors and warnings in red
    logging.addLevelName(logging.ERROR, "\033[91m  %s\033[0m" % logging.getLevelName(logging.ERROR))
    logging.addLevelName(logging.WARNING, "\033[91m%s\033[0m" % logging.getLevelName(logging.WARNING))

    bgpd = os.path.join(args.directory, 'bgpd')
    isisd = os.path.join(args.directory, 'isisd')
    ospfd = os.path.join(args.directory, 'ospfd')
    ospf6d = os.path.join(args.directory, 'ospf6d')
    ripd = os.path.join(args.directory, 'ripd')
    ripngd = os.path.join(args.directory, 'ripngd')
    zebra = os.path.join(args.directory, 'zebra')
    parser_files = []

    for (directory, foo, files) in sorted(os.walk(args.directory)):

        # We do not care about crunching files in these directories
        if (directory.endswith('vtysh') or
            directory.endswith('quagga-0.99.23.1/') or
            directory.endswith('lib') or
            directory.endswith('isisd') or
            directory.endswith('ripd') or
            directory.endswith('ripngd') or
            directory.endswith('m4') or
            directory.endswith('tests')):
            continue

        if args.daemon not in directory:
            continue

        for x in sorted(files):
            if x.endswith('.c'):
                filename = os.path.join(directory, x)
                parser_files.append(filename)

    commands = {}
    defun_to_context = {}

    for filename in parser_files:

        with open(filename, 'r') as fh:
            state = 'LIMBO'
            line_number = 1

            for line in fh.readlines():

                if state == 'LIMBO':
                    if (line.startswith('DEFUN ') or line.startswith('ALIAS ')):
                        state = 'DEFUN_LINE_1'

                    elif 'install_element' in line:
                        # install_element (BGP_NODE, &neighbor_bfd_cmd);
                        re_line = re.search('install_element\s*\(\s*(\S+)\s*, \&(\S+)\)', line)

                        if re_line:
                            context = re_line.group(1)
                            defun = re_line.group(2)

                            if defun not in defun_to_context:
                                defun_to_context[defun] = []
                            defun_to_context[defun].append(context)
                        else:
                            log.warning("regex failed on '%s'" % line.strip())

                elif state == 'DEFUN_LINE_1':
                    state = 'DEFUN_LINE_2'
                    # remove spaces and trailing comma
                    defun = line.strip()[0:-1]

                elif state == 'DEFUN_LINE_2':
                    if 'ifdef HAVE_IPV6' in line:
                        pass
                    else:
                        state = 'LIMBO'

                        # remove the leading and trailing spaces
                        # remove the leading and trailing "
                        # remove the trailing ,
                        line = line.strip()
                        line = replace_constants(line)

                        if line.endswith(','):
                            line = line.rstrip().lstrip()[:-1]

                        if line.startswith('"'):
                            line = line.rstrip().lstrip()[1:]

                        if line.endswith('"'):
                            line = line.rstrip().lstrip()[:-1]

                        line = line.replace(' " ', ' ')
                        line = line.replace(' "', ' ')
                        line = line.replace('" ', ' ')
                        line = line.replace('( ', '(')
                        line = line.replace(' )', ')')

                        line = line.replace('| ', '|')
                        line = line.replace(' |', '|')

                        # compress multiple whitespaces
                        while '  ' in line:
                            line = line.replace('  ', ' ')

                        commands[line] = Command(defun, line, line_number)
                        defun = None
                line_number += 1

    # Fill in the context for each Command based on its defun
    for cmd in commands.itervalues():
        cmd.context = defun_to_context.get(cmd.defun)
        if cmd.context is None:
            log.error("%s: could not find defun for %s" % (cmd, cmd.defun))
            continue
        cmd.set_docstring()

    normal = []
    expert = []

    if args.print_docstring:
        if args.daemon == 'bgpd':
            normal.append('    quagga show bgp [ipv4|ipv6] [unicast|multicast] summary [json]')
            normal.append('    quagga show bgp [ipv4|ipv6] [unicast|multicast] [<ip>|<ip/prefixlen>] [bestpath|multipath] [json]')
            normal.append('    quagga show bgp neighbor [<ip>|<interface>]')
            normal.append('    quagga clear bgp (<ip>|<interface>|*)')
            normal.append('    quagga clear bgp (<ip>|<interface>|*) soft [in|out]')
            normal.append('    quagga clear bgp prefix <ip/prefixlen>')
            normal.append('    quagga (add|del) debug bgp bestpath <ip/prefixlen>')
            normal.append('    quagga (add|del) debug bgp keepalives (<ip><interface>)')
            normal.append('    quagga (add|del) debug bgp neighbor-events (<ip>|<interface>)')
            expert.append('    quagga (add|del) debug bgp nht')
            expert.append('    quagga (add|del) debug bgp update-groups')
            normal.append('    quagga (add|del) debug bgp updates prefix <ip/prefixlen>')
            normal.append('    quagga (add|del) debug bgp zebra prefix <ip/prefixlen>')

            bgp_bgp = ['always-compare-med',
                       'bestpath',
                       'client-to-client reflection',
                       'cluster-id',
                       'confederation peers',
                       'default ipv4-unicast',
                       'default local-preference',
                       'default show-hostname',
                       'default subgroup-pkt-queue-max',
                       'deterministic-med',
                       'disable-ebgp-connected-route-check',
                       'enforce-first-as',
                       'fast-external-failover',
                       'graceful-restart',
                       'listen',
                       'log-neighbor-changes',
                       'max-med',
                       'network import-check',
                       'route-map delay-timer',
                       'route-reflector allow-outbound-policy',
                       'router-id']

            # ======
            # global
            # ======
            normal.append('    quagga (add|del) bgp always-compare-med')
            expert.append('    quagga (add|del) bgp bestpath as-path (confed|ignore)')
            normal.append('    quagga (add|del) bgp bestpath as-path multipath-relax [as-set|no-as-set]')
            expert.append('    quagga (add|del) bgp bestpath med (confed|missing-as-worst)')
            expert.append('    quagga (add|del) bgp client-to-client reflection')
            expert.append('    quagga (add|del) bgp cluster-id (<ipv4>|<1-4294967295>)')
            expert.append('    quagga (add|del) bgp confederation peers <1-4294967295>')
            expert.append('    quagga (add|del) bgp default ipv4-unicast')
            expert.append('    quagga (add|del) bgp default local-preference <0-4294967295>')
            expert.append('    quagga (add|del) bgp default show-hostname')
            expert.append('    quagga (add|del) bgp default subgroup-pkt-queue-max <20-100>')
            expert.append('    quagga (add|del) bgp deterministic-med')
            expert.append('    quagga (add|del) bgp disable-ebgp-connected-route-check')
            expert.append('    quagga (add|del) bgp enforce-first-as')
            expert.append('    quagga (add|del) bgp fast-external-failover')
            expert.append('    quagga (add|del) bgp graceful-restart')
            expert.append('    quagga (add|del) bgp listen limit <1-5000>')
            expert.append('    quagga (add|del) bgp listen range (<ipv4/prefixlen>|<ipv6/prefixlen>) peer-group <text>')
            expert.append('    quagga (add|del) bgp log-neighbor-changes')
            expert.append('    quagga (add|del) bgp max-med administrative <0-4294967294>')
            expert.append('    quagga (add|del) bgp max-med on-startup <5-86400> [<0-4294967294>]')
            expert.append('    quagga (add|del) bgp network import-check')
            expert.append('    quagga (add|del) bgp route-map delay-timer <0-600>')
            expert.append('    quagga (add|del) bgp route-reflector allow-outbound-policy')
            normal.append('    quagga (add|del) bgp router-id <ipv4>')
            expert.append('    quagga (add|del) bgp coalesce-time <0-4294967295>')
            expert.append('    quagga (add|del) bgp distance <1-255> <ipv4/prefixlen> <text>')
            expert.append('    quagga (add|del) bgp distance bgp <1-255> <1-255> <1-255>')
            expert.append('    quagga (add|del) bgp timers bgp <0-65535> <0-65535>')
            expert.append('    quagga (add|del) bgp update-delay <0-3600> [<1-3600>]')
            expert.append('    quagga (add|del) bgp write-quanta <1-10000>')

            # ====================
            # peer global afi/safi
            # ====================
            normal.append('    quagga (add|del) bgp neighbor <interface> interface')
            normal.append('    quagga (add|del) bgp neighbor <interface> interface peer-group <text>')
            expert.append('    quagga (add|del) bgp neighbor <interface> interface v6only')
            expert.append('    quagga (add|del) bgp neighbor <interface> interface v6only peer-group <text>')
            normal.append('    quagga (add|del) bgp neighbor <interface> peer-group')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) advertisement-interval <0-600>')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) bfd')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) capability dynamic')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) capability extended-nexthop')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) description <text>')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) disable-connected-check')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) dont-capability-negotiate')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) ebgp-multihop [<1-255>]')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) enforce-multihop')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) local-as <1-4294967295> [no-prepend] [replace-as]')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) override-capability')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) passive')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) password <text>')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) port <0-65535>')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) remote-as (<1-4294967295>|external|internal)')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) shutdown')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) solo')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) strict-capability-match')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) timers <0-65535> <0-65535>')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) timers connect <1-65535>')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) ttl-security hops <1-254>')
            normal.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) update-source (<ipv4>|<ipv6>|<interface>)')
            expert.append('    quagga (add|del) bgp neighbor (<ip>|<interface>) weight <0-65535>')

            # =================
            # peer per afi/safi
            # =================
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) addpath-tx-all-paths')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) addpath-tx-bestpath-per-AS')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) allowas-in [<1-10>]')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) as-override')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) attribute-unchanged [as-path] [next-hop] [med]')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) capability orf prefix-list (both|send|receive)')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) default-originate [route-map <text>]')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) distribute-list (<1-199>|<1300-2699>|<text>) (in|out)')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) filter-list <text> (in|out)')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) maximum-prefix <1-4294967295>')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) next-hop-self [force]')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) peer-group <text>')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) prefix-list <text> (in|out)')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) remove-private-AS [all] [replace-AS]')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) route-map <text> (in|out)')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) route-reflector-client')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) route-server-client')
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) send-community [both|extended|standard]')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) soft-reconfiguration inbound')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] neighbor (<ip>|<interface>) unsuppress-map <text>')
            expert.append('    quagga (add|del) bgp ipv6 unicast neighbor (<ip>|<interface>) nexthop-local unchanged')

            # ============
            # per afi/safi
            # ============
            normal.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] maximum-paths [ibgp] <1-255> [equal-cluster-length]')
            normal.append('    quagga (add|del) bgp (ipv4|ipv6) [unicast|multicast] aggregate-address <ipv4/prefixlen> [as-set] [summary-only]')
            normal.append('    quagga (add|del) bgp (ipv4|ipv6) [unicast|multicast] network (<ipv4/prefixlen>|<ipv6/prefixlen>)')
            expert.append('    quagga (add|del) bgp (ipv4|ipv6) [unicast|multicast] network (<ipv4/prefixlen>|<ipv6/prefixlen>) route-map <text>')
            expert.append('    quagga (add|del) bgp (ipv4|ipv6) [unicast|multicast] bgp dampening <1-45> <1-20000> <1-20000> <1-255>')
            normal.append('    quagga (add|del) bgp (ipv4|ipv6) [unicast|multicast] redistribute (kernel|connected|static|rip|ospf|isis) [metric <0-4294967295>] [route-map <text>]')
            expert.append('    quagga (add|del) bgp [ipv4|ipv6] [unicast|multicast] table-map <text>')

        if args.daemon == 'ospfd':
            normal.append('    quagga clear ip ospf interface [<interface>]')
            normal.append('    quagga (add|del) debug ospf [<1-65535>] ism [status|events|timers]')
            normal.append('    quagga (add|del) debug ospf [<1-65535>] lsa [generate|flooding|install|refresh]')
            normal.append('    quagga (add|del) debug ospf [<1-65535>] nsm [status|events|timers]')
            expert.append('    quagga (add|del) debug ospf [<1-65535>] nssa')
            normal.append('    quagga (add|del) debug ospf [<1-65535>] packet [hello|dd|ls-request|ls-update|ls-ack|all] [send|recv|detail]')
            normal.append('    quagga (add|del) debug ospf [<1-65535>] zebra [interface|redistribute]')
            normal.append('    quagga show ip ospf [<1-65535>]')
            expert.append('    quagga show ip ospf [<1-65535>] border-routers')
            expert.append('    quagga show ip ospf [<1-65535>] database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as|max-age|self-originate) [self-originate]')
            expert.append('    quagga show ip ospf [<1-65535>] database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as|max-age|self-originate) adv-router <ipv4>')
            normal.append('    quagga show ip ospf [<1-65535>] interface [<interface>] [json]')
            normal.append('    quagga show ip ospf [<1-65535>] neighbor (all|<interface>|<ipv4>) [detail] [json]')
            normal.append('    quagga show ip ospf [<1-65535>] route')

            normal.append('    quagga (add|del) <interface> ip ospf [<1-65535>] area (<ipv4>|<0-4294967295>)')
            normal.append('    quagga (add|del) <interface> ip ospf dead-interval <1-65535>')
            normal.append('    quagga (add|del) <interface> ip ospf hello-interval <1-65535>')
            normal.append('    quagga (add|del) <interface> ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)')
            normal.append('    quagga (add|del) ospf network <ipv4/prefixlen> area (<ipv4>|<0-4294967295>)')
            normal.append('    quagga (add|del) ospf passive-interface IFNAME')
            normal.append('    quagga (add|del) ospf router-id <ipv4>')
            normal.append('    quagga (add|del) ospf timers throttle spf <0-600000> <0-600000> <0-600000>')



        ignore_list = bgp_clear_ignore + bgp_debug_ignore + bgp_show_ignore + bgp_config_ignore
        ignore_list += ospf_clear_ignore + ospf_debug_ignore + ospf_show_ignore + ospf_config_ignore

        for cmd in commands.itervalues():
            if not cmd.text.startswith('no ') and cmd.context:
                if cmd.docstring:
                    if cmd.docstring not in ignore_list:
                        normal.append(cmd.docstring)

    elif args.print_quagga:
        for cmd in commands.itervalues():
            if not cmd.text.startswith('no ') and cmd.context:
                normal.append(cmd.text)

    elif args.print_context:
        for cmd in commands.itervalues():
            if not cmd.text.startswith('no ') and cmd.context:
                normal.append("%s - %s" % (cmd.context, cmd.text))
    else:
        raise Exception("No print option specified")

    normal = sorted(normal)
    print '\n'.join(map(str, normal))
