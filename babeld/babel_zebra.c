/*  
 *  This file is free software: you may copy, redistribute and/or modify it  
 *  under the terms of the GNU General Public License as published by the  
 *  Free Software Foundation, either version 2 of the License, or (at your  
 *  option) any later version.  
 *  
 *  This file is distributed in the hope that it will be useful, but  
 *  WITHOUT ANY WARRANTY; without even the implied warranty of  
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
 *  General Public License for more details.  
 *  
 *  You should have received a copy of the GNU General Public License  
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  
 *  
 * This file incorporates work covered by the following copyright and  
 * permission notice:  
 *
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* quagga's includes */
#include <zebra.h>
#include "command.h"
#include "zclient.h"
#include "stream.h"

/* babel's includes*/
#include "babel_zebra.h"
#include "babel_interface.h"
#include "xroute.h"

void babelz_zebra_init(void);


/* we must use a pointer because of zclient.c's functions (new, free). */
struct zclient *zclient;
static int zebra_config_write (struct vty *vty);
/* Redistribution types */
static struct {
    int type;
    int str_min_len;
    const char *str;
} redist_type[] = {
    {ZEBRA_ROUTE_KERNEL,  1, "kernel"},
    {ZEBRA_ROUTE_CONNECT, 1, "connected"},
    {ZEBRA_ROUTE_STATIC,  1, "static"},
    {ZEBRA_ROUTE_OSPF6,   1, "ospf6"},
    {ZEBRA_ROUTE_BGP,     1, "bgp"},
    {0, 0, NULL}
};

/* Zebra node structure. */
struct cmd_node zebra_node =
{
    ZEBRA_NODE,
    "%s(config-router)# ",
    1 /* vtysh? yes */
};


/* Zebra route add and delete treatment (ipv6). */
static int
babel_zebra_read_ipv6 (int command, struct zclient *zclient,
		       zebra_size_t length)
{
    struct stream *s;
    struct zapi_ipv6 api;
    unsigned long ifindex = -1;
    struct in6_addr nexthop;
    struct prefix_ipv6 prefix;

    s = zclient->ibuf;
    ifindex = 0;
    memset (&nexthop, 0, sizeof (struct in6_addr));
    memset (&api, 0, sizeof(struct zapi_ipv6));
    memset (&prefix, 0, sizeof (struct prefix_ipv6));

    /* Type, flags, message. */
    api.type = stream_getc (s);
    api.flags = stream_getc (s);
    api.message = stream_getc (s);

    /* IPv6 prefix. */
    prefix.family = AF_INET6;
    prefix.prefixlen = stream_getc (s);
    stream_get (&prefix.prefix, s, PSIZE (prefix.prefixlen));

    /* Nexthop, ifindex, distance, metric. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP)) {
        api.nexthop_num = stream_getc (s);
        stream_get (&nexthop, s, sizeof(nexthop));
    }
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX)) {
        api.ifindex_num = stream_getc (s);
        ifindex = stream_getl (s);
    }
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
        api.distance = stream_getc (s);
    else
        api.distance = 0;
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
        api.metric = stream_getl (s);
    else
        api.metric = 0;

    if (command == ZEBRA_IPV6_ROUTE_ADD)
        babel_ipv6_route_add(&api, &prefix, ifindex, &nexthop);
    else
        babel_ipv6_route_delete(&api, &prefix, ifindex);

    return 0;
}

static int
babel_zebra_read_ipv4 (int command, struct zclient *zclient,
		       zebra_size_t length)
{
    struct stream *s;
    struct zapi_ipv4 api;
    unsigned long ifindex = -1;
    struct in_addr nexthop;
    struct prefix_ipv4 prefix;

    s = zclient->ibuf;
    ifindex = 0;
    memset (&nexthop, 0, sizeof (struct in_addr));
    memset (&api, 0, sizeof(struct zapi_ipv4));
    memset (&prefix, 0, sizeof (struct prefix_ipv4));

    /* Type, flags, message. */
    api.type = stream_getc (s);
    api.flags = stream_getc (s);
    api.message = stream_getc (s);

    /* IPv6 prefix. */
    prefix.family = AF_INET;
    prefix.prefixlen = stream_getc (s);
    stream_get (&prefix.prefix, s, PSIZE (prefix.prefixlen));

    /* Nexthop, ifindex, distance, metric. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP)) {
        api.nexthop_num = stream_getc (s);
        stream_get (&nexthop, s, sizeof(nexthop));
    }
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX)) {
        api.ifindex_num = stream_getc (s);
        ifindex = stream_getl (s);
    }
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
        api.distance = stream_getc (s);
    else
        api.distance = 0;
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
        api.metric = stream_getl (s);
    else
        api.metric = 0;

    if (command == ZEBRA_IPV6_ROUTE_ADD) {
        babel_ipv4_route_add(&api, &prefix, ifindex, &nexthop);
    } else {
        babel_ipv4_route_delete(&api, &prefix, ifindex);
    }

    return 0;
}

static int
babel_redistribute_unset (int type)
{
    if (! zclient->redist[type])
        return CMD_SUCCESS;

    zclient->redist[type] = 0;

    if (zclient->sock > 0)
        zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, type);

    /* perhaps should we remove xroutes having the same type... */

    return CMD_SUCCESS;
}


/* [Babel Command] */
DEFUN (babel_redistribute_type,
       babel_redistribute_type_cmd,
       "redistribute (kernel|connected|static|ospf6|bgp)",
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPFv3)\n"
       "Border Gateway Protocol (BGP)\n")
{
    int i;

    for(i = 0; redist_type[i].str != NULL; i++) {
        if (strncmp (redist_type[i].str, argv[0],
                     redist_type[i].str_min_len) == 0) {
            zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient,
                                  redist_type[i].type);
            return CMD_SUCCESS;
        }
    }

    vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);

    return CMD_WARNING;
}

/* [Babel Command] */
DEFUN (no_babel_redistribute_type,
       no_babel_redistribute_type_cmd,
       "no redistribute (kernel|connected|static|ospf6|bgp)",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPFv3)\n"
       "Border Gateway Protocol (BGP)\n")
{
    int i;

    for (i = 0; redist_type[i].str; i++) {
        if (strncmp(redist_type[i].str, argv[0],
                    redist_type[i].str_min_len) == 0) {
            return babel_redistribute_unset (redist_type[i].type);
        }
    }

    vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);

    return CMD_WARNING;
}


void babelz_zebra_init(void)
{
    zclient = zclient_new();
    zclient_init(zclient, ZEBRA_ROUTE_BABEL);

    zclient->interface_add = babel_interface_add;
    zclient->interface_delete = babel_interface_delete;
    zclient->interface_up = babel_interface_up;
    zclient->interface_down = babel_interface_down;
    zclient->interface_address_add = babel_interface_address_add;
    zclient->interface_address_delete = babel_interface_address_delete;
    zclient->ipv4_route_add = babel_zebra_read_ipv4;
    zclient->ipv4_route_delete = babel_zebra_read_ipv4;
    zclient->ipv6_route_add = babel_zebra_read_ipv6;
    zclient->ipv6_route_delete = babel_zebra_read_ipv6;

    install_node (&zebra_node, zebra_config_write);
    install_element(BABEL_NODE, &babel_redistribute_type_cmd);
    install_element(BABEL_NODE, &no_babel_redistribute_type_cmd);
}

static int
zebra_config_write (struct vty *vty)
{
    fprintf(stderr, "\tzebra_config_write\n");
    if (! zclient->enable)
    {
        vty_out (vty, "no router zebra%s", VTY_NEWLINE);
        return 1;
    }
    else if (! zclient->redist[ZEBRA_ROUTE_BABEL])
    {
        vty_out (vty, "router zebra%s", VTY_NEWLINE);
        vty_out (vty, " no redistribute babel%s", VTY_NEWLINE);
        return 1;
    }
    return 0;
}

void
babel_zebra_close_connexion(void)
{
    zclient_stop(zclient);
}
