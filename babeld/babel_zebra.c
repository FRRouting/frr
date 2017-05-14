/*
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

/* FRR's includes */
#include <zebra.h>
#include "command.h"
#include "zclient.h"
#include "stream.h"

/* babel's includes*/
#include "babel_zebra.h"
#include "babel_interface.h"
#include "xroute.h"
#include "util.h"

void babelz_zebra_init(void);


/* we must use a pointer because of zclient.c's functions (new, free). */
struct zclient *zclient;
static int zebra_config_write (struct vty *vty);

/* Debug types */
static struct {
    int type;
    int str_min_len;
    const char *str;
} debug_type[] = {
    {BABEL_DEBUG_COMMON,  1, "common"},
    {BABEL_DEBUG_KERNEL,  1, "kernel"},
    {BABEL_DEBUG_FILTER,  1, "filter"},
    {BABEL_DEBUG_TIMEOUT, 1, "timeout"},
    {BABEL_DEBUG_IF,      1, "interface"},
    {BABEL_DEBUG_ROUTE,   1, "route"},
    {BABEL_DEBUG_ALL,     1, "all"},
    {0, 0, NULL}
};

static struct {
    int str_min_len;
    const char *str;
} proto_redistnum_type[ZEBRA_ROUTE_MAX] = {
    [ZEBRA_ROUTE_BABEL]   = {2, "babel"},
    [ZEBRA_ROUTE_BGP]     = {2, "bgp"},
    [ZEBRA_ROUTE_CONNECT] = {1, "connected"},
    [ZEBRA_ROUTE_HSLS]    = {1, "hsls"},
    [ZEBRA_ROUTE_ISIS]    = {1, "isis"},
    [ZEBRA_ROUTE_KERNEL]  = {1, "kernel"},
    [ZEBRA_ROUTE_OLSR]    = {2, "olsr"},
    [ZEBRA_ROUTE_OSPF]    = {2, "ospf"},
    [ZEBRA_ROUTE_OSPF6]   = {5, "ospf6"},
    [ZEBRA_ROUTE_RIP]     = {1, "rip"},
    [ZEBRA_ROUTE_RIPNG]   = {4, "ripng"},
    [ZEBRA_ROUTE_STATIC]  = {2, "static"},
    [ZEBRA_ROUTE_SYSTEM]  = {2, "system"},
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
		       zebra_size_t length, vrf_id_t vrf)
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
		       zebra_size_t length, vrf_id_t vrf)
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

    if (command == ZEBRA_IPV4_ROUTE_ADD) {
        babel_ipv4_route_add(&api, &prefix, ifindex, &nexthop);
    } else {
        babel_ipv4_route_delete(&api, &prefix, ifindex);
    }

    return 0;
}

static int
babel_proto_redistnum(const char *s)
{
    int i;
    if (! s)
        return -1;
    int len = strlen(s);

    for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
        if (len <= (int)strlen(proto_redistnum_type[i].str) &&
            strncmp(proto_redistnum_type[i].str, s,
                    proto_redistnum_type[i].str_min_len) == 0) {
            return i;
        }
    }

    return -1;
}

/* [Babel Command] */
DEFUN (babel_redistribute_type,
       babel_redistribute_type_cmd,
       "redistribute " FRR_REDIST_STR_BABELD,
       "Redistribute\n"
       FRR_REDIST_HELP_STR_BABELD)
{
    int type;

    type = babel_proto_redistnum(argv[1]->arg);

    if (type < 0) {
        vty_out(vty, "Invalid type %s%s", argv[1]->arg, VTY_NEWLINE);
        return CMD_WARNING;
    }

    zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP, type, 0, VRF_DEFAULT);
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFUN (no_babel_redistribute_type,
       no_babel_redistribute_type_cmd,
       "no redistribute " FRR_REDIST_STR_BABELD,
       NO_STR
       "Redistribute\n"
       FRR_REDIST_HELP_STR_BABELD)
{
    int type;

    type = babel_proto_redistnum(argv[2]->arg);

    if (type < 0) {
        vty_out(vty, "Invalid type %s%s", argv[2]->arg, VTY_NEWLINE);
        return CMD_WARNING;
    }

    zclient_redistribute (ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP, type, 0, VRF_DEFAULT);
    /* perhaps should we remove xroutes having the same type... */
    return CMD_SUCCESS;
}

#ifndef NO_DEBUG
/* [Babel Command] */
DEFUN (debug_babel,
       debug_babel_cmd,
       "debug babel <common|kernel|filter|timeout|interface|route|all>",
       "Enable debug messages for specific or all part.\n"
       "Babel information\n"
       "Common messages (default)\n"
       "Kernel messages\n"
       "Filter messages\n"
       "Timeout messages\n"
       "Interface messages\n"
       "Route messages\n"
       "All messages\n")
{
    int i;

    for(i = 0; debug_type[i].str != NULL; i++) {
        if (strncmp (debug_type[i].str, argv[2]->arg,
                     debug_type[i].str_min_len) == 0) {
            debug |= debug_type[i].type;
            return CMD_SUCCESS;
        }
    }

    vty_out(vty, "Invalid type %s%s", argv[2]->arg, VTY_NEWLINE);

    return CMD_WARNING;
}

/* [Babel Command] */
DEFUN (no_debug_babel,
       no_debug_babel_cmd,
       "no debug babel <common|kernel|filter|timeout|interface|route|all>",
       NO_STR
       "Disable debug messages for specific or all part.\n"
       "Babel information\n"
       "Common messages (default)\n"
       "Kernel messages\n"
       "Filter messages\n"
       "Timeout messages\n"
       "Interface messages\n"
       "Route messages\n"
       "All messages\n")
{
    int i;

    for (i = 0; debug_type[i].str; i++) {
        if (strncmp(debug_type[i].str, argv[3]->arg,
                    debug_type[i].str_min_len) == 0) {
            debug &= ~debug_type[i].type;
            return CMD_SUCCESS;
        }
    }

    vty_out(vty, "Invalid type %s%s", argv[3]->arg, VTY_NEWLINE);

    return CMD_WARNING;
}
#endif /* NO_DEBUG */

/* Output "debug" statement lines, if necessary. */
int
debug_babel_config_write (struct vty * vty)
{
#ifdef NO_DEBUG
    return 0;
#else
    int i, lines = 0;

    if (debug == BABEL_DEBUG_ALL)
    {
        vty_out (vty, "debug babel all%s", VTY_NEWLINE);
        lines++;
    }
    else
        for (i = 0; debug_type[i].str != NULL; i++)
            if
            (
                debug_type[i].type != BABEL_DEBUG_ALL
                && CHECK_FLAG (debug, debug_type[i].type)
            )
            {
                vty_out (vty, "debug babel %s%s", debug_type[i].str, VTY_NEWLINE);
                lines++;
            }
    if (lines)
    {
        vty_out (vty, "!%s", VTY_NEWLINE);
        lines++;
    }
    return lines;
#endif /* NO_DEBUG */
}

void babelz_zebra_init(void)
{
    zclient = zclient_new(master);
    zclient_init(zclient, ZEBRA_ROUTE_BABEL, 0);

    zclient->interface_add = babel_interface_add;
    zclient->interface_delete = babel_interface_delete;
    zclient->interface_up = babel_interface_up;
    zclient->interface_down = babel_interface_down;
    zclient->interface_address_add = babel_interface_address_add;
    zclient->interface_address_delete = babel_interface_address_delete;
    zclient->redistribute_route_ipv4_add = babel_zebra_read_ipv4;
    zclient->redistribute_route_ipv4_del = babel_zebra_read_ipv4;
    zclient->redistribute_route_ipv6_add = babel_zebra_read_ipv6;
    zclient->redistribute_route_ipv6_del = babel_zebra_read_ipv6;

    install_node (&zebra_node, zebra_config_write);
    install_element(BABEL_NODE, &babel_redistribute_type_cmd);
    install_element(BABEL_NODE, &no_babel_redistribute_type_cmd);
    install_element(ENABLE_NODE, &debug_babel_cmd);
    install_element(ENABLE_NODE, &no_debug_babel_cmd);
    install_element(CONFIG_NODE, &debug_babel_cmd);
    install_element(CONFIG_NODE, &no_debug_babel_cmd);
}

static int
zebra_config_write (struct vty *vty)
{
    if (! zclient->enable)
    {
        vty_out (vty, "no router zebra%s", VTY_NEWLINE);
        return 1;
    }
    else if (! vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_BABEL], VRF_DEFAULT))
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
