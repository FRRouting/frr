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

/* Zebra route add and delete treatment. */
static int
babel_zebra_read_route (ZAPI_CALLBACK_ARGS)
{
    struct zapi_route api;

    if (zapi_route_decode(zclient->ibuf, &api) < 0)
        return -1;

    /* we completely ignore srcdest routes for now. */
    if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
        return 0;

    if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD) {
        babel_route_add(&api);
    } else {
        babel_route_delete(&api);
    }

    return 0;
}

/* [Babel Command] */
DEFUN (babel_redistribute_type,
       babel_redistribute_type_cmd,
       "[no] redistribute <ipv4 " FRR_IP_REDIST_STR_BABELD "|ipv6 " FRR_IP6_REDIST_STR_BABELD ">",
       NO_STR
       "Redistribute\n"
       "Redistribute IPv4 routes\n"
       FRR_IP_REDIST_HELP_STR_BABELD
       "Redistribute IPv6 routes\n"
       FRR_IP6_REDIST_HELP_STR_BABELD)
{
    int negate = 0;
    int family;
    int afi;
    int type;
    int idx = 0;

    if (argv_find(argv, argc, "no", &idx))
        negate = 1;
    argv_find(argv, argc, "redistribute", &idx);
    family = str2family(argv[idx + 1]->text);
    if (family < 0)
        return CMD_WARNING_CONFIG_FAILED;

    afi = family2afi(family);
    if (!afi)
        return CMD_WARNING_CONFIG_FAILED;

    type = proto_redistnum(afi, argv[idx + 2]->text);
    if (type < 0) {
        vty_out (vty, "Invalid type %s\n", argv[idx + 2]->arg);
        return CMD_WARNING_CONFIG_FAILED;
    }

    if (!negate)
        zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type, 0, VRF_DEFAULT);
    else {
        zclient_redistribute (ZEBRA_REDISTRIBUTE_DELETE, zclient, afi, type, 0, VRF_DEFAULT);
        /* perhaps should we remove xroutes having the same type... */
    }
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

    vty_out (vty, "Invalid type %s\n", argv[2]->arg);

    return CMD_WARNING_CONFIG_FAILED;
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

    vty_out (vty, "Invalid type %s\n", argv[3]->arg);

    return CMD_WARNING_CONFIG_FAILED;
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
        vty_out (vty, "debug babel all\n");
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
                vty_out (vty, "debug babel %s\n", debug_type[i].str);
                lines++;
            }
    if (lines)
    {
        vty_out (vty, "!\n");
        lines++;
    }
    return lines;
#endif /* NO_DEBUG */
}

DEFUN_NOSH (show_debugging_babel,
	    show_debugging_babel_cmd,
	    "show debugging [babel]",
	    SHOW_STR
	    DEBUG_STR
	    "Babel")
{
	vty_out(vty, "BABEL debugging status\n");

	debug_babel_config_write(vty);

	return CMD_SUCCESS;
}

static void
babel_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

void babelz_zebra_init(void)
{
    zclient = zclient_new(master, &zclient_options_default);
    zclient_init(zclient, ZEBRA_ROUTE_BABEL, 0, &babeld_privs);

    zclient->zebra_connected = babel_zebra_connected;
    zclient->interface_address_add = babel_interface_address_add;
    zclient->interface_address_delete = babel_interface_address_delete;
    zclient->redistribute_route_add = babel_zebra_read_route;
    zclient->redistribute_route_del = babel_zebra_read_route;

    install_element(BABEL_NODE, &babel_redistribute_type_cmd);
    install_element(ENABLE_NODE, &debug_babel_cmd);
    install_element(ENABLE_NODE, &no_debug_babel_cmd);
    install_element(CONFIG_NODE, &debug_babel_cmd);
    install_element(CONFIG_NODE, &no_debug_babel_cmd);

    install_element(VIEW_NODE, &show_debugging_babel_cmd);
}

void
babel_zebra_close_connexion(void)
{
    zclient_stop(zclient);
    zclient_free(zclient);
}
