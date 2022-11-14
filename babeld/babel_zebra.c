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

/* clang-format off */
DEFINE_DEBUGFLAG(BABEL_COMMON, "babel common",
	"Babel information\n"
	"Common messages (default)\n"
);
DEFINE_DEBUGFLAG(BABEL_KERNEL, "babel kernel",
	"Babel information\n"
	"Kernel messages\n"
);
DEFINE_DEBUGFLAG(BABEL_FILTER, "babel filter",
	"Babel information\n"
	"Filter messages\n"
);
DEFINE_DEBUGFLAG(BABEL_TIMEOUT, "babel timeout",
	"Babel information\n"
	"Timeout messages\n"
);
DEFINE_DEBUGFLAG(BABEL_IF, "babel interface",
	"Babel information\n"
	"Interface messages\n"
);
DEFINE_DEBUGFLAG(BABEL_ROUTE, "babel route",
	"Babel information\n"
	"Route messages\n"
);
/* clang-format on */

void babelz_zebra_init(void);


/* we must use a pointer because of zclient.c's functions (new, free). */
struct zclient *zclient;

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

static void
babel_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

static zclient_handler *const babel_handlers[] = {
    [ZEBRA_INTERFACE_ADDRESS_ADD] = babel_interface_address_add,
    [ZEBRA_INTERFACE_ADDRESS_DELETE] = babel_interface_address_delete,
    [ZEBRA_REDISTRIBUTE_ROUTE_ADD] = babel_zebra_read_route,
    [ZEBRA_REDISTRIBUTE_ROUTE_DEL] = babel_zebra_read_route,
};

void babelz_zebra_init(void)
{
    zclient = zclient_new(master, &zclient_options_default, babel_handlers,
			  array_size(babel_handlers));
    zclient_init(zclient, ZEBRA_ROUTE_BABEL, 0, &babeld_privs);

    zclient->zebra_connected = babel_zebra_connected;

    install_element(BABEL_NODE, &babel_redistribute_type_cmd);
}

void
babel_zebra_close_connexion(void)
{
    zclient_stop(zclient);
    zclient_free(zclient);
}
