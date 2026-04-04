// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
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
struct zclient *babel_zclient;

/* Zebra route add and delete treatment. */
static int babel_zebra_read_route(ZAPI_CALLBACK_ARGS)
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
	uint8_t type;
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
	if (type == ZEBRA_ROUTE_ERROR) {
		vty_out(vty, "Invalid type %s\n", argv[idx + 2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!negate)
		zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, babel_zclient, afi, type, 0,
				     VRF_DEFAULT);
	else {
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, babel_zclient, afi, type, 0,
				     VRF_DEFAULT);
		/* perhaps should we remove xroutes having the same type... */
	}
	return CMD_SUCCESS;
}

DEFUN (debug_babel_all,
       debug_babel_all_cmd,
       "[no] debug babel all",
       NO_STR
       DEBUG_STR
       BABEL_DEBUG_DOC
       "All messages\n")
{
	zlog_debugflag_cli(_dbg_BABEL_COMMON, vty, argc, argv);
	zlog_debugflag_cli(_dbg_BABEL_KERNEL, vty, argc, argv);
	zlog_debugflag_cli(_dbg_BABEL_FILTER, vty, argc, argv);
	zlog_debugflag_cli(_dbg_BABEL_TIMEOUT, vty, argc, argv);
	zlog_debugflag_cli(_dbg_BABEL_IF, vty, argc, argv);
	zlog_debugflag_cli(_dbg_BABEL_ROUTE, vty, argc, argv);

	return CMD_SUCCESS;
}

static void babel_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static zclient_handler *const babel_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = babel_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = babel_interface_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = babel_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = babel_zebra_read_route,
};

void babelz_zebra_init(void)
{
	babel_zclient = zclient_new(master, &zclient_options_default, babel_handlers,
				    array_size(babel_handlers));
	zclient_init(babel_zclient, ZEBRA_ROUTE_BABEL, 0, &babeld_privs);

	babel_zclient->zebra_connected = babel_zebra_connected;

	install_element(BABEL_NODE, &babel_redistribute_type_cmd);
	install_element(ENABLE_NODE, &debug_babel_all_cmd);
	install_element(CONFIG_NODE, &debug_babel_all_cmd);
}

void babel_zebra_close_connexion(void)
{
	zclient_stop(babel_zclient);
	zclient_free(babel_zclient);
}
