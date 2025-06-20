// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 19, 2025, fenglei <fengleiljx@gmail.com>
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "northbound.h"
#include "libfrr.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_nb.h"

/*
 * XPath: /frr-ospfd:clear-ospf-process
 */
int clear_ospf_process_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ospfd:clear-ospf-neighbor
 */
int clear_ospf_neighbor_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ospfd:clear-ospf-interface
 */
int clear_ospf_interface_rpc(struct nb_cb_rpc_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}
