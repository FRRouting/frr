// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.c
 *                             Dynamic hostname cache
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "vty.h"
#include "linklist.h"
#include "memory.h"
#include "log.h"
#include "stream.h"
#include "command.h"
#include "if.h"
#include "frrevent.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_DYNHN, "ISIS dyn hostname");

static void dyn_cache_cleanup(struct event *);

void dyn_cache_init(struct isis *isis)
{
	isis->dyn_cache = list_new();
	if (!CHECK_FLAG(im->options, F_ISIS_UNIT_TEST))
		event_add_timer(master, dyn_cache_cleanup, isis, 120,
				&isis->t_dync_clean);
}

void dyn_cache_finish(struct isis *isis)
{
	struct listnode *node, *nnode;
	struct isis_dynhn *dyn;

	EVENT_OFF(isis->t_dync_clean);

	for (ALL_LIST_ELEMENTS(isis->dyn_cache, node, nnode, dyn)) {
		list_delete_node(isis->dyn_cache, node);
		XFREE(MTYPE_ISIS_DYNHN, dyn);
	}

	list_delete(&isis->dyn_cache);
}

static void dyn_cache_cleanup(struct event *thread)
{
	struct listnode *node, *nnode;
	struct isis_dynhn *dyn;
	time_t now = time(NULL);
	struct isis *isis = NULL;

	isis = EVENT_ARG(thread);

	isis->t_dync_clean = NULL;

	for (ALL_LIST_ELEMENTS(isis->dyn_cache, node, nnode, dyn)) {
		if ((now - dyn->refresh) < MAX_LSP_LIFETIME)
			continue;
		list_delete_node(isis->dyn_cache, node);
		XFREE(MTYPE_ISIS_DYNHN, dyn);
	}

	event_add_timer(master, dyn_cache_cleanup, isis, 120,
			&isis->t_dync_clean);
}

struct isis_dynhn *dynhn_find_by_id(struct isis *isis, const uint8_t *id)
{
	struct listnode *node = NULL;
	struct isis_dynhn *dyn = NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->dyn_cache, node, dyn))
		if (memcmp(dyn->id, id, ISIS_SYS_ID_LEN) == 0)
			return dyn;

	return NULL;
}

struct isis_dynhn *dynhn_find_by_name(struct isis *isis, const char *hostname)
{
	struct listnode *node = NULL;
	struct isis_dynhn *dyn = NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->dyn_cache, node, dyn))
		if (strncmp(dyn->hostname, hostname, 255) == 0)
			return dyn;

	return NULL;
}

void isis_dynhn_insert(struct isis *isis, const uint8_t *id,
		       const char *hostname, int level)
{
	struct isis_dynhn *dyn;

	dyn = dynhn_find_by_id(isis, id);
	if (!dyn) {
		dyn = XCALLOC(MTYPE_ISIS_DYNHN, sizeof(struct isis_dynhn));
		memcpy(dyn->id, id, ISIS_SYS_ID_LEN);
		dyn->level = level;
		listnode_add(isis->dyn_cache, dyn);
	}

	snprintf(dyn->hostname, sizeof(dyn->hostname), "%s", hostname);
	dyn->refresh = time(NULL);
}

void isis_dynhn_remove(struct isis *isis, const uint8_t *id)
{
	struct isis_dynhn *dyn;

	dyn = dynhn_find_by_id(isis, id);
	if (!dyn)
		return;
	listnode_delete(isis->dyn_cache, dyn);
	XFREE(MTYPE_ISIS_DYNHN, dyn);
}

/*
 * Level  System ID      Dynamic Hostname  (notag)
 *  2     0000.0000.0001 foo-gw
 *  2     0000.0000.0002 bar-gw
 *      * 0000.0000.0004 this-gw
 */
void dynhn_print_all(struct vty *vty, struct isis *isis)
{
	struct listnode *node;
	struct isis_dynhn *dyn;

	vty_out(vty, "vrf     : %s\n", isis->name);
	if (!isis->sysid_set)
		return;
	vty_out(vty, "Level  System ID      Dynamic Hostname\n");
	for (ALL_LIST_ELEMENTS_RO(isis->dyn_cache, node, dyn)) {
		vty_out(vty, "%-7d", dyn->level);
		vty_out(vty, "%pSY %-15s\n", dyn->id, dyn->hostname);
	}

	vty_out(vty, "     * %pSY %s\n", isis->sysid, cmd_hostname_get());
	return;
}

struct isis_dynhn *dynhn_snmp_next(struct isis *isis, const uint8_t *id,
				   int level)
{
	struct listnode *node = NULL;
	struct isis_dynhn *dyn = NULL;
	struct isis_dynhn *found_dyn = NULL;
	int res;

	for (ALL_LIST_ELEMENTS_RO(isis->dyn_cache, node, dyn)) {
		res = memcmp(dyn->id, id, ISIS_SYS_ID_LEN);

		if (res < 0)
			continue;

		if (res == 0 && dyn->level <= level)
			continue;

		if (res == 0) {
			/*
			 * This is the best match, we can stop
			 * searching
			 */

			found_dyn = dyn;
			break;
		}

		if (found_dyn == NULL
		    || memcmp(dyn->id, found_dyn->id, ISIS_SYS_ID_LEN) < 0) {
			found_dyn = dyn;
		}
	}

	return found_dyn;
}
