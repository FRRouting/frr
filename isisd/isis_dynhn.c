/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.c
 *                             Dynamic hostname cache
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "vty.h"
#include "linklist.h"
#include "memory.h"
#include "log.h"
#include "stream.h"
#include "command.h"
#include "if.h"
#include "thread.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"

extern struct host host;

struct list *dyn_cache = NULL;
static int dyn_cache_cleanup(struct thread *);

void dyn_cache_init(void)
{
	if (dyn_cache == NULL)
		dyn_cache = list_new();
	thread_add_timer(master, dyn_cache_cleanup, NULL, 120,
			 &isis->t_dync_clean);
	return;
}

static int dyn_cache_cleanup(struct thread *thread)
{
	struct listnode *node, *nnode;
	struct isis_dynhn *dyn;
	time_t now = time(NULL);

	isis->t_dync_clean = NULL;

	for (ALL_LIST_ELEMENTS(dyn_cache, node, nnode, dyn)) {
		if ((now - dyn->refresh) < MAX_LSP_LIFETIME)
			continue;

		list_delete_node(dyn_cache, node);
		XFREE(MTYPE_ISIS_DYNHN, dyn);
	}

	thread_add_timer(master, dyn_cache_cleanup, NULL, 120,
			 &isis->t_dync_clean);
	return ISIS_OK;
}

struct isis_dynhn *dynhn_find_by_id(const uint8_t *id)
{
	struct listnode *node = NULL;
	struct isis_dynhn *dyn = NULL;

	for (ALL_LIST_ELEMENTS_RO(dyn_cache, node, dyn))
		if (memcmp(dyn->id, id, ISIS_SYS_ID_LEN) == 0)
			return dyn;

	return NULL;
}

struct isis_dynhn *dynhn_find_by_name(const char *hostname)
{
	struct listnode *node = NULL;
	struct isis_dynhn *dyn = NULL;

	for (ALL_LIST_ELEMENTS_RO(dyn_cache, node, dyn))
		if (strncmp(dyn->hostname, hostname, 255) == 0)
			return dyn;

	return NULL;
}

void isis_dynhn_insert(const uint8_t *id, const char *hostname, int level)
{
	struct isis_dynhn *dyn;

	dyn = dynhn_find_by_id(id);
	if (!dyn) {
		dyn = XCALLOC(MTYPE_ISIS_DYNHN, sizeof(struct isis_dynhn));
		memcpy(dyn->id, id, ISIS_SYS_ID_LEN);
		dyn->level = level;
		listnode_add(dyn_cache, dyn);
	}

	snprintf(dyn->hostname, sizeof(dyn->hostname), "%s", hostname);
	dyn->refresh = time(NULL);
}

void isis_dynhn_remove(const uint8_t *id)
{
	struct isis_dynhn *dyn;

	dyn = dynhn_find_by_id(id);
	if (!dyn)
		return;
	listnode_delete(dyn_cache, dyn);
	XFREE(MTYPE_ISIS_DYNHN, dyn);
}

/*
 * Level  System ID      Dynamic Hostname  (notag)
 *  2     0000.0000.0001 foo-gw
 *  2     0000.0000.0002 bar-gw
 *      * 0000.0000.0004 this-gw
 */
void dynhn_print_all(struct vty *vty)
{
	struct listnode *node;
	struct isis_dynhn *dyn;

	vty_out(vty, "Level  System ID      Dynamic Hostname\n");
	for (ALL_LIST_ELEMENTS_RO(dyn_cache, node, dyn)) {
		vty_out(vty, "%-7d", dyn->level);
		vty_out(vty, "%-15s%-15s\n", sysid_print(dyn->id),
			dyn->hostname);
	}

	vty_out(vty, "     * %s %s\n", sysid_print(isis->sysid),
		cmd_hostname_get());
	return;
}
