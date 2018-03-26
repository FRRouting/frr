/*
 * NetNS backend for non Linux systems
 * Copyright (C) 2018 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


#if !defined(GNU_LINUX) && (defined(SUNOS_5) || defined(OPEN_BSD))
/* SUNOS_5 or OPEN_BSD */

#include <zebra.h>
#include "ns.h"
#include "log.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, NS, "NetNS Context")
DEFINE_MTYPE_STATIC(LIB, NS_NAME, "NetNS Name")


static inline int ns_compare(const struct ns *ns, const struct ns *ns2);

RB_GENERATE(ns_head, ns, entry, ns_compare)

struct ns_head ns_tree = RB_INITIALIZER(&ns_tree);

static inline int ns_compare(const struct ns *a, const struct ns *b)
{
	return (a->ns_id - b->ns_id);
}

void ns_terminate(void)
{
}

/* API to initialize NETNS managerment
 * parameter is the default ns_id
 */
void ns_init_management(ns_id_t ns_id)
{
}


/*
 * NS utilities
 */

/* Create a socket serving for the given NS
 */
int ns_socket(int domain, int type, int protocol, ns_id_t ns_id)
{
	return -1;
}

/* return the path of the NETNS */
char *ns_netns_pathname(struct vty *vty, const char *name)
{
	return NULL;
}

/* Parse and execute a function on all the NETNS */
void ns_walk_func(int (*func)(struct ns *))
{
}

/* API to get the NETNS name, from the ns pointer */
const char *ns_get_name(struct ns *ns)
{
	return NULL;
}

/* only called from vrf ( when removing netns from vrf)
 * or at VRF or logical router termination
 */
void ns_delete(struct ns *ns)
{
}

/* return > 0 if netns is available
 * called by VRF to check netns backend is available for VRF
 */
int ns_have_netns(void)
{
	return 0;
}

/* API to get context information of a NS */
void *ns_info_lookup(ns_id_t ns_id)
{
	return NULL;
}

/*
 * NS init routine
 * should be called from backendx
 */
void ns_init(void)
{
}

/* API to retrieve default NS */
ns_id_t ns_get_default_id(void)
{
	return NS_UNKNOWN;
}


/* API that can be used to change from NS */
int ns_switchback_to_initial(void)
{
	return 0;
}
int ns_switch_to_netns(const char *netns_name)
{
	return 0;
}

/*
 * NS handling routines.
 * called by modules that use NS backend
 */

/* API to search for already present NETNS */
struct ns *ns_lookup(ns_id_t ns_id)
{
	return NULL;
}

struct ns *ns_lookup_name(const char *name)
{
	return NULL;
}

/* API to handle NS : creation, enable, disable
 * for enable, a callback function is passed as parameter
 * the callback belongs to the module that uses NS as backend
 * upon enabling the NETNS, the upper layer is informed
 */
int ns_enable(struct ns *ns, int (*func)(ns_id_t, void *))
{
	return 0;
}

ns_id_t ns_map_nsid_with_external(ns_id_t ns_id, bool maporunmap)
{
	return NS_UNKNOWN;
}

struct ns *ns_get_created(struct ns *ns, char *name, ns_id_t ns_id)
{
	return NULL;
}

void ns_disable(struct ns *ns)
{
}

#endif /* !GNU_LINUX */
