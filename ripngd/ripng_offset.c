// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPng offset-list
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

/* RIPng support by Vincent Jardin <vincent.jardin@6wind.com>
 * Copyright (C) 2002 6WIND
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "filter.h"
#include "command.h"
#include "linklist.h"
#include "memory.h"

#include "ripngd/ripngd.h"

DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_OFFSET_LIST, "RIPng offset lst");

#define OFFSET_LIST_IN_NAME(O)  ((O)->direct[RIPNG_OFFSET_LIST_IN].alist_name)
#define OFFSET_LIST_IN_METRIC(O)  ((O)->direct[RIPNG_OFFSET_LIST_IN].metric)

#define OFFSET_LIST_OUT_NAME(O)  ((O)->direct[RIPNG_OFFSET_LIST_OUT].alist_name)
#define OFFSET_LIST_OUT_METRIC(O)  ((O)->direct[RIPNG_OFFSET_LIST_OUT].metric)

struct ripng_offset_list *ripng_offset_list_new(struct ripng *ripng,
						const char *ifname)
{
	struct ripng_offset_list *new;

	new = XCALLOC(MTYPE_RIPNG_OFFSET_LIST,
		      sizeof(struct ripng_offset_list));
	new->ripng = ripng;
	new->ifname = strdup(ifname);
	listnode_add_sort(ripng->offset_list_master, new);

	return new;
}

void ripng_offset_list_del(struct ripng_offset_list *offset)
{
	listnode_delete(offset->ripng->offset_list_master, offset);
	ripng_offset_list_free(offset);
}

void ripng_offset_list_free(struct ripng_offset_list *offset)
{
	if (OFFSET_LIST_IN_NAME(offset))
		free(OFFSET_LIST_IN_NAME(offset));
	if (OFFSET_LIST_OUT_NAME(offset))
		free(OFFSET_LIST_OUT_NAME(offset));
	free(offset->ifname);
	XFREE(MTYPE_RIPNG_OFFSET_LIST, offset);
}

struct ripng_offset_list *ripng_offset_list_lookup(struct ripng *ripng,
						   const char *ifname)
{
	struct ripng_offset_list *offset;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ripng->offset_list_master, node, nnode,
			       offset)) {
		if (strcmp(offset->ifname, ifname) == 0)
			return offset;
	}
	return NULL;
}

/* If metric is modified return 1. */
int ripng_offset_list_apply_in(struct ripng *ripng, struct prefix_ipv6 *p,
			       struct interface *ifp, uint8_t *metric)
{
	struct ripng_offset_list *offset;
	struct access_list *alist;

	/* Look up offset-list with interface name. */
	offset = ripng_offset_list_lookup(ripng, ifp->name);
	if (offset && OFFSET_LIST_IN_NAME(offset)) {
		alist = access_list_lookup(AFI_IP6,
					   OFFSET_LIST_IN_NAME(offset));

		if (alist && access_list_apply(alist, (struct prefix *)p) ==
				     FILTER_PERMIT) {
			*metric += OFFSET_LIST_IN_METRIC(offset);
			return 1;
		}
		return 0;
	}
	/* Look up offset-list without interface name. */
	offset = ripng_offset_list_lookup(ripng, "*");
	if (offset && OFFSET_LIST_IN_NAME(offset)) {
		alist = access_list_lookup(AFI_IP6,
					   OFFSET_LIST_IN_NAME(offset));

		if (alist && access_list_apply(alist, (struct prefix *)p) ==
				     FILTER_PERMIT) {
			*metric += OFFSET_LIST_IN_METRIC(offset);
			return 1;
		}
		return 0;
	}
	return 0;
}

/* If metric is modified return 1. */
int ripng_offset_list_apply_out(struct ripng *ripng, struct prefix_ipv6 *p,
				struct interface *ifp, uint8_t *metric)
{
	struct ripng_offset_list *offset;
	struct access_list *alist;

	/* Look up offset-list with interface name. */
	offset = ripng_offset_list_lookup(ripng, ifp->name);
	if (offset && OFFSET_LIST_OUT_NAME(offset)) {
		alist = access_list_lookup(AFI_IP6,
					   OFFSET_LIST_OUT_NAME(offset));

		if (alist && access_list_apply(alist, (struct prefix *)p) ==
				     FILTER_PERMIT) {
			*metric += OFFSET_LIST_OUT_METRIC(offset);
			return 1;
		}
		return 0;
	}

	/* Look up offset-list without interface name. */
	offset = ripng_offset_list_lookup(ripng, "*");
	if (offset && OFFSET_LIST_OUT_NAME(offset)) {
		alist = access_list_lookup(AFI_IP6,
					   OFFSET_LIST_OUT_NAME(offset));

		if (alist && access_list_apply(alist, (struct prefix *)p) ==
				     FILTER_PERMIT) {
			*metric += OFFSET_LIST_OUT_METRIC(offset);
			return 1;
		}
		return 0;
	}
	return 0;
}

int offset_list_cmp(struct ripng_offset_list *o1, struct ripng_offset_list *o2)
{
	return strcmp(o1->ifname, o2->ifname);
}
