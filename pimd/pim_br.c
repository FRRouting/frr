/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "if.h"

#include "pimd.h"
#include "pim_str.h"
#include "pim_br.h"
#include "linklist.h"

struct pim_br {
	struct prefix_sg sg;
	struct in_addr pmbr;
};

struct in_addr pim_br_unknown = {.s_addr = 0};

static struct list *pim_br_list = NULL;

struct in_addr pim_br_get_pmbr(struct prefix_sg *sg)
{
	struct listnode *node;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS_RO(pim_br_list, node, pim_br)) {
		if (sg->src.s_addr == pim_br->sg.src.s_addr
		    && sg->grp.s_addr == pim_br->sg.grp.s_addr)
			return pim_br->pmbr;
	}

	return pim_br_unknown;
}

void pim_br_set_pmbr(struct prefix_sg *sg, struct in_addr br)
{
	struct listnode *node, *next;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS(pim_br_list, node, next, pim_br)) {
		if (sg->src.s_addr == pim_br->sg.src.s_addr
		    && sg->grp.s_addr == pim_br->sg.grp.s_addr)
			break;
	}

	if (!pim_br) {
		pim_br = XCALLOC(MTYPE_PIM_BR, sizeof(*pim_br));
		if (!pim_br) {
			zlog_err("PIM XCALLOC(%zu) failure", sizeof(*pim_br));
			return;
		}

		pim_br->sg = *sg;

		listnode_add(pim_br_list, pim_br);
	}

	pim_br->pmbr = br;
}

/*
 * Remove the (S,G) from the stored values
 */
void pim_br_clear_pmbr(struct prefix_sg *sg)
{
	struct listnode *node, *next;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS(pim_br_list, node, next, pim_br)) {
		if (sg->src.s_addr == pim_br->sg.src.s_addr
		    && sg->grp.s_addr == pim_br->sg.grp.s_addr)
			break;
	}

	if (!pim_br)
		return;

	listnode_delete(pim_br_list, pim_br);
}

void pim_br_init(void)
{
	pim_br_list = list_new();
	if (!pim_br_list) {
		zlog_err("%s: Failure to create pim_br_list",
			 __PRETTY_FUNCTION__);
		return;
	}
}
