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
	pim_sgaddr sg;
	pim_addr pmbr;
};

static struct list *pim_br_list = NULL;

pim_addr pim_br_get_pmbr(pim_sgaddr *sg)
{
	struct listnode *node;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS_RO(pim_br_list, node, pim_br)) {
		if (!pim_sgaddr_cmp(*sg, pim_br->sg))
			return pim_br->pmbr;
	}

	return PIMADDR_ANY;
}

void pim_br_set_pmbr(pim_sgaddr *sg, pim_addr br)
{
	struct listnode *node, *next;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS(pim_br_list, node, next, pim_br)) {
		if (!pim_sgaddr_cmp(*sg, pim_br->sg))
			break;
	}

	if (!pim_br) {
		pim_br = XCALLOC(MTYPE_PIM_BR, sizeof(*pim_br));
		pim_br->sg = *sg;

		listnode_add(pim_br_list, pim_br);
	}

	pim_br->pmbr = br;
}

/*
 * Remove the (S,G) from the stored values
 */
void pim_br_clear_pmbr(pim_sgaddr *sg)
{
	struct listnode *node, *next;
	struct pim_br *pim_br;

	for (ALL_LIST_ELEMENTS(pim_br_list, node, next, pim_br)) {
		if (!pim_sgaddr_cmp(*sg, pim_br->sg))
			break;
	}

	if (!pim_br)
		return;

	listnode_delete(pim_br_list, pim_br);
}

void pim_br_init(void)
{
	pim_br_list = list_new();
}
