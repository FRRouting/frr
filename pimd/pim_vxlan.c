/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <zebra.h>

#include <hash.h>
#include <jhash.h>
#include <log.h>
#include <prefix.h>
#include <vrf.h>

#include "pimd.h"
#include "pim_iface.h"
#include "pim_memory.h"
#include "pim_oil.h"
#include "pim_register.h"
#include "pim_str.h"
#include "pim_upstream.h"
#include "pim_ifchannel.h"
#include "pim_nht.h"
#include "pim_zebra.h"
#include "pim_vxlan.h"


/************************** vxlan SG cache management ************************/
static unsigned int pim_vxlan_sg_hash_key_make(void *p)
{
	struct pim_vxlan_sg *vxlan_sg = p;

	return (jhash_2words(vxlan_sg->sg.src.s_addr,
				vxlan_sg->sg.grp.s_addr, 0));
}

static bool pim_vxlan_sg_hash_eq(const void *p1, const void *p2)
{
	const struct pim_vxlan_sg *sg1 = p1;
	const struct pim_vxlan_sg *sg2 = p2;

	return ((sg1->sg.src.s_addr == sg2->sg.src.s_addr)
			&& (sg1->sg.grp.s_addr == sg2->sg.grp.s_addr));
}

static struct pim_vxlan_sg *pim_vxlan_sg_new(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = XCALLOC(MTYPE_PIM_VXLAN_SG, sizeof(*vxlan_sg));

	vxlan_sg->pim = pim;
	vxlan_sg->sg = *sg;
	pim_str_sg_set(sg, vxlan_sg->sg_str);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s alloc", vxlan_sg->sg_str);

	vxlan_sg = hash_get(pim->vxlan.sg_hash, vxlan_sg, hash_alloc_intern);

	return vxlan_sg;
}

struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg lookup;

	lookup.sg = *sg;
	return hash_lookup(pim->vxlan.sg_hash, &lookup);
}

struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (vxlan_sg)
		return vxlan_sg;

	vxlan_sg = pim_vxlan_sg_new(pim, sg);

	return vxlan_sg;
}

void pim_vxlan_sg_del(struct pim_instance *pim, struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (!vxlan_sg)
		return;

	hash_release(vxlan_sg->pim->vxlan.sg_hash, vxlan_sg);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s free", vxlan_sg->sg_str);

	XFREE(MTYPE_PIM_VXLAN_SG, vxlan_sg);
}

void pim_vxlan_init(struct pim_instance *pim)
{
	char hash_name[64];

	snprintf(hash_name, sizeof(hash_name),
		"PIM %s vxlan SG hash", pim->vrf->name);
	pim->vxlan.sg_hash = hash_create(pim_vxlan_sg_hash_key_make,
			pim_vxlan_sg_hash_eq, hash_name);
}

void pim_vxlan_exit(struct pim_instance *pim)
{
	if (pim->vxlan.sg_hash) {
		hash_clean(pim->vxlan.sg_hash, NULL);
		hash_free(pim->vxlan.sg_hash);
		pim->vxlan.sg_hash = NULL;
	}
}
