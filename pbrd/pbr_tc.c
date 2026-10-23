// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR traffic class model (QoS 2.21)
 * Copyright (C) 2026 Aviz Networks
 */
#include <zebra.h>

#include "memory.h"
#include "vty.h"
#include "linklist.h"
#include "vrf.h"

#include "pbrd/pbr_memory.h"

#include "pbrd/pbr_map.h"
#include "pbrd/pbr_tc.h"
#include "pbrd/pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_TC_NAME, "PBR traffic class name");

struct pbr_tc_model pbr_tc;

/* IEEE 802.1Q-style default names */
static const char *const pbr_tc_default_names[PBR_TC_COUNT] = {
	"best-effort",	   "background", "spare", "excellent-effort",
	"controlled-load", "video",	 "voice", "network-control",
};

void pbr_tc_init(void)
{
	memset(&pbr_tc, 0, sizeof(pbr_tc));
	pbr_tc.default_tc = PBR_TC_DEFAULT;
	pbr_tc.mark_mask = PBR_TC_MARK_MASK_DFLT;
}

void pbr_tc_terminate(void)
{
	for (int i = 0; i < PBR_TC_COUNT; i++)
		XFREE(MTYPE_PBR_TC_NAME, pbr_tc.name[i]);
}

const char *pbr_tc_name(uint8_t tc)
{
	if (tc > PBR_TC_MAX)
		return "?";

	return pbr_tc.name[tc] ? pbr_tc.name[tc] : pbr_tc_default_names[tc];
}

int pbr_tc_set_name(uint8_t tc, const char *name)
{
	if (tc > PBR_TC_MAX)
		return -1;

	XFREE(MTYPE_PBR_TC_NAME, pbr_tc.name[tc]);
	if (name && strcmp(name, pbr_tc_default_names[tc]) != 0)
		pbr_tc.name[tc] = XSTRDUP(MTYPE_PBR_TC_NAME, name);

	return 0;
}

void pbr_tc_set_default(uint8_t tc)
{
	if (tc <= PBR_TC_MAX)
		pbr_tc.default_tc = tc;
}

/*
 * The mark mask travels with every rule, so a change re-sends every
 * sequence that sets a traffic class.
 */
void pbr_tc_set_mark_mask(uint32_t mask)
{
	struct pbr_map *pbrm;
	struct pbr_map_sequence *pbrms;
	struct listnode *node;

	if (pbr_tc.mark_mask == mask)
		return;

	pbr_tc.mark_mask = mask;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps)
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
			if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_TRAFFIC_CLASS))
				pbr_map_check(pbrms, true);
}

void pbr_tc_config_write(struct vty *vty)
{
	if (pbr_tc.default_tc != PBR_TC_DEFAULT)
		vty_out(vty, "pbr traffic-class default %u\n", pbr_tc.default_tc);

	if (pbr_tc.mark_mask != PBR_TC_MARK_MASK_DFLT)
		vty_out(vty, "pbr traffic-class mark-mask 0x%08x\n", pbr_tc.mark_mask);

	for (int i = 0; i < PBR_TC_COUNT; i++)
		if (pbr_tc.name[i])
			vty_out(vty, "pbr traffic-class %d name %s\n", i, pbr_tc.name[i]);
}
