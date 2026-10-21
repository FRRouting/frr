// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR traffic class model (QoS 2.21)
 * Copyright (C) 2026 Aviz Networks
 */
#ifndef __PBR_TC_H__
#define __PBR_TC_H__

#include "pbr.h"

struct vty;

/*
 * The system-wide traffic class model: 8 classes (0..7), a default class
 * and the skb->mark bits that carry the class across Linux forwarding
 * (routed IPv4 rewrites skb->priority from the TOS byte).
 */
struct pbr_tc_model {
	uint8_t default_tc;
	uint32_t mark_mask;	  /* 0 = mark carrier off */
	char *name[PBR_TC_COUNT]; /* NULL = built-in name */
};

extern struct pbr_tc_model pbr_tc;

extern void pbr_tc_init(void);
extern void pbr_tc_terminate(void);

extern const char *pbr_tc_name(uint8_t tc);
extern int pbr_tc_set_name(uint8_t tc, const char *name);
extern void pbr_tc_set_default(uint8_t tc);
extern void pbr_tc_set_mark_mask(uint32_t mask);

extern void pbr_tc_config_write(struct vty *vty);

#endif
