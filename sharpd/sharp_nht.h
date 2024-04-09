// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHARP - code to track nexthops
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __SHARP_NHT_H__
#define __SHARP_NHT_H__

struct sharp_nh_tracker {
	/* What are we watching */
	struct prefix p;

	/* Number of valid nexthops */
	uint32_t nhop_num;

	uint32_t updates;
};

extern struct sharp_nh_tracker *sharp_nh_tracker_get(struct prefix *p);
extern void sharp_nh_tracker_free(struct sharp_nh_tracker *nht);

extern void sharp_nh_tracker_dump(struct vty *vty);

extern uint32_t sharp_nhgroup_get_id(const char *name);
extern void sharp_nhgroup_id_set_installed(uint32_t id, bool installed);
extern bool sharp_nhgroup_id_is_installed(uint32_t id);

extern void sharp_nhgroup_init(void);
#endif
