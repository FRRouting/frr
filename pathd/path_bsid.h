/*
 * Copyright 2022 6WIND S.A.
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

#ifndef _FRR_PATH_BSID_H_
#define _FRR_PATH_BSID_H_

#include "lib/mpls.h"
#include "lib/debug.h"
#include "lib/vty.h"

#define SRTE_BSID_LOWER_BOUND 24000
#define SRTE_BSID_UPPER_BOUND 64000

struct srte_label_block {
#define SRTE_LABEL_BLOCK_ACTIVE 0x1
#define SRTE_LABEL_BLOCK_NEEDED 0x2
	uint16_t flags;
	uint32_t conf_lower_bound;
	uint32_t conf_upper_bound;
	uint32_t start;
	uint32_t end;
	uint32_t current;
	uint32_t max_block;
	uint64_t *used_mark;
};

extern struct srte_label_block srte_bsid_pool;
extern struct debug path_debug_bsid;

#define PATH_BSID_DEBUG_BASIC 0x01

#define PATH_BSID_DEBUG(fmt, ...)                                              \
	do {                                                                   \
		if (DEBUG_FLAGS_CHECK(&path_debug_bsid,                        \
				      PATH_BSID_DEBUG_BASIC))                  \
			DEBUGD(&path_debug_bsid, "bsid: " fmt, ##__VA_ARGS__); \
	} while (0)

extern void path_bsid_init(void);
extern mpls_label_t path_bsid_request_label(void);
extern int path_bsid_release_label(mpls_label_t label);
extern bool path_bsid_configure_label_range(uint32_t lower_bound,
					    uint32_t upper_bound);
extern void path_bsid_show_debugging(struct vty *vty);
extern void path_bsid_is_allocated(void);
extern bool path_bsid_enable_pool(bool enable);

#endif /* _FRR_PATH_BSID_H_ */
