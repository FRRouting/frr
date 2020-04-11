/*
 * SR-TE definitions
 * Copyright 2020 NetDef Inc.
 *                Sascha Kattelmann
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_SRTE_H
#define _FRR_SRTE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SRTE_POLICY_NAME_MAX_LENGTH 64

enum zebra_sr_policy_status {
	ZEBRA_SR_POLICY_UP = 0,
	ZEBRA_SR_POLICY_DOWN,
};

static inline int sr_policy_compare(const struct ipaddr *a_endpoint,
				    const struct ipaddr *b_endpoint,
				    uint32_t a_color, uint32_t b_color)
{
	int ret;

	ret = ipaddr_cmp(a_endpoint, b_endpoint);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	return a_color - b_color;
}

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SRTE_H */
