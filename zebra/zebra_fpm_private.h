/*
 * Private header file for the zebra FPM module.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#ifndef _ZEBRA_FPM_PRIVATE_H
#define _ZEBRA_FPM_PRIVATE_H

#include "zebra/debug.h"

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L

#define zfpm_debug(...)                                                        \
	do {                                                                   \
		if (IS_ZEBRA_DEBUG_FPM)                                        \
			zlog_debug("FPM: " __VA_ARGS__);                       \
	} while (0)

#elif defined __GNUC__

#define zfpm_debug(_args...)                                                   \
	do {                                                                   \
		if (IS_ZEBRA_DEBUG_FPM)                                        \
			zlog_debug("FPM: " _args);                             \
	} while (0)

#else
static inline void zfpm_debug(const char *format, ...)
{
	return;
}
#endif


/*
 * Externs
 */
extern int zfpm_netlink_encode_route(int cmd, rib_dest_t *dest,
				     struct route_entry *re, char *in_buf,
				     size_t in_buf_len);

extern int zfpm_protobuf_encode_route(rib_dest_t *dest, struct route_entry *re,
				      uint8_t *in_buf, size_t in_buf_len);

extern struct route_entry *zfpm_route_for_update(rib_dest_t *dest);
#endif /* _ZEBRA_FPM_PRIVATE_H */
