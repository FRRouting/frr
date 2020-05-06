/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#ifndef _FRR_PATH_UTIL_H_
#define _FRR_PATH_UTIL_H_

#include "lib/ipaddr.h"

#define IPADDR_COPY(DEST_PTR, SRC_PTR)                                         \
	do {                                                                   \
		memset((DEST_PTR), 0, sizeof(struct ipaddr));                  \
		(DEST_PTR)->ipa_type = (SRC_PTR)->ipa_type;                    \
		if ((SRC_PTR)->ipa_type == IPADDR_V4) {                        \
			memcpy(&(DEST_PTR)->ipaddr_v4, &(SRC_PTR)->ipaddr_v4,  \
			       sizeof(struct in_addr));                        \
		} else if ((SRC_PTR)->ipa_type == IPADDR_V6) {                 \
			memcpy(&(DEST_PTR)->ipaddr_v6, &(SRC_PTR)->ipaddr_v6,  \
			       sizeof(struct in6_addr));                       \
		}                                                              \
	} while (0)                                                            \

#endif /* _FRR_PATH__UTIL_H_ */
