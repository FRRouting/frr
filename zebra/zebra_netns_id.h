/* zebra NETNS ID handling routines
 * Copyright (C) 2018 6WIND
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
#if !defined(__ZEBRA_NS_ID_H__)
#define __ZEBRA_NS_ID_H__
#include "zebra.h"
#include "ns.h"

#ifdef __cplusplus
extern "C" {
#endif

extern ns_id_t zebra_ns_id_get(const char *netnspath, int fd);
extern ns_id_t zebra_ns_id_get_default(void);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NS_ID_H__ */
