/*
 * This is an implementation of RFC 3623 Graceful OSPF Restart.
 *
 * Author: Sascha Kattelmann <sascha@netdef.org>
 * Copyright 2020 6WIND (c), All rights reserved.
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

#ifndef _ZEBRA_OSPF_GR_H
#define _ZEBRA_OSPF_GR_H

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |      LS age     |Options |    9   |  A
 * +--------+--------+--------+--------+  |
 * |    3   |            0             |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Only type-9 is used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for GR.
 * |              Values ...           |  V
 * +--------+--------+--------+--------+ ---
 *
 * Opaque LSA's link state ID for Graceful Restart is 0x03000000.
 * Opaque Type: 3
 * opaque ID  : 0
 *
 */

#define IS_GR_LSA(header)                                                      \
	((header)->type == OSPF_OPAQUE_LINK_LSA                                \
	 && ntohl((header)->id.s_addr)                                         \
		    == SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0))

#define OSPF_GR_DEFAULT_GRACE_PERIOD 120
#define OSPF_GR_DEFAULT_PREPARE_PERIOD 120

#define GR_REASON_UNKNOWN 0 /* unknown */
#define GR_REASON_RESTART 1 /* software restart */
#define GR_REASON_UPGRADE 2 /* software reload/upgrade */
#define GR_REASON_SWITCH 3  /* switch to redundant control processer */

/* Prototypes. */
extern int ospf_gr_init(void);
extern void ospf_gr_term(void);

#endif /* _ZEBRA_OSPF_GR_H */
