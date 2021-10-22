/* VxLAN common header.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef __VXLAN_H__
#define __VXLAN_H__

#ifdef __cplusplus
extern "C" {
#endif

/* EVPN MH DF election algorithm */
#define EVPN_MH_DF_ALG_SERVICE_CARVING 0
#define EVPN_MH_DF_ALG_HRW 1
#define EVPN_MH_DF_ALG_PREF 2

/* preference range for DF election */
#define EVPN_MH_DF_PREF_MIN 0
#define EVPN_MH_DF_PREF_DEFAULT 32767
#define EVPN_MH_DF_PREF_MAX 65535

/* VxLAN Network Identifier - 24-bit (RFC 7348) */
typedef uint32_t vni_t;
#define VNI_MAX 16777215 /* (2^24 - 1) */

/* Flooding mechanisms for BUM packets. */
/* Currently supported mechanisms are head-end (ingress) replication
 * (which is the default) and no flooding. Future options could be
 * using PIM-SM, PIM-Bidir etc.
 */
enum vxlan_flood_control {
	VXLAN_FLOOD_HEAD_END_REPL = 0,
	VXLAN_FLOOD_DISABLED,
	VXLAN_FLOOD_PIM_SM,
};

#ifdef __cplusplus
}
#endif

#endif /* __VXLAN_H__ */
