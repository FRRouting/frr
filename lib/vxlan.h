// SPDX-License-Identifier: GPL-2.0-or-later
/* VxLAN common header.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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
