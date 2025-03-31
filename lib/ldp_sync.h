// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Defines and structures common to LDP-Sync for OSPFv2 and OSPFv3 and ISIS
 * Copyright (C) 2020 Volta Networks, Inc.
 */

#ifndef _LIBLDPSYNC_H
#define _LIBLDPSYNC_H

#ifdef __cplusplus
extern "C" {
#endif

/* LDP-IGP Sync values */
#define LDP_SYNC_FLAG_ENABLE     (1 << 0) /* LDP-SYNC enabled */
#define LDP_SYNC_FLAG_HOLDDOWN   (1 << 1) /* Holddown timer enabled */
#define LDP_SYNC_FLAG_IF_CONFIG  (1 << 2) /* LDP-SYNC enabled on interface */
#define LDP_SYNC_FLAG_SET_METRIC (1 << 3) /* Metric has been set on ISIS intf */

#define LDP_IGP_SYNC_DEFAULT        0
#define LDP_IGP_SYNC_ENABLED        1

#define LDP_IGP_SYNC_STATE_NOT_REQUIRED     0
#define LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP  1
#define LDP_IGP_SYNC_STATE_REQUIRED_UP      2

#define LDP_IGP_SYNC_HOLDDOWN_DEFAULT 0

/* LDP-IGP Sync structures */
struct ldp_sync_info_cmd {
	uint16_t flags;
	uint16_t holddown;       /* timer value */
};

struct ldp_sync_info {
	uint16_t flags;          /* indicate if set on interface or globally */
	uint8_t enabled;         /* enabled */
	uint8_t state;           /* running state */
	uint16_t holddown;       /* timer value */
	struct event *t_holddown; /* holddown timer*/
	uint32_t metric[2];      /* isis interface metric */
};

/* Prototypes. */
extern struct ldp_sync_info *ldp_sync_info_create(void);
extern bool ldp_sync_if_is_enabled(struct ldp_sync_info *ldp_sync_info);
extern bool ldp_sync_if_down(struct ldp_sync_info *ldp_sync_info);
extern void ldp_sync_info_free(struct ldp_sync_info **ldp_sync_info);

struct ldp_igp_sync_announce {
	int proto;
};

struct ldp_igp_sync_if_state {
	ifindex_t ifindex;
	bool sync_start;
};

struct ldp_igp_sync_if_state_req {
	int proto;
	ifindex_t ifindex;
	char name[IFNAMSIZ];
};

#ifdef __cplusplus
}
#endif

#endif /* _LIBLDPSYNC_H */
